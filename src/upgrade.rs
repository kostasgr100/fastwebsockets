use base64;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper::{Request, Response};
use sha1::Digest;
use sha1::Sha1;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::future::Future;

use crate::{Role, WebSocket, WebSocketError, UringStream};

// Note: We'll assume a tokio-uring compatible stream for the upgrade.
// For simplicity, this uses tokio_uring::net::TcpStream directly.
// If TLS is needed server-side, you'd wrap it with tokio_uring_rustls::TlsStream.

fn sec_websocket_protocol(key: &[u8]) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(key);
    sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"); // magic string
    let result = sha1.finalize();
    STANDARD.encode(&result[..])
}

type Error = WebSocketError;

pub struct IncomingUpgrade {
    key: String,
    on_upgrade: hyper::upgrade::OnUpgrade,
}

impl IncomingUpgrade {
    pub fn upgrade(self) -> Result<(Response<Empty<Bytes>>, UpgradeFut), Error> {
        let response = Response::builder()
            .status(hyper::StatusCode::SWITCHING_PROTOCOLS)
            .header(hyper::header::CONNECTION, "upgrade")
            .header(hyper::header::UPGRADE, "websocket")
            .header("Sec-WebSocket-Accept", self.key)
            .body(Empty::new())
            .expect("bug: failed to build response");

        let stream = UpgradeFut {
            inner: self.on_upgrade,
        };

        Ok((response, stream))
    }
}

#[cfg(feature = "with_axum")]
impl<S> axum_core::extract::FromRequestParts<S> for IncomingUpgrade
where
    S: Send + Sync,
{
    type Rejection = hyper::StatusCode;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let key = parts
            .headers
            .get("Sec-WebSocket-Key")
            .ok_or(hyper::StatusCode::BAD_REQUEST)?;
        if parts
            .headers
            .get("Sec-WebSocket-Version")
            .map(|v| v.as_bytes())
            != Some(b"13")
        {
            return Err(hyper::StatusCode::BAD_REQUEST);
        }

        let on_upgrade = parts
            .extensions
            .remove::<hyper::upgrade::OnUpgrade>()
            .ok_or(hyper::StatusCode::BAD_REQUEST)?;
        Ok(Self {
            on_upgrade,
            key: sec_websocket_protocol(key.as_bytes()),
        })
    }
}

#[pin_project::pin_project]
#[derive(Debug)]
pub struct UpgradeFut {
    #[pin]
    inner: hyper::upgrade::OnUpgrade,
}

// Implement UringStream for hyper::upgrade::Upgraded (requires a shim)
impl UringStream for tokio_uring::net::TcpStream {
    fn read(&mut self, buf: Vec<u8>) -> impl Future<Output = (std::io::Result<usize>, Vec<u8>)> + Send {
        self.read(buf)
    }
    fn write(&mut self, buf: Bytes) -> impl Future<Output = (std::io::Result<usize>, Bytes)> + Send {
        self.write(buf)
    }
}

pub fn upgrade<B>(
    mut request: impl std::borrow::BorrowMut<Request<B>>,
) -> Result<(Response<Empty<Bytes>>, UpgradeFut), Error> {
    let request = request.borrow_mut();

    let key = request
        .headers()
        .get("Sec-WebSocket-Key")
        .ok_or(WebSocketError::MissingSecWebSocketKey)?;
    if request
        .headers()
        .get("Sec-WebSocket-Version")
        .map(|v| v.as_bytes())
        != Some(b"13")
    {
        return Err(WebSocketError::InvalidSecWebsocketVersion);
    }

    let response = Response::builder()
        .status(hyper::StatusCode::SWITCHING_PROTOCOLS)
        .header(hyper::header::CONNECTION, "upgrade")
        .header(hyper::header::UPGRADE, "websocket")
        .header("Sec-WebSocket-Accept", sec_websocket_protocol(key.as_bytes()))
        .body(Empty::new())
        .expect("bug: failed to build response");

    let stream = UpgradeFut {
        inner: hyper::upgrade::on(request),
    };

    Ok((response, stream))
}

pub fn is_upgrade_request<B>(request: &hyper::Request<B>) -> bool {
    header_contains_value(request.headers(), hyper::header::CONNECTION, "Upgrade")
        && header_contains_value(request.headers(), hyper::header::UPGRADE, "websocket")
}

fn header_contains_value(
    headers: &hyper::HeaderMap,
    header: impl hyper::header::AsHeaderName,
    value: impl AsRef<[u8]>,
) -> bool {
    let value = value.as_ref();
    for header in headers.get_all(header) {
        if header
            .as_bytes()
            .split(|&c| c == b',')
            .any(|x| trim(x).eq_ignore_ascii_case(value))
        {
            return true;
        }
    }
    false
}

fn trim(data: &[u8]) -> &[u8] {
    trim_end(trim_start(data))
}

fn trim_start(data: &[u8]) -> &[u8] {
    if let Some(start) = data.iter().position(|x| !x.is_ascii_whitespace()) {
        &data[start..]
    } else {
        b""
    }
}

fn trim_end(data: &[u8]) -> &[u8] {
    if let Some(last) = data.iter().rposition(|x| !x.is_ascii_whitespace()) {
        &data[..last + 1]
    } else {
        b""
    }
}

impl std::future::Future for UpgradeFut {
    type Output = Result<WebSocket<tokio_uring::net::TcpStream>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.project();
        let upgraded = match this.inner.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(x) => x,
        };
        let tokio_stream = upgraded?;
        // Convert hyper::upgrade::Upgraded to tokio_uring::net::TcpStream
        // This requires unsafe or a tokio-uring-specific upgrade mechanism
        let tcp_stream = unsafe {
            tokio_uring::net::TcpStream::from_raw_fd(
                tokio_stream.into_inner().into_std()?.into_raw_fd(),
            )
        };
        Poll::Ready(Ok(WebSocket::after_handshake(tcp_stream, Role::Server)))
    }
}
