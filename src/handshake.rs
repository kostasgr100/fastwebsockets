use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper::header::{CONNECTION, UPGRADE};
use rand;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::future::Future;
use std::pin::Pin;
use bytes::Bytes;
use std::io;
use http_body_util::{Empty, BodyExt};
use http_body_util::combinators::BoxBody;

use crate::{Role, WebSocket, WebSocketError};

use tokio_uring_rustls::TlsStream;
use rustls::ClientConnection;

pub trait UringStream: 'static {
    fn read(&mut self, buf: Vec<u8>) -> impl Future<Output = (std::io::Result<usize>, Vec<u8>)>;
    fn write(&mut self, buf: Bytes) -> impl Future<Output = (std::io::Result<usize>, Bytes)>;
}

impl UringStream for TlsStream<ClientConnection> {
    fn read(&mut self, buf: Vec<u8>) -> impl Future<Output = (std::io::Result<usize>, Vec<u8>)> {
        self.read(buf)
    }
    fn write(&mut self, buf: Bytes) -> impl Future<Output = (std::io::Result<usize>, Bytes)> {
        self.write(buf)
    }
}

pub async fn client_uring<E, B>(
    executor: &E,
    request: Request<B>,
    mut socket: TlsStream<ClientConnection>,
) -> Result<(WebSocket<TlsStream<ClientConnection>>, Response<Incoming>), WebSocketError>
where
    E: hyper::rt::Executor<Pin<Box<dyn Future<Output = ()>>>>,
    B: hyper::body::Body + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let uri = request.uri();
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let host = uri.host().unwrap_or("localhost");
    let ws_key = generate_key();
    let request_str = format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n",
        request.method(),
        path,
        host,
        ws_key
    );
    let request_bytes = Bytes::from(request_str);

    let (res, _) = socket.write(request_bytes).await;
    res.map_err(WebSocketError::IoError)?;

    let mut response_buf = Vec::new();
    let mut temp_buf = vec![0u8; 1024];
    loop {
        let (res, buf) = socket.read(temp_buf).await;
        let n = res.map_err(WebSocketError::IoError)?;
        if n == 0 {
            return Err(WebSocketError::IoError(
                io::Error::new(io::ErrorKind::BrokenPipe, "Connection closed during handshake")
            ));
        }
        response_buf.extend_from_slice(&buf[..n]);
        if response_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        temp_buf = buf;
    }

    let header_end = response_buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .ok_or_else(|| {
            WebSocketError::IoError(io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to parse HTTP headers",
            ))
        })?;
    let header_bytes = &response_buf[..header_end];

    let response_str = std::str::from_utf8(header_bytes)
        .map_err(|_| WebSocketError::IoError(
            io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 in handshake response")
        ))?;
    if !response_str.contains("HTTP/1.1 101") {
        let status = StatusCode::from_bytes(response_str.as_bytes().get(9..12).unwrap_or(b"500"))
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return Err(WebSocketError::InvalidStatusCode(status.as_u16()));
    }
    if !response_str.contains("Upgrade: websocket") || !response_str.contains("Connection: Upgrade") {
        return Err(WebSocketError::InvalidUpgradeHeader);
    }

    let response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "Upgrade")
        .body(Empty::<Bytes>::new().map_err(|_| unreachable!()).boxed())
        .map_err(|e| WebSocketError::HTTPError(hyper::Error::new(e)))?;

    let mut ws = WebSocket::after_handshake(socket, Role::Client);
    ws.set_auto_close(true);
    ws.set_auto_pong(true);
    ws.set_writev(false);

    Ok((ws, response))
}

pub fn generate_key() -> String {
    let r: [u8; 16] = rand::random();
    STANDARD.encode(r)
}

#[cfg(feature = "tokio")]
pub async fn client<S, E, B>(
    executor: &E,
    request: Request<B>,
    socket: S,
) -> Result<(WebSocket<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>, Response<Incoming>), WebSocketError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    E: hyper::rt::Executor<Pin<Box<dyn Future<Output = ()> + Send>>>,
    B: hyper::body::Body + 'static + Send,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(socket)).await?;
    let fut = Box::pin(async move {
        if let Err(e) = conn.with_upgrades().await {
            eprintln!("Error polling connection: {}", e);
        }
    });
    executor.execute(fut);

    let mut response = sender.send_request(request).await?;
    verify(&response)?;

    match hyper::upgrade::on(&mut response).await {
        Ok(upgraded) => Ok((
            WebSocket::after_handshake(hyper_util::rt::TokioIo::new(upgraded), Role::Client),
            response,
        )),
        Err(e) => Err(e.into()),
    }
}

fn verify(response: &Response<Incoming>) -> Result<(), WebSocketError> {
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(WebSocketError::InvalidStatusCode(response.status().as_u16()));
    }
    let headers = response.headers();
    if !headers.get(UPGRADE).and_then(|h| h.to_str().ok()).map(|h| h.eq_ignore_ascii_case("websocket")).unwrap_or(false) {
        return Err(WebSocketError::InvalidUpgradeHeader);
    }
    if !headers.get(CONNECTION).and_then(|h| h.to_str().ok()).map(|h| h.eq_ignore_ascii_case("Upgrade")).unwrap_or(false) {
        return Err(WebSocketError::InvalidConnectionHeader);
    }
    Ok(())
}
