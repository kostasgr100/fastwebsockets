
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper::header::{CONNECTION, UPGRADE};
use rand;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::future::Future;
use std::pin::Pin;

use crate::{Role, WebSocket, WebSocketError};

// Replace TokioIo with direct tokio-uring stream usage
use tokio_uring_rustls::TlsStream;
use rustls::ClientConnection;

// Custom trait for tokio-uring streams (optional, see notes)
pub trait UringStream {
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

/// Perform the client handshake for tokio-uring streams.
///
/// This function performs the WebSocket handshake over a tokio-uring TlsStream.
/// It takes an executor compatible with tokio-uring and a hyper Request.
///
/// # Example
/// ```rust
/// use fastwebsockets::handshake;
/// use fastwebsockets::WebSocket;
/// use hyper::{Request, body::Bytes, header::{UPGRADE, CONNECTION}};
/// use http_body_util::Empty;
/// use tokio_uring::net::TcpStream;
/// use tokio_uring_rustls::TlsConnector;
/// use rustls::pki_types::ServerName;
/// use std::future::Future;
/// use anyhow::Result;
///
/// async fn connect() -> Result<WebSocket<tokio_uring_rustls::TlsStream<rustls::ClientConnection>>> {
///     let stream = TcpStream::connect("gateway.discord.gg:443").await?;
///     let conn = TlsConnector::from(std::sync::Arc::new(rustls::client::ClientConfig::builder()
///         .with_root_certificates({
///             let mut roots = rustls::RootCertStore::empty();
///             roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| ta.to_owned()));
///             roots
///         })
///         .with_no_client_auth()));
///     let server_name = ServerName::try_from("gateway.discord.gg").unwrap();
///     let tls_stream = conn.connect(server_name, stream).await?;
///
///     let req = Request::builder()
///         .method("GET")
///         .uri("wss://gateway.discord.gg:443/?v=10&encoding=json")
///         .header("Host", "gateway.discord.gg")
///         .header(UPGRADE, "websocket")
///         .header(CONNECTION, "upgrade")
///         .header("Sec-WebSocket-Key", handshake::generate_key())
///         .header("Sec-WebSocket-Version", "13")
///         .body(Empty::<Bytes>::new())?;
///
///     let (ws, _) = handshake::client_uring(&SpawnExecutor, req, tls_stream).await?;
///     Ok(ws)
/// }
///
/// struct SpawnExecutor;
/// impl<Fut> hyper::rt::Executor<Fut> for SpawnExecutor
/// where
///     Fut: Future + Send + 'static,
///     Fut::Output: Send + 'static,
/// {
///     fn execute(&self, fut: Fut) {
///         tokio_uring::spawn(fut);
///     }
/// }
/// ```

pub async fn client_uring<E, B>(
    executor: &E,
    request: Request<B>,
    mut socket: tokio_uring_rustls::TlsStream<rustls::ClientConnection>,
) -> Result<(WebSocket<tokio_uring_rustls::TlsStream<rustls::ClientConnection>>, Response<Incoming>), WebSocketError>
where
    E: hyper::rt::Executor<Pin<Box<dyn Future<Output = ()> + Send>>>,
    B: hyper::body::Body + 'static + Send,
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
    res.map_err(|e| WebSocketError::IoError(e.to_string()))?;

    let mut response_buf = Vec::new();
    let mut temp_buf = vec![0u8; 1024];
    loop {
        let (res, buf) = socket.read(temp_buf).await;
        let n = res.map_err(|e| WebSocketError::IoError(e.to_string()))?;
        if n == 0 {
            return Err(WebSocketError::IoError("Connection closed during handshake".into()));
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
        .ok_or(WebSocketError::HTTPError(hyper::error::ErrorKind::Parse.into()))?;
    let header_bytes = &response_buf[..header_end];

    let response_str = std::str::from_utf8(header_bytes)
        .map_err(|_| WebSocketError::IoError("Invalid UTF-8 in handshake response".into()))?;
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
        .body(Incoming::new_empty())
        .unwrap();

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

/// Generate a random key for the `Sec-WebSocket-Key` header.
pub fn generate_key() -> String {
    let r: [u8; 16] = rand::random();
    STANDARD.encode(r)
}

// Keep the original client function for Tokio compatibility
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

// Original verify function (unchanged)
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

