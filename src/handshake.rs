// Copyright 2023 Divy Srivastava <dj.srivastava@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use tokio_uring::buf::IoBufMut;
use tokio_uring::net::TcpStream;
use tokio_uring::io::{self, AsyncBufReadExt, AsyncWriteExt};
use bytes::{Bytes, BytesMut};
use futures_util::stream::Stream;
use hyper::header::{HeaderValue, UPGRADE, CONNECTION};
use hyper::http::Request;
use hyper::upgrade::Upgraded;
use hyper::{Body, Response, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha1::{Digest, Sha1};
use std::pin::Pin;
use std::task::{Context, Poll};
use crate::WebSocketError;
use rand::Rng;

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Handles the WebSocket handshake for a given stream.
pub struct Handshake<S> {
    stream: S,
    buffer: BytesMut,
}

impl<S> Handshake<S>
where
    S: IoBufMut,
{
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buffer: BytesMut::with_capacity(4096),
        }
    }

    pub async fn perform_handshake(&mut self) -> Result<(), WebSocketError> {
        // Read handshake request from the stream.
        let (res, mut buf) = io::read_to_end(&mut self.stream, self.buffer.split()).await;
        res.map_err(|_| WebSocketError::HandshakeError)?;
        self.buffer = buf;

        // Parse HTTP request using hyper.
        let req = String::from_utf8_lossy(&self.buffer);
        let req: Request<Body> = req.parse().map_err(|_| WebSocketError::HandshakeError)?;

        // Extract the Sec-WebSocket-Key from headers.
        let key = req.headers().get("Sec-WebSocket-Key").ok_or(WebSocketError::HandshakeError)?;

        // Generate the Sec-WebSocket-Accept value.
        let mut sha1 = Sha1::new();
        sha1.update(key.as_bytes());
        sha1.update(WS_GUID);
        let accept_key = STANDARD.encode(sha1.finalize());

        // Create the response.
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            accept_key
        );

        // Write the handshake response to the stream.
        self.stream.write_all(response.as_bytes()).await.map_err(|_| WebSocketError::HandshakeError)?;

        Ok(())
    }

    /// Perform the client handshake for WebSocket.
    pub async fn client_handshake(
        &mut self,
        request: Request<Body>,
    ) -> Result<(Upgraded, Response<Body>), WebSocketError> {
        // Sending the request to the server.
        let response = self.send_request(request).await?;
        self.verify_response(&response)?;

        match hyper::upgrade::on(response).await {
            Ok(upgraded) => Ok((upgraded, response)),
            Err(_) => Err(WebSocketError::HandshakeError),
        }
    }

    /// Sends the handshake request.
    async fn send_request(&mut self, request: Request<Body>) -> Result<Response<Body>, WebSocketError> {
        // Write the request to the stream.
        let req_str = format!(
            "{} {} HTTP/1.1\r\n{}\r\n\r\n",
            request.method(),
            request.uri(),
            request.headers()
                .iter()
                .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
                .collect::<Vec<_>>()
                .join("\r\n")
        );
        self.stream.write_all(req_str.as_bytes()).await.map_err(|_| WebSocketError::HandshakeError)?;

        // Read the response from the server.
        let (res, mut buf) = io::read_to_end(&mut self.stream, self.buffer.split()).await;
        res.map_err(|_| WebSocketError::HandshakeError)?;
        self.buffer = buf;

        // Parse the response.
        let response_str = String::from_utf8_lossy(&self.buffer);
        let response: Response<Body> = response_str.parse().map_err(|_| WebSocketError::HandshakeError)?;

        Ok(response)
    }

    /// Verifies the handshake response.
    fn verify_response(&self, response: &Response<Body>) -> Result<(), WebSocketError> {
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(WebSocketError::InvalidStatusCode(response.status().as_u16()));
        }

        let headers = response.headers();

        if !headers
            .get("Upgrade")
            .and_then(|h| h.to_str().ok())
            .map(|h| h.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
        {
            return Err(WebSocketError::InvalidUpgradeHeader);
        }

        if !headers
            .get("Connection")
            .and_then(|h| h.to_str().ok())
            .map(|h| h.eq_ignore_ascii_case("Upgrade"))
            .unwrap_or(false)
        {
            return Err(WebSocketError::InvalidConnectionHeader);
        }

        Ok(())
    }

    /// Handles the client-side WebSocket handshake.
    pub async fn client(
        stream: TcpStream,
        request: Request<Body>,
    ) -> Result<(Upgraded, Response<Body>), WebSocketError> {
        let mut handshake = Handshake::new(stream);
        handshake.client_handshake(request).await
    }
}

/// Stream implementation for Handshake, which allows reading from the stream.
impl<S> Stream for Handshake<S>
where
    S: IoBufMut,
{
    type Item = Result<Bytes, WebSocketError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut buf = [0u8; 1024];

        match Pin::new(&mut this.stream).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(n)) if n == 0 => Poll::Ready(None),
            Poll::Ready(Ok(n)) => Poll::Ready(Some(Ok(Bytes::copy_from_slice(&buf[..n])))),
            Poll::Ready(Err(_)) => Poll::Ready(Some(Err(WebSocketError::ReadError))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Generate a random key for the `Sec-WebSocket-Key` header.
pub fn generate_key() -> String {
    let r: [u8; 16] = rand::thread_rng().gen();
    STANDARD.encode(r)
}
