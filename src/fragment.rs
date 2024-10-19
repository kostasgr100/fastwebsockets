// Copyright 2023 Divy Srivastava <dj.srivastava23@gmail.com>
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

#[cfg(feature = "unstable-split")]
use std::future::Future;

use crate::error::WebSocketError;
use crate::frame::Frame;
use crate::OpCode;
use crate::ReadHalf;
use crate::WebSocket;
#[cfg(feature = "unstable-split")]
use crate::WebSocketRead;
use crate::WriteHalf;
use tokio_uring::buf::{IoBuf, IoBufMut};
use tokio_uring::net::TcpStream;
use encoding_rs::UTF_8;

pub enum Fragment {
  Text(Option<utf8::Incomplete>, Vec<u8>),
  Binary(Vec<u8>),
}

impl Fragment {
  /// Returns the payload of the fragment.
  fn take_buffer(self) -> Vec<u8> {
    match self {
      Fragment::Text(_, buffer) => buffer,
      Fragment::Binary(buffer) => buffer,
    }
  }
}

/// Collects fragmented messages over a WebSocket connection and returns the completed message once all fragments have been received.
///
/// This is useful for applications that do not want to deal with fragmented messages and the default behavior of tungstenite.
/// The payload is buffered in memory until the final fragment is received
/// so use this when streaming messages is not an option.
///
/// # Example
///
/// ```
/// use tokio_uring::net::TcpStream;
/// use fastwebsockets::{WebSocket, FragmentCollector, OpCode, Role};
/// use anyhow::Result;
///
/// async fn handle_client(
///   socket: TcpStream,
/// ) -> Result<()> {
///   tokio_uring::start(async move {
///     let ws = WebSocket::after_handshake(socket, Role::Server).await?;
///     let mut ws = FragmentCollector::new(ws);
///     // Handle WebSocket connection...
///     Ok(())
///   })
/// }
/// ```
pub struct FragmentCollector<S> {
  socket: S,
  fragments: Option<Fragment>,
  opcode: OpCode,
}

impl<S> FragmentCollector<S>
where
  S: IoBufMut,
{
  pub fn new(socket: S) -> Self {
    Self {
      socket,
      fragments: None,
      opcode: OpCode::Text,
    }
  }

  pub async fn process_frame(&mut self, frame: Frame) -> Result<Option<Frame>, WebSocketError> {
    match frame.opcode {
      OpCode::Continuation => match self.fragments.as_mut() {
        None => {
          return Err(WebSocketError::InvalidContinuationFrame);
        }
        Some(Fragment::Text(data, input)) => {
          let mut tail = &frame.payload[..];
          if let Some(mut incomplete) = data.take() {
            if let Some((result, rest)) = incomplete.try_complete(&frame.payload) {
              tail = rest;
              match result {
                Ok(text) => {
                  input.extend_from_slice(text.as_bytes());
                }
                Err(_) => {
                  return Err(WebSocketError::InvalidUTF8);
                }
              }
            } else {
              tail = &[];
              data.replace(incomplete);
            }
          }

          match utf8::decode(tail) {
            Ok(text) => {
              input.extend_from_slice(text.as_bytes());
            }
            Err(utf8::DecodeError::Incomplete {
              valid_prefix,
              incomplete_suffix,
            }) => {
              input.extend_from_slice(valid_prefix.as_bytes());
              *data = Some(incomplete_suffix);
            }
            Err(utf8::DecodeError::Invalid { valid_prefix, .. }) => {
              input.extend_from_slice(valid_prefix.as_bytes());
              return Err(WebSocketError::InvalidUTF8);
            }
          }

          if frame.fin {
            return Ok(Some(Frame::new(
              true,
              self.opcode,
              None,
              self.fragments.take().unwrap().take_buffer().into(),
            )));
          }
        }
        Some(Fragment::Binary(data)) => {
          data.extend_from_slice(&frame.payload);
          if frame.fin {
            return Ok(Some(Frame::new(
              true,
              self.opcode,
              None,
              self.fragments.take().unwrap().take_buffer().into(),
            )));
          }
        }
      },
      _ => return Ok(Some(frame)),
    }

    Ok(None)
  }

  /// Accumulates frames into a single complete message.
  pub fn accumulate<'f>(&'f mut self, frame: Frame) -> impl Future<Output = Result<Option<Frame>, WebSocketError>> + 'f {
    async move {
      if self.fragments.is_none() {
        self.opcode = frame.opcode;
        self.fragments = Some(match frame.opcode {
          OpCode::Text => Fragment::Text(None, frame.payload.into()),
          OpCode::Binary => Fragment::Binary(frame.payload.into()),
          _ => return Ok(Some(frame)),
        });
      } else {
        match self.fragments.as_mut().unwrap() {
          Fragment::Text(_, data) | Fragment::Binary(data) => {
            data.extend_from_slice(&frame.payload);
          }
        }
      }

      if frame.fin {
        return Ok(Some(Frame::new(
          true,
          self.opcode,
          None,
          self.fragments.take().unwrap().take_buffer().into(),
        )));
      }

      Ok(None)
    }
  }

  /// Reads a WebSocket frame, collecting fragmented messages until the final frame is received and returns the completed message.
  ///
  /// Text frames payload is guaranteed to be valid UTF-8.
  pub async fn read_frame(&mut self) -> Result<Frame, WebSocketError>
  where
    S: IoBufMut,
  {
    loop {
      let frame = self.socket.read().await?;
      if let Some(frame) = self.fragments.as_mut().unwrap().accumulate(frame).await? {
        return Ok(frame);
      }
    }
  }

  /// See `WebSocket::write_frame`.
  pub async fn write_frame(
    &mut self,
    frame: Frame,
  ) -> Result<(), WebSocketError>
  where
    S: IoBufMut,
  {
    self.socket.write(frame.payload()).await?;
    Ok(())
  }

  /// Consumes the `FragmentCollector` and returns the underlying stream.
  #[inline]
  pub fn into_inner(self) -> S {
    self.socket
  }
}

#[cfg(feature = "unstable-split")]
pub struct FragmentCollectorRead<S> {
  stream: S,
  read_half: ReadHalf,
  fragments: Fragments,
}

#[cfg(feature = "unstable-split")]
impl<'f, S> FragmentCollectorRead<S> {
  /// Creates a new `FragmentCollector` with the provided `WebSocket`.
  pub fn new(ws: WebSocketRead<S>) -> FragmentCollectorRead<S>
  where
    S: IoBufMut,
  {
    let (stream, read_half) = ws.into_parts_internal();
    FragmentCollectorRead {
      stream,
      read_half,
      fragments: Fragments::new(),
    }
  }

  /// Reads a WebSocket frame, collecting fragmented messages until the final frame is received and returns the completed message.
  ///
  /// Text frames payload is guaranteed to be valid UTF-8.
  pub async fn read_frame<R, E>(
    &mut self,
    send_fn: &mut impl FnMut(Frame) -> R,
  ) -> Result<Frame, WebSocketError>
  where
    S: IoBufMut,
    E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    R: Future<Output = Result<(), E>>,
  {
    loop {
      let frame = self.read_half.read_frame_inner(&mut self.stream).await?;
      if let Some(frame) = self.fragments.accumulate(frame).await? {
        return Ok(frame);
      }
    }
  }
}

/// Accumulates potentially fragmented [`Frame`]s to defragment the incoming WebSocket stream.
struct Fragments {
  fragments: Option<Fragment>,
  opcode: OpCode,
}

impl Fragments {
  pub fn new() -> Self {
    Self {
      fragments: None,
      opcode: OpCode::Close,
    }
  }

  /// Accumulates a frame into the current fragment, returning a complete frame if finished.
  pub async fn accumulate(&mut self, frame: Frame) -> Result<Option<Frame>, WebSocketError> {
    if self.fragments.is_none() {
      self.opcode = frame.opcode;
      self.fragments = Some(match frame.opcode {
        OpCode::Text => Fragment::Text(None, frame.payload.into()),
        OpCode::Binary => Fragment::Binary(frame.payload.into()),
        _ => return Ok(Some(frame)),
      });
    } else {
      match self.fragments.as_mut().unwrap() {
        Fragment::Text(_, data) | Fragment::Binary(data) => {
          data.extend_from_slice(&frame.payload);
        }
      }
    }

    if frame.fin {
      return Ok(Some(Frame::new(
        true,
        self.opcode,
        None,
        self.fragments.take().unwrap().take_buffer().into(),
      )));
    }

    Ok(None)
  }
}

