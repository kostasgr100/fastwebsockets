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

use tokio_uring::buf::IoBuf;
use tokio_uring::buf::IoBufMut;
use tokio_uring::net::TcpStream;

use bytes::BytesMut;
use core::ops::Deref;
use std::io::IoSlice;

use crate::WebSocketError;

const MAX_HEAD_SIZE: usize = 14;

macro_rules! repr_u8 {
    ($(#[$meta:meta])* $vis:vis enum $name:ident {
      $($(#[$vmeta:meta])* $vname:ident $(= $val:expr)?,)*
    }) => {
      $(#[$meta])*
      $vis enum $name {
        $($(#[$vmeta])* $vname $(= $val)?,)*
      }

      impl core::convert::TryFrom<u8> for $name {
        type Error = WebSocketError;

        fn try_from(v: u8) -> Result<Self, Self::Error> {
          match v {
            $(x if x == $name::$vname as u8 => Ok($name::$vname),)*
            _ => Err(WebSocketError::InvalidValue),
          }
        }
      }
    }
}

pub enum Payload<'a> {
  BorrowedMut(&'a mut [u8]),
  Borrowed(&'a [u8]),
  Owned(Vec<u8>),
  Bytes(BytesMut),
}

impl<'a> core::fmt::Debug for Payload<'a> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Payload").field("len", &self.len()).finish()
  }
}

impl Deref for Payload<'_> {
  type Target = [u8];

  fn deref(&self) -> &Self::Target {
    match self {
      Payload::Borrowed(borrowed) => borrowed,
      Payload::BorrowedMut(borrowed_mut) => borrowed_mut,
      Payload::Owned(owned) => owned.as_ref(),
      Payload::Bytes(b) => b.as_ref(),
    }
  }
}

impl<'a> From<&'a mut [u8]> for Payload<'a> {
  fn from(buffer: &'a mut [u8]) -> Self {
    Payload::BorrowedMut(buffer)
  }
}

impl<'a> From<&'a [u8]> for Payload<'a> {
  fn from(buffer: &'a [u8]) -> Self {
    Payload::Borrowed(buffer)
  }
}

impl<'a> From<Vec<u8>> for Payload<'a> {
  fn from(buffer: Vec<u8>) -> Self {
    Payload::Owned(buffer)
  }
}

impl<'a> From<BytesMut> for Payload<'a> {
  fn from(buffer: BytesMut) -> Self {
    Payload::Bytes(buffer)
  }
}

impl<'a> Payload<'a> {
  pub fn len(&self) -> usize {
    match self {
      Payload::Borrowed(buffer) => buffer.len(),
      Payload::BorrowedMut(buffer) => buffer.len(),
      Payload::Owned(buffer) => buffer.len(),
      Payload::Bytes(buffer) => buffer.len(),
    }
  }
}

pub struct Frame<'a> {
  pub payload: Payload<'a>,
  pub mask: Option<[u8; 4]>,
  pub fin: bool,
  pub opcode: OpCode,
}

impl<'a> Frame<'a> {
  pub fn fmt_head(&self, head: &mut [u8]) -> usize {
    let len = self.payload.len();
    head[0] = self.opcode as u8;
    if self.fin {
      head[0] |= 0x80;
    }

    let size = if len < 126 {
      head[1] = len as u8;
      2
    } else if len < 65536 {
      head[1] = 126;
      head[2..4].copy_from_slice(&(len as u16).to_be_bytes());
      4
    } else {
      head[1] = 127;
      head[2..10].copy_from_slice(&(len as u64).to_be_bytes());
      10
    };

    if let Some(mask) = self.mask {
      head[1] |= 0x80;
      head[size..size + 4].copy_from_slice(&mask);
      size + 4
    } else {
      size
    }
  }

  pub async fn writev<S>(
    &mut self,
    stream: &mut S,
  ) -> Result<(), std::io::Error>
  where
    S: IoBufMut,
  {
    let mut head = [0; MAX_HEAD_SIZE];
    let size = self.fmt_head(&mut head);
    let total = size + self.payload.len();

    let mut b = [IoSlice::new(&head[..size]), IoSlice::new(&self.payload)];

    let mut n = stream.writev(&b).await?.0;
    if n == total {
      return Ok(());
    }

    // Slightly more optimized than (unstable) write_all_vectored for 2 iovecs.
    while n <= size {
      b[0] = IoSlice::new(&head[n..size]);
      n += stream.writev(&b).await?.0;
    }

    // Header out of the way.
    if n < total && n > size {
      let payload_offset = n - size;
      stream.write_all(&self.payload[payload_offset..]).await?;
    }

    Ok(())
  }

  /// Writes the frame to the buffer and returns a slice of the buffer containing the frame.
  pub fn write<'b>(&mut self, buf: &'b mut Vec<u8>) -> &'b [u8] {
    fn reserve_enough(buf: &mut Vec<u8>, len: usize) {
      if buf.len() < len {
        buf.resize(len, 0);
      }
    }
    let len = self.payload.len();
    reserve_enough(buf, len + MAX_HEAD_SIZE);

    let size = self.fmt_head(buf);
    buf[size..size + len].copy_from_slice(&self.payload);
    &buf[..size + len]
  }

  /// Optimized writing for multiple buffers using vectored IO
  pub async fn write_vectored<S>(
    &mut self,
    stream: &mut S,
  ) -> Result<(), std::io::Error>
  where
    S: IoBufMut,
  {
    let mut head = [0; MAX_HEAD_SIZE];
    let size = self.fmt_head(&mut head);

    let total_len = size + self.payload.len();
    let mut iovec = [IoSlice::new(&head[..size]), IoSlice::new(&self.payload)];

    let mut written = 0;
    while written < total_len {
      let (res, _) = stream.writev(&iovec).await;
      let n = res?;
      written += n;

      if written < size {
        iovec[0] = IoSlice::new(&head[written..size]);
      } else if written < total_len {
        let payload_offset = written.saturating_sub(size);
        iovec[1] = IoSlice::new(&self.payload[payload_offset..]);
      }
    }

    Ok(())
  }

  pub fn text(payload: Payload<'a>) -> Self {
    Self {
      fin: true,
      opcode: OpCode::Text,
      mask: None,
      payload,
    }
  }

  pub fn binary(payload: Payload<'a>) -> Self {
    Self {
      fin: true,
      opcode: OpCode::Binary,
      mask: None,
      payload,
    }
  }

  pub fn close(code: u16, reason: &[u8]) -> Self {
    let mut payload = Vec::with_capacity(2 + reason.len());
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(reason);

    Self {
      fin: true,
      opcode: OpCode::Close,
      mask: None,
      payload: payload.into(),
    }
  }

  pub fn close_raw(payload: Payload<'a>) -> Self {
    Self {
      fin: true,
      opcode: OpCode::Close,
      mask: None,
      payload,
    }
  }

  pub fn pong(payload: Payload<'a>) -> Self {
    Self {
      fin: true,
      opcode: OpCode::Pong,
      mask: None,
      payload,
    }
  }

  pub fn is_utf8(&self) -> bool {
    #[cfg(feature = "simd")]
    return simdutf8::basic::from_utf8(&self.payload).is_ok();

    #[cfg(not(feature = "simd"))]
    return std::str::from_utf8(&self.payload).is_ok();
  }

  pub fn mask(&mut self) {
    if let Some(mask) = self.mask {
      crate::mask::unmask(self.payload.to_mut(), mask);
    } else {
      let mask: [u8; 4] = rand::random();
      crate::mask::unmask(self.payload.to_mut(), mask);
      self.mask = Some(mask);
    }
  }

  pub fn unmask(&mut self) {
    if let Some(mask) = self.mask {
      crate::mask::unmask(self.payload.to_mut(), mask);
    }
  }
}

repr_u8! {
    #[repr(u8)]
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub enum OpCode {
        Continuation = 0x0,
        Text = 0x1,
        Binary = 0x2,
        Close = 0x8,
        Ping = 0x9,
        Pong = 0xA,
    }
}

#[inline]
pub fn is_control(opcode: OpCode) -> bool {
  matches!(opcode, OpCode::Close | OpCode::Ping | OpCode::Pong)
}

