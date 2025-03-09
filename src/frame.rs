use bytes::{Bytes, BytesMut};
use core::ops::Deref;

use crate::{WebSocketError, UringStream};

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
    fn from(borrowed: &'a mut [u8]) -> Payload<'a> {
        Payload::BorrowedMut(borrowed)
    }
}

impl<'a> From<&'a [u8]> for Payload<'a> {
    fn from(borrowed: &'a [u8]) -> Payload<'a> {
        Payload::Borrowed(borrowed)
    }
}

impl From<Vec<u8>> for Payload<'_> {
    fn from(owned: Vec<u8>) -> Self {
        Payload::Owned(owned)
    }
}

impl From<Payload<'_>> for Vec<u8> {
    fn from(cow: Payload<'_>) -> Self {
        match cow {
            Payload::Borrowed(borrowed) => borrowed.to_vec(),
            Payload::BorrowedMut(borrowed_mut) => borrowed_mut.to_vec(),
            Payload::Owned(owned) => owned,
            Payload::Bytes(b) => Vec::from(b),
        }
    }
}

impl Payload<'_> {
    #[inline(always)]
    pub fn to_mut(&mut self) -> &mut [u8] {
        match self {
            Payload::Borrowed(borrowed) => {
                *self = Payload::Owned(borrowed.to_owned());
                match self {
                    Payload::Owned(owned) => owned,
                    _ => unreachable!(),
                }
            }
            Payload::BorrowedMut(borrowed) => borrowed,
            Payload::Owned(ref mut owned) => owned,
            Payload::Bytes(b) => b.as_mut(),
        }
    }
}

impl<'a> PartialEq<&'_ [u8]> for Payload<'a> {
    fn eq(&self, other: &&'_ [u8]) -> bool {
        self.deref() == *other
    }
}

impl<'a, const N: usize> PartialEq<&'_ [u8; N]> for Payload<'a> {
    fn eq(&self, other: &&'_ [u8; N]) -> bool {
        self.deref() == *other
    }
}

pub struct Frame<'f> {
    pub fin: bool,
    pub opcode: OpCode,
    mask: Option<[u8; 4]>,
    pub payload: Payload<'f>,
}

const MAX_HEAD_SIZE: usize = 16;

impl<'f> Frame<'f> {
    pub fn new(fin: bool, opcode: OpCode, mask: Option<[u8; 4]>, payload: Payload<'f>) -> Self {
        Self { fin, opcode, mask, payload }
    }

    pub fn text(payload: Payload<'f>) -> Self {
        Self { fin: true, opcode: OpCode::Text, mask: None, payload }
    }

    pub fn binary(payload: Payload<'f>) -> Self {
        Self { fin: true, opcode: OpCode::Binary, mask: None, payload }
    }

    pub fn close(code: u16, reason: &[u8]) -> Self {
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason);
        Self { fin: true, opcode: OpCode::Close, mask: None, payload: payload.into() }
    }

    pub fn close_raw(payload: Payload<'f>) -> Self {
        Self { fin: true, opcode: OpCode::Close, mask: None, payload }
    }

    pub fn pong(payload: Payload<'f>) -> Self {
        Self { fin: true, opcode: OpCode::Pong, mask: None, payload }
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

    pub fn fmt_head(&mut self, head: &mut [u8]) -> usize {
        head[0] = (self.fin as u8) << 7 | (self.opcode as u8);
        let len = self.payload.len();
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

    pub fn make_header(&self) -> [u8; MAX_HEAD_SIZE] {
        let mut head = [0; MAX_HEAD_SIZE];
        self.fmt_head(&mut head);
        head
    }

    pub async fn writev<S>(&mut self, stream: &mut S) -> Result<(), WebSocketError>
    where
        S: UringStream,
    {
        let mut head = [0; MAX_HEAD_SIZE];
        let size = self.fmt_head(&mut head);
        let total = size + self.payload.len();

        let (res, _) = stream.write(head[..size].to_vec().into()).await;
        let mut n = res.map_err(WebSocketError::IoError)?;
        if n < size {
            let (res, _) = stream.write(head[n..size].to_vec().into()).await;
            n += res.map_err(WebSocketError::IoError)?;
        }

        if n == total {
            return Ok(());
        }

        let payload_offset = n - size;
        let mut remaining = &self.payload[payload_offset..];
        while !remaining.is_empty() {
            let (res, _) = stream.write(remaining.to_vec().into()).await;
            let written = res.map_err(WebSocketError::IoError)?;
            remaining = &remaining[written..];
        }

        Ok(())
    }

    pub fn write<'a>(&mut self, buf: &'a mut Vec<u8>) -> &'a [u8] {
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

pub fn is_control(opcode: OpCode) -> bool {
    matches!(opcode, OpCode::Close | OpCode::Ping | OpCode::Pong)
}
