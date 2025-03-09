#![cfg_attr(docsrs, feature(doc_cfg))]

mod close;
mod error;
mod fragment;
mod frame;
#[cfg(feature = "upgrade")]
#[cfg_attr(docsrs, doc(cfg(feature = "upgrade")))]
pub mod handshake;
mod mask;
#[cfg(feature = "upgrade")]
#[cfg_attr(docsrs, doc(cfg(feature = "upgrade")))]
pub mod upgrade;

use bytes::{Buf, Bytes, BytesMut};
#[cfg(feature = "unstable-split")]
use std::future::Future;

pub use crate::close::CloseCode;
pub use crate::error::WebSocketError;
pub use crate::fragment::FragmentCollector;
#[cfg(feature = "unstable-split")]
pub use crate::fragment::FragmentCollectorRead;
pub use crate::frame::{Frame, OpCode, Payload};
pub use crate::mask::unmask;

#[derive(Copy, Clone, PartialEq)]
pub enum Role {
    Server,
    Client,
}

pub(crate) struct WriteHalf {
    role: Role,
    closed: bool,
    vectored: bool,
    auto_apply_mask: bool,
    writev_threshold: usize,
    write_buffer: Vec<u8>,
}

pub(crate) struct ReadHalf {
    role: Role,
    auto_apply_mask: bool,
    auto_close: bool,
    auto_pong: bool,
    writev_threshold: usize,
    max_message_size: usize,
    buffer: BytesMut,
}

#[cfg(feature = "unstable-split")]
pub struct WebSocketRead<S> {
    stream: S,
    read_half: ReadHalf,
}

#[cfg(feature = "unstable-split")]
pub struct WebSocketWrite<S> {
    stream: S,
    write_half: WriteHalf,
}

// Custom trait for tokio-uring streams
pub trait UringStream {
    fn read(&mut self, buf: Vec<u8>) -> impl Future<Output = (std::io::Result<usize>, Vec<u8>)> + Send;
    fn write(&mut self, buf: Bytes) -> impl Future<Output = (std::io::Result<usize>, Bytes)> + Send;
}

impl UringStream for tokio_uring_rustls::TlsStream<rustls::ClientConnection> {
    fn read(&mut self, buf: Vec<u8>) -> impl Future<Output = (std::io::Result<usize>, Vec<u8>)> + Send {
        self.read(buf)
    }
    fn write(&mut self, buf: Bytes) -> impl Future<Output = (std::io::Result<usize>, Bytes)> + Send {
        self.write(buf)
    }
}

#[cfg(feature = "unstable-split")]
pub fn after_handshake_split<R, W>(
    read: R,
    write: W,
    role: Role,
) -> (WebSocketRead<R>, WebSocketWrite<W>)
where
    R: UringStream,
    W: UringStream,
{
    (
        WebSocketRead {
            stream: read,
            read_half: ReadHalf::after_handshake(role),
        },
        WebSocketWrite {
            stream: write,
            write_half: WriteHalf::after_handshake(role),
        },
    )
}

#[cfg(feature = "unstable-split")]
impl<S> WebSocketRead<S> {
    pub(crate) fn into_parts_internal(self) -> (S, ReadHalf) {
        (self.stream, self.read_half)
    }

    pub fn set_writev_threshold(&mut self, threshold: usize) {
        self.read_half.writev_threshold = threshold;
    }

    pub fn set_auto_close(&mut self, auto_close: bool) {
        self.read_half.auto_close = auto_close;
    }

    pub fn set_auto_pong(&mut self, auto_pong: bool) {
        self.read_half.auto_pong = auto_pong;
    }

    pub fn set_max_message_size(&mut self, max_message_size: usize) {
        self.read_half.max_message_size = max_message_size;
    }

    pub fn set_auto_apply_mask(&mut self, auto_apply_mask: bool) {
        self.read_half.auto_apply_mask = auto_apply_mask;
    }

    pub async fn read_frame<'f, R, E>(
        &mut self,
        send_fn: &mut impl FnMut(Frame<'f>) -> R,
    ) -> Result<Frame, WebSocketError>
    where
        S: UringStream,
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
        R: Future<Output = Result<(), E>>,
    {
        loop {
            let (res, obligated_send) = self.read_half.read_frame_inner(&mut self.stream).await;
            if let Some(frame) = obligated_send {
                send_fn(frame).await.map_err(|e| WebSocketError::SendError(e.into()))?;
            }
            if let Some(frame) = res? {
                break Ok(frame);
            }
        }
    }
}

#[cfg(feature = "unstable-split")]
impl<'f, S> WebSocketWrite<S> {
    pub fn set_writev(&mut self, vectored: bool) {
        self.write_half.vectored = vectored;
    }

    pub fn set_writev_threshold(&mut self, threshold: usize) {
        self.write_half.writev_threshold = threshold;
    }

    pub fn set_auto_apply_mask(&mut self, auto_apply_mask: bool) {
        self.write_half.auto_apply_mask = auto_apply_mask;
    }

    pub fn is_closed(&self) -> bool {
        self.write_half.closed
    }

    pub async fn write_frame(&mut self, frame: Frame<'f>) -> Result<(), WebSocketError>
    where
        S: UringStream,
    {
        self.write_half.write_frame(&mut self.stream, frame).await
    }

    pub async fn flush(&mut self) -> Result<(), WebSocketError>
    where
        S: UringStream,
    {
        flush(&mut self.stream).await
    }
}

#[inline]
async fn flush<S>(stream: &mut S) -> Result<(), WebSocketError>
where
    S: UringStream,
{
    let (res, _) = stream.write(Bytes::new()).await;
    res.map_err(WebSocketError::IoError)
}

pub struct WebSocket<S> {
    stream: S,
    write_half: WriteHalf,
    read_half: ReadHalf,
}

impl<'f, S> WebSocket<S> {
    pub fn after_handshake(stream: S, role: Role) -> Self
    where
        S: UringStream,
    {
        Self {
            stream,
            write_half: WriteHalf::after_handshake(role),
            read_half: ReadHalf::after_handshake(role),
        }
    }

    #[cfg(feature = "unstable-split")]
    pub fn split<R, W>(
        self,
        split_fn: impl FnOnce(S) -> (R, W),
    ) -> (WebSocketRead<R>, WebSocketWrite<W>)
    where
        S: UringStream,
        R: UringStream,
        W: UringStream,
    {
        let (stream, read, write) = self.into_parts_internal();
        let (r, w) = split_fn(stream);
        (
            WebSocketRead {
                stream: r,
                read_half: read,
            },
            WebSocketWrite {
                stream: w,
                write_half: write,
            },
        )
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    pub(crate) fn into_parts_internal(self) -> (S, ReadHalf, WriteHalf) {
        (self.stream, self.read_half, self.write_half)
    }

    pub fn set_writev(&mut self, vectored: bool) {
        self.write_half.vectored = vectored;
    }

    pub fn set_writev_threshold(&mut self, threshold: usize) {
        self.read_half.writev_threshold = threshold;
        self.write_half.writev_threshold = threshold;
    }

    pub fn set_auto_close(&mut self, auto_close: bool) {
        self.read_half.auto_close = auto_close;
    }

    pub fn set_auto_pong(&mut self, auto_pong: bool) {
        self.read_half.auto_pong = auto_pong;
    }

    pub fn set_max_message_size(&mut self, max_message_size: usize) {
        self.read_half.max_message_size = max_message_size;
    }

    pub fn set_auto_apply_mask(&mut self, auto_apply_mask: bool) {
        self.read_half.auto_apply_mask = auto_apply_mask;
        self.write_half.auto_apply_mask = auto_apply_mask;
    }

    pub fn is_closed(&self) -> bool {
        self.write_half.closed
    }

    pub async fn write_frame(&mut self, frame: Frame<'f>) -> Result<(), WebSocketError>
    where
        S: UringStream,
    {
        self.write_half.write_frame(&mut self.stream, frame).await?;
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<(), WebSocketError>
    where
        S: UringStream,
    {
        flush(&mut self.stream).await
    }

    pub async fn read_frame(&mut self) -> Result<Frame<'f>, WebSocketError>
    where
        S: UringStream,
    {
        loop {
            let (res, obligated_send) = self.read_half.read_frame_inner(&mut self.stream).await;
            let is_closed = self.write_half.closed;
            if let Some(frame) = obligated_send {
                if !is_closed {
                    self.write_half.write_frame(&mut self.stream, frame).await?;
                }
            }
            if let Some(frame) = res? {
                if is_closed && frame.opcode != OpCode::Close {
                    return Err(WebSocketError::ConnectionClosed);
                }
                break Ok(frame);
            }
        }
    }
}

const MAX_HEADER_SIZE: usize = 14;

impl ReadHalf {
    pub fn after_handshake(role: Role) -> Self {
        let buffer = BytesMut::with_capacity(8192);
        Self {
            role,
            auto_apply_mask: true,
            auto_close: true,
            auto_pong: true,
            writev_threshold: 1024,
            max_message_size: 64 << 20,
            buffer,
        }
    }

    pub(crate) async fn read_frame_inner<'f, S>(
        &mut self,
        stream: &mut S,
    ) -> (Result<Option<Frame<'f>>, WebSocketError>, Option<Frame<'f>>)
    where
        S: UringStream,
    {
        let mut frame = match self.parse_frame_header(stream).await {
            Ok(frame) => frame,
            Err(e) => return (Err(e), None),
        };

        if self.role == Role::Server && self.auto_apply_mask {
            frame.unmask()
        };

        match frame.opcode {
            OpCode::Close if self.auto_close => {
                match frame.payload.len() {
                    0 => {}
                    1 => return (Err(WebSocketError::InvalidCloseFrame), None),
                    _ => {
                        let code = close::CloseCode::from(u16::from_be_bytes(
                            frame.payload[0..2].try_into().unwrap(),
                        ));
                        #[cfg(feature = "simd")]
                        if simdutf8::basic::from_utf8(&frame.payload[2..]).is_err() {
                            return (Err(WebSocketError::InvalidUTF8), None);
                        }
                        #[cfg(not(feature = "simd"))]
                        if std::str::from_utf8(&frame.payload[2..]).is_err() {
                            return (Err(WebSocketError::InvalidUTF8), None);
                        }
                        if !code.is_allowed() {
                            return (
                                Err(WebSocketError::InvalidCloseCode),
                                Some(Frame::close(1002, &frame.payload[2..])),
                            );
                        }
                    }
                };
                let obligated_send = Frame::close_raw(frame.payload.to_owned().into());
                (Ok(Some(frame)), Some(obligated_send))
            }
            OpCode::Ping if self.auto_pong => {
                (Ok(None), Some(Frame::pong(frame.payload)))
            }
            OpCode::Text => {
                if frame.fin && !frame.is_utf8() {
                    (Err(WebSocketError::InvalidUTF8), None)
                } else {
                    (Ok(Some(frame)), None)
                }
            }
            _ => (Ok(Some(frame)), None),
        }
    }

    async fn parse_frame_header<'a, S>(
        &mut self,
        stream: &mut S,
    ) -> Result<Frame<'a>, WebSocketError>
    where
        S: UringStream,
    {
        macro_rules! eof {
            ($n:expr) => {{
                if $n == 0 {
                    return Err(WebSocketError::UnexpectedEOF);
                }
            }};
        }

        while self.buffer.remaining() < 2 {
            let (res, buf) = stream.read(self.buffer.to_vec()).await;
            let n = res.map_err(WebSocketError::IoError)?;
            self.buffer = BytesMut::from(&buf[..n]);
            eof!(n);
        }

        let fin = self.buffer[0] & 0b10000000 != 0;
        let rsv1 = self.buffer[0] & 0b01000000 != 0;
        let rsv2 = self.buffer[0] & 0b00100000 != 0;
        let rsv3 = self.buffer[0] & 0b00010000 != 0;

        if rsv1 || rsv2 || rsv3 {
            return Err(WebSocketError::ReservedBitsNotZero);
        }

        let opcode = frame::OpCode::try_from(self.buffer[0] & 0b00001111)?;
        let masked = self.buffer[1] & 0b10000000 != 0;
        let length_code = self.buffer[1] & 0x7F;
        let extra = match length_code {
            126 => 2,
            127 => 8,
            _ => 0,
        };

        self.buffer.advance(2);
        while self.buffer.remaining() < extra + masked as usize * 4 {
            let (res, buf) = stream.read(self.buffer.to_vec()).await;
            let n = res.map_err(WebSocketError::IoError)?;
            self.buffer = BytesMut::from(&buf[..n]);
            eof!(n);
        }

        let payload_len: usize = match extra {
            0 => usize::from(length_code),
            2 => self.buffer.get_u16() as usize,
            #[cfg(any(target_pointer_width = "64", target_pointer_width = "128"))]
            8 => self.buffer.get_u64() as usize,
            #[cfg(any(target_pointer_width = "8", target_pointer_width = "16", target_pointer_width = "32"))]
            8 => match usize::try_from(self.buffer.get_u64()) {
                Ok(length) => length,
                Err(_) => return Err(WebSocketError::FrameTooLarge),
            },
            _ => unreachable!(),
        };

        let mask = if masked {
            Some(self.buffer.get_u32().to_be_bytes())
        } else {
            None
        };

        if frame::is_control(opcode) && !fin {
            return Err(WebSocketError::ControlFrameFragmented);
        }

        if opcode == OpCode::Ping && payload_len > 125 {
            return Err(WebSocketError::PingFrameTooLarge);
        }

        if payload_len >= self.max_message_size {
            return Err(WebSocketError::FrameTooLarge);
        }

        self.buffer.reserve(payload_len + MAX_HEADER_SIZE);
        while payload_len > self.buffer.remaining() {
            let (res, buf) = stream.read(self.buffer.to_vec()).await;
            let n = res.map_err(WebSocketError::IoError)?;
            self.buffer = BytesMut::from(&buf[..n]);
            eof!(n);
        }

        let payload = self.buffer.split_to(payload_len);
        let frame = Frame::new(fin, opcode, mask, Payload::Bytes(payload));
        Ok(frame)
    }
}

impl WriteHalf {
    pub fn after_handshake(role: Role) -> Self {
        Self {
            role,
            closed: false,
            auto_apply_mask: true,
            vectored: true,
            writev_threshold: 1024,
            write_buffer: Vec::with_capacity(2),
        }
    }

    pub async fn write_frame<'a, S>(
        &'a mut self,
        stream: &mut S,
        mut frame: Frame<'a>,
    ) -> Result<(), WebSocketError>
    where
        S: UringStream,
    {
        if self.role == Role::Client && self.auto_apply_mask {
            frame.mask();
        }

        if frame.opcode == OpCode::Close {
            self.closed = true;
        } else if self.closed {
            return Err(WebSocketError::ConnectionClosed);
        }

        if self.vectored && frame.payload.len() > self.writev_threshold {
            frame.writev_uring(stream).await?;
        } else {
            let text = frame.write(&mut self.write_buffer);
            let (res, _) = stream.write(text.to_vec().into()).await;
            res.map_err(WebSocketError::IoError)?;
        }

        Ok(())
    }
}

// Add writev_uring to Frame (in frame.rs)
impl<'a> Frame<'a> {
    pub async fn writev_uring<S: UringStream>(&self, stream: &mut S) -> Result<(), WebSocketError> {
        let header = self.make_header();
        let mut payload = self.payload.to_vec();
        if let Some(mask) = self.mask {
            mask::apply_mask(&mut payload, mask);
        }
        let (res, _) = stream.write(header.to_vec().into()).await;
        res.map_err(WebSocketError::IoError)?;
        let (res, _) = stream.write(payload.into()).await;
        res.map_err(WebSocketError::IoError)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Tests would need a mock UringStream implementation; omitted for brevity
}
