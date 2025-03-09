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

use crate::{error::WebSocketError, frame::Frame, OpCode, ReadHalf, WebSocket, WriteHalf};
#[cfg(feature = "unstable-split")]
use crate::WebSocketRead;
use crate::UringStream;

pub enum Fragment {
    Text(Option<utf8::Incomplete>, Vec<u8>),
    Binary(Vec<u8>),
}

impl Fragment {
    fn take_buffer(self) -> Vec<u8> {
        match self {
            Fragment::Text(_, buffer) => buffer,
            Fragment::Binary(buffer) => buffer,
        }
    }
}

pub struct FragmentCollector<S> {
    stream: S,
    read_half: ReadHalf,
    write_half: WriteHalf,
    fragments: Fragments,
}

impl<'f, S> FragmentCollector<S> {
    pub fn new(ws: WebSocket<S>) -> FragmentCollector<S>
    where
        S: UringStream,
    {
        let (stream, read_half, write_half) = ws.into_parts_internal();
        FragmentCollector {
            stream,
            read_half,
            write_half,
            fragments: Fragments::new(),
        }
    }

    pub async fn read_frame(&mut self) -> Result<Frame<'f>, WebSocketError>
    where
        S: UringStream,
    {
        loop {
            let (res, obligated_send) = self.read_half.read_frame_inner(&mut self.stream).await;
            let is_closed = self.write_half.closed;
            if let Some(obligated_send) = obligated_send {
                if !is_closed {
                    self.write_frame(obligated_send).await?;
                }
            }
            let Some(frame) = res? else {
                continue;
            };
            if is_closed && frame.opcode != OpCode::Close {
                return Err(WebSocketError::ConnectionClosed);
            }
            if let Some(frame) = self.fragments.accumulate(frame)? {
                return Ok(frame);
            }
        }
    }

    pub async fn write_frame(&mut self, frame: Frame<'f>) -> Result<(), WebSocketError>
    where
        S: UringStream,
    {
        self.write_half.write_frame(&mut self.stream, frame).await?;
        Ok(())
    }

    #[inline]
    pub fn into_inner(self) -> S {
        self.stream
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
    pub fn new(ws: WebSocketRead<S>) -> FragmentCollectorRead<S>
    where
        S: UringStream,
    {
        let (stream, read_half) = ws.into_parts_internal();
        FragmentCollectorRead {
            stream,
            read_half,
            fragments: Fragments::new(),
        }
    }

    pub async fn read_frame<R, E>(
        &mut self,
        send_fn: &mut impl FnMut(Frame<'f>) -> R,
    ) -> Result<Frame<'f>, WebSocketError>
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
            let Some(frame) = res? else {
                continue;
            };
            if let Some(frame) = self.fragments.accumulate(frame)? {
                return Ok(frame);
            }
        }
    }
}

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

    pub fn accumulate<'f>(&mut self, frame: Frame<'f>) -> Result<Option<Frame<'f>>, WebSocketError> {
        match frame.opcode {
            OpCode::Text | OpCode::Binary => {
                if frame.fin {
                    if self.fragments.is_some() {
                        return Err(WebSocketError::InvalidFragment);
                    }
                    return Ok(Some(Frame::new(true, frame.opcode, None, frame.payload)));
                } else {
                    self.fragments = match frame.opcode {
                        OpCode::Text => match utf8::decode(&frame.payload) {
                            Ok(text) => Some(Fragment::Text(None, text.as_bytes().to_vec())),
                            Err(utf8::DecodeError::Incomplete { valid_prefix, incomplete_suffix }) => {
                                Some(Fragment::Text(Some(incomplete_suffix), valid_prefix.as_bytes().to_vec()))
                            }
                            Err(utf8::DecodeError::Invalid { .. }) => return Err(WebSocketError::InvalidUTF8),
                        },
                        OpCode::Binary => Some(Fragment::Binary(frame.payload.into())),
                        _ => unreachable!(),
                    };
                    self.opcode = frame.opcode;
                }
            }
            OpCode::Continuation => match self.fragments.as_mut() {
                None => return Err(WebSocketError::InvalidContinuationFrame),
                Some(Fragment::Text(data, input)) => {
                    let mut tail = &frame.payload[..];
                    if let Some(mut incomplete) = data.take() {
                        if let Some((result, rest)) = incomplete.try_complete(&frame.payload) {
                            tail = rest;
                            match result {
                                Ok(text) => input.extend_from_slice(text.as_bytes()),
                                Err(_) => return Err(WebSocketError::InvalidUTF8),
                            }
                        } else {
                            tail = &[];
                            data.replace(incomplete);
                        }
                    }
                    match utf8::decode(tail) {
                        Ok(text) => input.extend_from_slice(text.as_bytes()),
                        Err(utf8::DecodeError::Incomplete { valid_prefix, incomplete_suffix }) => {
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
}
