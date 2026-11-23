use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 2: 32-bit frame lengths, media connections (ROLE_MEDIA), rich message bodies.
pub const PROTOCOL_VERSION: u8 = 2;

pub const ROLE_MAIN: u8 = 0;
pub const ROLE_PROBE: u8 = 1;
/// HELLO token carries a one-time pairing code; the server answers with PAIRED.
pub const ROLE_PAIR: u8 = 2;
/// Short-lived connection for attachment downloads (MEDIA_GET) and uploads (MEDIA_PUT).
pub const ROLE_MEDIA: u8 = 3;

pub const FRAME_HELLO: u8 = 0x01;
pub const FRAME_WELCOME: u8 = 0x02;
pub const FRAME_MSG: u8 = 0x03;
pub const FRAME_ACK: u8 = 0x04;
pub const FRAME_PING: u8 = 0x05;
pub const FRAME_PONG: u8 = 0x06;
pub const FRAME_SET_INTERVAL: u8 = 0x07;
pub const FRAME_BYE: u8 = 0x08;
pub const FRAME_PAIRED: u8 = 0x09;
pub const FRAME_MEDIA_GET: u8 = 0x0A;
pub const FRAME_MEDIA_DATA: u8 = 0x0B;
pub const FRAME_MEDIA_PUT: u8 = 0x0C;
pub const FRAME_MEDIA_PUT_ACK: u8 = 0x0D;
pub const FRAME_MEDIA_ERR: u8 = 0x0E;

pub const BYE_NORMAL: u8 = 0x00;
pub const BYE_REPLACED: u8 = 0x01;
pub const BYE_AUTH_FAILED: u8 = 0x02;
pub const BYE_BAD_VERSION: u8 = 0x03;
pub const BYE_PROTOCOL_ERROR: u8 = 0x04;
pub const BYE_SERVER_SHUTDOWN: u8 = 0x05;

pub const FALLBACK_INTERVAL_S: u16 = 60;
pub const PONG_TIMEOUT_S: u64 = 10;
pub const ACK_TIMEOUT_S: u64 = 5;
pub const PROBE_CAP_S: u64 = 60 * 60;
/// Probe server must never close idle connections before PROBE_CAP + 5 min (65 min).
pub const PROBE_SERVER_IDLE_S: u64 = PROBE_CAP_S + 5 * 60 + 30;

/// Frame header: type (u8) + payload length (u32 BE).
pub const HEADER_LEN: usize = 5;
pub const MAX_PAYLOAD_LEN: usize = 4 * 1024 * 1024;
pub const MAX_MSG_BODY_LEN: usize = MAX_PAYLOAD_LEN - 8;
/// Bytes of file data per MEDIA_DATA / MEDIA_PUT frame.
pub const MEDIA_CHUNK_LEN: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Hello {
        version: u8,
        role: u8,
        token: Vec<u8>,
        last_rx_seq: u64,
        interval_s: u16,
    },
    Welcome {
        last_rx_seq: u64,
    },
    Msg {
        seq: u64,
        body: Vec<u8>,
    },
    Ack {
        seq: u64,
    },
    Ping {
        nonce: u32,
    },
    Pong {
        nonce: u32,
    },
    SetInterval {
        interval_s: u16,
    },
    Bye {
        reason: u8,
    },
    /// Reply to a ROLE_PAIR HELLO: the new client's id and its wire token.
    Paired {
        client_id: String,
        token: String,
    },
    /// Phone -> server: send attachment `id` from byte `offset` (preview, or the full-size file).
    MediaGet {
        id: String,
        full: bool,
        offset: u64,
    },
    /// Server -> phone: one piece of the requested file; the last one ends at `total`.
    MediaData {
        total: u64,
        offset: u64,
        mime: String,
        name: String,
        data: Vec<u8>,
    },
    /// Phone -> server: one piece of an upload; the server answers MEDIA_PUT_ACK once it has `total`.
    MediaPut {
        id: String,
        offset: u64,
        total: u64,
        data: Vec<u8>,
    },
    MediaPutAck {
        id: String,
        received: u64,
    },
    MediaErr {
        message: String,
    },
}

pub fn bye_reason_name(reason: u8) -> &'static str {
    match reason {
        BYE_NORMAL => "normal",
        BYE_REPLACED => "replaced",
        BYE_AUTH_FAILED => "auth_failed",
        BYE_BAD_VERSION => "bad_version",
        BYE_PROTOCOL_ERROR => "protocol_error",
        BYE_SERVER_SHUTDOWN => "server_shutdown",
        _ => "unknown",
    }
}

fn put_str16(buf: &mut Vec<u8>, s: &str) -> Result<()> {
    if s.len() > u16::MAX as usize {
        bail!("string too long: {} bytes", s.len());
    }
    buf.extend_from_slice(&(s.len() as u16).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
    Ok(())
}

struct Rd<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            bail!("frame payload too short");
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into()?))
    }
    fn str16(&mut self) -> Result<String> {
        let n = u16::from_be_bytes(self.take(2)?.try_into()?) as usize;
        Ok(std::str::from_utf8(self.take(n)?)?.to_string())
    }
    fn rest(&mut self) -> Vec<u8> {
        let s = self.data[self.pos..].to_vec();
        self.pos = self.data.len();
        s
    }
}

impl Frame {
    pub fn frame_type(&self) -> u8 {
        match self {
            Frame::Hello { .. } => FRAME_HELLO,
            Frame::Welcome { .. } => FRAME_WELCOME,
            Frame::Msg { .. } => FRAME_MSG,
            Frame::Ack { .. } => FRAME_ACK,
            Frame::Ping { .. } => FRAME_PING,
            Frame::Pong { .. } => FRAME_PONG,
            Frame::SetInterval { .. } => FRAME_SET_INTERVAL,
            Frame::Bye { .. } => FRAME_BYE,
            Frame::Paired { .. } => FRAME_PAIRED,
            Frame::MediaGet { .. } => FRAME_MEDIA_GET,
            Frame::MediaData { .. } => FRAME_MEDIA_DATA,
            Frame::MediaPut { .. } => FRAME_MEDIA_PUT,
            Frame::MediaPutAck { .. } => FRAME_MEDIA_PUT_ACK,
            Frame::MediaErr { .. } => FRAME_MEDIA_ERR,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        match self {
            Frame::Hello {
                version,
                role,
                token,
                last_rx_seq,
                interval_s,
            } => {
                if token.len() > u8::MAX as usize {
                    bail!("HELLO token length {} exceeds 255", token.len());
                }
                payload.push(*version);
                payload.push(*role);
                payload.push(token.len() as u8);
                payload.extend_from_slice(token);
                payload.extend_from_slice(&last_rx_seq.to_be_bytes());
                payload.extend_from_slice(&interval_s.to_be_bytes());
            }
            Frame::Welcome { last_rx_seq } => {
                payload.extend_from_slice(&last_rx_seq.to_be_bytes());
            }
            Frame::Msg { seq, body } => {
                if body.len() > MAX_MSG_BODY_LEN {
                    bail!("MSG body length {} exceeds max {}", body.len(), MAX_MSG_BODY_LEN);
                }
                payload.reserve(8 + body.len());
                payload.extend_from_slice(&seq.to_be_bytes());
                payload.extend_from_slice(body);
            }
            Frame::Ack { seq } => {
                payload.extend_from_slice(&seq.to_be_bytes());
            }
            Frame::Ping { nonce } => {
                payload.extend_from_slice(&nonce.to_be_bytes());
            }
            Frame::Pong { nonce } => {
                payload.extend_from_slice(&nonce.to_be_bytes());
            }
            Frame::SetInterval { interval_s } => {
                payload.extend_from_slice(&interval_s.to_be_bytes());
            }
            Frame::Bye { reason } => {
                payload.push(*reason);
            }
            Frame::Paired { client_id, token } => {
                for s in [client_id, token] {
                    if s.len() > u8::MAX as usize {
                        bail!("PAIRED field length {} exceeds 255", s.len());
                    }
                    payload.push(s.len() as u8);
                    payload.extend_from_slice(s.as_bytes());
                }
            }
            Frame::MediaGet { id, full, offset } => {
                put_str16(&mut payload, id)?;
                payload.push(*full as u8);
                payload.extend_from_slice(&offset.to_be_bytes());
            }
            Frame::MediaData {
                total,
                offset,
                mime,
                name,
                data,
            } => {
                payload.extend_from_slice(&total.to_be_bytes());
                payload.extend_from_slice(&offset.to_be_bytes());
                put_str16(&mut payload, mime)?;
                put_str16(&mut payload, name)?;
                payload.extend_from_slice(data);
            }
            Frame::MediaPut {
                id,
                offset,
                total,
                data,
            } => {
                put_str16(&mut payload, id)?;
                payload.extend_from_slice(&offset.to_be_bytes());
                payload.extend_from_slice(&total.to_be_bytes());
                payload.extend_from_slice(data);
            }
            Frame::MediaPutAck { id, received } => {
                put_str16(&mut payload, id)?;
                payload.extend_from_slice(&received.to_be_bytes());
            }
            Frame::MediaErr { message } => {
                put_str16(&mut payload, message)?;
            }
        }

        if payload.len() > MAX_PAYLOAD_LEN {
            bail!("frame payload {} exceeds {}", payload.len(), MAX_PAYLOAD_LEN);
        }

        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.push(self.frame_type());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    pub fn decode(frame_type: u8, payload: &[u8]) -> Result<Self> {
        let mut r = Rd { data: payload, pos: 0 };
        let frame = match frame_type {
            FRAME_HELLO => {
                let version = r.u8()?;
                let role = r.u8()?;
                let token_len = r.u8()? as usize;
                let token = r.take(token_len)?.to_vec();
                let last_rx_seq = r.u64()?;
                let interval_s = u16::from_be_bytes(r.take(2)?.try_into()?);
                Frame::Hello {
                    version,
                    role,
                    token,
                    last_rx_seq,
                    interval_s,
                }
            }
            FRAME_WELCOME => Frame::Welcome { last_rx_seq: r.u64()? },
            FRAME_MSG => Frame::Msg {
                seq: r.u64()?,
                body: r.rest(),
            },
            FRAME_ACK => Frame::Ack { seq: r.u64()? },
            FRAME_PING => Frame::Ping {
                nonce: u32::from_be_bytes(r.take(4)?.try_into()?),
            },
            FRAME_PONG => Frame::Pong {
                nonce: u32::from_be_bytes(r.take(4)?.try_into()?),
            },
            FRAME_SET_INTERVAL => Frame::SetInterval {
                interval_s: u16::from_be_bytes(r.take(2)?.try_into()?),
            },
            FRAME_BYE => Frame::Bye { reason: r.u8()? },
            FRAME_PAIRED => {
                let mut fields = Vec::with_capacity(2);
                for _ in 0..2 {
                    let len = r.u8()? as usize;
                    fields.push(std::str::from_utf8(r.take(len)?)?.to_string());
                }
                let token = fields.pop().unwrap_or_default();
                let client_id = fields.pop().unwrap_or_default();
                Frame::Paired { client_id, token }
            }
            FRAME_MEDIA_GET => Frame::MediaGet {
                id: r.str16()?,
                full: r.u8()? != 0,
                offset: r.u64()?,
            },
            FRAME_MEDIA_DATA => Frame::MediaData {
                total: r.u64()?,
                offset: r.u64()?,
                mime: r.str16()?,
                name: r.str16()?,
                data: r.rest(),
            },
            FRAME_MEDIA_PUT => Frame::MediaPut {
                id: r.str16()?,
                offset: r.u64()?,
                total: r.u64()?,
                data: r.rest(),
            },
            FRAME_MEDIA_PUT_ACK => Frame::MediaPutAck {
                id: r.str16()?,
                received: r.u64()?,
            },
            FRAME_MEDIA_ERR => Frame::MediaErr { message: r.str16()? },
            other => bail!("unknown frame type 0x{:02x}", other),
        };
        if r.pos != payload.len() {
            bail!(
                "frame 0x{:02x} has {} trailing bytes",
                frame_type,
                payload.len() - r.pos
            );
        }
        Ok(frame)
    }
}

/// Largest frame accepted before a connection has authenticated (HELLO) and on probe
/// connections (PING/BYE): a stranger must not make the server allocate MAX_PAYLOAD_LEN.
pub const MAX_HANDSHAKE_PAYLOAD_LEN: usize = 1024;

/// Reads a single frame from an AsyncRead stream. Returns Ok(None) on clean EOF at frame boundary.
/// Note: NOT cancel-safe; always run in a dedicated reader task.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Frame>> {
    read_frame_max(reader, MAX_PAYLOAD_LEN).await
}

/// Like [`read_frame`], refusing frames whose payload is longer than `max`.
pub async fn read_frame_max<R: AsyncRead + Unpin>(reader: &mut R, max: usize) -> Result<Option<Frame>> {
    let mut header = [0u8; HEADER_LEN];
    match reader.read(&mut header[0..1]).await {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    reader.read_exact(&mut header[1..HEADER_LEN]).await?;
    let frame_type = header[0];
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > max {
        bail!("frame payload length {} exceeds {}", len, max);
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    let frame = Frame::decode(frame_type, &payload)?;
    Ok(Some(frame))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame) -> Result<()> {
    let bytes = frame.encode()?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_all_frames() {
        let frames = vec![
            Frame::Hello {
                version: PROTOCOL_VERSION,
                role: ROLE_MAIN,
                token: b"deadbeef01234567".to_vec(),
                last_rx_seq: 42,
                interval_s: 300,
            },
            Frame::Welcome { last_rx_seq: 99 },
            Frame::Msg {
                seq: 7,
                body: vec![1, 2, 3, 4, 5],
            },
            Frame::Ack { seq: 7 },
            Frame::Ping { nonce: 0x12345678 },
            Frame::Pong { nonce: 0x12345678 },
            Frame::SetInterval { interval_s: 1200 },
            Frame::Bye {
                reason: BYE_REPLACED,
            },
            Frame::Paired {
                client_id: "phone-1a2b".into(),
                token: "00ff".repeat(16),
            },
            Frame::MediaGet {
                id: "m-1".into(),
                full: true,
                offset: 1024,
            },
            Frame::MediaData {
                total: 300_000,
                offset: 262_144,
                mime: "image/jpeg".into(),
                name: "IMG_0001.jpg".into(),
                data: vec![0xAB; MEDIA_CHUNK_LEN],
            },
            Frame::MediaPut {
                id: "u-1".into(),
                offset: 0,
                total: 3,
                data: vec![1, 2, 3],
            },
            Frame::MediaPutAck {
                id: "u-1".into(),
                received: 3,
            },
            Frame::MediaErr {
                message: "not found".into(),
            },
        ];

        let mut buf = Vec::new();
        for f in &frames {
            write_frame(&mut buf, f).await.unwrap();
        }

        let mut cursor = &buf[..];
        for expected in &frames {
            let decoded = read_frame(&mut cursor).await.unwrap().unwrap();
            assert_eq!(&decoded, expected);
        }
        assert!(read_frame(&mut cursor).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn handshake_limit_rejects_big_frames_before_allocating() {
        let mut buf = vec![FRAME_HELLO];
        buf.extend_from_slice(&(MAX_PAYLOAD_LEN as u32).to_be_bytes());
        let mut cursor = &buf[..];
        assert!(read_frame_max(&mut cursor, MAX_HANDSHAKE_PAYLOAD_LEN).await.is_err());
        let hello = Frame::Hello {
            version: PROTOCOL_VERSION,
            role: ROLE_MAIN,
            token: vec![b'a'; 64],
            last_rx_seq: 0,
            interval_s: 60,
        }
        .encode()
        .unwrap();
        let mut cursor = &hello[..];
        assert!(read_frame_max(&mut cursor, MAX_HANDSHAKE_PAYLOAD_LEN).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn rejects_oversized_length() {
        let mut buf = vec![FRAME_MSG];
        buf.extend_from_slice(&((MAX_PAYLOAD_LEN as u32) + 1).to_be_bytes());
        let mut cursor = &buf[..];
        assert!(read_frame(&mut cursor).await.is_err());
    }
}
