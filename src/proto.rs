use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u8 = 1;

pub const ROLE_MAIN: u8 = 0;
pub const ROLE_PROBE: u8 = 1;
/// HELLO token carries a one-time pairing code; the server answers with PAIRED.
pub const ROLE_PAIR: u8 = 2;

pub const FRAME_HELLO: u8 = 0x01;
pub const FRAME_WELCOME: u8 = 0x02;
pub const FRAME_MSG: u8 = 0x03;
pub const FRAME_ACK: u8 = 0x04;
pub const FRAME_PING: u8 = 0x05;
pub const FRAME_PONG: u8 = 0x06;
pub const FRAME_SET_INTERVAL: u8 = 0x07;
pub const FRAME_BYE: u8 = 0x08;
pub const FRAME_PAIRED: u8 = 0x09;

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

pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;
pub const MAX_MSG_BODY_LEN: usize = MAX_PAYLOAD_LEN - 8;

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
        }

        if payload.len() > MAX_PAYLOAD_LEN {
            bail!("frame payload {} exceeds {}", payload.len(), MAX_PAYLOAD_LEN);
        }

        let mut out = Vec::with_capacity(3 + payload.len());
        out.push(self.frame_type());
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    pub fn decode(frame_type: u8, payload: &[u8]) -> Result<Self> {
        match frame_type {
            FRAME_HELLO => {
                if payload.len() < 3 {
                    bail!("HELLO payload too short: {}", payload.len());
                }
                let version = payload[0];
                let role = payload[1];
                let token_len = payload[2] as usize;
                let expected = 3 + token_len + 8 + 2;
                if payload.len() != expected {
                    bail!(
                        "HELLO payload length mismatch: got {}, expected {}",
                        payload.len(),
                        expected
                    );
                }
                let token = payload[3..3 + token_len].to_vec();
                let seq_off = 3 + token_len;
                let last_rx_seq = u64::from_be_bytes(payload[seq_off..seq_off + 8].try_into()?);
                let interval_s = u16::from_be_bytes(payload[seq_off + 8..seq_off + 10].try_into()?);
                Ok(Frame::Hello {
                    version,
                    role,
                    token,
                    last_rx_seq,
                    interval_s,
                })
            }
            FRAME_WELCOME => {
                if payload.len() != 8 {
                    bail!("WELCOME payload length {} != 8", payload.len());
                }
                let last_rx_seq = u64::from_be_bytes(payload[0..8].try_into()?);
                Ok(Frame::Welcome { last_rx_seq })
            }
            FRAME_MSG => {
                if payload.len() < 8 {
                    bail!("MSG payload too short: {}", payload.len());
                }
                let seq = u64::from_be_bytes(payload[0..8].try_into()?);
                let body = payload[8..].to_vec();
                Ok(Frame::Msg { seq, body })
            }
            FRAME_ACK => {
                if payload.len() != 8 {
                    bail!("ACK payload length {} != 8", payload.len());
                }
                let seq = u64::from_be_bytes(payload[0..8].try_into()?);
                Ok(Frame::Ack { seq })
            }
            FRAME_PING => {
                if payload.len() != 4 {
                    bail!("PING payload length {} != 4", payload.len());
                }
                let nonce = u32::from_be_bytes(payload[0..4].try_into()?);
                Ok(Frame::Ping { nonce })
            }
            FRAME_PONG => {
                if payload.len() != 4 {
                    bail!("PONG payload length {} != 4", payload.len());
                }
                let nonce = u32::from_be_bytes(payload[0..4].try_into()?);
                Ok(Frame::Pong { nonce })
            }
            FRAME_SET_INTERVAL => {
                if payload.len() != 2 {
                    bail!("SET_INTERVAL payload length {} != 2", payload.len());
                }
                let interval_s = u16::from_be_bytes(payload[0..2].try_into()?);
                Ok(Frame::SetInterval { interval_s })
            }
            FRAME_BYE => {
                if payload.len() != 1 {
                    bail!("BYE payload length {} != 1", payload.len());
                }
                Ok(Frame::Bye { reason: payload[0] })
            }
            FRAME_PAIRED => {
                let mut fields = Vec::with_capacity(2);
                let mut pos = 0usize;
                for _ in 0..2 {
                    let len = *payload.get(pos).ok_or_else(|| anyhow::anyhow!("PAIRED payload too short"))? as usize;
                    pos += 1;
                    let end = pos + len;
                    if end > payload.len() {
                        bail!("PAIRED payload too short");
                    }
                    fields.push(std::str::from_utf8(&payload[pos..end])?.to_string());
                    pos = end;
                }
                if pos != payload.len() {
                    bail!("PAIRED payload has trailing bytes");
                }
                let token = fields.pop().unwrap_or_default();
                let client_id = fields.pop().unwrap_or_default();
                Ok(Frame::Paired { client_id, token })
            }
            other => bail!("unknown frame type 0x{:02x}", other),
        }
    }
}

/// Reads a single frame from an AsyncRead stream. Returns Ok(None) on clean EOF at frame boundary.
/// Note: NOT cancel-safe; always run in a dedicated reader task.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Frame>> {
    let mut header = [0u8; 3];
    let first = match reader.read(&mut header[0..1]).await {
        Ok(0) => return Ok(None),
        Ok(n) => n,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    debug_assert_eq!(first, 1);
    reader.read_exact(&mut header[1..3]).await?;
    let frame_type = header[0];
    let len = u16::from_be_bytes([header[1], header[2]]) as usize;
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
}
