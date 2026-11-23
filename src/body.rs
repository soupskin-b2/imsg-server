use anyhow::{bail, Result};

pub const BODY_SEND_TEXT: u8 = 0x01;
pub const BODY_SEND_RESULT: u8 = 0x02;
pub const BODY_INCOMING_TEXT: u8 = 0x03;
pub const BODY_RECEIPT: u8 = 0x04;
pub const BODY_GET_HANDLES: u8 = 0x05;
pub const BODY_HANDLES: u8 = 0x06;
pub const BODY_CHECK_TARGETS: u8 = 0x07;
pub const BODY_TARGET_STATUS: u8 = 0x08;
pub const BODY_SEND_GROUP_TEXT: u8 = 0x09;
pub const BODY_SETUP_STATUS: u8 = 0x0A;
pub const BODY_SIM_INFO: u8 = 0x0B;
pub const BODY_SEND_REG_SMS: u8 = 0x0C;
pub const BODY_REG_RESP: u8 = 0x0D;
pub const BODY_REG_INFO_REQ: u8 = 0x0E;
pub const BODY_REG_INFO: u8 = 0x0F;

/// SETUP_STATUS states (server -> phone).
pub const SETUP_READY: u8 = 0;
pub const SETUP_NEED_SIM: u8 = 1;
pub const SETUP_WORKING: u8 = 2;
pub const SETUP_WAITING_SMS: u8 = 3;
pub const SETUP_FAILED: u8 = 4;

/// REG_INFO states (server -> phone).
pub const REG_STATE_OK: u8 = 0;
pub const REG_STATE_RENEWING: u8 = 1;
pub const REG_STATE_NEEDS_PHONE: u8 = 2;
pub const REG_STATE_FAILED: u8 = 3;

pub const RECEIPT_DELIVERED: u8 = 1;
pub const RECEIPT_READ: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppBody {
    SendText {
        client_msg_id: String,
        target: String,
        text: String,
        sender_guid: Option<String>,
    },
    SendResult {
        client_msg_id: String,
        ok: bool,
        apple_msg_id: Option<String>,
        error: Option<String>,
    },
    IncomingText {
        apple_msg_id: String,
        sender: String,
        participants: Vec<String>,
        sender_guid: Option<String>,
        timestamp_ms: u64,
        text: String,
    },
    Receipt {
        kind: u8,
        apple_msg_id: String,
        sender: String,
        timestamp_ms: u64,
    },
    GetHandles,
    Handles {
        handles: Vec<String>,
        preferred: Option<String>,
    },
    CheckTargets {
        req_id: String,
        targets: Vec<String>,
    },
    TargetStatus {
        req_id: String,
        registered: Vec<String>,
        unregistered: Vec<String>,
    },
    SendGroupText {
        client_msg_id: String,
        participants: Vec<String>,
        text: String,
        sender_guid: Option<String>,
    },
    /// Server -> phone: where phone-number setup stands.
    SetupStatus {
        state: u8,
        detail: String,
    },
    /// Phone -> server: the SIM's carrier (MCC+MNC) and number, if the phone knows it.
    SimInfo {
        mccmnc: String,
        number: Option<String>,
    },
    /// Server -> phone: send this SMS to Apple's registration gateway.
    SendRegSms {
        gateway: String,
        text: String,
    },
    /// Phone -> server: Apple's REG-RESP reply, as received.
    RegResp {
        text: String,
    },
    /// Phone -> server: request current Apple registration / renewal status.
    RegInfoReq,
    /// Server -> phone: Apple registration / renewal and built-in relay status.
    RegInfo {
        auth_expires_at_ms: u64,
        next_rereg_at_ms: u64,
        renew_at_ms: u64,
        provider_connected: bool,
        state: u8,
        detail: String,
    },
}

fn write_str(buf: &mut Vec<u8>, s: &str) -> Result<()> {
    let bytes = s.as_bytes();
    if bytes.len() > u16::MAX as usize {
        bail!("string too long: {} bytes", bytes.len());
    }
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
    Ok(())
}

fn write_opt_str(buf: &mut Vec<u8>, s: &Option<String>) -> Result<()> {
    match s {
        None => {
            buf.push(0);
            Ok(())
        }
        Some(val) => {
            buf.push(1);
            write_str(buf, val)
        }
    }
}

fn write_str_list(buf: &mut Vec<u8>, items: &[String]) -> Result<()> {
    if items.len() > u16::MAX as usize {
        bail!("string list too long: {} items", items.len());
    }
    buf.extend_from_slice(&(items.len() as u16).to_be_bytes());
    for item in items {
        write_str(buf, item)?;
    }
    Ok(())
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos + 1 > self.data.len() {
            bail!("unexpected EOF reading u8");
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16(&mut self) -> Result<u16> {
        if self.pos + 2 > self.data.len() {
            bail!("unexpected EOF reading u16");
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u64(&mut self) -> Result<u64> {
        if self.pos + 8 > self.data.len() {
            bail!("unexpected EOF reading u64");
        }
        let v = u64::from_be_bytes(self.data[self.pos..self.pos + 8].try_into()?);
        self.pos += 8;
        Ok(v)
    }

    fn read_str(&mut self) -> Result<String> {
        let len = self.read_u16()? as usize;
        if self.pos + len > self.data.len() {
            bail!("unexpected EOF reading string of length {}", len);
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        let s = std::str::from_utf8(slice)?;
        Ok(s.to_string())
    }

    fn read_opt_str(&mut self) -> Result<Option<String>> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_str()?)),
            other => bail!("invalid option tag: {}", other),
        }
    }

    fn read_str_list(&mut self) -> Result<Vec<String>> {
        let count = self.read_u16()? as usize;
        let mut out = Vec::with_capacity(count.min(256));
        for _ in 0..count {
            out.push(self.read_str()?);
        }
        Ok(out)
    }

    fn ensure_eof(&self) -> Result<()> {
        if self.pos != self.data.len() {
            bail!(
                "trailing bytes in body: {} unread bytes",
                self.data.len() - self.pos
            );
        }
        Ok(())
    }
}

impl AppBody {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        match self {
            AppBody::SendText {
                client_msg_id,
                target,
                text,
                sender_guid,
            } => {
                buf.push(BODY_SEND_TEXT);
                write_str(&mut buf, client_msg_id)?;
                write_str(&mut buf, target)?;
                write_str(&mut buf, text)?;
                write_opt_str(&mut buf, sender_guid)?;
            }
            AppBody::SendResult {
                client_msg_id,
                ok,
                apple_msg_id,
                error,
            } => {
                buf.push(BODY_SEND_RESULT);
                write_str(&mut buf, client_msg_id)?;
                buf.push(if *ok { 1 } else { 0 });
                write_opt_str(&mut buf, apple_msg_id)?;
                write_opt_str(&mut buf, error)?;
            }
            AppBody::IncomingText {
                apple_msg_id,
                sender,
                participants,
                sender_guid,
                timestamp_ms,
                text,
            } => {
                buf.push(BODY_INCOMING_TEXT);
                write_str(&mut buf, apple_msg_id)?;
                write_str(&mut buf, sender)?;
                write_str_list(&mut buf, participants)?;
                write_opt_str(&mut buf, sender_guid)?;
                buf.extend_from_slice(&timestamp_ms.to_be_bytes());
                write_str(&mut buf, text)?;
            }
            AppBody::Receipt {
                kind,
                apple_msg_id,
                sender,
                timestamp_ms,
            } => {
                buf.push(BODY_RECEIPT);
                buf.push(*kind);
                write_str(&mut buf, apple_msg_id)?;
                write_str(&mut buf, sender)?;
                buf.extend_from_slice(&timestamp_ms.to_be_bytes());
            }
            AppBody::GetHandles => {
                buf.push(BODY_GET_HANDLES);
            }
            AppBody::Handles { handles, preferred } => {
                buf.push(BODY_HANDLES);
                write_str_list(&mut buf, handles)?;
                write_opt_str(&mut buf, preferred)?;
            }
            AppBody::CheckTargets { req_id, targets } => {
                buf.push(BODY_CHECK_TARGETS);
                write_str(&mut buf, req_id)?;
                write_str_list(&mut buf, targets)?;
            }
            AppBody::TargetStatus {
                req_id,
                registered,
                unregistered,
            } => {
                buf.push(BODY_TARGET_STATUS);
                write_str(&mut buf, req_id)?;
                write_str_list(&mut buf, registered)?;
                write_str_list(&mut buf, unregistered)?;
            }
            AppBody::SendGroupText {
                client_msg_id,
                participants,
                text,
                sender_guid,
            } => {
                buf.push(BODY_SEND_GROUP_TEXT);
                write_str(&mut buf, client_msg_id)?;
                write_str_list(&mut buf, participants)?;
                write_str(&mut buf, text)?;
                write_opt_str(&mut buf, sender_guid)?;
            }
            AppBody::SetupStatus { state, detail } => {
                buf.push(BODY_SETUP_STATUS);
                buf.push(*state);
                write_str(&mut buf, detail)?;
            }
            AppBody::SimInfo { mccmnc, number } => {
                buf.push(BODY_SIM_INFO);
                write_str(&mut buf, mccmnc)?;
                write_opt_str(&mut buf, number)?;
            }
            AppBody::SendRegSms { gateway, text } => {
                buf.push(BODY_SEND_REG_SMS);
                write_str(&mut buf, gateway)?;
                write_str(&mut buf, text)?;
            }
            AppBody::RegResp { text } => {
                buf.push(BODY_REG_RESP);
                write_str(&mut buf, text)?;
            }
            AppBody::RegInfoReq => {
                buf.push(BODY_REG_INFO_REQ);
            }
            AppBody::RegInfo {
                auth_expires_at_ms,
                next_rereg_at_ms,
                renew_at_ms,
                provider_connected,
                state,
                detail,
            } => {
                buf.push(BODY_REG_INFO);
                buf.extend_from_slice(&auth_expires_at_ms.to_be_bytes());
                buf.extend_from_slice(&next_rereg_at_ms.to_be_bytes());
                buf.extend_from_slice(&renew_at_ms.to_be_bytes());
                buf.push(if *provider_connected { 1 } else { 0 });
                buf.push(*state);
                write_str(&mut buf, detail)?;
            }
        }
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(data);
        let kind = c.read_u8()?;
        let body = match kind {
            BODY_SEND_TEXT => AppBody::SendText {
                client_msg_id: c.read_str()?,
                target: c.read_str()?,
                text: c.read_str()?,
                sender_guid: c.read_opt_str()?,
            },
            BODY_SEND_RESULT => AppBody::SendResult {
                client_msg_id: c.read_str()?,
                ok: match c.read_u8()? {
                    0 => false,
                    1 => true,
                    v => bail!("invalid bool tag: {}", v),
                },
                apple_msg_id: c.read_opt_str()?,
                error: c.read_opt_str()?,
            },
            BODY_INCOMING_TEXT => AppBody::IncomingText {
                apple_msg_id: c.read_str()?,
                sender: c.read_str()?,
                participants: c.read_str_list()?,
                sender_guid: c.read_opt_str()?,
                timestamp_ms: c.read_u64()?,
                text: c.read_str()?,
            },
            BODY_RECEIPT => AppBody::Receipt {
                kind: c.read_u8()?,
                apple_msg_id: c.read_str()?,
                sender: c.read_str()?,
                timestamp_ms: c.read_u64()?,
            },
            BODY_GET_HANDLES => AppBody::GetHandles,
            BODY_HANDLES => AppBody::Handles {
                handles: c.read_str_list()?,
                preferred: c.read_opt_str()?,
            },
            BODY_CHECK_TARGETS => AppBody::CheckTargets {
                req_id: c.read_str()?,
                targets: c.read_str_list()?,
            },
            BODY_TARGET_STATUS => AppBody::TargetStatus {
                req_id: c.read_str()?,
                registered: c.read_str_list()?,
                unregistered: c.read_str_list()?,
            },
            BODY_SEND_GROUP_TEXT => AppBody::SendGroupText {
                client_msg_id: c.read_str()?,
                participants: c.read_str_list()?,
                text: c.read_str()?,
                sender_guid: c.read_opt_str()?,
            },
            BODY_SETUP_STATUS => AppBody::SetupStatus {
                state: c.read_u8()?,
                detail: c.read_str()?,
            },
            BODY_SIM_INFO => AppBody::SimInfo {
                mccmnc: c.read_str()?,
                number: c.read_opt_str()?,
            },
            BODY_SEND_REG_SMS => AppBody::SendRegSms {
                gateway: c.read_str()?,
                text: c.read_str()?,
            },
            BODY_REG_RESP => AppBody::RegResp {
                text: c.read_str()?,
            },
            BODY_REG_INFO_REQ => AppBody::RegInfoReq,
            BODY_REG_INFO => AppBody::RegInfo {
                auth_expires_at_ms: c.read_u64()?,
                next_rereg_at_ms: c.read_u64()?,
                renew_at_ms: c.read_u64()?,
                provider_connected: match c.read_u8()? {
                    0 => false,
                    1 => true,
                    v => bail!("invalid bool tag: {}", v),
                },
                state: c.read_u8()?,
                detail: c.read_str()?,
            },
            other => bail!("unknown body kind 0x{:02x}", other),
        };
        c.ensure_eof()?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_bodies() {
        let cases = vec![
            AppBody::SetupStatus {
                state: SETUP_WAITING_SMS,
                detail: "Waiting for Apple".into(),
            },
            AppBody::SimInfo {
                mccmnc: "310260".into(),
                number: Some("+15551234567".into()),
            },
            AppBody::SimInfo {
                mccmnc: "".into(),
                number: None,
            },
            AppBody::SendRegSms {
                gateway: "22223333".into(),
                text: "REG-REQ?v=3;t=AB;r=1;".into(),
            },
            AppBody::RegResp {
                text: "REG-RESP?v=3;r=1;n=+15551234567;s=00".into(),
            },
            AppBody::SendText {
                client_msg_id: "c-1".into(),
                target: "tel:+15551234567".into(),
                text: "Hello world 👋".into(),
                sender_guid: Some("guid-abc".into()),
            },
            AppBody::SendResult {
                client_msg_id: "c-1".into(),
                ok: true,
                apple_msg_id: Some("apple-123".into()),
                error: None,
            },
            AppBody::SendResult {
                client_msg_id: "c-2".into(),
                ok: false,
                apple_msg_id: None,
                error: Some("not registered on iMessage".into()),
            },
            AppBody::IncomingText {
                apple_msg_id: "apple-456".into(),
                sender: "mailto:friend@icloud.com".into(),
                participants: vec![
                    "mailto:friend@icloud.com".into(),
                    "tel:+15551234567".into(),
                ],
                sender_guid: None,
                timestamp_ms: 1700000000000,
                text: "Hey there".into(),
            },
            AppBody::Receipt {
                kind: RECEIPT_DELIVERED,
                apple_msg_id: "apple-123".into(),
                sender: "tel:+15551234567".into(),
                timestamp_ms: 1700000005000,
            },
            AppBody::GetHandles,
            AppBody::Handles {
                handles: vec!["mailto:me@icloud.com".into(), "tel:+15550001111".into()],
                preferred: Some("mailto:me@icloud.com".into()),
            },
            AppBody::CheckTargets {
                req_id: "q-1".into(),
                targets: vec!["tel:+15551234567".into(), "mailto:alice@icloud.com".into()],
            },
            AppBody::TargetStatus {
                req_id: "q-1".into(),
                registered: vec!["mailto:alice@icloud.com".into()],
                unregistered: vec!["tel:+15551234567".into()],
            },
            AppBody::SendGroupText {
                client_msg_id: "c-3".into(),
                participants: vec!["tel:+15551234567".into(), "mailto:alice@icloud.com".into()],
                text: "Group hello".into(),
                sender_guid: Some("guid-group".into()),
            },
            AppBody::RegInfoReq,
            AppBody::RegInfo {
                auth_expires_at_ms: 1_800_000_000_000,
                next_rereg_at_ms: 1_795_000_000_000,
                renew_at_ms: 1_799_395_200_000,
                provider_connected: true,
                state: REG_STATE_OK,
                detail: "".into(),
            },
            AppBody::RegInfo {
                auth_expires_at_ms: 0,
                next_rereg_at_ms: 0,
                renew_at_ms: 0,
                provider_connected: false,
                state: REG_STATE_NEEDS_PHONE,
                detail: "Waiting for phone".into(),
            },
        ];

        for body in cases {
            let encoded = body.encode().unwrap();
            let decoded = AppBody::decode(&encoded).unwrap();
            assert_eq!(body, decoded);
        }
    }
}
