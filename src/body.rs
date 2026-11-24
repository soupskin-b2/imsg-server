use anyhow::{bail, Result};

pub const BODY_SEND_MESSAGE: u8 = 0x01;
pub const BODY_SEND_RESULT: u8 = 0x02;
pub const BODY_INCOMING_MESSAGE: u8 = 0x03;
pub const BODY_RECEIPT: u8 = 0x04;
pub const BODY_GET_HANDLES: u8 = 0x05;
pub const BODY_HANDLES: u8 = 0x06;
pub const BODY_CHECK_TARGETS: u8 = 0x07;
pub const BODY_TARGET_STATUS: u8 = 0x08;
pub const BODY_SEND_REACTION: u8 = 0x09;
pub const BODY_SETUP_STATUS: u8 = 0x0A;
pub const BODY_SIM_INFO: u8 = 0x0B;
pub const BODY_SEND_REG_SMS: u8 = 0x0C;
pub const BODY_REG_RESP: u8 = 0x0D;
pub const BODY_REG_INFO_REQ: u8 = 0x0E;
pub const BODY_REG_INFO: u8 = 0x0F;
pub const BODY_REACTION: u8 = 0x10;
pub const BODY_EDIT: u8 = 0x11;
pub const BODY_UNSEND: u8 = 0x12;
pub const BODY_GROUP_EVENT: u8 = 0x13;

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

// Receipt kinds: part of the protocol, but the server no longer sends receipts to the phone.
#[allow(dead_code)]
pub const RECEIPT_DELIVERED: u8 = 1;
#[allow(dead_code)]
pub const RECEIPT_READ: u8 = 2;

/// Incoming attachment kinds (what the phone should expect from MEDIA_GET).
pub const ATTACH_IMAGE: u8 = 1;
pub const ATTACH_VIDEO: u8 = 2;
pub const ATTACH_AUDIO: u8 = 3;
pub const ATTACH_VOICE: u8 = 4;
pub const ATTACH_VCARD: u8 = 5;
/// Anything else: no preview; the phone shows the name and can only save the original.
pub const ATTACH_FILE: u8 = 6;
pub const ATTACH_STICKER: u8 = 7;

/// Tapback kinds, in Apple's order.
pub const REACT_HEART: u8 = 0;
pub const REACT_LIKE: u8 = 1;
pub const REACT_DISLIKE: u8 = 2;
pub const REACT_LAUGH: u8 = 3;
pub const REACT_EMPHASIZE: u8 = 4;
pub const REACT_QUESTION: u8 = 5;
/// Any emoji (`emoji` holds it).
pub const REACT_EMOJI: u8 = 6;
/// A sticker placed on the message (receive only).
pub const REACT_STICKER: u8 = 7;

pub const GROUP_RENAMED: u8 = 1;
pub const GROUP_PARTICIPANTS: u8 = 2;
pub const GROUP_ICON: u8 = 3;

/// An upload (MEDIA_PUT) to attach to an outgoing message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutAttachment {
    pub upload_id: String,
    pub name: String,
    pub mime: String,
}

/// An attachment of an incoming message, fetched with MEDIA_GET `media_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InAttachment {
    pub media_id: String,
    pub kind: u8,
    pub name: String,
    /// Size of the original file in bytes (0 if unknown).
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppBody {
    /// Phone -> server: send a message to `participants` (one for a 1:1 chat).
    SendMessage {
        client_msg_id: String,
        participants: Vec<String>,
        sender_guid: Option<String>,
        text: String,
        attachments: Vec<OutAttachment>,
    },
    SendResult {
        client_msg_id: String,
        ok: bool,
        apple_msg_id: Option<String>,
        error: Option<String>,
    },
    IncomingMessage {
        apple_msg_id: String,
        sender: String,
        participants: Vec<String>,
        sender_guid: Option<String>,
        timestamp_ms: u64,
        text: String,
        /// Apple id of the message this one replies to (inline reply).
        reply_to: Option<String>,
        attachments: Vec<InAttachment>,
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
    /// Phone -> server: add (`enable`) or remove a tapback on message `target_id`.
    SendReaction {
        client_msg_id: String,
        participants: Vec<String>,
        sender_guid: Option<String>,
        target_id: String,
        reaction: u8,
        emoji: Option<String>,
        enable: bool,
        /// The reacted-to message's text, for Apple's notification and non-Apple fallbacks.
        target_text: String,
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
    /// Server -> phone: someone (possibly the user, from another device) added or removed a tapback.
    Reaction {
        apple_msg_id: String,
        sender: String,
        participants: Vec<String>,
        sender_guid: Option<String>,
        timestamp_ms: u64,
        target_id: String,
        reaction: u8,
        emoji: Option<String>,
        enable: bool,
    },
    /// Server -> phone: message `target_id` now reads `text`.
    Edit {
        apple_msg_id: String,
        sender: String,
        timestamp_ms: u64,
        target_id: String,
        text: String,
    },
    /// Server -> phone: message `target_id` was unsent.
    Unsend {
        apple_msg_id: String,
        sender: String,
        timestamp_ms: u64,
        target_id: String,
    },
    /// Server -> phone: a group chat was renamed, changed members, or changed its photo.
    GroupEvent {
        apple_msg_id: String,
        sender: String,
        /// Members before the change.
        participants: Vec<String>,
        sender_guid: Option<String>,
        timestamp_ms: u64,
        event: u8,
        /// GROUP_RENAMED: the new name ("" when the name was removed).
        name: String,
        /// GROUP_PARTICIPANTS: the members after the change.
        new_participants: Vec<String>,
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

/// Message text may exceed 64 KiB; it gets a 32-bit length.
fn write_text(buf: &mut Vec<u8>, s: &str) -> Result<()> {
    let bytes = s.as_bytes();
    if bytes.len() > (crate::proto::MAX_MSG_BODY_LEN / 2) {
        bail!("text too long: {} bytes", bytes.len());
    }
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
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

fn write_count(buf: &mut Vec<u8>, n: usize) -> Result<()> {
    if n > u16::MAX as usize {
        bail!("list too long: {} items", n);
    }
    buf.extend_from_slice(&(n as u16).to_be_bytes());
    Ok(())
}

fn write_str_list(buf: &mut Vec<u8>, items: &[String]) -> Result<()> {
    write_count(buf, items.len())?;
    for item in items {
        write_str(buf, item)?;
    }
    Ok(())
}

fn write_bool(buf: &mut Vec<u8>, b: bool) {
    buf.push(if b { 1 } else { 0 });
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            bail!("unexpected EOF reading {} bytes", n);
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into()?))
    }

    fn read_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?))
    }

    fn read_u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into()?))
    }

    fn read_bool(&mut self) -> Result<bool> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            v => bail!("invalid bool tag: {}", v),
        }
    }

    fn read_str(&mut self) -> Result<String> {
        let len = self.read_u16()? as usize;
        Ok(std::str::from_utf8(self.take(len)?)?.to_string())
    }

    fn read_text(&mut self) -> Result<String> {
        let len = self.read_u32()? as usize;
        Ok(std::str::from_utf8(self.take(len)?)?.to_string())
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
            AppBody::SendMessage {
                client_msg_id,
                participants,
                sender_guid,
                text,
                attachments,
            } => {
                buf.push(BODY_SEND_MESSAGE);
                write_str(&mut buf, client_msg_id)?;
                write_str_list(&mut buf, participants)?;
                write_opt_str(&mut buf, sender_guid)?;
                write_text(&mut buf, text)?;
                write_count(&mut buf, attachments.len())?;
                for a in attachments {
                    write_str(&mut buf, &a.upload_id)?;
                    write_str(&mut buf, &a.name)?;
                    write_str(&mut buf, &a.mime)?;
                }
            }
            AppBody::SendResult {
                client_msg_id,
                ok,
                apple_msg_id,
                error,
            } => {
                buf.push(BODY_SEND_RESULT);
                write_str(&mut buf, client_msg_id)?;
                write_bool(&mut buf, *ok);
                write_opt_str(&mut buf, apple_msg_id)?;
                write_opt_str(&mut buf, error)?;
            }
            AppBody::IncomingMessage {
                apple_msg_id,
                sender,
                participants,
                sender_guid,
                timestamp_ms,
                text,
                reply_to,
                attachments,
            } => {
                buf.push(BODY_INCOMING_MESSAGE);
                write_str(&mut buf, apple_msg_id)?;
                write_str(&mut buf, sender)?;
                write_str_list(&mut buf, participants)?;
                write_opt_str(&mut buf, sender_guid)?;
                buf.extend_from_slice(&timestamp_ms.to_be_bytes());
                write_text(&mut buf, text)?;
                write_opt_str(&mut buf, reply_to)?;
                write_count(&mut buf, attachments.len())?;
                for a in attachments {
                    write_str(&mut buf, &a.media_id)?;
                    buf.push(a.kind);
                    write_str(&mut buf, &a.name)?;
                    buf.extend_from_slice(&a.size.to_be_bytes());
                }
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
            AppBody::SendReaction {
                client_msg_id,
                participants,
                sender_guid,
                target_id,
                reaction,
                emoji,
                enable,
                target_text,
            } => {
                buf.push(BODY_SEND_REACTION);
                write_str(&mut buf, client_msg_id)?;
                write_str_list(&mut buf, participants)?;
                write_opt_str(&mut buf, sender_guid)?;
                write_str(&mut buf, target_id)?;
                buf.push(*reaction);
                write_opt_str(&mut buf, emoji)?;
                write_bool(&mut buf, *enable);
                write_text(&mut buf, target_text)?;
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
                write_bool(&mut buf, *provider_connected);
                buf.push(*state);
                write_str(&mut buf, detail)?;
            }
            AppBody::Reaction {
                apple_msg_id,
                sender,
                participants,
                sender_guid,
                timestamp_ms,
                target_id,
                reaction,
                emoji,
                enable,
            } => {
                buf.push(BODY_REACTION);
                write_str(&mut buf, apple_msg_id)?;
                write_str(&mut buf, sender)?;
                write_str_list(&mut buf, participants)?;
                write_opt_str(&mut buf, sender_guid)?;
                buf.extend_from_slice(&timestamp_ms.to_be_bytes());
                write_str(&mut buf, target_id)?;
                buf.push(*reaction);
                write_opt_str(&mut buf, emoji)?;
                write_bool(&mut buf, *enable);
            }
            AppBody::Edit {
                apple_msg_id,
                sender,
                timestamp_ms,
                target_id,
                text,
            } => {
                buf.push(BODY_EDIT);
                write_str(&mut buf, apple_msg_id)?;
                write_str(&mut buf, sender)?;
                buf.extend_from_slice(&timestamp_ms.to_be_bytes());
                write_str(&mut buf, target_id)?;
                write_text(&mut buf, text)?;
            }
            AppBody::Unsend {
                apple_msg_id,
                sender,
                timestamp_ms,
                target_id,
            } => {
                buf.push(BODY_UNSEND);
                write_str(&mut buf, apple_msg_id)?;
                write_str(&mut buf, sender)?;
                buf.extend_from_slice(&timestamp_ms.to_be_bytes());
                write_str(&mut buf, target_id)?;
            }
            AppBody::GroupEvent {
                apple_msg_id,
                sender,
                participants,
                sender_guid,
                timestamp_ms,
                event,
                name,
                new_participants,
            } => {
                buf.push(BODY_GROUP_EVENT);
                write_str(&mut buf, apple_msg_id)?;
                write_str(&mut buf, sender)?;
                write_str_list(&mut buf, participants)?;
                write_opt_str(&mut buf, sender_guid)?;
                buf.extend_from_slice(&timestamp_ms.to_be_bytes());
                buf.push(*event);
                write_str(&mut buf, name)?;
                write_str_list(&mut buf, new_participants)?;
            }
        }
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(data);
        let kind = c.read_u8()?;
        let body = match kind {
            BODY_SEND_MESSAGE => {
                let client_msg_id = c.read_str()?;
                let participants = c.read_str_list()?;
                let sender_guid = c.read_opt_str()?;
                let text = c.read_text()?;
                let n = c.read_u16()? as usize;
                let mut attachments = Vec::with_capacity(n.min(64));
                for _ in 0..n {
                    attachments.push(OutAttachment {
                        upload_id: c.read_str()?,
                        name: c.read_str()?,
                        mime: c.read_str()?,
                    });
                }
                AppBody::SendMessage {
                    client_msg_id,
                    participants,
                    sender_guid,
                    text,
                    attachments,
                }
            }
            BODY_SEND_RESULT => AppBody::SendResult {
                client_msg_id: c.read_str()?,
                ok: c.read_bool()?,
                apple_msg_id: c.read_opt_str()?,
                error: c.read_opt_str()?,
            },
            BODY_INCOMING_MESSAGE => {
                let apple_msg_id = c.read_str()?;
                let sender = c.read_str()?;
                let participants = c.read_str_list()?;
                let sender_guid = c.read_opt_str()?;
                let timestamp_ms = c.read_u64()?;
                let text = c.read_text()?;
                let reply_to = c.read_opt_str()?;
                let n = c.read_u16()? as usize;
                let mut attachments = Vec::with_capacity(n.min(64));
                for _ in 0..n {
                    attachments.push(InAttachment {
                        media_id: c.read_str()?,
                        kind: c.read_u8()?,
                        name: c.read_str()?,
                        size: c.read_u64()?,
                    });
                }
                AppBody::IncomingMessage {
                    apple_msg_id,
                    sender,
                    participants,
                    sender_guid,
                    timestamp_ms,
                    text,
                    reply_to,
                    attachments,
                }
            }
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
            BODY_SEND_REACTION => AppBody::SendReaction {
                client_msg_id: c.read_str()?,
                participants: c.read_str_list()?,
                sender_guid: c.read_opt_str()?,
                target_id: c.read_str()?,
                reaction: c.read_u8()?,
                emoji: c.read_opt_str()?,
                enable: c.read_bool()?,
                target_text: c.read_text()?,
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
                provider_connected: c.read_bool()?,
                state: c.read_u8()?,
                detail: c.read_str()?,
            },
            BODY_REACTION => AppBody::Reaction {
                apple_msg_id: c.read_str()?,
                sender: c.read_str()?,
                participants: c.read_str_list()?,
                sender_guid: c.read_opt_str()?,
                timestamp_ms: c.read_u64()?,
                target_id: c.read_str()?,
                reaction: c.read_u8()?,
                emoji: c.read_opt_str()?,
                enable: c.read_bool()?,
            },
            BODY_EDIT => AppBody::Edit {
                apple_msg_id: c.read_str()?,
                sender: c.read_str()?,
                timestamp_ms: c.read_u64()?,
                target_id: c.read_str()?,
                text: c.read_text()?,
            },
            BODY_UNSEND => AppBody::Unsend {
                apple_msg_id: c.read_str()?,
                sender: c.read_str()?,
                timestamp_ms: c.read_u64()?,
                target_id: c.read_str()?,
            },
            BODY_GROUP_EVENT => AppBody::GroupEvent {
                apple_msg_id: c.read_str()?,
                sender: c.read_str()?,
                participants: c.read_str_list()?,
                sender_guid: c.read_opt_str()?,
                timestamp_ms: c.read_u64()?,
                event: c.read_u8()?,
                name: c.read_str()?,
                new_participants: c.read_str_list()?,
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
            AppBody::SendMessage {
                client_msg_id: "c-1".into(),
                participants: vec!["tel:+15551234567".into()],
                sender_guid: Some("guid-abc".into()),
                text: "Hello world 👋".into(),
                attachments: vec![],
            },
            AppBody::SendMessage {
                client_msg_id: "c-3".into(),
                participants: vec!["tel:+15551234567".into(), "mailto:alice@icloud.com".into()],
                sender_guid: None,
                text: "".into(),
                attachments: vec![OutAttachment {
                    upload_id: "u-1".into(),
                    name: "IMG_0001.jpg".into(),
                    mime: "image/jpeg".into(),
                }],
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
            AppBody::IncomingMessage {
                apple_msg_id: "apple-456".into(),
                sender: "mailto:friend@icloud.com".into(),
                participants: vec![
                    "mailto:friend@icloud.com".into(),
                    "tel:+15551234567".into(),
                ],
                sender_guid: None,
                timestamp_ms: 1700000000000,
                text: "Hey there".into(),
                reply_to: Some("apple-123".into()),
                attachments: vec![InAttachment {
                    media_id: "m-1".into(),
                    kind: ATTACH_IMAGE,
                    name: "IMG_0002.HEIC".into(),
                    size: 2_345_678,
                }],
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
            AppBody::SendReaction {
                client_msg_id: "c-4".into(),
                participants: vec!["tel:+15551234567".into()],
                sender_guid: None,
                target_id: "apple-456".into(),
                reaction: REACT_HEART,
                emoji: None,
                enable: true,
                target_text: "Hey there".into(),
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
            AppBody::Reaction {
                apple_msg_id: "apple-789".into(),
                sender: "tel:+15551234567".into(),
                participants: vec!["tel:+15551234567".into()],
                sender_guid: Some("g".into()),
                timestamp_ms: 1,
                target_id: "apple-456".into(),
                reaction: REACT_EMOJI,
                emoji: Some("🔥".into()),
                enable: false,
            },
            AppBody::Edit {
                apple_msg_id: "apple-790".into(),
                sender: "tel:+15551234567".into(),
                timestamp_ms: 2,
                target_id: "apple-456".into(),
                text: "Hey there!".into(),
            },
            AppBody::Unsend {
                apple_msg_id: "apple-791".into(),
                sender: "tel:+15551234567".into(),
                timestamp_ms: 3,
                target_id: "apple-456".into(),
            },
            AppBody::GroupEvent {
                apple_msg_id: "apple-792".into(),
                sender: "tel:+15551234567".into(),
                participants: vec!["tel:+15551234567".into(), "tel:+15550001111".into()],
                sender_guid: Some("g".into()),
                timestamp_ms: 4,
                event: GROUP_PARTICIPANTS,
                name: "".into(),
                new_participants: vec![
                    "tel:+15551234567".into(),
                    "tel:+15550001111".into(),
                    "mailto:sam@icloud.com".into(),
                ],
            },
        ];

        for body in cases {
            let encoded = body.encode().unwrap();
            let decoded = AppBody::decode(&encoded).unwrap();
            assert_eq!(body, decoded);
        }
    }
}
