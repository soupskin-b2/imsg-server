use crate::body::{
    AppBody, InAttachment, OutAttachment, ATTACH_AUDIO, ATTACH_FILE, ATTACH_IMAGE, ATTACH_STICKER,
    ATTACH_VCARD, ATTACH_VIDEO, ATTACH_VOICE, GROUP_ICON, GROUP_PARTICIPANTS, GROUP_RENAMED,
    REACT_DISLIKE, REACT_EMOJI, REACT_EMPHASIZE, REACT_HEART, REACT_LAUGH, REACT_LIKE,
    REACT_QUESTION, REACT_STICKER, REG_STATE_FAILED,
    REG_STATE_NEEDS_PHONE, REG_STATE_OK, REG_STATE_RENEWING, SETUP_FAILED, SETUP_NEED_SIM,
    SETUP_READY, SETUP_WAITING_SMS, SETUP_WORKING,
};
use crate::media::{self, MediaStore};
use crate::config::Config;
use crate::push::{Hub, IncomingClientMsg};
use crate::relay::{RelayHub, RelayStatus};
use anyhow::{anyhow, bail, Context, Result};
use keystore::init_keystore;
use keystore::software::{SoftwareEncryptor, SoftwareKeystore};
use log::{debug, error, info, warn};
use openssl::asn1::Asn1Time;
use openssl::x509::X509;
use plist::Data;
use rand::RngCore;
use rustpush::{
    authenticate_phone, get_gateways_for_mccmnc, register, APSConnection, APSConnectionResource,
    APSState, Attachment, AuthPhone, BalloonLayout, ConversationData, EditMessage, ExtensionApp,
    IDSNGMIdentity, UnsendMessage,
    IDSUser, IMClient, IndexedMessagePart, MMCSFile, Message, MessageInst, MessagePart,
    MessageParts, MessageType, NormalMessage, OSConfig, PushError, Reaction, ReactMessage,
    ReactMessageType, RelayConfig, ResourceFailure, ResourceState, MADRID_SERVICE,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

const IDENTITY_TAG: &str = "imsg-server";
const MS_PER_DAY: u64 = 86_400_000;
const RENEWAL_STEP_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const PROACTIVE_RETRY_INTERVAL: Duration = Duration::from_secs(24 * 3600);
const URGENT_RETRY_INTERVAL: Duration = Duration::from_secs(15 * 60);
const RENEWAL_CHECK_INTERVAL: Duration = Duration::from_secs(60);

static KEYSTORE_INIT: Once = Once::new();

#[derive(Serialize, Deserialize, Clone)]
struct SavedHardwareState {
    push: APSState,
    relay: RelayConfig,
    identity: Data,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedAppleStatus {
    state: String,
    detail: String,
    auth_expires_at_ms: Option<u64>,
    next_rereg_at_ms: Option<u64>,
    renewal_lead_days: u64,
    last_success_ms: Option<u64>,
    last_error: Option<String>,
    renewal_pending: bool,
    provider_connected: bool,
    provider_last_answered_ms: Option<u64>,
    updated_at_ms: u64,
}

struct AppleStatusTracker {
    path: PathBuf,
    state: u8,
    detail: String,
    auth_expires_at_ms: Option<u64>,
    next_rereg_at_ms: Option<u64>,
    renewal_lead_days: u64,
    last_success_ms: Option<u64>,
    last_error: Option<String>,
    renewal_pending: bool,
    provider_connected: bool,
    provider_last_answered_ms: Option<u64>,
}

impl AppleStatusTracker {
    fn new(state_dir: &Path, renewal_lead_days: u64, relay_status: &RelayStatus) -> Self {
        Self {
            path: state_dir.join("apple_status.json"),
            state: REG_STATE_NEEDS_PHONE,
            detail: String::new(),
            auth_expires_at_ms: None,
            next_rereg_at_ms: None,
            renewal_lead_days,
            last_success_ms: None,
            last_error: None,
            renewal_pending: false,
            provider_connected: relay_status.provider_connected,
            provider_last_answered_ms: relay_status.last_answered_ms,
        }
    }

    /// Takes the relay's status; true if the phone's view of it (REG_INFO) changed. The last
    /// answer time changes on every validation request the iPhone answers but isn't in REG_INFO,
    /// so it's only saved (apple_status.json), not pushed: an identical REG_INFO wakes the phone.
    fn update_relay(&mut self, rs: &RelayStatus) -> bool {
        let changed = self.provider_connected != rs.provider_connected;
        let answered = self.provider_last_answered_ms != rs.last_answered_ms;
        self.provider_connected = rs.provider_connected;
        self.provider_last_answered_ms = rs.last_answered_ms;
        if answered && !changed {
            self.save();
        }
        changed
    }

    fn update_from_users(&mut self, users: &[IDSUser]) {
        self.auth_expires_at_ms = users_auth_expires_at_ms(users);
        self.next_rereg_at_ms = users_next_rereg_at_ms(users);
    }

    fn renew_at_ms(&self) -> u64 {
        compute_renew_at_ms(self.auth_expires_at_ms, self.renewal_lead_days)
    }

    fn to_reg_info(&self) -> AppBody {
        AppBody::RegInfo {
            auth_expires_at_ms: self.auth_expires_at_ms.unwrap_or(0),
            next_rereg_at_ms: self.next_rereg_at_ms.unwrap_or(0),
            renew_at_ms: self.renew_at_ms(),
            provider_connected: self.provider_connected,
            state: self.state,
            detail: self.detail.clone(),
        }
    }

    fn save(&self) {
        let snapshot = PersistedAppleStatus {
            state: reg_state_name(self.state).to_string(),
            detail: self.detail.clone(),
            auth_expires_at_ms: self.auth_expires_at_ms,
            next_rereg_at_ms: self.next_rereg_at_ms,
            renewal_lead_days: self.renewal_lead_days,
            last_success_ms: self.last_success_ms,
            last_error: self.last_error.clone(),
            renewal_pending: self.renewal_pending,
            provider_connected: self.provider_connected,
            provider_last_answered_ms: self.provider_last_answered_ms,
            updated_at_ms: now_epoch_ms(),
        };
        if let Err(e) = save_json_atomic(&self.path, &snapshot) {
            warn!("failed to write {}: {:#}", self.path.display(), e);
        }
    }

    async fn save_and_broadcast(&self, hub: &Hub) {
        self.save();
        if let Ok(encoded) = self.to_reg_info().encode() {
            hub.deliver_connected(encoded).await;
        }
    }

    async fn send_to(&self, hub: &Hub, client_id: &str) {
        deliver(hub, client_id, self.to_reg_info()).await;
    }
}

fn reg_state_name(state: u8) -> &'static str {
    match state {
        REG_STATE_OK => "ok",
        REG_STATE_RENEWING => "renewing",
        REG_STATE_NEEDS_PHONE => "needs_phone",
        REG_STATE_FAILED => "failed",
        _ => "unknown",
    }
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Parses a DER-encoded X.509 certificate and returns its `notAfter` timestamp as epoch milliseconds.
pub fn cert_not_after_ms(der: &[u8]) -> Result<u64> {
    let x509 = X509::from_der(der).context("failed to parse DER X.509 certificate")?;
    let epoch = Asn1Time::from_unix(0)?;
    let diff = epoch.as_ref().diff(x509.not_after())?;
    let secs = (diff.days as i64) * 86_400 + (diff.secs as i64);
    Ok((secs.max(0) as u64).saturating_mul(1000))
}

fn users_auth_expires_at_ms(users: &[IDSUser]) -> Option<u64> {
    let phone_min = users
        .iter()
        .filter(|u| u.user_id.starts_with("P:"))
        .filter_map(|u| cert_not_after_ms(&u.auth_keypair.cert).ok())
        .min();
    if phone_min.is_some() {
        return phone_min;
    }
    users
        .iter()
        .filter_map(|u| cert_not_after_ms(&u.auth_keypair.cert).ok())
        .min()
}

fn users_next_rereg_at_ms(users: &[IDSUser]) -> Option<u64> {
    users
        .iter()
        .filter_map(|u| {
            let reg = u.registration.get("com.apple.madrid")?;
            if let Some(hbi) = reg.heartbeat_interval_s {
                Some(reg.registered_at_s.saturating_add(hbi).saturating_mul(1000))
            } else {
                cert_not_after_ms(&reg.id_keypair.cert)
                    .ok()
                    .map(|ms| ms.saturating_sub(300_000))
            }
        })
        .min()
}

pub fn compute_renew_at_ms(auth_expires_at_ms: Option<u64>, lead_days: u64) -> u64 {
    auth_expires_at_ms
        .map(|exp| exp.saturating_sub(lead_days.saturating_mul(MS_PER_DAY)))
        .unwrap_or(0)
}

fn apply_builtin_relay(relay_cfg: &mut RelayConfig, internal_relay: &(String, String)) {
    relay_cfg.host = internal_relay.0.clone();
    relay_cfg.code = internal_relay.1.clone();
    relay_cfg.beeper_token = None;
}

fn save_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(value)?;
    {
        let mut f = File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn save_plist_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("plist.tmp.{}", std::process::id()));
    plist::to_file_xml(&tmp, value)
        .with_context(|| format!("failed to write temp plist {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| {
        format!(
            "failed to move temp plist {} -> {}",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(())
}

/// Initializes rustpush's software keystore using a persistent 32-byte key in `apple_dir/keystore.key`.
/// Must be called before APS activation or IDS identity creation/restoration.
fn init_software_keystore(apple_dir: &Path) -> Result<()> {
    fs::create_dir_all(apple_dir)
        .with_context(|| format!("failed to create apple_dir {}", apple_dir.display()))?;

    let key_path = apple_dir.join("keystore.key");
    let key32: [u8; 32] = if key_path.exists() {
        let raw = fs::read(&key_path)
            .with_context(|| format!("failed to read {}", key_path.display()))?;
        if raw.len() != 32 {
            bail!(
                "invalid keystore key length in {} (expected 32 bytes, got {})",
                key_path.display(),
                raw.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        arr
    } else {
        let mut arr = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut arr);
        let mut f = File::create(&key_path)
            .with_context(|| format!("failed to create {}", key_path.display()))?;
        f.write_all(&arr)?;
        f.sync_all()?;
        crate::config::restrict_permissions(&key_path);
        arr
    };

    let ks_path = apple_dir.join("keystore.plist");
    KEYSTORE_INIT.call_once(|| {
        let state = plist::from_file(&ks_path).unwrap_or_default();
        let save_path = ks_path.clone();
        init_keystore(SoftwareKeystore {
            state,
            update_state: Box::new(move |s| {
                if let Err(e) = save_plist_atomic(&save_path, s) {
                    error!("failed to save keystore plist: {:#}", e);
                }
            }),
            encryptor: SoftwareEncryptor(key32),
        });
    });

    Ok(())
}

async fn setup_push_connection(
    apple_dir: &Path,
    relay: &RelayConfig,
    identity: &IDSNGMIdentity,
    saved_push: Option<APSState>,
) -> Result<(APSConnection, Option<PushError>)> {
    let os_cfg: Arc<dyn OSConfig> = Arc::new(relay.clone());
    let (conn, err) = APSConnectionResource::new(os_cfg, saved_push).await;

    let saved_identity = identity
        .save(IDENTITY_TAG)
        .map_err(|e| anyhow!("failed to save IDSNGMIdentity: {}", e))?;

    let hw_path = apple_dir.join("hw_info.plist");
    if err.is_none() {
        let hw = SavedHardwareState {
            push: conn.state.read().await.clone(),
            relay: relay.clone(),
            identity: saved_identity.clone().into(),
        };
        save_plist_atomic(&hw_path, &hw)?;
    }

    let mut generated_rx = conn.generated_signal.subscribe();
    let weak_conn = Arc::downgrade(&conn);
    let relay_clone = relay.clone();
    let id_bytes = saved_identity;
    let hw_path_task = hw_path;
    tokio::spawn(async move {
        loop {
            match generated_rx.recv().await {
                Ok(()) => {
                    let Some(c) = weak_conn.upgrade() else {
                        break;
                    };
                    let hw = SavedHardwareState {
                        push: c.state.read().await.clone(),
                        relay: relay_clone.clone(),
                        identity: id_bytes.clone().into(),
                    };
                    if let Err(e) = save_plist_atomic(&hw_path_task, &hw) {
                        warn!("failed to persist refreshed APS state: {:#}", e);
                    } else {
                        info!("persisted refreshed APS state to {}", hw_path_task.display());
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    Ok((conn, err))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRegResp {
    pub req_id: Option<String>,
    pub number: String,
    pub sig_bytes: Vec<u8>,
}

/// Parses either a full `REG-RESP?v=3;r=...;n=+15551234567;s=<hex>` SMS reply
/// (tolerating leading garbage before `REG-RESP`) or `<number>|<sig_hex>`.
pub fn parse_reg_resp(raw: &str) -> Result<ParsedRegResp> {
    let trimmed = raw.trim();
    if let Some(idx) = trimmed.find("REG-RESP") {
        let slice = &trimmed[idx..];
        let query = slice
            .split_once('?')
            .map(|(_, q)| q)
            .ok_or_else(|| anyhow!("REG-RESP missing '?' query string"))?;
        let mut req_id = None;
        let mut number = None;
        let mut sig_hex = None;
        for part in query.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((k, v)) = part.split_once('=') {
                match k.trim() {
                    "r" => req_id = Some(v.trim().to_string()),
                    "n" => number = Some(v.trim().to_string()),
                    "s" => sig_hex = Some(v.trim().to_string()),
                    _ => {}
                }
            }
        }
        let number = number.ok_or_else(|| anyhow!("REG-RESP missing 'n=' phone number field"))?;
        let sig_hex = sig_hex.ok_or_else(|| anyhow!("REG-RESP missing 's=' signature field"))?;
        let sig_bytes = hex::decode(sig_hex.trim())
            .with_context(|| format!("invalid hex in REG-RESP 's=' field: {}", sig_hex))?;
        return Ok(ParsedRegResp {
            req_id,
            number: number.strip_prefix("tel:").unwrap_or(&number).to_string(),
            sig_bytes,
        });
    }

    if let Some((num, sig_hex)) = trimmed.split_once('|') {
        let number = num
            .trim()
            .strip_prefix("tel:")
            .unwrap_or(num.trim())
            .to_string();
        let sig_bytes = hex::decode(sig_hex.trim())
            .with_context(|| format!("invalid hex signature: {}", sig_hex.trim()))?;
        if number.is_empty() {
            bail!("empty phone number before '|'");
        }
        return Ok(ParsedRegResp {
            req_id: None,
            number,
            sig_bytes,
        });
    }

    bail!("could not parse REG-RESP (expected 'REG-RESP?v=3;...;n=...;s=...' or '<number>|<sig_hex>')")
}

pub fn normalize_target(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with("tel:") || trimmed.starts_with("mailto:") {
        return trimmed.to_string();
    }
    if trimmed.contains('@') {
        return format!("mailto:{}", trimmed);
    }
    let mut cleaned = String::with_capacity(trimmed.len() + 5);
    cleaned.push_str("tel:");
    let mut first = true;
    for ch in trimmed.chars() {
        if first && ch == '+' {
            cleaned.push('+');
            first = false;
        } else if ch.is_ascii_digit() {
            if first {
                cleaned.push('+');
                first = false;
            }
            cleaned.push(ch);
        }
    }
    cleaned
}

pub fn pick_sender_handle(handles: &[String], preferred: Option<&str>) -> Option<String> {
    if let Some(pref) = preferred {
        if let Some(found) = handles.iter().find(|h| h.eq_ignore_ascii_case(pref)) {
            return Some(found.clone());
        }
    }
    handles.first().cloned()
}

/// Runs the Apple side. With a saved registration it starts the bridge right away; otherwise it
/// walks the first paired phone through phone-number registration, then starts the bridge.
pub async fn run_apple(
    cfg: &Config,
    hub: Arc<Hub>,
    relay: Arc<RelayHub>,
    internal_relay: (String, String),
    mut incoming_rx: mpsc::Receiver<IncomingClientMsg>,
) -> Result<()> {
    init_software_keystore(&cfg.apple_dir)?;
    crate::fairplay::install(&crate::fairplay::dir(&cfg.apple_dir))?;
    if cfg.apple_dir.join("id.plist").exists() {
        return run_bridge(cfg, hub, relay, internal_relay, incoming_rx).await;
    }
    info!("not registered with Apple yet; waiting for a paired phone to register its number");

    let mut relay_status_rx = relay.subscribe_status();
    let mut connect_rx = hub.subscribe_connects();
    let mut status = AppleStatusTracker::new(
        &cfg.state_dir,
        cfg.renewal.lead_days,
        &relay.status(),
    );
    status.state = REG_STATE_NEEDS_PHONE;
    status.detail = "Not registered yet".to_string();
    status.save();

    let mut setup = PhoneSetup::default();
    loop {
        tokio::select! {
            changed = relay_status_rx.changed() => {
                if changed.is_ok() {
                    let rs = relay_status_rx.borrow().clone();
                    if status.update_relay(&rs) {
                        status.save_and_broadcast(&hub).await;
                    }
                }
            }
            joined = connect_rx.recv() => {
                if let Ok(cid) = joined {
                    status.send_to(&hub, &cid).await;
                }
            }
            maybe_msg = incoming_rx.recv() => {
                let Some(msg) = maybe_msg else { break };
                let body = match AppBody::decode(&msg.body) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("client '{}' sent an undecodable body: {:#}", msg.client_id, e);
                        continue;
                    }
                };
                let client = msg.client_id.as_str();
                match body {
                    AppBody::RegInfoReq => {
                        status.send_to(&hub, client).await;
                    }
                    AppBody::GetHandles => {
                        send_status(&hub, client, SETUP_NEED_SIM, "Send SIM info to register").await;
                    }
                    AppBody::SimInfo { mccmnc, number } => {
                        info!("client '{}' SIM info: mccmnc={} number={:?}", client, mccmnc, number);
                        send_status(&hub, client, SETUP_WORKING, "Activating with Apple...").await;
                        match setup.start(cfg, &internal_relay, &mccmnc).await {
                            Ok((gateway, text)) => {
                                info!("asking client '{}' to text {} to {}", client, text, gateway);
                                deliver(&hub, client, AppBody::SendRegSms { gateway, text }).await;
                                send_status(&hub, client, SETUP_WAITING_SMS, "Waiting for Apple's reply...")
                                    .await;
                            }
                            Err(e) => {
                                warn!("phone setup failed: {:#}", e);
                                status.last_error = Some(format!("{:#}", e));
                                status.save();
                                send_status(&hub, client, SETUP_FAILED, &format!("{:#}", e)).await;
                            }
                        }
                    }
                    AppBody::RegResp { text } => {
                        send_status(&hub, client, SETUP_WORKING, "Registering your number...").await;
                        match setup.finish(cfg, &text).await {
                            Ok(done) => {
                                info!("registered {} with Apple", done.number);
                                let ready = AppBody::SetupStatus {
                                    state: SETUP_READY,
                                    detail: done.number.clone(),
                                };
                                if let Ok(encoded) = ready.encode() {
                                    let _ = hub.deliver_all(encoded).await;
                                }
                                return bridge_loop(
                                    cfg,
                                    hub,
                                    relay,
                                    incoming_rx,
                                    done.conn,
                                    done.relay,
                                    done.identity,
                                    done.users,
                                )
                                .await;
                            }
                            Err(e) => {
                                warn!("phone registration failed: {:#}", e);
                                status.last_error = Some(format!("{:#}", e));
                                status.save();
                                send_status(&hub, client, SETUP_FAILED, &format!("{:#}", e)).await;
                            }
                        }
                    }
                    AppBody::SendMessage { client_msg_id, .. }
                    | AppBody::SendReaction { client_msg_id, .. }
                    | AppBody::SendEdit { client_msg_id, .. }
                    | AppBody::SendUnsend { client_msg_id, .. } => {
                        let reply = AppBody::SendResult {
                            client_msg_id,
                            ok: false,
                            apple_msg_id: None,
                            error: Some("iMessage is not set up yet".to_string()),
                        };
                        deliver(&hub, client, reply).await;
                    }
                    AppBody::CheckTargets { req_id, .. } => {
                        // Unknown, not unregistered: the phone caches a "not on iMessage" answer for a
                        // day and would keep sending those contacts SMS after setup finishes.
                        let reply = AppBody::TargetStatus {
                            req_id,
                            registered: Vec::new(),
                            unregistered: Vec::new(),
                        };
                        deliver(&hub, client, reply).await;
                    }
                    other => warn!("client '{}' sent {:?} before setup finished", client, other),
                }
            }
        }
    }
    Ok(())
}

async fn deliver(hub: &Hub, client_id: &str, body: AppBody) {
    match body.encode() {
        Ok(encoded) => {
            if let Err(e) = hub.deliver(client_id, encoded).await {
                warn!("failed to deliver to client '{}': {:#}", client_id, e);
            }
        }
        Err(e) => warn!("failed to encode body: {:#}", e),
    }
}

async fn send_status(hub: &Hub, client_id: &str, state: u8, detail: &str) {
    let body = AppBody::SetupStatus {
        state,
        detail: detail.to_string(),
    };
    deliver(hub, client_id, body).await;
}

async fn build_reg_sms_request(conn: &APSConnection, mccmnc: &str) -> Result<(String, String, String)> {
    let mccmnc = mccmnc.trim();
    if mccmnc.is_empty() {
        bail!("No SIM card found. Insert the SIM for the number you want to use.");
    }
    let carrier = get_gateways_for_mccmnc(mccmnc)
        .await
        .map_err(|e| anyhow!("Apple has no SMS gateway for carrier {} ({})", mccmnc, e))?;
    let token_hex = hex::encode(conn.get_token().await).to_uppercase();
    let req_id: u32 = rand::random::<u32>() % 1_900_000_000 + 100_000_000;
    let req_id_str = req_id.to_string();
    Ok((
        carrier.gateway,
        format!("REG-REQ?v=3;t={};r={};", token_hex, req_id_str),
        req_id_str,
    ))
}

struct Activated {
    relay: RelayConfig,
    identity: IDSNGMIdentity,
    conn: APSConnection,
}

struct Registered {
    relay: RelayConfig,
    identity: IDSNGMIdentity,
    conn: APSConnection,
    users: Vec<IDSUser>,
    number: String,
}

#[derive(Default)]
struct PhoneSetup {
    activated: Option<Activated>,
    req_id: Option<String>,
}

impl PhoneSetup {
    /// Activates with Apple if needed and returns (gateway, REG-REQ text) for the phone to send.
    async fn start(
        &mut self,
        cfg: &Config,
        internal_relay: &(String, String),
        mccmnc: &str,
    ) -> Result<(String, String)> {
        if mccmnc.trim().is_empty() {
            bail!("No SIM card found. Insert the SIM for the number you want to use.");
        }
        if self.activated.is_none() {
            self.activated = Some(activate(cfg, internal_relay).await?);
        }
        let act = self.activated.as_ref().expect("activated");
        let (gateway, text, req_id) = build_reg_sms_request(&act.conn, mccmnc).await?;
        self.req_id = Some(req_id);
        Ok((gateway, text))
    }

    /// Registers the number from Apple's REG-RESP and saves the credentials.
    async fn finish(&mut self, cfg: &Config, reg_resp: &str) -> Result<Registered> {
        let parsed = parse_reg_resp(reg_resp)?;
        if let (Some(want), Some(got)) = (&self.req_id, &parsed.req_id) {
            if want != got {
                warn!(
                    "REG-RESP r={} does not match our request r={}; continuing",
                    got, want
                );
            }
        }
        let act = self
            .activated
            .as_ref()
            .ok_or_else(|| anyhow!("Got Apple's reply before setup started. Try again."))?;
        let push_token = act.conn.get_token().await;
        let os_cfg: Arc<dyn OSConfig> = Arc::new(act.relay.clone());
        let phone_user = authenticate_phone(
            &parsed.number,
            AuthPhone {
                push_token: push_token.to_vec().into(),
                sigs: vec![parsed.sig_bytes.into()],
            },
            &*os_cfg,
        )
        .await
        .context("Apple rejected the phone number")?;
        let mut users = vec![phone_user];
        register_users(&*os_cfg, &act.conn, &mut users, &act.identity).await?;
        save_plist_atomic(&cfg.apple_dir.join("id.plist"), &users)?;
        let hw = SavedHardwareState {
            push: act.conn.state.read().await.clone(),
            relay: act.relay.clone(),
            identity: act
                .identity
                .save(IDENTITY_TAG)
                .map_err(|e| anyhow!("failed to save identity: {}", e))?
                .into(),
        };
        save_plist_atomic(&cfg.apple_dir.join("hw_info.plist"), &hw)?;

        let act = self.activated.take().expect("activated");
        Ok(Registered {
            relay: act.relay,
            identity: act.identity,
            conn: act.conn,
            users,
            number: parsed.number,
        })
    }
}

async fn register_users(
    os_cfg: &dyn OSConfig,
    conn: &APSConnection,
    users: &mut [IDSUser],
    identity: &IDSNGMIdentity,
) -> Result<()> {
    let reg = register(
        os_cfg,
        &*conn.state.read().await,
        &[&MADRID_SERVICE],
        users,
        identity,
    )
    .await;
    if let Err(err) = reg {
        match err {
            PushError::CustomerMessage(alert) => {
                bail!("Apple rejected the registration: {:?}", alert)
            }
            PushError::DeviceNotFound => {
                bail!("Built-in relay has no iPhone provider connected")
            }
            other => return Err(anyhow!(other)).context("IDS registration failed"),
        }
    }
    Ok(())
}

/// Connects to Apple push, activating a new device through the built-in relay if there is none saved.
async fn activate(cfg: &Config, internal_relay: &(String, String)) -> Result<Activated> {
    let hw_path = cfg.apple_dir.join("hw_info.plist");
    let (relay, identity, saved_push) = if hw_path.exists() {
        let mut hw: SavedHardwareState = plist::from_file(&hw_path)
            .with_context(|| format!("failed to load {}", hw_path.display()))?;
        apply_builtin_relay(&mut hw.relay, internal_relay);
        let identity = IDSNGMIdentity::restore(hw.identity.as_ref(), IDENTITY_TAG)
            .map_err(|e| anyhow!("failed to restore IDSNGMIdentity: {}", e))?;
        (hw.relay, identity, Some(hw.push))
    } else {
        if crate::fairplay::loaded() == 0 {
            bail!(
                "No FairPlay certs loaded; put a .crt chain + .key pair in {} and restart to activate a new device",
                crate::fairplay::dir(&cfg.apple_dir).display()
            );
        }
        info!("activating a new device through built-in registration relay");
        let version = RelayConfig::get_versions(&internal_relay.0, &internal_relay.1, &None)
            .await
            .map_err(|e| match e {
                PushError::DeviceNotFound => anyhow!(
                    "Built-in relay has no iPhone provider connected. Check relayserver on your iPhone."
                ),
                other => anyhow!("Built-in relay error: {}", other),
            })?;
        let mut udid_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut udid_bytes);
        let relay = RelayConfig {
            version,
            icloud_ua: "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0".to_string(),
            aoskit_version: "com.apple.AOSKit/282 (com.apple.accountsd/113)".to_string(),
            dev_uuid: Uuid::new_v4().to_string(),
            protocol_version: 1660,
            host: internal_relay.0.clone(),
            code: internal_relay.1.clone(),
            beeper_token: None,
            udid: Some(hex::encode(udid_bytes).to_uppercase()),
        };
        relay.generate_validation_data().await.map_err(|e| match e {
            PushError::DeviceNotFound => anyhow!(
                "Built-in relay iPhone provider disconnected while fetching validation data"
            ),
            other => anyhow!("Built-in relay rejected validation request: {}", other),
        })?;
        let identity =
            IDSNGMIdentity::new().map_err(|e| anyhow!("failed to create IDSNGMIdentity: {}", e))?;
        (relay, identity, None)
    };
    let (conn, err) = setup_push_connection(&cfg.apple_dir, &relay, &identity, saved_push).await?;
    if let Some(err) = err {
        bail!("Apple push activation failed: {}", err);
    }
    Ok(Activated {
        relay,
        identity,
        conn,
    })
}

async fn run_bridge(
    cfg: &Config,
    hub: Arc<Hub>,
    relay: Arc<RelayHub>,
    internal_relay: (String, String),
    incoming_rx: mpsc::Receiver<IncomingClientMsg>,
) -> Result<()> {
    let hw_path = cfg.apple_dir.join("hw_info.plist");
    let id_path = cfg.apple_dir.join("id.plist");
    let mut hw: SavedHardwareState = plist::from_file(&hw_path)
        .with_context(|| format!("failed to load {}", hw_path.display()))?;
    // Always point the loaded RelayConfig at the built-in loopback bridge (migrates existing installs).
    apply_builtin_relay(&mut hw.relay, &internal_relay);
    let users: Vec<IDSUser> = plist::from_file(&id_path)
        .with_context(|| format!("failed to load {}", id_path.display()))?;
    let identity = IDSNGMIdentity::restore(hw.identity.as_ref(), IDENTITY_TAG)
        .map_err(|e| anyhow!("failed to restore IDSNGMIdentity: {}", e))?;

    info!("restoring Apple APS connection...");
    let (conn, push_err) =
        setup_push_connection(&cfg.apple_dir, &hw.relay, &identity, Some(hw.push)).await?;
    if let Some(err) = push_err {
        warn!("APS restore returned error: {}", err);
    }
    bridge_loop(cfg, hub, relay, incoming_rx, conn, hw.relay, identity, users).await
}

enum RenewalPhase {
    Idle,
    WaitingForPhone,
    WaitingForSimInfo {
        client_id: String,
        started_at: Instant,
    },
    WaitingForRegResp {
        client_id: String,
        req_id: String,
        started_at: Instant,
    },
}

struct RenewalController {
    phase: RenewalPhase,
    urgent: bool,
    last_attempt: Option<Instant>,
}

impl RenewalController {
    fn new() -> Self {
        Self {
            phase: RenewalPhase::Idle,
            urgent: false,
            last_attempt: None,
        }
    }

    fn is_in_flight(&self) -> bool {
        matches!(
            self.phase,
            RenewalPhase::WaitingForSimInfo { .. } | RenewalPhase::WaitingForRegResp { .. }
        )
    }

    fn is_active_or_pending(&self) -> bool {
        !matches!(self.phase, RenewalPhase::Idle)
    }

    fn can_start_attempt(&self, urgent: bool) -> bool {
        let Some(last) = self.last_attempt else {
            return true;
        };
        let cooldown = if urgent {
            URGENT_RETRY_INTERVAL
        } else {
            PROACTIVE_RETRY_INTERVAL
        };
        last.elapsed() >= cooldown
    }

    fn timed_out_client(&self) -> Option<&str> {
        match &self.phase {
            RenewalPhase::WaitingForSimInfo {
                client_id,
                started_at,
            }
            | RenewalPhase::WaitingForRegResp {
                client_id,
                started_at,
                ..
            } if started_at.elapsed() >= RENEWAL_STEP_TIMEOUT => Some(client_id.as_str()),
            _ => None,
        }
    }
}

fn is_fatal_auth_failure(failure: &ResourceFailure) -> bool {
    failure.retry_wait.is_none()
        || matches!(&*failure.error, PushError::DoNotRetry(_))
        || failure.error.to_string().contains("6005")
}

fn format_retryable_failure(failure: &ResourceFailure, provider_connected: bool) -> String {
    let wait_s = failure.retry_wait.unwrap_or(300);
    if !provider_connected || matches!(&*failure.error, PushError::DeviceNotFound) {
        format!("Relay offline, retrying in {}s", wait_s)
    } else {
        format!("{}, retrying in {}s", failure.error, wait_s)
    }
}

enum SessionOutcome {
    Shutdown,
    RestartWithUsers(Vec<IDSUser>),
}

/// Runs `IMClient` sessions in a loop; after a successful phone-number renewal/re-auth, rebuilds
/// `IMClient` cleanly on the live `APSConnection` with the fresh `IDSUser` credentials.
async fn bridge_loop(
    cfg: &Config,
    hub: Arc<Hub>,
    relay: Arc<RelayHub>,
    mut incoming_rx: mpsc::Receiver<IncomingClientMsg>,
    conn: APSConnection,
    relay_cfg: RelayConfig,
    identity: IDSNGMIdentity,
    mut users: Vec<IDSUser>,
) -> Result<()> {
    let mut status = AppleStatusTracker::new(
        &cfg.state_dir,
        cfg.renewal.lead_days,
        &relay.status(),
    );
    status.state = REG_STATE_OK;
    status.detail.clear();
    status.last_success_ms = Some(now_epoch_ms());
    status.update_from_users(&users);
    if let Some(exp_ms) = status.auth_expires_at_ms {
        let days_left = exp_ms.saturating_sub(now_epoch_ms()) / MS_PER_DAY;
        info!(
            "Apple phone auth certificate expires in ~{} days (proactive renewal lead={} days)",
            days_left, cfg.renewal.lead_days
        );
    }
    status.save_and_broadcast(&hub).await;
    hub.media.set_aps(conn.clone());

    loop {
        let outcome = bridge_session(
            cfg,
            &hub,
            &relay,
            &mut incoming_rx,
            &conn,
            &relay_cfg,
            &identity,
            users,
            &mut status,
        )
        .await?;

        match outcome {
            SessionOutcome::Shutdown => return Ok(()),
            SessionOutcome::RestartWithUsers(new_users) => {
                info!("rebuilding IMClient with renewed phone registration");
                users = new_users;
                status.state = REG_STATE_OK;
                status.detail.clear();
                status.last_error = None;
                status.last_success_ms = Some(now_epoch_ms());
                status.renewal_pending = false;
                status.update_from_users(&users);
                status.save_and_broadcast(&hub).await;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn bridge_session(
    cfg: &Config,
    hub: &Arc<Hub>,
    relay: &Arc<RelayHub>,
    incoming_rx: &mut mpsc::Receiver<IncomingClientMsg>,
    conn: &APSConnection,
    relay_cfg: &RelayConfig,
    identity: &IDSNGMIdentity,
    users: Vec<IDSUser>,
    status: &mut AppleStatusTracker,
) -> Result<SessionOutcome> {
    let id_path = cfg.apple_dir.join("id.plist");

    // Subscribe to APS messages BEFORE creating/entering the receive loop.
    let mut aps_rx = conn.messages_cont.subscribe();

    let os_cfg: Arc<dyn OSConfig> = Arc::new(relay_cfg.clone());
    let id_path_cb = id_path.clone();
    let im_client = Arc::new(
        IMClient::new(
            conn.clone(),
            users,
            identity.clone(),
            &[&MADRID_SERVICE],
            cfg.apple_dir.join("id_cache.plist"),
            Arc::clone(&os_cfg),
            Box::new(move |updated_users| {
                info!("IdentityManager updated keys; persisting id.plist");
                if let Err(e) = save_plist_atomic(&id_path_cb, &updated_users) {
                    warn!("failed to save updated id.plist: {:#}", e);
                }
            }),
        )
        .await,
    );

    let handles = im_client.identity.get_handles().await;
    info!("Apple bridge active; handles: {:?}", handles);

    // Task 1: Apple -> Push clients
    let rx_client = Arc::clone(&im_client);
    let rx_hub = Arc::clone(hub);
    let rx_preferred = cfg.preferred_handle.clone();
    let rx_media = Arc::clone(&hub.media);
    let recv_task = tokio::spawn(async move {
        loop {
            let aps_msg = match aps_rx.recv().await {
                Ok(m) => m,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("APS message broadcast lagged by {} messages", n);
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    warn!("APS message stream closed");
                    break;
                }
            };

            let inst = match rx_client.handle(aps_msg).await {
                Ok(Some(inst)) => inst,
                Ok(None) => continue,
                Err(e) => {
                    warn!("IMClient::handle error: {}", e);
                    continue;
                }
            };

            let ts_ms = if inst.sent_timestamp > 0 {
                inst.sent_timestamp
            } else {
                now_epoch_ms()
            };
            let sender = inst.sender.clone().unwrap_or_default();
            let (participants, sender_guid) = match &inst.conversation {
                Some(conv) => (conv.participants.clone(), conv.sender_guid.clone()),
                None => (Vec::new(), None),
            };
            let is_normal = matches!(inst.message, Message::Message(_));
            let group_event = |event: u8, name: String, new_participants: Vec<String>| {
                AppBody::GroupEvent {
                    apple_msg_id: inst.id.clone(),
                    sender: sender.clone(),
                    participants: participants.clone(),
                    sender_guid: sender_guid.clone(),
                    timestamp_ms: ts_ms,
                    event,
                    name,
                    new_participants,
                }
            };

            let body = match &inst.message {
                Message::Message(nm) => {
                    let (text, attachments) = render_message(nm, &rx_media);
                    info!(
                        "[apple->client] INCOMING id={} from={} text_len={} attachments={}",
                        inst.id,
                        sender,
                        text.len(),
                        attachments.len()
                    );
                    Some(AppBody::IncomingMessage {
                        apple_msg_id: inst.id.clone(),
                        sender: sender.clone(),
                        participants: participants.clone(),
                        sender_guid: sender_guid.clone(),
                        timestamp_ms: ts_ms,
                        text,
                        reply_to: nm.reply_guid.clone(),
                        attachments,
                    })
                }
                Message::React(r) => reaction_code(r).map(|(reaction, emoji, enable)| {
                    info!(
                        "[apple->client] REACTION {} from={} on={} kind={} enable={}",
                        inst.id, sender, r.to_uuid, reaction, enable
                    );
                    AppBody::Reaction {
                        apple_msg_id: inst.id.clone(),
                        sender: sender.clone(),
                        participants: participants.clone(),
                        sender_guid: sender_guid.clone(),
                        timestamp_ms: ts_ms,
                        target_id: r.to_uuid.clone(),
                        reaction,
                        emoji,
                        enable,
                    }
                }),
                Message::Edit(e) => {
                    info!("[apple->client] EDIT {} from={} on={}", inst.id, sender, e.tuuid);
                    Some(AppBody::Edit {
                        apple_msg_id: inst.id.clone(),
                        sender: sender.clone(),
                        timestamp_ms: ts_ms,
                        target_id: e.tuuid.clone(),
                        text: parts_text(&e.new_parts, None),
                    })
                }
                Message::Unsend(u) => {
                    info!("[apple->client] UNSEND {} from={} on={}", inst.id, sender, u.tuuid);
                    Some(AppBody::Unsend {
                        apple_msg_id: inst.id.clone(),
                        sender: sender.clone(),
                        timestamp_ms: ts_ms,
                        target_id: u.tuuid.clone(),
                    })
                }
                Message::RenameMessage(r) => {
                    Some(group_event(GROUP_RENAMED, r.new_name.clone(), Vec::new()))
                }
                Message::ChangeParticipants(c) => Some(group_event(
                    GROUP_PARTICIPANTS,
                    String::new(),
                    c.new_participants.clone(),
                )),
                Message::IconChange(i) => Some(group_event(
                    GROUP_ICON,
                    if i.file.is_some() { "set".to_string() } else { String::new() },
                    Vec::new(),
                )),
                // Delivered/read receipts for what the phone sent aren't shown there, and each
                // one would wake it (CPU and radio), up to twice per sent message: dropped here.
                Message::Delivered | Message::Read => {
                    debug!("[apple] receipt {} from {} not forwarded", inst.id, sender);
                    None
                }
                _ => {
                    debug!("[apple] ignoring message id={} (not shown on the phone)", inst.id);
                    None
                }
            };
            // Persist to client outbox(es) BEFORE certifying delivery to Apple. What isn't
            // forwarded (receipts, kinds the phone doesn't show) is handled all the same, so it's
            // certified too: Apple resends what isn't, which would only wake us again.
            if let Some(body) = body {
                match body.encode() {
                    Ok(encoded) => {
                        let _ = rx_hub.deliver_all(encoded).await;
                    }
                    Err(e) => {
                        warn!("failed to encode body for {}: {:#}", inst.id, e);
                        continue;
                    }
                }
            }

            // Certify or send delivery receipt after outbox persistence.
            if let Some(ctx) = inst.certified_context {
                if let Err(e) = rx_client
                    .identity
                    .certify_delivery("com.apple.madrid", &ctx, inst.send_delivered)
                    .await
                {
                    warn!("certify_delivery failed for {}: {}", inst.id, e);
                }
            } else if is_normal && inst.send_delivered && !sender.is_empty() {
                let my_handles = rx_client.identity.get_handles().await;
                if let Some(me) = pick_sender_handle(&my_handles, rx_preferred.as_deref()) {
                    let mut delivered = MessageInst::new(
                        ConversationData {
                            participants: vec![sender.clone()],
                            cv_name: None,
                            sender_guid,
                            after_guid: None,
                        },
                        &me,
                        Message::Delivered,
                    );
                    delivered.id = inst.id.clone();
                    delivered.target = inst.target;
                    if let Err(e) = rx_client.send(&mut delivered).await {
                        warn!("failed to send Message::Delivered for {}: {}", inst.id, e);
                    }
                }
            }
        }
    });

    // Subscriptions for status, renewal, provider health, and phone connects.
    let mut id_state_rx = im_client.identity.resource_state.subscribe();
    let mut relay_status_rx = relay.subscribe_status();
    let mut connect_rx = hub.subscribe_connects();
    let mut renewal_tick = tokio::time::interval(RENEWAL_CHECK_INTERVAL);

    let mut renewal = RenewalController::new();
    let mut retryable_identity_failed = false;

    let preferred_handle = cfg.preferred_handle.clone();
    let mut outcome = SessionOutcome::Shutdown;

    // Immediately evaluate if the loaded cert is already within renewal lead time.
    maybe_trigger_proactive_renewal(hub, status, &mut renewal).await;

    loop {
        tokio::select! {
            changed = id_state_rx.changed() => {
                if changed.is_err() {
                    continue;
                }
                let state = id_state_rx.borrow().clone();
                match state {
                    ResourceState::Generated => {
                        retryable_identity_failed = false;
                        let cur_users = im_client.identity.users.read().await.clone();
                        status.update_from_users(&cur_users);
                        status.last_success_ms = Some(now_epoch_ms());
                        status.last_error = None;
                        if !renewal.is_active_or_pending() {
                            status.state = REG_STATE_OK;
                            status.detail.clear();
                        }
                        status.save_and_broadcast(hub).await;
                    }
                    ResourceState::Generating => {
                        debug!("IdentityManager re-registering with Apple...");
                    }
                    ResourceState::Failed(failure) => {
                        if is_fatal_auth_failure(&failure) {
                            warn!("IdentityManager fatal auth failure (re-auth required): {}", failure);
                            retryable_identity_failed = false;
                            status.last_error = Some(failure.to_string());
                            renewal.urgent = true;
                            if !renewal.is_in_flight() {
                                start_renewal_with_connected_or_wait(
                                    hub,
                                    status,
                                    &mut renewal,
                                    "Apple rejected auth (6005); renewing...",
                                )
                                .await;
                            }
                        } else {
                            let msg = format_retryable_failure(&failure, status.provider_connected);
                            warn!("IdentityManager retryable failure: {}", msg);
                            retryable_identity_failed = true;
                            status.last_error = Some(msg.clone());
                            if !renewal.is_active_or_pending() {
                                status.state = REG_STATE_OK;
                                status.detail = msg;
                            }
                            status.save_and_broadcast(hub).await;
                        }
                    }
                    ResourceState::Closed => {
                        warn!("IdentityManager closed unexpectedly; scheduling re-auth");
                        renewal.urgent = true;
                        if !renewal.is_in_flight() {
                            start_renewal_with_connected_or_wait(
                                hub,
                                status,
                                &mut renewal,
                                "Registration stopped; renewing...",
                            )
                            .await;
                        }
                    }
                }
            }

            changed = relay_status_rx.changed() => {
                if changed.is_ok() {
                    let rs = relay_status_rx.borrow().clone();
                    let was_connected = status.provider_connected;
                    if status.update_relay(&rs) {
                        status.save_and_broadcast(hub).await;
                    }
                    // If the iPhone provider just reconnected while IDS re-reg was backed off,
                    // poke IdentityManager to retry right away.
                    if !was_connected && rs.provider_connected && retryable_identity_failed {
                        info!("relay provider reconnected; retrying IDS re-registration now");
                        let id = Arc::clone(&im_client.identity);
                        tokio::spawn(async move {
                            let _ = id.refresh_now().await;
                        });
                    }
                }
            }

            joined = connect_rx.recv() => {
                if let Ok(cid) = joined {
                    status.send_to(hub, &cid).await;
                    if matches!(renewal.phase, RenewalPhase::WaitingForPhone) {
                        info!("client '{}' connected; starting pending phone renewal", cid);
                        begin_sim_info_request(hub, status, &mut renewal, cid).await;
                    }
                }
            }

            _ = renewal_tick.tick() => {
                if let Some(cid) = renewal.timed_out_client().map(str::to_string) {
                    warn!(
                        "phone renewal attempt with '{}' timed out after {}s",
                        cid,
                        RENEWAL_STEP_TIMEOUT.as_secs()
                    );
                    renewal.last_attempt = Some(Instant::now());
                    renewal.phase = RenewalPhase::Idle;
                    status.last_error = Some("Phone renewal timed out".to_string());
                    if renewal.urgent {
                        status.state = REG_STATE_FAILED;
                        status.detail = "Renewal timed out; will retry".to_string();
                        status.renewal_pending = true;
                    } else {
                        status.state = REG_STATE_OK;
                        status.detail = "Renewal timed out; retrying tomorrow".to_string();
                        status.renewal_pending = false;
                    }
                    status.save_and_broadcast(hub).await;
                } else if matches!(renewal.phase, RenewalPhase::Idle) {
                    if renewal.urgent && renewal.can_start_attempt(true) {
                        start_renewal_with_connected_or_wait(
                            hub,
                            status,
                            &mut renewal,
                            "Retrying iMessage renewal...",
                        )
                        .await;
                    } else {
                        maybe_trigger_proactive_renewal(hub, status, &mut renewal).await;
                    }
                }
            }

            maybe_msg = incoming_rx.recv() => {
                let Some(msg) = maybe_msg else {
                    break;
                };
                let body = match AppBody::decode(&msg.body) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(
                            "client '{}' seq={} failed to decode body: {:#}",
                            msg.client_id, msg.seq, e
                        );
                        continue;
                    }
                };

                match body {
                    AppBody::RegInfoReq => {
                        status.send_to(hub, &msg.client_id).await;
                    }
                    AppBody::GetHandles => {
                        let handles = im_client.identity.get_handles().await.to_vec();
                        let preferred = pick_sender_handle(&handles, preferred_handle.as_deref());
                        let reply = AppBody::Handles { handles, preferred };
                        deliver(hub, &msg.client_id, reply).await;
                    }
                    AppBody::SendMessage {
                        client_msg_id,
                        participants,
                        sender_guid,
                        text,
                        attachments,
                    } => {
                        let im_client = Arc::clone(&im_client);
                        let hub = Arc::clone(hub);
                        let conn = conn.clone();
                        let preferred = preferred_handle.clone();
                        let client_id = msg.client_id;

                        tokio::spawn(async move {
                            let result = send_imessage(
                                &im_client,
                                &conn,
                                &hub.media,
                                preferred.as_deref(),
                                &participants,
                                text,
                                &attachments,
                                sender_guid,
                            )
                            .await;
                            if result.is_ok() {
                                for a in &attachments {
                                    hub.media.remove_upload(&a.upload_id);
                                }
                            }
                            deliver(&hub, &client_id, send_result(client_msg_id, result)).await;
                        });
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
                        let im_client = Arc::clone(&im_client);
                        let hub = Arc::clone(hub);
                        let preferred = preferred_handle.clone();
                        let client_id = msg.client_id;

                        tokio::spawn(async move {
                            let result = send_reaction(
                                &im_client,
                                preferred.as_deref(),
                                &participants,
                                sender_guid,
                                target_id,
                                reaction,
                                emoji,
                                enable,
                                target_text,
                            )
                            .await;
                            deliver(&hub, &client_id, send_result(client_msg_id, result)).await;
                        });
                    }
                    AppBody::SendEdit {
                        client_msg_id,
                        participants,
                        sender_guid,
                        target_id,
                        part,
                        text,
                    } => {
                        let im_client = Arc::clone(&im_client);
                        let hub = Arc::clone(hub);
                        let preferred = preferred_handle.clone();
                        let client_id = msg.client_id;
                        tokio::spawn(async move {
                            let result = send_edit(
                                &im_client,
                                preferred.as_deref(),
                                &participants,
                                sender_guid,
                                target_id,
                                part,
                                text,
                            )
                            .await;
                            deliver(&hub, &client_id, send_result(client_msg_id, result)).await;
                        });
                    }
                    AppBody::SendUnsend {
                        client_msg_id,
                        participants,
                        sender_guid,
                        target_id,
                        parts,
                    } => {
                        let im_client = Arc::clone(&im_client);
                        let hub = Arc::clone(hub);
                        let preferred = preferred_handle.clone();
                        let client_id = msg.client_id;
                        tokio::spawn(async move {
                            let result = send_unsend(
                                &im_client,
                                preferred.as_deref(),
                                &participants,
                                sender_guid,
                                target_id,
                                parts,
                            )
                            .await;
                            deliver(&hub, &client_id, send_result(client_msg_id, result)).await;
                        });
                    }
                    AppBody::CheckTargets { req_id, targets } => {
                        let im_client = Arc::clone(&im_client);
                        let hub = Arc::clone(hub);
                        let preferred = preferred_handle.clone();
                        let client_id = msg.client_id;

                        tokio::spawn(async move {
                            let reply = check_imessage_targets(
                                &im_client,
                                preferred.as_deref(),
                                req_id,
                                targets,
                            )
                            .await;
                            deliver(&hub, &client_id, reply).await;
                        });
                    }
                    AppBody::SimInfo { mccmnc, number } => {
                        if renewal.is_active_or_pending() {
                            info!(
                                "renewal: client '{}' SIM info mccmnc={} number={:?}",
                                msg.client_id, mccmnc, number
                            );
                            match build_reg_sms_request(conn, &mccmnc).await {
                                Ok((gateway, text, req_id)) => {
                                    info!(
                                        "renewal: asking client '{}' to text {} to {}",
                                        msg.client_id, text, gateway
                                    );
                                    deliver(
                                        hub,
                                        &msg.client_id,
                                        AppBody::SendRegSms { gateway, text },
                                    )
                                    .await;
                                    send_status(
                                        hub,
                                        &msg.client_id,
                                        SETUP_WAITING_SMS,
                                        "Waiting for Apple's reply...",
                                    )
                                    .await;
                                    renewal.phase = RenewalPhase::WaitingForRegResp {
                                        client_id: msg.client_id.clone(),
                                        req_id,
                                        started_at: Instant::now(),
                                    };
                                    status.state = REG_STATE_RENEWING;
                                    status.detail = "Waiting for Apple SMS reply...".to_string();
                                    status.save_and_broadcast(hub).await;
                                }
                                Err(e) => {
                                    warn!("renewal SIM_INFO step failed: {:#}", e);
                                    fail_renewal_attempt(hub, status, &mut renewal, format!("{:#}", e))
                                        .await;
                                }
                            }
                        } else {
                            let handles = im_client.identity.get_handles().await.to_vec();
                            let detail = handles.first().cloned().unwrap_or_default();
                            send_status(hub, &msg.client_id, SETUP_READY, &detail).await;
                        }
                    }
                    AppBody::RegResp { text } => {
                        if renewal.is_active_or_pending() {
                            let expected_req_id = match &renewal.phase {
                                RenewalPhase::WaitingForRegResp { req_id, .. } => {
                                    Some(req_id.clone())
                                }
                                _ => None,
                            };
                            status.state = REG_STATE_RENEWING;
                            status.detail = "Registering renewed number with Apple...".to_string();
                            status.save_and_broadcast(hub).await;

                            let current_users = im_client.identity.users.read().await.clone();
                            match finish_phone_renewal(
                                cfg,
                                conn,
                                &*os_cfg,
                                identity,
                                current_users,
                                &text,
                                expected_req_id.as_deref(),
                            )
                            .await
                            {
                                Ok((new_users, number)) => {
                                    info!("successfully renewed Apple phone registration for {}", number);
                                    let ready = AppBody::SetupStatus {
                                        state: SETUP_READY,
                                        detail: number,
                                    };
                                    if let Ok(encoded) = ready.encode() {
                                        hub.deliver_connected(encoded).await;
                                    }
                                    outcome = SessionOutcome::RestartWithUsers(new_users);
                                    break;
                                }
                                Err(e) => {
                                    warn!("phone renewal failed: {:#}", e);
                                    fail_renewal_attempt(hub, status, &mut renewal, format!("{:#}", e))
                                        .await;
                                }
                            }
                        } else {
                            let handles = im_client.identity.get_handles().await.to_vec();
                            let detail = handles.first().cloned().unwrap_or_default();
                            send_status(hub, &msg.client_id, SETUP_READY, &detail).await;
                        }
                    }
                    other => {
                        warn!(
                            "client '{}' seq={} sent unsupported upstream body: {:?}",
                            msg.client_id, msg.seq, other
                        );
                    }
                }
            }
        }
    }

    recv_task.abort();
    im_client.identity.close();
    Ok(outcome)
}

async fn maybe_trigger_proactive_renewal(
    hub: &Hub,
    status: &mut AppleStatusTracker,
    renewal: &mut RenewalController,
) {
    if !matches!(renewal.phase, RenewalPhase::Idle) {
        return;
    }
    let renew_at = status.renew_at_ms();
    if renew_at == 0 {
        return;
    }
    let now = now_epoch_ms();
    if now < renew_at {
        return;
    }
    let expired = status.auth_expires_at_ms.map_or(false, |e| now >= e);
    if expired {
        renewal.urgent = true;
    }
    if !renewal.can_start_attempt(renewal.urgent) {
        return;
    }
    info!(
        "phone auth cert within {}d renewal window (expired={}); starting automatic renewal",
        status.renewal_lead_days, expired
    );
    start_renewal_with_connected_or_wait(
        hub,
        status,
        renewal,
        "Renewing iMessage registration...",
    )
    .await;
}

async fn start_renewal_with_connected_or_wait(
    hub: &Hub,
    status: &mut AppleStatusTracker,
    renewal: &mut RenewalController,
    detail: &str,
) {
    if let Some(cid) = hub.connected_client_ids().into_iter().next() {
        begin_sim_info_request(hub, status, renewal, cid).await;
    } else {
        info!("no phone connected for renewal; waiting for a phone to connect");
        renewal.phase = RenewalPhase::WaitingForPhone;
        status.state = REG_STATE_NEEDS_PHONE;
        status.detail = if detail.is_empty() {
            "Waiting for phone to renew".to_string()
        } else {
            detail.to_string()
        };
        status.renewal_pending = true;
        status.save_and_broadcast(hub).await;
    }
}

async fn begin_sim_info_request(
    hub: &Hub,
    status: &mut AppleStatusTracker,
    renewal: &mut RenewalController,
    client_id: String,
) {
    info!("starting SMS renewal with client '{}'", client_id);
    renewal.phase = RenewalPhase::WaitingForSimInfo {
        client_id: client_id.clone(),
        started_at: Instant::now(),
    };
    status.state = REG_STATE_RENEWING;
    status.detail = "Renewing registration...".to_string();
    status.renewal_pending = true;
    status.save_and_broadcast(hub).await;
    send_status(hub, &client_id, SETUP_NEED_SIM, "Renewing registration...").await;
}

async fn fail_renewal_attempt(
    hub: &Hub,
    status: &mut AppleStatusTracker,
    renewal: &mut RenewalController,
    err: String,
) {
    renewal.last_attempt = Some(Instant::now());
    renewal.phase = RenewalPhase::Idle;
    status.last_error = Some(err.clone());
    if renewal.urgent {
        status.state = REG_STATE_FAILED;
        status.detail = err;
        status.renewal_pending = true;
    } else {
        // Proactive renewal failed while the existing registration still works; retry tomorrow.
        status.state = REG_STATE_OK;
        status.detail = format!("Renewal retry scheduled ({})", err);
        status.renewal_pending = false;
    }
    status.save_and_broadcast(hub).await;
}

async fn finish_phone_renewal(
    cfg: &Config,
    conn: &APSConnection,
    os_cfg: &dyn OSConfig,
    identity: &IDSNGMIdentity,
    mut users: Vec<IDSUser>,
    reg_resp: &str,
    expected_req_id: Option<&str>,
) -> Result<(Vec<IDSUser>, String)> {
    let parsed = parse_reg_resp(reg_resp)?;
    if let (Some(want), Some(got)) = (expected_req_id, parsed.req_id.as_deref()) {
        if want != got {
            warn!(
                "renewal REG-RESP r={} does not match our request r={}; continuing",
                got, want
            );
        }
    }
    let push_token = conn.get_token().await;
    let phone_user = authenticate_phone(
        &parsed.number,
        AuthPhone {
            push_token: push_token.to_vec().into(),
            sigs: vec![parsed.sig_bytes.into()],
        },
        os_cfg,
    )
    .await
    .context("Apple rejected the phone number during renewal")?;

    if let Some(slot) = users
        .iter_mut()
        .find(|u| u.user_id == phone_user.user_id || u.user_id.starts_with("P:"))
    {
        *slot = phone_user;
    } else {
        users.push(phone_user);
    }

    register_users(os_cfg, conn, &mut users, identity).await?;
    save_plist_atomic(&cfg.apple_dir.join("id.plist"), &users)?;
    Ok((users, parsed.number))
}

async fn check_imessage_targets(
    im_client: &IMClient,
    preferred_handle: Option<&str>,
    req_id: String,
    raw_targets: Vec<String>,
) -> AppBody {
    let normalized: Vec<String> = raw_targets.iter().map(|t| normalize_target(t)).collect();
    if normalized.is_empty() {
        return AppBody::TargetStatus {
            req_id,
            registered: Vec::new(),
            unregistered: Vec::new(),
        };
    }
    let handles = im_client.identity.get_handles().await;
    let Some(me) = pick_sender_handle(&handles, preferred_handle) else {
        return AppBody::TargetStatus {
            req_id,
            registered: Vec::new(),
            unregistered: Vec::new(),
        };
    };
    match registered_targets(im_client, &normalized, &me).await {
        Ok(valid) => {
            let mut registered = Vec::new();
            let mut unregistered = Vec::new();
            for t in normalized {
                if valid.iter().any(|v| v.eq_ignore_ascii_case(&t)) {
                    registered.push(t);
                } else {
                    unregistered.push(t);
                }
            }
            AppBody::TargetStatus {
                req_id,
                registered,
                unregistered,
            }
        }
        Err(e) => {
            warn!("check_imessage_targets failed: {}", e);
            AppBody::TargetStatus {
                req_id,
                registered: Vec::new(),
                unregistered: Vec::new(),
            }
        }
    }
}

fn send_result(client_msg_id: String, result: Result<String>) -> AppBody {
    match result {
        Ok(apple_id) => AppBody::SendResult {
            client_msg_id,
            ok: true,
            apple_msg_id: Some(apple_id),
            error: None,
        },
        Err(e) => AppBody::SendResult {
            client_msg_id,
            ok: false,
            apple_msg_id: None,
            error: Some(format!("{:#}", e)),
        },
    }
}

struct Outgoing {
    me: String,
    targets: Vec<String>,
    conv: ConversationData,
}

/// Normalizes `raw_targets`, picks our sending handle, and (with `check_registered`) refuses
/// targets that are not on iMessage.
async fn outgoing_conversation(
    im_client: &IMClient,
    preferred_handle: Option<&str>,
    raw_targets: &[String],
    sender_guid: Option<String>,
    check_registered: bool,
) -> Result<Outgoing> {
    let handles = im_client.identity.get_handles().await;
    let me = pick_sender_handle(&handles, preferred_handle)
        .ok_or_else(|| anyhow!("no registered iMessage handle available"))?;
    let mut targets: Vec<String> = Vec::with_capacity(raw_targets.len());
    for raw in raw_targets {
        let t = normalize_target(raw);
        if !t.eq_ignore_ascii_case(&me) && !targets.iter().any(|x| x.eq_ignore_ascii_case(&t)) {
            targets.push(t);
        }
    }
    if targets.is_empty() {
        bail!("no recipients specified");
    }

    if check_registered {
        match registered_targets(im_client, &targets, &me).await {
            Ok(valid) => {
                for target in &targets {
                    if !valid.iter().any(|v| v.eq_ignore_ascii_case(target)) {
                        bail!("target '{}' is not registered on iMessage", target);
                    }
                }
            }
            Err(e) => {
                warn!(
                    "validate_targets for {:?} failed ({}); proceeding to send anyway",
                    targets, e
                );
            }
        }
    }

    let mut participants = targets.clone();
    participants.push(me.clone());
    Ok(Outgoing {
        me,
        targets,
        conv: ConversationData {
            participants,
            cv_name: None,
            sender_guid,
            after_guid: None,
        },
    })
}

/// Sends `inst`, waiting at most SEND_CONFIRM_WAIT for every recipient device to confirm.
async fn send_and_confirm(im_client: &IMClient, inst: &mut MessageInst) -> Result<()> {
    let job = im_client
        .send(inst)
        .await
        .map_err(|e| anyhow!("IMClient::send failed: {}", e))?;

    // rustpush keeps retrying devices that have not confirmed (an iPad or Mac that is off) for
    // minutes, but the phone gives up after 25 seconds and sends the text as SMS. Apple has the
    // message by now, so stop waiting after a while and let delivery go on in the background.
    if let Some(handle) = job.handle {
        match tokio::time::timeout(SEND_CONFIRM_WAIT, handle).await {
            Ok(joined) => joined
                .map_err(|e| anyhow!("send task join error: {}", e))?
                .map_err(|e| anyhow!("Apple delivery failed: {}", e))?,
            Err(_) => info!(
                "iMessage id={} not confirmed by every device after {:?}; reporting it sent",
                inst.id, SEND_CONFIRM_WAIT
            ),
        }
    }
    Ok(())
}

/// Uploads one attachment (converted for iPhones) to Apple.
async fn upload_attachment(
    conn: &APSConnection,
    media: &MediaStore,
    a: &OutAttachment,
) -> Result<Attachment> {
    let out = media.prepare_outgoing(&a.upload_id, &a.name, &a.mime).await?;
    let prepared = MMCSFile::prepare_put(fs::File::open(&out.path)?)
        .await
        .map_err(|e| anyhow!("preparing {} for Apple failed: {}", out.name, e))?;
    let att = Attachment::new_mmcs(
        conn,
        &prepared,
        fs::File::open(&out.path)?,
        &out.mime,
        &out.uti,
        &out.name,
        |_, _| {},
    )
    .await
    .map_err(|e| anyhow!("uploading {} to Apple failed: {}", out.name, e))?;
    info!("uploaded {} ({}, {} bytes) to Apple", out.name, out.mime, att.get_size());
    Ok(att)
}

#[allow(clippy::too_many_arguments)]
async fn send_imessage(
    im_client: &IMClient,
    conn: &APSConnection,
    media: &MediaStore,
    preferred_handle: Option<&str>,
    raw_targets: &[String],
    text: String,
    attachments: &[OutAttachment],
    sender_guid: Option<String>,
) -> Result<String> {
    let out = outgoing_conversation(im_client, preferred_handle, raw_targets, sender_guid, true).await?;

    let mut parts = Vec::with_capacity(attachments.len() + 1);
    for a in attachments {
        parts.push(IndexedMessagePart {
            part: MessagePart::Attachment(upload_attachment(conn, media, a).await?),
            idx: None,
            ext: None,
        });
    }
    if !text.is_empty() || parts.is_empty() {
        parts.push(IndexedMessagePart {
            part: MessagePart::Text(text, Default::default()),
            idx: None,
            ext: None,
        });
    }
    let mut nm = NormalMessage::new(String::new(), MessageType::IMessage);
    nm.parts = MessageParts(parts);

    let mut inst = MessageInst::new(out.conv, &out.me, Message::Message(nm));
    info!(
        "[client->apple] sending iMessage id={} from={} to={:?} attachments={}",
        inst.id,
        out.me,
        out.targets,
        attachments.len()
    );
    send_and_confirm(im_client, &mut inst).await?;
    Ok(inst.id)
}

fn reaction_from_code(code: u8, emoji: Option<String>) -> Result<Reaction> {
    Ok(match code {
        REACT_HEART => Reaction::Heart,
        REACT_LIKE => Reaction::Like,
        REACT_DISLIKE => Reaction::Dislike,
        REACT_LAUGH => Reaction::Laugh,
        REACT_EMPHASIZE => Reaction::Emphasize,
        REACT_QUESTION => Reaction::Question,
        REACT_EMOJI => Reaction::Emoji(
            emoji
                .filter(|e| !e.is_empty())
                .ok_or_else(|| anyhow!("emoji reaction without an emoji"))?,
        ),
        other => bail!("can't send reaction kind {}", other),
    })
}

#[allow(clippy::too_many_arguments)]
async fn send_reaction(
    im_client: &IMClient,
    preferred_handle: Option<&str>,
    raw_targets: &[String],
    sender_guid: Option<String>,
    target_id: String,
    code: u8,
    emoji: Option<String>,
    enable: bool,
    target_text: String,
) -> Result<String> {
    let reaction = reaction_from_code(code, emoji)?;
    let out = outgoing_conversation(im_client, preferred_handle, raw_targets, sender_guid, false).await?;
    let mut inst = MessageInst::new(
        out.conv,
        &out.me,
        Message::React(ReactMessage {
            to_uuid: target_id.clone(),
            to_part: Some(0),
            reaction: ReactMessageType::React { reaction, enable },
            to_text: target_text,
            embedded_profile: None,
        }),
    );
    info!(
        "[client->apple] sending reaction id={} kind={} enable={} on={} to={:?}",
        inst.id, code, enable, target_id, out.targets
    );
    send_and_confirm(im_client, &mut inst).await?;
    Ok(inst.id)
}

/// Replaces the text of the phone's own message `target_id` (its part `part`).
async fn send_edit(
    im_client: &IMClient,
    preferred_handle: Option<&str>,
    raw_targets: &[String],
    sender_guid: Option<String>,
    target_id: String,
    part: u8,
    text: String,
) -> Result<String> {
    if text.trim().is_empty() {
        bail!("An edit can't be empty (unsend the message instead)");
    }
    let out = outgoing_conversation(im_client, preferred_handle, raw_targets, sender_guid, false).await?;
    let new_parts = MessageParts(vec![IndexedMessagePart {
        part: MessagePart::Text(text, Default::default()),
        idx: None,
        ext: None,
    }]);
    let mut inst = MessageInst::new(
        out.conv,
        &out.me,
        Message::Edit(EditMessage {
            tuuid: target_id.clone(),
            edit_part: part as u64,
            new_parts,
        }),
    );
    info!(
        "[client->apple] sending edit id={} on={} part={} to={:?}",
        inst.id, target_id, part, out.targets
    );
    send_and_confirm(im_client, &mut inst).await?;
    Ok(inst.id)
}

/// Takes back the phone's own message `target_id`, each of its `parts`.
async fn send_unsend(
    im_client: &IMClient,
    preferred_handle: Option<&str>,
    raw_targets: &[String],
    sender_guid: Option<String>,
    target_id: String,
    parts: u8,
) -> Result<String> {
    let out = outgoing_conversation(im_client, preferred_handle, raw_targets, sender_guid, false).await?;
    let mut first_id = None;
    for part in 0..parts.max(1) {
        let mut inst = MessageInst::new(
            out.conv.clone(),
            &out.me,
            Message::Unsend(UnsendMessage {
                tuuid: target_id.clone(),
                edit_part: part as u64,
            }),
        );
        info!(
            "[client->apple] sending unsend id={} on={} part={} to={:?}",
            inst.id, target_id, part, out.targets
        );
        match send_and_confirm(im_client, &mut inst).await {
            Ok(()) => {
                first_id.get_or_insert(inst.id);
            }
            // The first part decides: once one went out, the message is (partly) taken back.
            Err(e) if first_id.is_none() => return Err(e),
            Err(e) => warn!("unsend of {} part {} failed: {:#}", target_id, part, e),
        }
    }
    first_id.ok_or_else(|| anyhow!("nothing to unsend"))
}

/// (kind, emoji, enable) of an incoming tapback, or None for iMessage-app updates.
fn reaction_code(r: &ReactMessage) -> Option<(u8, Option<String>, bool)> {
    match &r.reaction {
        ReactMessageType::React { reaction, enable } => Some(match reaction {
            Reaction::Heart => (REACT_HEART, None, *enable),
            Reaction::Like => (REACT_LIKE, None, *enable),
            Reaction::Dislike => (REACT_DISLIKE, None, *enable),
            Reaction::Laugh => (REACT_LAUGH, None, *enable),
            Reaction::Emphasize => (REACT_EMPHASIZE, None, *enable),
            Reaction::Question => (REACT_QUESTION, None, *enable),
            Reaction::Emoji(e) => (REACT_EMOJI, Some(e.clone()), *enable),
            Reaction::Sticker { .. } => (REACT_STICKER, None, *enable),
        }),
        // A sticker dropped onto the message.
        ReactMessageType::Extension { spec, .. } if spec.balloon.is_none() => {
            Some((REACT_STICKER, None, true))
        }
        ReactMessageType::Extension { .. } => None,
    }
}

/// "[Apple Cash]", "[GamePigeon: 8 Ball]": a readable stand-in for an iMessage app bubble.
fn object_label(breadcrumb: &str, app: Option<&ExtensionApp>) -> String {
    let mut label = breadcrumb.trim().to_string();
    let mut detail = String::new();
    if let Some(app) = app {
        if label.is_empty() {
            label = app.name.trim().to_string();
        }
        if let Some(b) = &app.balloon {
            if let Some(BalloonLayout::TemplateLayout {
                caption, subcaption, ..
            }) = &b.layout
            {
                detail = [caption.trim(), subcaption.trim()]
                    .iter()
                    .filter(|s| !s.is_empty())
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ");
            }
            if detail.is_empty() {
                if let Some(t) = &b.ld_text {
                    detail = t.trim().to_string();
                }
            }
        }
    }
    if label.is_empty() {
        label = "iMessage app".to_string();
    }
    if !detail.is_empty() && !detail.eq_ignore_ascii_case(&label) {
        format!("[{}: {}]", label, detail)
    } else {
        format!("[{}]", label)
    }
}

fn human_size(bytes: u64) -> String {
    if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{} KB", bytes / 1_000)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Text shown when an attachment can't be delivered as media.
fn attachment_placeholder(kind: u8, name: &str, size: u64) -> String {
    match kind {
        ATTACH_IMAGE => "[Photo]".to_string(),
        ATTACH_STICKER => "[Sticker]".to_string(),
        ATTACH_VIDEO => "[Video]".to_string(),
        ATTACH_VOICE => "[Voice message]".to_string(),
        ATTACH_AUDIO => format!("[Audio: {}]", name),
        ATTACH_VCARD => format!("[Contact: {}]", name.trim_end_matches(".vcf")),
        _ if size > 0 => format!("[File: {}, {}]", name, human_size(size)),
        _ => format!("[File: {}]", name),
    }
}

fn push_line(text: &mut String, line: &str) {
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(line);
}

fn is_link_preview(app: &ExtensionApp) -> bool {
    app.bundle_id.contains("URLBalloonProvider")
}

/// The text of `parts` with mentions flattened, app bubbles labelled and attachments left out.
fn parts_text(parts: &MessageParts, app: Option<&ExtensionApp>) -> String {
    let mut text = String::new();
    for p in &parts.0 {
        match &p.part {
            MessagePart::Text(t, _) => text.push_str(t),
            MessagePart::Mention(_, t) => {
                text.push('@');
                text.push_str(t);
            }
            MessagePart::Object(b) => push_line(&mut text, &object_label(b, app)),
            MessagePart::Attachment(_) => {}
        }
    }
    text.trim().to_string()
}

/// Turns an incoming message into phone text plus media to fetch (registered with `media`).
fn render_message(nm: &NormalMessage, media: &Arc<MediaStore>) -> (String, Vec<InAttachment>) {
    let app = nm.app.as_ref().filter(|a| !is_link_preview(a));
    let mut text = String::new();
    let mut attachments = Vec::new();
    let mut saw_object = false;
    for p in &nm.parts.0 {
        match &p.part {
            MessagePart::Text(t, _) => text.push_str(t),
            MessagePart::Mention(_, t) => {
                text.push('@');
                text.push_str(t);
            }
            MessagePart::Object(b) => {
                saw_object = true;
                push_line(&mut text, &object_label(b, app));
            }
            MessagePart::Attachment(a) => {
                let sticker = p.ext.is_some();
                let size = a.get_size() as u64;
                let kind = media::classify(&a.mime, &a.uti_type, &a.name, nm.voice, sticker);
                if kind == ATTACH_FILE {
                    push_line(&mut text, &attachment_placeholder(kind, &a.name, size));
                    continue;
                }
                match media.register_incoming(a, nm.voice, sticker) {
                    Ok(r) => attachments.push(r),
                    Err(e) => {
                        warn!("couldn't keep attachment {}: {:#}", a.name, e);
                        push_line(&mut text, &attachment_placeholder(kind, &a.name, size));
                    }
                }
            }
        }
    }
    if let Some(app) = app {
        if !saw_object {
            let label = object_label("", Some(app));
            text = if text.trim().is_empty() {
                label
            } else {
                format!("{}\n{}", label, text)
            };
        }
    }
    let mut text = text.trim().to_string();
    if let Some(subject) = nm.subject.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        text = if text.is_empty() {
            subject.to_string()
        } else {
            format!("{}\n{}", subject, text)
        };
    }
    (text, attachments)
}

/// How long a send waits for every recipient device to confirm (the phone waits 25 seconds).
const SEND_CONFIRM_WAIT: Duration = Duration::from_secs(12);

/// Which of `targets` can receive iMessage, through rustpush's lookup cache. An answer with no
/// devices stays cached for an hour; Apple gives those while it throttles a new registration, so
/// asking again sooner (or clearing the cache) only adds lookups.
async fn registered_targets(
    im_client: &IMClient,
    targets: &[String],
    me: &str,
) -> Result<Vec<String>, PushError> {
    let devices = im_client
        .identity
        .targets_for_handles("com.apple.madrid", targets, me)
        .await?;
    Ok(targets
        .iter()
        .filter(|t| devices.iter().any(|d| d.participant.eq_ignore_ascii_case(t)))
        .cloned()
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::X509Builder;

    fn att(name: &str, mime: &str, uti: &str, data: &[u8]) -> Attachment {
        Attachment {
            a_type: rustpush::AttachmentType::Inline(data.to_vec()),
            part: 0,
            uti_type: uti.to_string(),
            mime: mime.to_string(),
            name: name.to_string(),
            iris: false,
        }
    }

    fn part(p: MessagePart) -> IndexedMessagePart {
        IndexedMessagePart { part: p, idx: None, ext: None }
    }

    fn store() -> Arc<MediaStore> {
        let dir = std::env::temp_dir().join(format!("imsg-test-{}", Uuid::new_v4()));
        Arc::new(MediaStore::new(&dir, Some("/nonexistent/ffmpeg"), 1).unwrap())
    }

    #[tokio::test]
    async fn renders_text_mentions_objects_and_files() {
        let media = store();
        let mut nm = NormalMessage::new(String::new(), MessageType::IMessage);
        nm.parts = MessageParts(vec![
            part(MessagePart::Mention("tel:+15551234567".into(), "Sam".into())),
            part(MessagePart::Text(" sent you money".into(), Default::default())),
            part(MessagePart::Object("Apple Cash".into())),
            part(MessagePart::Attachment(att("report.pdf", "application/pdf", "com.adobe.pdf", &[0u8; 2048]))),
        ]);
        let (text, atts) = render_message(&nm, &media);
        assert_eq!(text, "@Sam sent you money\n[Apple Cash]\n[File: report.pdf, 2 KB]");
        assert!(atts.is_empty());
    }

    #[tokio::test]
    async fn photos_become_fetchable_attachments() {
        let media = store();
        let mut nm = NormalMessage::new(String::new(), MessageType::IMessage);
        nm.parts = MessageParts(vec![
            part(MessagePart::Attachment(att("IMG_0001.HEIC", "image/heic", "public.heic", b"x"))),
            part(MessagePart::Text("look".into(), Default::default())),
        ]);
        nm.subject = Some("Trip".into());
        let (text, atts) = render_message(&nm, &media);
        assert_eq!(text, "Trip\nlook");
        assert_eq!(atts.len(), 1);
        assert_eq!(atts[0].kind, ATTACH_IMAGE);
        assert_eq!(atts[0].name, "IMG_0001.HEIC");
        assert!(crate::media::valid_id(&atts[0].media_id));
    }

    #[test]
    fn labels_and_placeholders() {
        assert_eq!(object_label("", None), "[iMessage app]");
        assert_eq!(object_label(" Check In ", None), "[Check In]");
        assert_eq!(attachment_placeholder(ATTACH_VOICE, "Audio Message.caf", 10), "[Voice message]");
        assert_eq!(attachment_placeholder(ATTACH_FILE, "a.zip", 3_400_000), "[File: a.zip, 3.4 MB]");
        assert_eq!(reaction_from_code(REACT_LAUGH, None).map(|r| matches!(r, Reaction::Laugh)).ok(), Some(true));
        assert!(reaction_from_code(REACT_EMOJI, None).is_err());
        assert!(reaction_from_code(REACT_STICKER, None).is_err());
    }

    #[test]
    fn normalize_target_cases() {
        assert_eq!(normalize_target("+1 (555) 123-4567"), "tel:+15551234567");
        assert_eq!(normalize_target("15551234567"), "tel:+15551234567");
        assert_eq!(normalize_target("tel:+15551234567"), "tel:+15551234567");
        assert_eq!(
            normalize_target("alice@icloud.com"),
            "mailto:alice@icloud.com"
        );
        assert_eq!(
            normalize_target("mailto:alice@icloud.com"),
            "mailto:alice@icloud.com"
        );
    }

    #[test]
    fn pick_sender_handle_prefers_configured() {
        let handles = vec![
            "tel:+15550001111".to_string(),
            "mailto:me@icloud.com".to_string(),
        ];
        assert_eq!(
            pick_sender_handle(&handles, Some("MAILTO:me@icloud.com")),
            Some("mailto:me@icloud.com".to_string())
        );
        assert_eq!(
            pick_sender_handle(&handles, None),
            Some("tel:+15550001111".to_string())
        );
    }

    #[test]
    fn parse_reg_resp_variants() {
        let full = "REG-RESP?v=3;r=123456;n=+15551234567;s=0102aabb;";
        let p = parse_reg_resp(full).unwrap();
        assert_eq!(p.req_id.as_deref(), Some("123456"));
        assert_eq!(p.number, "+15551234567");
        assert_eq!(p.sig_bytes, vec![0x01, 0x02, 0xaa, 0xbb]);

        let prefixed = "junk header REG-RESP?v=3;r=99;n=+15550009999;s=deadbeef";
        let p2 = parse_reg_resp(prefixed).unwrap();
        assert_eq!(p2.number, "+15550009999");
        assert_eq!(p2.sig_bytes, vec![0xde, 0xad, 0xbe, 0xef]);

        let short = "+15552223333|cafe01";
        let p3 = parse_reg_resp(short).unwrap();
        assert_eq!(p3.req_id, None);
        assert_eq!(p3.number, "+15552223333");
        assert_eq!(p3.sig_bytes, vec![0xca, 0xfe, 0x01]);
    }

    #[test]
    fn cert_not_after_and_renew_at_computation() {
        let rsa = Rsa::generate(1024).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        let nb = Asn1Time::from_unix(1_700_000_000).unwrap();
        let na = Asn1Time::from_unix(1_800_000_000).unwrap();
        builder.set_not_before(&nb).unwrap();
        builder.set_not_after(&na).unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let der = builder.build().to_der().unwrap();

        let exp_ms = cert_not_after_ms(&der).unwrap();
        assert_eq!(exp_ms, 1_800_000_000_000);
        assert_eq!(
            compute_renew_at_ms(Some(exp_ms), 7),
            1_800_000_000_000 - 7 * MS_PER_DAY
        );
    }
}
