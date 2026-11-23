use crate::body::{
    AppBody, RECEIPT_DELIVERED, RECEIPT_READ, SETUP_FAILED, SETUP_NEED_SIM, SETUP_READY,
    SETUP_WAITING_SMS, SETUP_WORKING,
};
use crate::config::Config;
use crate::push::{Hub, IncomingClientMsg};
use anyhow::{anyhow, bail, Context, Result};
use keystore::init_keystore;
use keystore::software::{SoftwareEncryptor, SoftwareKeystore};
use log::{debug, error, info, warn};
use plist::Data;
use rand::RngCore;
use rustpush::facetime::{FACETIME_SERVICE, VIDEO_SERVICE};
use rustpush::findmy::MULTIPLEX_SERVICE;
use rustpush::{
    authenticate_phone, get_gateways_for_mccmnc, register, APSConnection, APSConnectionResource,
    APSState, AuthPhone, ConversationData, IDSNGMIdentity, IDSUser, IMClient, Message,
    MessageInst, MessageType, NormalMessage, OSConfig, PushError, RelayConfig, MADRID_SERVICE,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Once};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

const IDENTITY_TAG: &str = "imsg-server";

static KEYSTORE_INIT: Once = Once::new();

#[derive(Serialize, Deserialize, Clone)]
struct SavedHardwareState {
    push: APSState,
    relay: RelayConfig,
    identity: Data,
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
        let number = num.trim().strip_prefix("tel:").unwrap_or(num.trim()).to_string();
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
    // Strip formatting characters from phone numbers while preserving leading '+'
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
    mut incoming_rx: mpsc::Receiver<IncomingClientMsg>,
) -> Result<()> {
    init_software_keystore(&cfg.apple_dir)?;
    if cfg.apple_dir.join("id.plist").exists() {
        return run_bridge(cfg, hub, incoming_rx).await;
    }
    info!("not registered with Apple yet; waiting for a paired phone to register its number");

    let mut setup = PhoneSetup::default();
    while let Some(msg) = incoming_rx.recv().await {
        let body = match AppBody::decode(&msg.body) {
            Ok(b) => b,
            Err(e) => {
                warn!("client '{}' sent an undecodable body: {:#}", msg.client_id, e);
                continue;
            }
        };
        let client = msg.client_id.as_str();
        match body {
            AppBody::GetHandles => {
                send_status(&hub, client, SETUP_NEED_SIM, "Send SIM info to register").await;
            }
            AppBody::SimInfo { mccmnc, number } => {
                info!("client '{}' SIM info: mccmnc={} number={:?}", client, mccmnc, number);
                send_status(&hub, client, SETUP_WORKING, "Activating with Apple...").await;
                match setup.start(cfg, &mccmnc).await {
                    Ok((gateway, text)) => {
                        info!("asking client '{}' to text {} to {}", client, text, gateway);
                        deliver(&hub, client, AppBody::SendRegSms { gateway, text }).await;
                        send_status(&hub, client, SETUP_WAITING_SMS, "Waiting for Apple's reply...")
                            .await;
                    }
                    Err(e) => {
                        warn!("phone setup failed: {:#}", e);
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
                        return bridge_with(
                            cfg,
                            hub,
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
                        send_status(&hub, client, SETUP_FAILED, &format!("{:#}", e)).await;
                    }
                }
            }
            AppBody::SendText { client_msg_id, .. } | AppBody::SendGroupText { client_msg_id, .. } => {
                let reply = AppBody::SendResult {
                    client_msg_id,
                    ok: false,
                    apple_msg_id: None,
                    error: Some("iMessage is not set up yet".to_string()),
                };
                deliver(&hub, client, reply).await;
            }
            AppBody::CheckTargets { req_id, targets } => {
                let reply = AppBody::TargetStatus {
                    req_id,
                    registered: Vec::new(),
                    unregistered: targets,
                };
                deliver(&hub, client, reply).await;
            }
            other => warn!("client '{}' sent {:?} before setup finished", client, other),
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
    async fn start(&mut self, cfg: &Config, mccmnc: &str) -> Result<(String, String)> {
        let mccmnc = mccmnc.trim();
        if mccmnc.is_empty() {
            bail!("No SIM card found. Insert the SIM for the number you want to use.");
        }
        if self.activated.is_none() {
            self.activated = Some(activate(cfg).await?);
        }
        let act = self.activated.as_ref().expect("activated");
        let carrier = get_gateways_for_mccmnc(mccmnc)
            .await
            .map_err(|e| anyhow!("Apple has no SMS gateway for carrier {} ({})", mccmnc, e))?;
        let token_hex = hex::encode(act.conn.get_token().await).to_uppercase();
        let req_id: u32 = rand::random::<u32>() % 1_900_000_000 + 100_000_000;
        self.req_id = Some(req_id.to_string());
        Ok((
            carrier.gateway,
            format!("REG-REQ?v=3;t={};r={};", token_hex, req_id),
        ))
    }

    /// Registers the number from Apple's REG-RESP and saves the credentials.
    async fn finish(&mut self, cfg: &Config, reg_resp: &str) -> Result<Registered> {
        let parsed = parse_reg_resp(reg_resp)?;
        if let (Some(want), Some(got)) = (&self.req_id, &parsed.req_id) {
            if want != got {
                warn!("REG-RESP r={} does not match our request r={}; continuing", got, want);
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
        let reg = register(
            &*os_cfg,
            &*act.conn.state.read().await,
            &[
                &MADRID_SERVICE,
                &MULTIPLEX_SERVICE,
                &FACETIME_SERVICE,
                &VIDEO_SERVICE,
            ],
            &mut users,
            &act.identity,
        )
        .await;
        if let Err(err) = reg {
            match err {
                PushError::CustomerMessage(alert) => {
                    bail!("Apple rejected the registration: {:?}", alert)
                }
                other => return Err(anyhow!(other)).context("IDS registration failed"),
            }
        }
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

/// Connects to Apple push, activating a new device through the relay if there is none saved.
async fn activate(cfg: &Config) -> Result<Activated> {
    let hw_path = cfg.apple_dir.join("hw_info.plist");
    let (relay, identity, saved_push) = if hw_path.exists() {
        let hw: SavedHardwareState = plist::from_file(&hw_path)
            .with_context(|| format!("failed to load {}", hw_path.display()))?;
        let identity = IDSNGMIdentity::restore(hw.identity.as_ref(), IDENTITY_TAG)
            .map_err(|e| anyhow!("failed to restore IDSNGMIdentity: {}", e))?;
        (hw.relay, identity, Some(hw.push))
    } else {
        let r = cfg
            .relay
            .as_ref()
            .ok_or_else(|| anyhow!("The server has no [relay] in config.toml"))?;
        info!("activating a new device through relay {}", r.host);
        let version = RelayConfig::get_versions(&r.host, &r.code, &None)
            .await
            .context("Could not reach the registration relay")?;
        let mut udid_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut udid_bytes);
        let relay = RelayConfig {
            version,
            icloud_ua: "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0".to_string(),
            aoskit_version: "com.apple.AOSKit/282 (com.apple.accountsd/113)".to_string(),
            dev_uuid: Uuid::new_v4().to_string(),
            protocol_version: 1660,
            host: r.host.clone(),
            code: r.code.clone(),
            beeper_token: None,
            udid: Some(hex::encode(udid_bytes).to_uppercase()),
        };
        relay
            .generate_validation_data()
            .await
            .context("The registration relay rejected the request")?;
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

pub async fn run_bridge(
    cfg: &Config,
    hub: Arc<Hub>,
    incoming_rx: mpsc::Receiver<IncomingClientMsg>,
) -> Result<()> {
    let hw_path = cfg.apple_dir.join("hw_info.plist");
    let id_path = cfg.apple_dir.join("id.plist");
    let hw: SavedHardwareState = plist::from_file(&hw_path)
        .with_context(|| format!("failed to load {}", hw_path.display()))?;
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
    bridge_with(cfg, hub, incoming_rx, conn, hw.relay, identity, users).await
}

async fn bridge_with(
    cfg: &Config,
    hub: Arc<Hub>,
    mut incoming_rx: mpsc::Receiver<IncomingClientMsg>,
    conn: APSConnection,
    relay: RelayConfig,
    identity: IDSNGMIdentity,
    users: Vec<IDSUser>,
) -> Result<()> {
    let id_path = cfg.apple_dir.join("id.plist");

    // Subscribe to APS messages BEFORE creating/entering the receive loop.
    let mut aps_rx = conn.messages_cont.subscribe();

    let os_cfg: Arc<dyn OSConfig> = Arc::new(relay.clone());
    let id_path_cb = id_path.clone();
    let im_client = Arc::new(
        IMClient::new(
            conn.clone(),
            users,
            identity,
            &[
                &MADRID_SERVICE,
                &MULTIPLEX_SERVICE,
                &FACETIME_SERVICE,
                &VIDEO_SERVICE,
            ],
            cfg.apple_dir.join("id_cache.plist"),
            os_cfg,
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
    let rx_hub = Arc::clone(&hub);
    let rx_preferred = cfg.preferred_handle.clone();
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

            match inst.message {
                Message::Message(nm) => {
                    let text = nm.parts.raw_text();
                    let (participants, sender_guid) = match &inst.conversation {
                        Some(conv) => (conv.participants.clone(), conv.sender_guid.clone()),
                        None => (Vec::new(), None),
                    };

                    info!(
                        "[apple->client] INCOMING_TEXT id={} from={} text_len={}",
                        inst.id,
                        sender,
                        text.len()
                    );

                    let body = AppBody::IncomingText {
                        apple_msg_id: inst.id.clone(),
                        sender: sender.clone(),
                        participants,
                        sender_guid: sender_guid.clone(),
                        timestamp_ms: ts_ms,
                        text,
                    };

                    // Persist to client outbox(es) BEFORE certifying delivery to Apple.
                    match body.encode() {
                        Ok(encoded) => {
                            let _ = rx_hub.deliver_all(encoded).await;
                        }
                        Err(e) => {
                            warn!("failed to encode INCOMING_TEXT: {:#}", e);
                            continue;
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
                    } else if inst.send_delivered && !sender.is_empty() {
                        let my_handles = rx_client.identity.get_handles().await;
                        if let Some(me) =
                            pick_sender_handle(&my_handles, rx_preferred.as_deref())
                        {
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
                Message::Delivered => {
                    let body = AppBody::Receipt {
                        kind: RECEIPT_DELIVERED,
                        apple_msg_id: inst.id,
                        sender,
                        timestamp_ms: ts_ms,
                    };
                    if let Ok(encoded) = body.encode() {
                        let _ = rx_hub.deliver_all(encoded).await;
                    }
                }
                Message::Read => {
                    let body = AppBody::Receipt {
                        kind: RECEIPT_READ,
                        apple_msg_id: inst.id,
                        sender,
                        timestamp_ms: ts_ms,
                    };
                    if let Ok(encoded) = body.encode() {
                        let _ = rx_hub.deliver_all(encoded).await;
                    }
                }
                _ => {
                    debug!("[apple] ignoring non-text message id={}", inst.id);
                }
            }
        }
    });

    // Task 2: Push clients -> Apple
    let preferred_handle = cfg.preferred_handle.clone();
    while let Some(msg) = incoming_rx.recv().await {
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
            AppBody::GetHandles => {
                let handles = im_client.identity.get_handles().await.to_vec();
                let preferred = pick_sender_handle(&handles, preferred_handle.as_deref());
                let reply = AppBody::Handles { handles, preferred };
                if let Ok(encoded) = reply.encode() {
                    if let Err(e) = hub.deliver(&msg.client_id, encoded).await {
                        warn!("failed to deliver HANDLES: {:#}", e);
                    }
                }
            }
            AppBody::SendText {
                client_msg_id,
                target,
                text,
                sender_guid,
            } => {
                let im_client = Arc::clone(&im_client);
                let hub = Arc::clone(&hub);
                let preferred = preferred_handle.clone();
                let client_id = msg.client_id;

                tokio::spawn(async move {
                    let result = send_imessage(
                        &im_client,
                        preferred.as_deref(),
                        &[target],
                        text,
                        sender_guid,
                    )
                    .await;

                    let reply = match result {
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
                    };

                    if let Ok(encoded) = reply.encode() {
                        if let Err(e) = hub.deliver(&client_id, encoded).await {
                            warn!("failed to deliver SEND_RESULT: {:#}", e);
                        }
                    }
                });
            }
            AppBody::SendGroupText {
                client_msg_id,
                participants,
                text,
                sender_guid,
            } => {
                let im_client = Arc::clone(&im_client);
                let hub = Arc::clone(&hub);
                let preferred = preferred_handle.clone();
                let client_id = msg.client_id;

                tokio::spawn(async move {
                    let result = send_imessage(
                        &im_client,
                        preferred.as_deref(),
                        &participants,
                        text,
                        sender_guid,
                    )
                    .await;

                    let reply = match result {
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
                    };

                    if let Ok(encoded) = reply.encode() {
                        if let Err(e) = hub.deliver(&client_id, encoded).await {
                            warn!("failed to deliver group SEND_RESULT: {:#}", e);
                        }
                    }
                });
            }
            AppBody::CheckTargets { req_id, targets } => {
                let im_client = Arc::clone(&im_client);
                let hub = Arc::clone(&hub);
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
                    if let Ok(encoded) = reply.encode() {
                        if let Err(e) = hub.deliver(&client_id, encoded).await {
                            warn!("failed to deliver TARGET_STATUS: {:#}", e);
                        }
                    }
                });
            }
            AppBody::SimInfo { .. } | AppBody::RegResp { .. } => {
                let handles = im_client.identity.get_handles().await.to_vec();
                let detail = handles.first().cloned().unwrap_or_default();
                send_status(&hub, &msg.client_id, SETUP_READY, &detail).await;
            }
            other => {
                warn!(
                    "client '{}' seq={} sent unsupported upstream body: {:?}",
                    msg.client_id, msg.seq, other
                );
            }
        }
    }

    recv_task.abort();
    Ok(())
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
    match im_client
        .identity
        .validate_targets(&normalized, "com.apple.madrid", &me)
        .await
    {
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

async fn send_imessage(
    im_client: &IMClient,
    preferred_handle: Option<&str>,
    raw_targets: &[String],
    text: String,
    sender_guid: Option<String>,
) -> Result<String> {
    if raw_targets.is_empty() {
        bail!("no recipients specified");
    }
    let mut targets: Vec<String> = Vec::with_capacity(raw_targets.len());
    for raw in raw_targets {
        let t = normalize_target(raw);
        if !targets.iter().any(|x| x.eq_ignore_ascii_case(&t)) {
            targets.push(t);
        }
    }
    let handles = im_client.identity.get_handles().await;
    let me = pick_sender_handle(&handles, preferred_handle)
        .ok_or_else(|| anyhow!("no registered iMessage handle available"))?;

    match im_client
        .identity
        .validate_targets(&targets, "com.apple.madrid", &me)
        .await
    {
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

    let mut participants = targets.clone();
    if !participants.iter().any(|p| p.eq_ignore_ascii_case(&me)) {
        participants.push(me.clone());
    }

    let conv = ConversationData {
        participants,
        cv_name: None,
        sender_guid,
        after_guid: None,
    };
    let mut inst = MessageInst::new(
        conv,
        &me,
        Message::Message(NormalMessage::new(text, MessageType::IMessage)),
    );

    info!(
        "[client->apple] sending iMessage id={} from={} to={:?}",
        inst.id, me, targets
    );

    let job = im_client
        .send(&mut inst)
        .await
        .map_err(|e| anyhow!("IMClient::send failed: {}", e))?;

    if let Some(handle) = job.handle {
        handle
            .await
            .map_err(|e| anyhow!("send task join error: {}", e))?
            .map_err(|e| anyhow!("Apple delivery failed: {}", e))?;
    }

    Ok(inst.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_target_cases() {
        assert_eq!(normalize_target("+1 (555) 123-4567"), "tel:+15551234567");
        assert_eq!(normalize_target("15551234567"), "tel:+15551234567");
        assert_eq!(normalize_target("tel:+15551234567"), "tel:+15551234567");
        assert_eq!(normalize_target("alice@icloud.com"), "mailto:alice@icloud.com");
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
}
