mod apple;
mod body;
mod config;
mod fairplay;
mod media;
mod pairing;
mod proto;
mod push;
mod relay;
mod state;

use crate::body::{
    AppBody, REG_STATE_NEEDS_PHONE, REG_STATE_OK, SETUP_NEED_SIM, SETUP_READY, SETUP_WAITING_SMS,
};
use crate::config::Config;
use crate::push::{Hub, IncomingClientMsg};
use crate::relay::RelayHub;
use anyhow::Result;
use clap::{Parser, Subcommand};
use log::{info, warn};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "imsg-server", version, about = "iMessage bridge server for flip phones")]
struct Cli {
    /// Path to config.toml
    #[arg(short, long, default_value = "config.toml", global = true)]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Write a new config.toml and initialize built-in relay credentials
    Init {
        /// Host name phones and relayserver connect to; must match your TLS certificate
        #[arg(long)]
        domain: String,
        /// Certificate chain (default: Let's Encrypt fullchain.pem for --domain)
        #[arg(long)]
        cert: Option<PathBuf>,
        /// Private key (default: Let's Encrypt privkey.pem for --domain)
        #[arg(long)]
        key: Option<PathBuf>,
        /// Address to listen on
        #[arg(long, default_value = "0.0.0.0:443")]
        listen: String,
        /// Days before phone auth certificate expiry to start automatic SMS renewal
        #[arg(long, default_value_t = 7)]
        renewal_lead_days: u64,
    },

    /// Print the built-in relay provider URL for OpenBubbles/relayserver on the jailbroken iPhone
    RelayUrl,

    /// Show a one-time code for pairing a phone (starts the server if it isn't running)
    Pair {
        /// Test mode: don't connect to Apple (see `run --no-apple`)
        #[arg(long)]
        no_apple: bool,
    },

    /// Run the server
    Run {
        /// Test mode: don't connect to Apple; simulate setup and echo messages back
        #[arg(long)]
        no_apple: bool,
    },
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn echo_deliver(hub: &Hub, client_id: &str, body: AppBody) {
    if let Ok(encoded) = body.encode() {
        if let Err(e) = hub.deliver(client_id, encoded).await {
            warn!("[echo] failed to deliver: {:#}", e);
        }
    }
}

fn echo_reg_info(
    handle: &str,
    fake_expires_ms: u64,
    lead_days: u64,
    provider_connected: bool,
) -> AppBody {
    if handle.is_empty() {
        AppBody::RegInfo {
            auth_expires_at_ms: 0,
            next_rereg_at_ms: 0,
            renew_at_ms: 0,
            provider_connected,
            state: REG_STATE_NEEDS_PHONE,
            detail: "Not registered yet".to_string(),
        }
    } else {
        AppBody::RegInfo {
            auth_expires_at_ms: fake_expires_ms,
            next_rereg_at_ms: now_epoch_ms() + 6 * 3600 * 1000,
            renew_at_ms: apple::compute_renew_at_ms(Some(fake_expires_ms), lead_days),
            provider_connected,
            state: REG_STATE_OK,
            detail: String::new(),
        }
    }
}

/// Test backend. Simulates phone-number setup (any REG-RESP is accepted), then echoes messages.
/// A test attachment as an iPhone would send it: a 3024x4032 HEIC-sized photo (JPEG here), a
/// HEVC-free MOV clip, a CAF voice message, or a transparent PNG sticker.
fn echo_media(hub: &Arc<Hub>, kind: &str) -> anyhow::Result<body::InAttachment> {
    let dir = std::env::temp_dir().join(format!("imsg-echo-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir)?;
    let (name, mime, args): (&str, &str, Vec<&str>) = match kind {
        "photo" => ("IMG_0042.jpg", "image/jpeg",
            vec!["-f", "lavfi", "-i", "testsrc2=size=3024x4032:rate=1", "-frames:v", "1"]),
        "video" => ("IMG_0043.mov", "video/quicktime",
            vec!["-f", "lavfi", "-i", "testsrc2=size=1920x1080:rate=30:duration=4", "-f", "lavfi",
                 "-i", "sine=frequency=660:duration=4", "-c:v", "libx264", "-c:a", "aac", "-shortest"]),
        "voice" => ("Audio Message.caf", "audio/x-caf",
            vec!["-f", "lavfi", "-i", "sine=frequency=300:duration=3", "-c:a", "pcm_s16le"]),
        _ => ("sticker.png", "image/png",
            vec!["-f", "lavfi", "-i", "color=c=red@0.0:size=400x400,format=rgba,drawbox=x=100:y=100:w=200:h=200:color=yellow@1:t=fill", "-frames:v", "1"]),
    };
    let out = dir.join(name);
    let status = std::process::Command::new("ffmpeg")
        .args(["-hide_banner", "-loglevel", "error", "-y"])
        .args(&args)
        .arg(&out)
        .status()?;
    anyhow::ensure!(status.success(), "ffmpeg failed");
    let att = hub.media.register_local(&out, name, mime);
    let _ = std::fs::remove_dir_all(&dir);
    att
}

fn normalize_echo(raw: &str) -> String {
    apple::normalize_target(raw)
}

/// What the echo backend answers a sent message with. Text starting with a command makes the
/// "other side" do something to the conversation instead of echoing:
/// `/react N|emoji` (on the sent message), `/reply text`, `/edit text` and `/unsend` (on the
/// last echo), `/rename name`, `/add handle`, `/remove handle`, `/icon`, `/photo`, `/video`,
/// `/voice`, `/sticker`. `/group text` has the other side start a group with a third person;
/// after that `/rename`, `/icon`, `/add`, `/remove` and `/gsay text` act on that group.
#[allow(clippy::too_many_arguments)]
fn echo_reply(
    hub: &Arc<Hub>,
    from: &str,
    participants: Vec<String>,
    sender_guid: Option<String>,
    text: &str,
    attachments: &[body::OutAttachment],
    sent_id: &str,
    last_echo_id: &mut Option<String>,
    echo_group: &mut Option<(Vec<String>, String)>,
    me: &str,
) -> AppBody {
    let id = format!("echo-in-{}", Uuid::new_v4()).to_uppercase();
    let sender = normalize_echo(from);
    let (participants, sender_guid) = {
        let group_cmd = text.starts_with("/group")
            || ["/rename", "/icon", "/add", "/remove", "/gsay"].iter().any(|c| text.starts_with(c));
        if text.starts_with("/group") {
            let members = vec![sender.clone(), "tel:+15553334444".to_string(), me.to_string()];
            *echo_group = Some((members, format!("echo-group-{}", Uuid::new_v4())));
        }
        match echo_group.as_ref().filter(|_| group_cmd && participants.len() <= 2) {
            Some((members, guid)) => (members.clone(), Some(guid.clone())),
            None => (participants, sender_guid),
        }
    };
    let ts = now_epoch_ms();
    let (cmd, arg) = match text.strip_prefix('/') {
        Some(rest) => {
            let (c, a) = rest.split_once(' ').unwrap_or((rest, ""));
            (c.to_ascii_lowercase(), a.trim().to_string())
        }
        None => (String::new(), String::new()),
    };
    let group = |event: u8, name: String, new_participants: Vec<String>| AppBody::GroupEvent {
        apple_msg_id: id.clone(),
        sender: sender.clone(),
        participants: participants.clone(),
        sender_guid: sender_guid.clone(),
        timestamp_ms: ts,
        event,
        name,
        new_participants,
    };
    match cmd.as_str() {
        "react" => {
            let (reaction, emoji) = match arg.parse::<u8>() {
                Ok(n) if n <= body::REACT_QUESTION => (n, None),
                _ if !arg.is_empty() => (body::REACT_EMOJI, Some(arg.clone())),
                _ => (body::REACT_HEART, None),
            };
            return AppBody::Reaction {
                apple_msg_id: id,
                sender,
                participants,
                sender_guid,
                timestamp_ms: ts,
                target_id: sent_id.to_string(),
                reaction,
                emoji,
                enable: true,
            };
        }
        "edit" | "unsend" if last_echo_id.is_some() => {
            let target_id = last_echo_id.clone().unwrap_or_default();
            return if cmd == "edit" {
                AppBody::Edit {
                    apple_msg_id: id,
                    sender,
                    timestamp_ms: ts,
                    target_id,
                    text: arg,
                }
            } else {
                AppBody::Unsend {
                    apple_msg_id: id,
                    sender,
                    timestamp_ms: ts,
                    target_id,
                }
            };
        }
        "photo" | "video" | "voice" | "sticker" => {
            // The other side sends media made with ffmpeg (tests incoming attachments).
            match echo_media(hub, &cmd) {
                Ok(att) => {
                    *last_echo_id = Some(id.clone());
                    return AppBody::IncomingMessage {
                        apple_msg_id: id,
                        sender,
                        participants,
                        sender_guid,
                        timestamp_ms: ts,
                        text: arg,
                        reply_to: None,
                        attachments: vec![att],
                    };
                }
                Err(e) => warn!("[echo] can't make test {}: {:#}", cmd, e),
            }
        }
        "rename" => return group(body::GROUP_RENAMED, arg, Vec::new()),
        "icon" => return group(body::GROUP_ICON, "set".into(), Vec::new()),
        "add" | "remove" if !arg.is_empty() => {
            let who = normalize_echo(&arg);
            let mut members: Vec<String> = participants
                .iter()
                .filter(|p| !p.eq_ignore_ascii_case(&who))
                .cloned()
                .collect();
            if cmd == "add" {
                members.push(who);
            }
            if let Some(g) = echo_group.as_mut() {
                g.0 = members.clone();
            }
            return group(body::GROUP_PARTICIPANTS, String::new(), members);
        }
        _ => {}
    }
    let (text, reply_to) = if cmd == "reply" {
        (arg, Some(sent_id.to_string()))
    } else if cmd == "group" || cmd == "gsay" {
        (if arg.is_empty() { "hi everyone".to_string() } else { arg }, None)
    } else {
        (text.to_string(), None)
    };
    let mut echoed = Vec::new();
    for a in attachments {
        match hub
            .media
            .upload_path(&a.upload_id)
            .and_then(|p| hub.media.register_local(&p, &a.name, &a.mime))
        {
            Ok(att) => echoed.push(att),
            Err(e) => warn!("[echo] can't echo attachment {}: {:#}", a.upload_id, e),
        }
        hub.media.remove_upload(&a.upload_id);
    }
    *last_echo_id = Some(id.clone());
    AppBody::IncomingMessage {
        apple_msg_id: id,
        sender,
        participants,
        sender_guid,
        timestamp_ms: ts,
        text,
        reply_to,
        attachments: echoed,
    }
}

async fn run_echo_backend(
    cfg: Config,
    hub: Arc<Hub>,
    relay: Arc<RelayHub>,
    mut incoming_rx: mpsc::Receiver<IncomingClientMsg>,
) {
    info!("running in --no-apple echo mode");
    let mut handle = String::new();
    let mut fake_expires_ms: u64 = 0;
    let mut relay_status_rx = relay.subscribe_status();
    let mut connect_rx = hub.subscribe_connects();
    let mut last_echo_id: Option<String> = None;
    let mut echo_group: Option<(Vec<String>, String)> = None;

    loop {
        tokio::select! {
            changed = relay_status_rx.changed() => {
                if changed.is_ok() {
                    let connected = relay_status_rx.borrow().provider_connected;
                    let info = echo_reg_info(&handle, fake_expires_ms, cfg.renewal.lead_days, connected);
                    if let Ok(encoded) = info.encode() {
                        hub.deliver_connected(encoded).await;
                    }
                }
            }
            joined = connect_rx.recv() => {
                if let Ok(cid) = joined {
                    let info = echo_reg_info(
                        &handle,
                        fake_expires_ms,
                        cfg.renewal.lead_days,
                        relay.status().provider_connected,
                    );
                    echo_deliver(&hub, &cid, info).await;
                }
            }
            maybe_msg = incoming_rx.recv() => {
                let Some(msg) = maybe_msg else { break };
                match AppBody::decode(&msg.body) {
                    Ok(AppBody::RegInfoReq) => {
                        let info = echo_reg_info(
                            &handle,
                            fake_expires_ms,
                            cfg.renewal.lead_days,
                            relay.status().provider_connected,
                        );
                        echo_deliver(&hub, &msg.client_id, info).await;
                    }
                    Ok(AppBody::SendMessage { client_msg_id, .. } | AppBody::SendReaction { client_msg_id, .. })
                        if handle.is_empty() =>
                    {
                        let reply = AppBody::SendResult {
                            client_msg_id,
                            ok: false,
                            apple_msg_id: None,
                            error: Some("iMessage is not set up yet".to_string()),
                        };
                        echo_deliver(&hub, &msg.client_id, reply).await;
                    }
                    Ok(AppBody::SendMessage {
                        client_msg_id,
                        participants,
                        sender_guid,
                        text,
                        attachments,
                    }) => {
                        info!(
                            "[echo] client '{}' seq={} SEND_MESSAGE id='{}' to={:?} text={:?} attachments={}",
                            msg.client_id, msg.seq, client_msg_id, participants, text, attachments.len()
                        );
                        let send_id = format!("echo-{}", Uuid::new_v4()).to_uppercase();
                        let res_body = AppBody::SendResult {
                            client_msg_id,
                            ok: true,
                            apple_msg_id: Some(send_id.clone()),
                            error: None,
                        };
                        echo_deliver(&hub, &msg.client_id, res_body).await;
                        let Some(first) = participants.first().cloned() else { continue };
                        let mut all = participants.clone();
                        all.push(handle.clone());
                        let reply = echo_reply(
                            &hub,
                            &first,
                            all,
                            sender_guid,
                            &text,
                            &attachments,
                            &send_id,
                            &mut last_echo_id,
                            &mut echo_group,
                            &handle,
                        );
                        echo_deliver(&hub, &msg.client_id, reply).await;
                    }
                    Ok(AppBody::SendReaction {
                        client_msg_id,
                        participants,
                        sender_guid,
                        target_id,
                        reaction,
                        emoji,
                        enable,
                        ..
                    }) => {
                        info!(
                            "[echo] client '{}' SEND_REACTION kind={} emoji={:?} enable={} on={}",
                            msg.client_id, reaction, emoji, enable, target_id
                        );
                        let res_body = AppBody::SendResult {
                            client_msg_id,
                            ok: true,
                            apple_msg_id: Some(format!("echo-r-{}", Uuid::new_v4()).to_uppercase()),
                            error: None,
                        };
                        echo_deliver(&hub, &msg.client_id, res_body).await;
                        // The other side reacts the same way.
                        if let Some(first) = participants.first().cloned() {
                            let mut all = participants;
                            all.push(handle.clone());
                            let back = AppBody::Reaction {
                                apple_msg_id: format!("echo-r-in-{}", Uuid::new_v4()).to_uppercase(),
                                sender: normalize_echo(&first),
                                participants: all,
                                sender_guid,
                                timestamp_ms: now_epoch_ms(),
                                target_id,
                                reaction,
                                emoji,
                                enable,
                            };
                            echo_deliver(&hub, &msg.client_id, back).await;
                        }
                    }
                    Ok(AppBody::GetHandles) => {
                        info!("[echo] client '{}' seq={} GET_HANDLES", msg.client_id, msg.seq);
                        let reply = if handle.is_empty() {
                            AppBody::SetupStatus {
                                state: SETUP_NEED_SIM,
                                detail: "Send SIM info to register".to_string(),
                            }
                        } else {
                            AppBody::Handles {
                                handles: vec![handle.clone()],
                                preferred: Some(handle.clone()),
                            }
                        };
                        echo_deliver(&hub, &msg.client_id, reply).await;
                    }
                    Ok(AppBody::SimInfo { mccmnc, number }) => {
                        info!(
                            "[echo] client '{}' SIM_INFO mccmnc={:?} number={:?}",
                            msg.client_id, mccmnc, number
                        );
                        let ask = AppBody::SendRegSms {
                            gateway: "28818773".to_string(),
                            text: "REG-REQ?v=3;t=0000ECHO;r=123456789;".to_string(),
                        };
                        echo_deliver(&hub, &msg.client_id, ask).await;
                        let waiting = AppBody::SetupStatus {
                            state: SETUP_WAITING_SMS,
                            detail: "Waiting for Apple's reply...".to_string(),
                        };
                        echo_deliver(&hub, &msg.client_id, waiting).await;
                    }
                    Ok(AppBody::RegResp { text }) => {
                        info!("[echo] client '{}' REG_RESP {:?}", msg.client_id, text);
                        let number = apple::parse_reg_resp(&text)
                            .map(|p| p.number)
                            .unwrap_or_else(|_| "+15550001111".to_string());
                        handle = format!("tel:{}", number);
                        fake_expires_ms = now_epoch_ms() + 30 * 86_400_000;
                        let ready = AppBody::SetupStatus {
                            state: SETUP_READY,
                            detail: handle.clone(),
                        };
                        if let Ok(encoded) = ready.encode() {
                            let _ = hub.deliver_all(encoded).await;
                        }
                        let info = echo_reg_info(
                            &handle,
                            fake_expires_ms,
                            cfg.renewal.lead_days,
                            relay.status().provider_connected,
                        );
                        if let Ok(encoded) = info.encode() {
                            hub.deliver_connected(encoded).await;
                        }
                    }
                    Ok(AppBody::CheckTargets { req_id, targets }) => {
                        info!(
                            "[echo] client '{}' seq={} CHECK_TARGETS id='{}' targets={:?}",
                            msg.client_id, msg.seq, req_id, targets
                        );
                        let mut registered = Vec::new();
                        let mut unregistered = Vec::new();
                        for t in targets {
                            if t.ends_with("0000") {
                                unregistered.push(t);
                            } else {
                                registered.push(t);
                            }
                        }
                        let reply = AppBody::TargetStatus {
                            req_id,
                            registered,
                            unregistered,
                        };
                        echo_deliver(&hub, &msg.client_id, reply).await;
                    }
                    Ok(other) => {
                        warn!(
                            "[echo] client '{}' seq={} ignoring unexpected body {:?}",
                            msg.client_id, msg.seq, other
                        );
                    }
                    Err(e) => {
                        warn!(
                            "[echo] client '{}' seq={} failed to decode body: {:#}",
                            msg.client_id, msg.seq, e
                        );
                    }
                }
            }
        }
    }
}

async fn run_server(cfg: Config, no_apple: bool) -> Result<()> {
    if let Some(legacy) = &cfg.relay {
        if legacy.host.is_some() || legacy.code.is_some() {
            warn!("ignoring legacy [relay] host/code in config.toml; imsg-server uses its built-in relay");
        }
    }

    let _instance_lock = acquire_instance_lock(&cfg.state_dir)?;
    let hub = Arc::new(Hub::new(&cfg)?);
    let relay = Arc::new(RelayHub::load_or_init(&cfg.apple_dir)?);
    let internal_relay = relay.start_internal_bridge().await?;
    if let Some(code) = relay.provider_code() {
        info!("built-in relay ready (locked provider code {})", code);
    } else {
        info!("built-in relay ready; run `imsg-server relay-url` to configure OpenBubbles/relayserver on your iPhone");
    }

    let (incoming_tx, incoming_rx) = mpsc::channel::<IncomingClientMsg>(256);
    if no_apple {
        let echo_hub = Arc::clone(&hub);
        let echo_relay = Arc::clone(&relay);
        let echo_cfg = cfg.clone();
        tokio::spawn(async move {
            run_echo_backend(echo_cfg, echo_hub, echo_relay, incoming_rx).await;
        });
        push::run_listeners(&cfg, hub, relay, incoming_tx).await
    } else {
        let apple_hub = Arc::clone(&hub);
        let apple_relay = Arc::clone(&relay);
        let push_fut = push::run_listeners(&cfg, hub, relay, incoming_tx);
        let apple_fut = apple::run_apple(&cfg, apple_hub, apple_relay, internal_relay, incoming_rx);
        tokio::try_join!(push_fut, apple_fut)?;
        Ok(())
    }
}

/// True if an `imsg-server` instance is already running for `cfg.state_dir`.
///
/// Uses a Unix domain socket in `state_dir` rather than probing `listen_addrs`, so another service
/// occupying port 443 (like nginx or caddy) is never mistaken for a running `imsg-server`.
fn already_running(cfg: &Config) -> bool {
    already_running_in(&cfg.state_dir)
}

#[cfg(unix)]
fn instance_sock_path(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("server.sock")
}

#[cfg(unix)]
struct InstanceLock {
    task: tokio::task::JoinHandle<()>,
    path: PathBuf,
}

#[cfg(unix)]
impl Drop for InstanceLock {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
fn already_running_in(state_dir: &std::path::Path) -> bool {
    std::os::unix::net::UnixStream::connect(instance_sock_path(state_dir)).is_ok()
}

#[cfg(unix)]
fn acquire_instance_lock(state_dir: &std::path::Path) -> Result<InstanceLock> {
    std::fs::create_dir_all(state_dir)?;
    let path = instance_sock_path(state_dir);
    if std::os::unix::net::UnixStream::connect(&path).is_ok() {
        anyhow::bail!(
            "imsg-server is already running for {}",
            state_dir.display()
        );
    }
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).map_err(|e| {
        anyhow::anyhow!("failed to create instance socket {}: {}", path.display(), e)
    })?;
    config::restrict_permissions(&path);
    let task = tokio::spawn(async move {
        while listener.accept().await.is_ok() {}
    });
    Ok(InstanceLock { task, path })
}

#[cfg(not(unix))]
struct InstanceLock;

#[cfg(not(unix))]
fn already_running_in(_state_dir: &std::path::Path) -> bool {
    false
}

#[cfg(not(unix))]
fn acquire_instance_lock(_state_dir: &std::path::Path) -> Result<InstanceLock> {
    Ok(InstanceLock)
}

fn print_relay_instructions(cfg: &Config, relay: &RelayHub) {
    let url = relay.provider_url(&cfg.phone_address());
    println!();
    println!("Built-in registration relay URL (for OpenBubbles/relayserver on your jailbroken iPhone):");
    println!();
    println!("  {}", url);
    println!();
    println!("On the jailbroken iPhone, write /var/mobile/config.json and restart relayserver:");
    println!(
        "  printf '{{\"url\":\"{}\",\"state\":null}}\\n' > /var/mobile/config.json",
        url
    );
    println!("  killall relayserver");
    if let Some(code) = relay.provider_code() {
        println!();
        println!("Locked provider code: {}", code);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            domain,
            cert,
            key,
            listen,
            renewal_lead_days,
        } => {
            config::init(
                &cli.config,
                &config::InitArgs {
                    domain,
                    cert,
                    key,
                    listen,
                    renewal_lead_days,
                },
            )?;
            let cfg = Config::load(&cli.config)?;
            let relay = RelayHub::load_or_init(&cfg.apple_dir)?;
            println!("Wrote {}", cli.config.display());
            print_relay_instructions(&cfg, &relay);
            println!();
            println!("Next: point OpenBubbles/relayserver at the URL above, then run `imsg-server pair`.");
        }
        Commands::RelayUrl => {
            let cfg = Config::load(&cli.config)?;
            let relay = RelayHub::load_or_init(&cfg.apple_dir)?;
            print_relay_instructions(&cfg, &relay);
        }
        Commands::Pair { no_apple } => {
            let cfg = Config::load(&cli.config)?;
            let code = pairing::create(&cfg.state_dir)?;
            println!();
            println!("On the phone: Messages > Settings > Advanced settings > Apple (iMessage) settings");
            println!();
            println!("  Server:        {}", cfg.phone_address());
            println!("  Pairing code:  {}", pairing::format_code(&code));
            println!();
            println!("The code works once and expires in {} minutes.", pairing::TTL_S / 60);
            if already_running(&cfg) {
                println!("The running server will pick it up.");
            } else {
                println!("Starting the server; keep this running (or run `imsg-server run` as a service).");
                println!();
                run_server(cfg, no_apple).await?;
            }
        }
        Commands::Run { no_apple } => {
            let cfg = Config::load(&cli.config)?;
            run_server(cfg, no_apple).await?;
        }
    }

    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn instance_lock_detects_running_server_and_cleans_up() {
        let dir = std::env::temp_dir().join(format!(
            "imsg_lock_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        assert!(!already_running_in(&dir));
        let lock = acquire_instance_lock(&dir).unwrap();
        assert!(already_running_in(&dir));
        assert!(acquire_instance_lock(&dir).is_err());

        drop(lock);
        assert!(!already_running_in(&dir));
        let _lock2 = acquire_instance_lock(&dir).unwrap();
        assert!(already_running_in(&dir));

        drop(_lock2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
