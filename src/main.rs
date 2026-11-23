mod apple;
mod body;
mod config;
mod pairing;
mod proto;
mod push;
mod state;

use crate::body::{AppBody, SETUP_NEED_SIM, SETUP_READY, SETUP_WAITING_SMS};
use crate::config::Config;
use crate::push::{Hub, IncomingClientMsg};
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
    /// Write a new config.toml
    Init {
        /// Host name phones connect to; must match your TLS certificate
        #[arg(long)]
        domain: String,
        /// Registration relay host
        #[arg(long)]
        relay_host: String,
        /// Registration relay code
        #[arg(long)]
        relay_code: String,
        /// Certificate chain (default: Let's Encrypt fullchain.pem for --domain)
        #[arg(long)]
        cert: Option<PathBuf>,
        /// Private key (default: Let's Encrypt privkey.pem for --domain)
        #[arg(long)]
        key: Option<PathBuf>,
        /// Address to listen on
        #[arg(long, default_value = "0.0.0.0:443")]
        listen: String,
    },

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

/// Test backend. Simulates phone-number setup (any REG-RESP is accepted), then echoes messages.
async fn run_echo_backend(hub: Arc<Hub>, mut incoming_rx: mpsc::Receiver<IncomingClientMsg>) {
    info!("running in --no-apple echo mode");
    // Our registered handle; empty until the simulated setup finishes.
    let mut handle = String::new();
    while let Some(msg) = incoming_rx.recv().await {
        match AppBody::decode(&msg.body) {
            Ok(AppBody::SendText { client_msg_id, .. } | AppBody::SendGroupText { client_msg_id, .. })
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
            Ok(AppBody::SendText {
                client_msg_id,
                target,
                text,
                sender_guid,
            }) => {
                info!(
                    "[echo] client '{}' seq={} SEND_TEXT id='{}' target='{}' text={:?}",
                    msg.client_id, msg.seq, client_msg_id, target, text
                );
                let send_id = format!("echo-{}", Uuid::new_v4());
                let res_body = AppBody::SendResult {
                    client_msg_id,
                    ok: true,
                    apple_msg_id: Some(send_id),
                    error: None,
                };
                if let Ok(encoded) = res_body.encode() {
                    if let Err(e) = hub.deliver(&msg.client_id, encoded).await {
                        warn!("[echo] failed to deliver SEND_RESULT: {:#}", e);
                    }
                }

                let echo_in = AppBody::IncomingText {
                    apple_msg_id: format!("echo-in-{}", Uuid::new_v4()),
                    sender: target.clone(),
                    participants: vec![target, handle.clone()],
                    sender_guid,
                    timestamp_ms: now_epoch_ms(),
                    text,
                };
                if let Ok(encoded) = echo_in.encode() {
                    if let Err(e) = hub.deliver(&msg.client_id, encoded).await {
                        warn!("[echo] failed to deliver INCOMING_TEXT: {:#}", e);
                    }
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
                info!("[echo] client '{}' SIM_INFO mccmnc={:?} number={:?}", msg.client_id, mccmnc, number);
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
                let ready = AppBody::SetupStatus {
                    state: SETUP_READY,
                    detail: handle.clone(),
                };
                if let Ok(encoded) = ready.encode() {
                    let _ = hub.deliver_all(encoded).await;
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
                if let Ok(encoded) = reply.encode() {
                    if let Err(e) = hub.deliver(&msg.client_id, encoded).await {
                        warn!("[echo] failed to deliver TARGET_STATUS: {:#}", e);
                    }
                }
            }
            Ok(AppBody::SendGroupText {
                client_msg_id,
                participants,
                text,
                sender_guid,
            }) => {
                info!(
                    "[echo] client '{}' seq={} SEND_GROUP_TEXT id='{}' participants={:?} text={:?}",
                    msg.client_id, msg.seq, client_msg_id, participants, text
                );
                let send_id = format!("echo-grp-{}", Uuid::new_v4());
                let res_body = AppBody::SendResult {
                    client_msg_id,
                    ok: true,
                    apple_msg_id: Some(send_id),
                    error: None,
                };
                if let Ok(encoded) = res_body.encode() {
                    if let Err(e) = hub.deliver(&msg.client_id, encoded).await {
                        warn!("[echo] failed to deliver SEND_RESULT: {:#}", e);
                    }
                }
                if let Some(first) = participants.first().cloned() {
                    let mut all = participants;
                    all.push(handle.clone());
                    let echo_in = AppBody::IncomingText {
                        apple_msg_id: format!("echo-grp-in-{}", Uuid::new_v4()),
                        sender: first,
                        participants: all,
                        sender_guid,
                        timestamp_ms: now_epoch_ms(),
                        text,
                    };
                    if let Ok(encoded) = echo_in.encode() {
                        if let Err(e) = hub.deliver(&msg.client_id, encoded).await {
                            warn!("[echo] failed to deliver group INCOMING_TEXT: {:#}", e);
                        }
                    }
                }
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

async fn run_server(cfg: Config, no_apple: bool) -> Result<()> {
    let hub = Arc::new(Hub::new(&cfg)?);
    let (incoming_tx, incoming_rx) = mpsc::channel::<IncomingClientMsg>(256);
    if no_apple {
        let echo_hub = Arc::clone(&hub);
        tokio::spawn(async move {
            run_echo_backend(echo_hub, incoming_rx).await;
        });
        push::run_listeners(&cfg, hub, incoming_tx).await
    } else {
        let apple_hub = Arc::clone(&hub);
        let push_fut = push::run_listeners(&cfg, hub, incoming_tx);
        let apple_fut = apple::run_apple(&cfg, apple_hub, incoming_rx);
        tokio::try_join!(push_fut, apple_fut)?;
        Ok(())
    }
}

/// True if something is already listening on our address (i.e. the server is running).
fn already_running(cfg: &Config) -> bool {
    cfg.listen_addrs.first().map_or(false, |addr| {
        matches!(
            std::net::TcpListener::bind(addr.as_str()),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse
        )
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            domain,
            relay_host,
            relay_code,
            cert,
            key,
            listen,
        } => {
            config::init(
                &cli.config,
                &config::InitArgs {
                    domain,
                    cert,
                    key,
                    listen,
                    relay_host,
                    relay_code,
                },
            )?;
            println!("Wrote {}", cli.config.display());
            println!("Next: run `imsg-server pair` and enter the code on your phone.");
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
