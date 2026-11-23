mod apple;
mod body;
mod config;
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
                        echo_deliver(&hub, &msg.client_id, res_body).await;

                        let echo_in = AppBody::IncomingText {
                            apple_msg_id: format!("echo-in-{}", Uuid::new_v4()),
                            sender: target.clone(),
                            participants: vec![target, handle.clone()],
                            sender_guid,
                            timestamp_ms: now_epoch_ms(),
                            text,
                        };
                        echo_deliver(&hub, &msg.client_id, echo_in).await;
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
                        echo_deliver(&hub, &msg.client_id, res_body).await;
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
                            echo_deliver(&hub, &msg.client_id, echo_in).await;
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
    }
}

async fn run_server(cfg: Config, no_apple: bool) -> Result<()> {
    if let Some(legacy) = &cfg.relay {
        if legacy.host.is_some() || legacy.code.is_some() {
            warn!("ignoring legacy [relay] host/code in config.toml; imsg-server uses its built-in relay");
        }
    }

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

/// True if something is already listening on our address (i.e. the server is running).
fn already_running(cfg: &Config) -> bool {
    cfg.listen_addrs.first().map_or(false, |addr| {
        matches!(
            std::net::TcpListener::bind(addr.as_str()),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse
        )
    })
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
