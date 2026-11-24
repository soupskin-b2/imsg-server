//! Built-in registration relay (OpenBubbles/relayserver provider WebSocket + bridge HTTP API).
//!
//! Serves the same HTTP/1.1 protocol as `beeper/registration-relay`:
//!   - `GET /api/v1/provider?t=<token>` (WebSocket upgrade for OpenBubbles/relayserver on the jailbroken iPhone)
//!   - `POST /api/v1/bridge/{get-version-info|get-validation-data}` (`Authorization: Bearer <code>`)
//!   - `GET /health`
//!
//! Also binds an internal loopback bridge on `127.0.0.1:0` with an ephemeral per-process bearer
//! token so `rustpush`'s `RelayConfig` talks directly to the in-process provider without hairpin
//! routing or external DNS/TLS roundtrips.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use hyper::header::{self, HeaderValue};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, StatusCode};
use log::{debug, info, warn};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::fs::{self, File};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

type HmacSha256 = Hmac<Sha256>;

const CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
const REGISTER_TIMEOUT: Duration = Duration::from_secs(15);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
/// OpenBubbles/relayserver sends an app-level `ping` every 60s, but its timer runs on iOS
/// uptime, which stops while the iPhone sleeps: an idle, sleeping iPhone goes silent for many
/// minutes while still answering at once whatever we send it. So silence is not a reason to
/// drop the provider (that made it reconnect every ~3 minutes and pushed a REG_INFO to the phone
/// each time). A dead link is found by OS TCP keepalives instead (see [`enable_keepalive`],
/// answered by the iPhone's kernel even asleep), and a hung app by [`COMMAND_TIMEOUT`]. We
/// can't ping it ourselves: relayserver panics/disconnects on server pings or WS Ping frames.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(120);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const KEEPALIVE_RETRIES: u32 = 4;
const AUTH_WINDOW: Duration = Duration::from_secs(60);
const MAX_AUTH_FAILURES_PER_WINDOW: usize = 20;

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Turns on OS TCP keepalives for a connection that turned out to be for the relay, so a provider
/// that vanished (iPhone off, network gone) is noticed in about 4 minutes without depending on its
/// app-level pings (see [`KEEPALIVE_IDLE`]). Phone push connections leave keepalives off.
pub fn enable_keepalive(stream: &tokio::net::TcpStream, peer: SocketAddr) {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_RETRIES);
    if let Err(e) = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive) {
        warn!("relay connection {}: could not enable TCP keepalive: {}", peer, e);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStatus {
    pub provider_connected: bool,
    pub provider_code: Option<String>,
    pub last_answered_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProviderStore {
    provider_token: String,
    #[serde(default)]
    code: Option<String>,
    /// Stable synthetic Mac identity substituted into `get-version-info` (see [`MacIdentity`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mac_identity: Option<MacIdentity>,
}

/// Synthetic `iMac13,1` serial number + UDID that replaces the iPhone's real identifiers in
/// `get-version-info` responses.
///
/// rustpush activates relay devices with Albert as `DeviceClass=MacOS` / `ProductType=iMac13,1`,
/// and since October 2026 Albert rejects a MacOS activation carrying an iPhone serial number.
/// Only `serial_number` and `unique_device_id` are rewritten (the same as OpenBubblesProxy and
/// jakecrowley/relayserver); the hardware/software version fields stay the iPhone's so they match
/// the validation data the iPhone generates. Persisted in `relay_provider.json` because Albert
/// activates each serial once, so it must not change across restarts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacIdentity {
    pub serial_number: String,
    pub unique_device_id: String,
}

const SERIAL_YEAR_CHARS: &[u8] = b"CDFGHJKLMNPQRSTUVWX";
const SERIAL_WEEK_CHARS: &[u8] = b"123456789CDFGHJKLMNPQRSTVW";
const SERIAL_UNIT_CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
/// Model-code suffixes of real `iMac13,1` / `iMac13,2` serials.
const SERIAL_MODEL_SUFFIXES: &[&str] = &[
    "DNCT", "DNCR", "DNML", "DNMM", "F8QM", "F8QN", "F9RN", "FC6M", "FC6N", "FC6P", "FD55",
    "FD5Y", "FF7L",
];

impl MacIdentity {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut serial = String::with_capacity(12);
        serial.push_str("C02");
        serial.push(SERIAL_YEAR_CHARS[rng.gen_range(0..SERIAL_YEAR_CHARS.len())] as char);
        serial.push(SERIAL_WEEK_CHARS[rng.gen_range(0..SERIAL_WEEK_CHARS.len())] as char);
        for _ in 0..3 {
            serial.push(SERIAL_UNIT_CHARS[rng.gen_range(0..SERIAL_UNIT_CHARS.len())] as char);
        }
        serial.push_str(SERIAL_MODEL_SUFFIXES[rng.gen_range(0..SERIAL_MODEL_SUFFIXES.len())]);
        Self {
            serial_number: serial,
            unique_device_id: uuid::Uuid::new_v4().to_string().to_uppercase(),
        }
    }

    fn is_valid(&self) -> bool {
        is_valid_mac_serial(&self.serial_number)
            && uuid::Uuid::parse_str(&self.unique_device_id).is_ok()
    }

    /// Rewrites `versions.serial_number` / `versions.unique_device_id` in a provider
    /// `get-version-info` response, leaving every other field untouched.
    fn apply_to_versions(&self, val: &mut serde_json::Value) {
        if let Some(versions) = val.get_mut("versions").and_then(|v| v.as_object_mut()) {
            versions.insert(
                "serial_number".into(),
                serde_json::Value::String(self.serial_number.clone()),
            );
            versions.insert(
                "unique_device_id".into(),
                serde_json::Value::String(self.unique_device_id.clone()),
            );
        }
    }
}

fn is_valid_mac_serial(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 12
        && s.starts_with("C02")
        && SERIAL_YEAR_CHARS.contains(&b[3])
        && SERIAL_WEEK_CHARS.contains(&b[4])
        && b[5..8].iter().all(|c| SERIAL_UNIT_CHARS.contains(c))
        && s.get(8..12).map_or(false, |m| SERIAL_MODEL_SUFFIXES.contains(&m))
}

#[derive(Debug, Deserialize)]
struct IncomingWsMsg {
    command: String,
    #[serde(default)]
    id: Option<i64>,
    #[serde(default)]
    data: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct OutgoingWsMsg<T: Serialize> {
    command: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
}

#[derive(Debug, Default, Deserialize)]
struct RegisterRequestData {
    #[serde(default)]
    code: String,
    #[serde(default)]
    secret: String,
    #[serde(default)]
    commit: String,
    #[serde(default)]
    versions: Option<RegisterVersions>,
}

#[derive(Debug, Default, Deserialize)]
struct RegisterVersions {
    #[serde(default)]
    hardware_version: String,
}

#[derive(Debug, Serialize)]
struct RegisterResponseData {
    code: String,
    secret: String,
}

enum ProviderOut {
    Text(String),
    Close,
}

enum BridgeError {
    Disconnected,
    Timeout,
    ProviderError(String),
    Other(String),
}

struct ProviderConn {
    id: u64,
    code: String,
    cmd_lock: AsyncMutex<()>,
    next_req_id: AtomicI64,
    out_tx: mpsc::Sender<ProviderOut>,
    waiter: StdMutex<Option<(i64, oneshot::Sender<serde_json::Value>)>>,
    closed: watch::Receiver<bool>,
}

pub struct RelayHub {
    apple_dir: PathBuf,
    secret: [u8; 32],
    provider_token: String,
    mac_identity: MacIdentity,
    internal_token: String,
    next_conn_id: AtomicU64,
    locked_code: StdMutex<Option<String>>,
    active: StdMutex<Option<Arc<ProviderConn>>>,
    status_tx: watch::Sender<RelayStatus>,
    auth_failures: StdMutex<VecDeque<Instant>>,
}

impl RelayHub {
    /// Loads (or generates) `apple_dir/relay_secret` and `apple_dir/relay_provider.json`.
    pub fn load_or_init(apple_dir: &Path) -> Result<Self> {
        fs::create_dir_all(apple_dir)
            .with_context(|| format!("failed to create apple_dir {}", apple_dir.display()))?;

        let secret = load_or_create_secret(&apple_dir.join("relay_secret"))?;
        let store_path = apple_dir.join("relay_provider.json");
        let mut store = load_or_create_store(&store_path)?;
        let mac_identity = match store.mac_identity.as_ref().filter(|m| m.is_valid()) {
            Some(m) => m.clone(),
            None => {
                let m = MacIdentity::generate();
                info!(
                    "generated synthetic Mac identity for Albert activation (serial {})",
                    m.serial_number
                );
                store.mac_identity = Some(m.clone());
                save_store_atomic(&store_path, &store)?;
                m
            }
        };

        let mut internal_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut internal_bytes);
        let internal_token = hex::encode(internal_bytes);

        let initial_status = RelayStatus {
            provider_connected: false,
            provider_code: store.code.clone(),
            last_answered_ms: None,
        };
        let (status_tx, _) = watch::channel(initial_status);

        Ok(Self {
            apple_dir: apple_dir.to_path_buf(),
            secret,
            provider_token: store.provider_token,
            mac_identity,
            internal_token,
            next_conn_id: AtomicU64::new(1),
            locked_code: StdMutex::new(store.code),
            active: StdMutex::new(None),
            status_tx,
            auth_failures: StdMutex::new(VecDeque::new()),
        })
    }

    /// WebSocket URL for OpenBubbles/relayserver (`/var/mobile/config.json` `"url"` field).
    pub fn provider_url(&self, phone_address: &str) -> String {
        format!(
            "wss://{}/api/v1/provider?t={}",
            phone_address, self.provider_token
        )
    }

    pub fn provider_code(&self) -> Option<String> {
        self.locked_code.lock().expect("relay lock poisoned").clone()
    }

    pub fn status(&self) -> RelayStatus {
        self.status_tx.borrow().clone()
    }

    pub fn subscribe_status(&self) -> watch::Receiver<RelayStatus> {
        self.status_tx.subscribe()
    }

    /// Binds an internal HTTP/1.1 bridge listener on `127.0.0.1:0` and returns `(base_url, bearer_token)`.
    pub async fn start_internal_bridge(self: &Arc<Self>) -> Result<(String, String)> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("failed to bind internal relay loopback bridge")?;
        let local_addr = listener.local_addr()?;
        let url = format!("http://{}", local_addr);
        let token = self.internal_token.clone();
        let hub = Arc::clone(self);

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let _ = stream.set_nodelay(true);
                        let hub = Arc::clone(&hub);
                        tokio::spawn(async move {
                            let service = service_fn(move |req| {
                                let hub = Arc::clone(&hub);
                                async move {
                                    Ok::<_, Infallible>(hub.handle_internal_request(req).await)
                                }
                            });
                            let conn = Http::new()
                                .http1_only(true)
                                .http1_header_read_timeout(Duration::from_secs(15))
                                .serve_connection(stream, service);
                            if let Err(e) = conn.await {
                                debug!("internal relay conn {} ended: {}", peer, e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("internal relay accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        Ok((url, token))
    }

    /// Serves a single public HTTP/1.1 connection (already TLS-decrypted and byte-sniffed).
    pub async fn handle_http_conn<S>(
        self: Arc<Self>,
        stream: S,
        peer: SocketAddr,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let hub = self;
        let service = service_fn(move |req| {
            let hub = Arc::clone(&hub);
            async move { Ok::<_, Infallible>(hub.handle_public_request(req, peer).await) }
        });

        Http::new()
            .http1_only(true)
            .http1_header_read_timeout(Duration::from_secs(15))
            .serve_connection(stream, service)
            .with_upgrades()
            .await
            .map_err(|e| anyhow::anyhow!("relay HTTP connection error: {}", e))
    }

    fn is_rate_limited(&self) -> bool {
        let now = Instant::now();
        let mut q = self.auth_failures.lock().expect("auth_failures poisoned");
        while let Some(&front) = q.front() {
            if now.saturating_duration_since(front) > AUTH_WINDOW {
                q.pop_front();
            } else {
                break;
            }
        }
        q.len() >= MAX_AUTH_FAILURES_PER_WINDOW
    }

    fn record_auth_failure(&self) -> bool {
        let now = Instant::now();
        let mut q = self.auth_failures.lock().expect("auth_failures poisoned");
        while let Some(&front) = q.front() {
            if now.saturating_duration_since(front) > AUTH_WINDOW {
                q.pop_front();
            } else {
                break;
            }
        }
        q.push_back(now);
        q.len() >= MAX_AUTH_FAILURES_PER_WINDOW
    }

    async fn handle_internal_request(
        self: Arc<Self>,
        req: Request<Body>,
    ) -> Response<Body> {
        if req.method() != Method::POST {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        let Some(command) = parse_bridge_command(req.uri().path()) else {
            return empty_response(StatusCode::NOT_FOUND);
        };
        let Some(bearer) = extract_bearer(&req) else {
            return empty_response(StatusCode::BAD_REQUEST);
        };
        if !ct_eq_str(bearer, &self.internal_token) {
            return empty_response(StatusCode::UNAUTHORIZED);
        }
        let conn = self.active.lock().expect("active lock poisoned").clone();
        let Some(conn) = conn else {
            return empty_response(StatusCode::NOT_FOUND);
        };
        self.execute_bridge_response(&conn, command).await
    }

    async fn handle_public_request(
        self: Arc<Self>,
        mut req: Request<Body>,
        peer: SocketAddr,
    ) -> Response<Body> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        match (method, path.as_str()) {
            (Method::GET, "/health") => {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/plain")
                    .body(Body::from("ok\n"))
                    .unwrap()
            }
            (Method::GET, "/api/v1/provider") => {
                if self.is_rate_limited() {
                    warn!("relay provider {}: rate-limited", peer);
                    return empty_response(StatusCode::TOO_MANY_REQUESTS);
                }
                let token_ok = query_param(req.uri().query(), "t")
                    .map_or(false, |t| ct_eq_str(t, &self.provider_token));
                if !token_ok {
                    let limited = self.record_auth_failure();
                    warn!("relay provider {}: invalid or missing ?t= token", peer);
                    return empty_response(if limited {
                        StatusCode::TOO_MANY_REQUESTS
                    } else {
                        StatusCode::UNAUTHORIZED
                    });
                }

                let is_ws_upgrade = header_contains_ignore_case(&req, header::CONNECTION, "upgrade")
                    && header_eq_ignore_case(&req, header::UPGRADE, "websocket");
                let Some(ws_key) = req
                    .headers()
                    .get(header::SEC_WEBSOCKET_KEY)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
                else {
                    return empty_response(StatusCode::BAD_REQUEST);
                };
                if !is_ws_upgrade {
                    return empty_response(StatusCode::BAD_REQUEST);
                }

                let accept = derive_accept_key(ws_key.as_bytes());
                let on_upgrade = hyper::upgrade::on(&mut req);
                let hub = Arc::clone(&self);
                tokio::spawn(async move {
                    match on_upgrade.await {
                        Ok(upgraded) => {
                            let ws = WebSocketStream::from_raw_socket(upgraded, Role::Server, None)
                                .await;
                            hub.run_provider_ws(ws, peer).await;
                        }
                        Err(e) => {
                            warn!("relay provider {} WebSocket upgrade error: {}", peer, e);
                        }
                    }
                });

                Response::builder()
                    .status(StatusCode::SWITCHING_PROTOCOLS)
                    .header(header::CONNECTION, "Upgrade")
                    .header(header::UPGRADE, "websocket")
                    .header(header::SEC_WEBSOCKET_ACCEPT, accept)
                    .body(Body::empty())
                    .unwrap()
            }
            (Method::POST, p) if parse_bridge_command(p).is_some() => {
                let command = parse_bridge_command(p).unwrap();
                let Some(bearer) = extract_bearer(&req) else {
                    return empty_response(StatusCode::BAD_REQUEST);
                };
                if self.is_rate_limited() {
                    return empty_response(StatusCode::TOO_MANY_REQUESTS);
                }
                let conn = self.active.lock().expect("active lock poisoned").clone();
                let Some(conn) = conn else {
                    return empty_response(StatusCode::NOT_FOUND);
                };
                if !ct_eq_str(bearer, &conn.code) {
                    let limited = self.record_auth_failure();
                    warn!("relay bridge {}: invalid bearer code", peer);
                    return empty_response(if limited {
                        StatusCode::TOO_MANY_REQUESTS
                    } else {
                        StatusCode::NOT_FOUND
                    });
                }
                self.execute_bridge_response(&conn, command).await
            }
            _ => empty_response(StatusCode::NOT_FOUND),
        }
    }

    async fn execute_bridge_response(
        &self,
        conn: &Arc<ProviderConn>,
        command: &str,
    ) -> Response<Body> {
        match self.execute_command(conn, command).await {
            Ok(bytes) => Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(Body::from(bytes))
                .unwrap(),
            Err(BridgeError::Disconnected) => empty_response(StatusCode::NOT_FOUND),
            Err(BridgeError::Timeout) => empty_response(StatusCode::GATEWAY_TIMEOUT),
            Err(BridgeError::ProviderError(msg)) => Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(msg))
                .unwrap(),
            Err(BridgeError::Other(msg)) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(msg))
                .unwrap(),
        }
    }

    async fn execute_command(
        &self,
        conn: &Arc<ProviderConn>,
        command: &str,
    ) -> Result<Vec<u8>, BridgeError> {
        let _guard = conn.cmd_lock.lock().await;
        let mut closed = conn.closed.clone();
        if *closed.borrow() {
            return Err(BridgeError::Disconnected);
        }

        let req_id = conn.next_req_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut waiter = conn.waiter.lock().expect("waiter poisoned");
            *waiter = Some((req_id, tx));
        }

        let payload = serde_json::to_string(&OutgoingWsMsg::<()> {
            command: match command {
                "get-version-info" => "get-version-info",
                "get-validation-data" => "get-validation-data",
                other => return Err(BridgeError::Other(format!("unknown command {}", other))),
            },
            id: Some(req_id),
            data: None,
        })
        .map_err(|e| BridgeError::Other(e.to_string()))?;

        debug!("relay -> provider ({}): command={} id={}", conn.code, command, req_id);
        if conn.out_tx.send(ProviderOut::Text(payload)).await.is_err() {
            conn.waiter.lock().expect("waiter poisoned").take();
            return Err(BridgeError::Disconnected);
        }

        let val = tokio::select! {
            res = rx => match res {
                Ok(v) => v,
                Err(_) => return Err(BridgeError::Disconnected),
            },
            _ = closed.changed() => {
                conn.waiter.lock().expect("waiter poisoned").take();
                return Err(BridgeError::Disconnected);
            }
            _ = tokio::time::sleep(COMMAND_TIMEOUT) => {
                conn.waiter.lock().expect("waiter poisoned").take();
                warn!("relay command '{}' timed out after {}s; closing provider WebSocket", command, COMMAND_TIMEOUT.as_secs());
                let _ = conn.out_tx.try_send(ProviderOut::Close);
                return Err(BridgeError::Timeout);
            }
        };

        // Turn provider-level `{"error": "..."}` into a non-200 HTTP response so rustpush
        // surfaces the error text instead of failing JSON deserialization on 200 OK.
        if let Some(err_str) = val.get("error").and_then(|v| v.as_str()) {
            warn!("relay provider returned error for '{}': {}", command, err_str);
            return Err(BridgeError::ProviderError(err_str.to_string()));
        }

        let mut val = val;
        if command == "get-version-info" {
            self.mac_identity.apply_to_versions(&mut val);
        }

        serde_json::to_vec(&val).map_err(|e| BridgeError::Other(e.to_string()))
    }

    async fn run_provider_ws<S>(self: Arc<Self>, ws: WebSocketStream<S>, peer: SocketAddr)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        info!("relay provider WebSocket connected from {}", peer);
        let (mut ws_sink, mut ws_stream) = ws.split();

        // Wait for initial `register` command.
        let first_msg = match tokio::time::timeout(REGISTER_TIMEOUT, async {
            loop {
                match ws_stream.next().await {
                    Some(Ok(Message::Text(t))) => return Ok(t),
                    Some(Ok(Message::Ping(p))) => {
                        let _ = ws_sink.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Pong(_))) => continue,
                    Some(Ok(Message::Close(_))) | None => bail!("provider closed before register"),
                    Some(Ok(_)) => bail!("unexpected non-text frame before register"),
                    Some(Err(e)) => bail!("ws read error before register: {}", e),
                }
            }
        })
        .await
        {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => {
                debug!("relay provider {} handshake failed: {:#}", peer, e);
                return;
            }
            Err(_) => {
                warn!("relay provider {} timed out waiting for register", peer);
                return;
            }
        };

        let incoming: IncomingWsMsg = match serde_json::from_str(&first_msg) {
            Ok(m) => m,
            Err(e) => {
                warn!("relay provider {} sent invalid JSON on register: {}", peer, e);
                return;
            }
        };
        if incoming.command != "register" {
            warn!(
                "relay provider {} sent '{}' instead of 'register'",
                peer, incoming.command
            );
            return;
        }
        let reg_req: RegisterRequestData =
            serde_json::from_value(incoming.data).unwrap_or_default();

        let (code, secret, issued_fresh) = match self.assign_or_validate_code(&reg_req) {
            Ok(v) => v,
            Err(e) => {
                warn!("relay provider {} failed to assign code: {:#}", peer, e);
                return;
            }
        };

        let hw = reg_req
            .versions
            .as_ref()
            .map(|v| v.hardware_version.as_str())
            .unwrap_or("");
        info!(
            "relay provider {} registered code={} fresh={} hw={:?} commit={:?}",
            peer, code, issued_fresh, hw, reg_req.commit
        );

        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let (out_tx, mut out_rx) = mpsc::channel::<ProviderOut>(32);
        let (closed_tx, closed_rx) = watch::channel(false);

        let conn = Arc::new(ProviderConn {
            id: conn_id,
            code: code.clone(),
            cmd_lock: AsyncMutex::new(()),
            next_req_id: AtomicI64::new(1),
            out_tx,
            waiter: StdMutex::new(None),
            closed: closed_rx,
        });

        let kicked = {
            let mut active = self.active.lock().expect("active lock poisoned");
            active.replace(Arc::clone(&conn))
        };
        if let Some(old) = kicked {
            info!(
                "relay kicking previous provider connection (old id={}, new id={})",
                old.id, conn_id
            );
            let _ = old.out_tx.try_send(ProviderOut::Close);
        }

        self.status_tx.send_modify(|s| {
            s.provider_connected = true;
            s.provider_code = Some(code.clone());
        });

        let reply = OutgoingWsMsg {
            command: "response",
            id: incoming.id,
            data: Some(RegisterResponseData {
                code: code.clone(),
                secret,
            }),
        };
        let reply_str = match serde_json::to_string(&reply) {
            Ok(s) => s,
            Err(e) => {
                warn!("failed to encode register response: {}", e);
                self.cleanup_provider(conn_id, &closed_tx, &conn, peer);
                return;
            }
        };
        if let Err(e) = ws_sink.send(Message::Text(reply_str)).await {
            warn!("relay provider {} failed to send register reply: {}", peer, e);
            self.cleanup_provider(conn_id, &closed_tx, &conn, peer);
            return;
        }

        loop {
            tokio::select! {
                maybe_out = out_rx.recv() => {
                    match maybe_out {
                        Some(ProviderOut::Text(txt)) => {
                            if let Err(e) = ws_sink.send(Message::Text(txt)).await {
                                debug!("relay provider {} write error: {}", peer, e);
                                break;
                            }
                        }
                        Some(ProviderOut::Close) | None => {
                            let _ = ws_sink.send(Message::Close(None)).await;
                            break;
                        }
                    }
                }
                maybe_in = ws_stream.next() => {
                    match maybe_in {
                        Some(Ok(Message::Text(txt))) => {
                            match serde_json::from_str::<IncomingWsMsg>(&txt) {
                                Ok(msg) => match msg.command.as_str() {
                                    "ping" => {
                                        let pong = serde_json::to_string(&OutgoingWsMsg::<()> {
                                            command: "pong",
                                            id: msg.id,
                                            data: None,
                                        }).unwrap();
                                        if ws_sink.send(Message::Text(pong)).await.is_err() {
                                            break;
                                        }
                                    }
                                    "pong" => {
                                        // Ignore unsolicited pong frames.
                                    }
                                    "response" => {
                                        let now_ms = now_epoch_ms();
                                        self.status_tx.send_modify(|s| {
                                            s.last_answered_ms = Some(now_ms);
                                        });
                                        let taken = conn.waiter.lock().expect("waiter poisoned").take();
                                        if let Some((expected_id, tx)) = taken {
                                            if let Some(got_id) = msg.id {
                                                if got_id != 0 && got_id != expected_id {
                                                    warn!(
                                                        "relay provider response id={} != expected {}; delivering anyway",
                                                        got_id, expected_id
                                                    );
                                                }
                                            }
                                            let _ = tx.send(msg.data);
                                        } else {
                                            warn!("relay provider sent unsolicited response id={:?}", msg.id);
                                        }
                                    }
                                    other => {
                                        debug!("relay provider {} sent unknown command '{}'", peer, other);
                                    }
                                },
                                Err(e) => {
                                    warn!("relay provider {} sent invalid JSON: {}", peer, e);
                                    break;
                                }
                            }
                        }
                        Some(Ok(Message::Ping(payload))) => {
                            if ws_sink.send(Message::Pong(payload)).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(Message::Pong(_))) => {}
                        Some(Ok(Message::Close(_))) | None => {
                            info!("relay provider {} closed connection", peer);
                            break;
                        }
                        Some(Ok(_)) => {}
                        Some(Err(e)) => {
                            debug!("relay provider {} read error: {}", peer, e);
                            break;
                        }
                    }
                }
            }
        }

        self.cleanup_provider(conn_id, &closed_tx, &conn, peer);
    }

    fn cleanup_provider(
        &self,
        conn_id: u64,
        closed_tx: &watch::Sender<bool>,
        conn: &Arc<ProviderConn>,
        peer: SocketAddr,
    ) {
        let _ = closed_tx.send(true);
        conn.waiter.lock().expect("waiter poisoned").take();

        let mut removed = false;
        {
            let mut active = self.active.lock().expect("active lock poisoned");
            if active.as_ref().map(|c| c.id) == Some(conn_id) {
                *active = None;
                removed = true;
            }
        }
        if removed {
            self.status_tx.send_modify(|s| {
                s.provider_connected = false;
            });
            info!("relay provider {} disconnected (no provider online)", peer);
        }
    }

    /// Validates an existing code+secret against our secret (and single-provider lock).
    /// When beepserv connects for the first time or migrates from Beeper's relay with foreign
    /// credentials, we issue our locked code + secret (or generate a fresh one once) so beepserv
    /// saves it automatically instead of looping forever.
    fn assign_or_validate_code(&self, req: &RegisterRequestData) -> Result<(String, String, bool)> {
        let mut locked = self.locked_code.lock().expect("locked_code poisoned");

        if !req.code.is_empty()
            && !req.secret.is_empty()
            && validate_code_secret(&self.secret, &req.code, &req.secret)
        {
            if let Some(existing) = locked.as_deref() {
                if ct_eq_str(existing, &req.code) {
                    return Ok((req.code.clone(), req.secret.clone(), false));
                }
            } else {
                *locked = Some(req.code.clone());
                self.save_store(locked.clone())?;
                return Ok((req.code.clone(), req.secret.clone(), false));
            }
        }

        let code = match locked.as_ref() {
            Some(existing) => existing.clone(),
            None => {
                let fresh = generate_provider_code();
                *locked = Some(fresh.clone());
                self.save_store(Some(fresh.clone()))?;
                fresh
            }
        };
        let secret = compute_secret_b64(&self.secret, &code);
        Ok((code, secret, true))
    }

    fn save_store(&self, code: Option<String>) -> Result<()> {
        let store = ProviderStore {
            provider_token: self.provider_token.clone(),
            code,
            mac_identity: Some(self.mac_identity.clone()),
        };
        save_store_atomic(&self.apple_dir.join("relay_provider.json"), &store)
    }
}

pub fn generate_provider_code() -> String {
    let mut rng = rand::thread_rng();
    let mut chars = [0u8; 16];
    for c in &mut chars {
        *c = CODE_ALPHABET[rng.gen_range(0..CODE_ALPHABET.len())];
    }
    let s = std::str::from_utf8(&chars).unwrap();
    format!("{}-{}-{}-{}", &s[0..4], &s[4..8], &s[8..12], &s[12..16])
}

pub fn compute_secret_b64(global_secret: &[u8; 32], code: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(global_secret).expect("HMAC accepts any key size");
    mac.update(code.as_bytes());
    let tag = mac.finalize().into_bytes();
    STANDARD_NO_PAD.encode(tag)
}

pub fn validate_code_secret(global_secret: &[u8; 32], code: &str, secret_b64: &str) -> bool {
    if code.len() != 19 || secret_b64.len() > 64 {
        return false;
    }
    let Ok(presented) = STANDARD_NO_PAD.decode(secret_b64) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(global_secret).expect("HMAC accepts any key size");
    mac.update(code.as_bytes());
    let expected = mac.finalize().into_bytes();
    presented.len() == expected.len() && bool::from(presented.as_slice().ct_eq(expected.as_slice()))
}

fn ct_eq_str(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

fn load_or_create_secret(path: &Path) -> Result<[u8; 32]> {
    if path.exists() {
        let raw = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        if raw.len() != 32 {
            bail!(
                "invalid relay secret length in {} (expected 32, got {})",
                path.display(),
                raw.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        return Ok(arr);
    }
    let mut arr = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut arr);
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut f = File::create(&tmp)?;
        f.write_all(&arr)?;
        f.sync_all()?;
    }
    crate::config::restrict_permissions(&tmp);
    fs::rename(&tmp, path)?;
    crate::config::restrict_permissions(path);
    Ok(arr)
}

fn load_or_create_store(path: &Path) -> Result<ProviderStore> {
    if path.exists() {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let store: ProviderStore = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        if !store.provider_token.is_empty() {
            return Ok(store);
        }
    }
    let mut tok = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut tok);
    let store = ProviderStore {
        provider_token: hex::encode(tok),
        code: None,
        mac_identity: None,
    };
    save_store_atomic(path, &store)?;
    Ok(store)
}

fn save_store_atomic(path: &Path, store: &ProviderStore) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(store)?;
    {
        let mut f = File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    crate::config::restrict_permissions(&tmp);
    fs::rename(&tmp, path)?;
    crate::config::restrict_permissions(path);
    Ok(())
}

fn parse_bridge_command(path: &str) -> Option<&str> {
    let cmd = path.strip_prefix("/api/v1/bridge/")?;
    match cmd {
        "get-version-info" | "get-validation-data" => Some(cmd),
        _ => None,
    }
}

fn extract_bearer(req: &Request<Body>) -> Option<&str> {
    let val = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let code = val.strip_prefix("Bearer ")?.trim();
    if code.is_empty() {
        None
    } else {
        Some(code)
    }
}

fn query_param<'a>(query: Option<&'a str>, key: &str) -> Option<&'a str> {
    for pair in query?.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key && !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

fn header_eq_ignore_case(req: &Request<Body>, name: header::HeaderName, expected: &str) -> bool {
    req.headers()
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.trim().eq_ignore_ascii_case(expected))
}

fn header_contains_ignore_case(
    req: &Request<Body>,
    name: header::HeaderName,
    needle: &str,
) -> bool {
    req.headers()
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|tok| tok.trim().eq_ignore_ascii_case(needle))
}

fn empty_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "imsg_relay_test_{}_{}_{}",
            tag,
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn provider_code_and_secret_roundtrip() {
        let code = generate_provider_code();
        assert_eq!(code.len(), 19);
        assert_eq!(&code[4..5], "-");
        assert_eq!(&code[9..10], "-");
        assert_eq!(&code[14..15], "-");
        for (i, b) in code.bytes().enumerate() {
            if i == 4 || i == 9 || i == 14 {
                assert_eq!(b, b'-');
            } else {
                assert!(CODE_ALPHABET.contains(&b));
            }
        }
        let secret = [0x42u8; 32];
        let b64 = compute_secret_b64(&secret, &code);
        assert!(validate_code_secret(&secret, &code, &b64));
        assert!(!validate_code_secret(&secret, &code, "wrong"));
        assert!(!validate_code_secret(&[0x43u8; 32], &code, &b64));
    }

    #[test]
    fn mac_identity_format() {
        for _ in 0..500 {
            let m = MacIdentity::generate();
            assert_eq!(m.serial_number.len(), 12, "{}", m.serial_number);
            assert!(is_valid_mac_serial(&m.serial_number), "{}", m.serial_number);
            assert!(m.is_valid());
            let u = uuid::Uuid::parse_str(&m.unique_device_id).unwrap();
            assert_eq!(u.get_version_num(), 4);
            assert_eq!(m.unique_device_id, m.unique_device_id.to_uppercase());
            assert_eq!(m.unique_device_id.len(), 36);
        }
        assert!(!is_valid_mac_serial("C02ABCDEFGHI"));
        assert!(!is_valid_mac_serial("F17XK0QXHG7F"));
        assert!(!is_valid_mac_serial("C02C1ABCDNC"));
        assert!(!is_valid_mac_serial("C02C1ABCDNé"));
    }

    #[test]
    fn mac_identity_stable_across_restarts() {
        let dir = temp_dir("macid");
        let first = RelayHub::load_or_init(&dir).unwrap();
        let id1 = first.mac_identity.clone();
        // Saving the code must keep the identity.
        first.save_store(Some("AAAA-BBBB-CCCC-DDDD".into())).unwrap();
        drop(first);
        let second = RelayHub::load_or_init(&dir).unwrap();
        assert_eq!(second.mac_identity, id1);
        assert_eq!(second.provider_code().as_deref(), Some("AAAA-BBBB-CCCC-DDDD"));

        // A store from before this field existed gets an identity added, keeping token + code.
        let path = dir.join("relay_provider.json");
        fs::write(&path, r#"{"provider_token":"abc123","code":"WWWW-XXXX-YYYY-ZZZZ"}"#).unwrap();
        let migrated = RelayHub::load_or_init(&dir).unwrap();
        assert_eq!(migrated.provider_token, "abc123");
        assert_eq!(migrated.provider_code().as_deref(), Some("WWWW-XXXX-YYYY-ZZZZ"));
        assert!(migrated.mac_identity.is_valid());
        let saved: ProviderStore =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(saved.mac_identity.as_ref(), Some(&migrated.mac_identity));
        assert_eq!(RelayHub::load_or_init(&dir).unwrap().mac_identity, migrated.mac_identity);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mac_identity_rewrites_only_serial_and_udid() {
        let m = MacIdentity {
            serial_number: "C02J1ABCDNCT".into(),
            unique_device_id: "6F1C2E1A-0B6C-4C55-9E0B-6B7E2C8D9A10".into(),
        };
        let mut v = serde_json::json!({
            "versions": {
                "hardware_version": "iPhone8,1",
                "software_name": "iPhone OS",
                "software_version": "12.5.8",
                "software_build_id": "16H88",
                "unique_device_id": "0123456789abcdef0123456789abcdef01234567",
                "serial_number": "F17XK0QXHG7F",
                "extra": 1
            }
        });
        m.apply_to_versions(&mut v);
        assert_eq!(
            v,
            serde_json::json!({
                "versions": {
                    "hardware_version": "iPhone8,1",
                    "software_name": "iPhone OS",
                    "software_version": "12.5.8",
                    "software_build_id": "16H88",
                    "unique_device_id": "6F1C2E1A-0B6C-4C55-9E0B-6B7E2C8D9A10",
                    "serial_number": "C02J1ABCDNCT",
                    "extra": 1
                }
            })
        );
        // Responses without `versions` pass through unchanged.
        let mut other = serde_json::json!({"data": "abc"});
        m.apply_to_versions(&mut other);
        assert_eq!(other, serde_json::json!({"data": "abc"}));
    }

    #[tokio::test]
    async fn end_to_end_provider_migration_and_bridge() {
        let dir = temp_dir("e2e");
        let hub = Arc::new(RelayHub::load_or_init(&dir).unwrap());
        let (internal_url, internal_token) = hub.start_internal_bridge().await.unwrap();

        // Bind a public TCP listener to test public WS + HTTP bridge endpoints.
        let pub_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pub_addr = pub_listener.local_addr().unwrap();
        let pub_hub = Arc::clone(&hub);
        let server_task = tokio::spawn(async move {
            while let Ok((stream, peer)) = pub_listener.accept().await {
                let h = Arc::clone(&pub_hub);
                tokio::spawn(async move {
                    let _ = h.handle_http_conn(stream, peer).await;
                });
            }
        });

        // 1. Missing/wrong token on /api/v1/provider -> 401
        let mut s = tokio::net::TcpStream::connect(pub_addr).await.unwrap();
        s.write_all(b"GET /api/v1/provider?t=wrong HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp_buf = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut s, &mut resp_buf)
            .await
            .unwrap();
        assert!(resp_buf.starts_with("HTTP/1.1 401"), "got: {}", resp_buf);

        // 2. Connect mock OpenBubbles/relayserver provider over WebSocket with explicit `"id": null`
        //    and foreign Beeper credentials (also verify `"ping"` with `"id": null, "data": null`).
        let ws_url = format!(
            "ws://{}/api/v1/provider?t={}",
            pub_addr, hub.provider_token
        );
        let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
        ws.send(Message::Text(
            r#"{"command":"register","id":null,"data":{"code":"AAAA-BBBB-CCCC-DDDD","secret":"notvalid"}}"#
                .to_string(),
        ))
        .await
        .unwrap();

        let reg_reply = match ws.next().await.unwrap().unwrap() {
            Message::Text(t) => serde_json::from_str::<serde_json::Value>(&t).unwrap(),
            other => panic!("expected text frame, got {:?}", other),
        };
        assert_eq!(reg_reply["command"], "response");
        let issued_code = reg_reply["data"]["code"].as_str().unwrap().to_string();
        let issued_secret = reg_reply["data"]["secret"].as_str().unwrap().to_string();
        assert_eq!(issued_code.len(), 19);
        assert_ne!(issued_code, "AAAA-BBBB-CCCC-DDDD");
        assert!(validate_code_secret(&hub.secret, &issued_code, &issued_secret));
        assert!(hub.status().provider_connected);

        // Verify OpenBubbles/relayserver's 60s ping format (`"id": null, "data": null`).
        ws.send(Message::Text(
            r#"{"command":"ping","id":null,"data":null}"#.to_string(),
        ))
        .await
        .unwrap();
        let pong_reply = match ws.next().await.unwrap().unwrap() {
            Message::Text(t) => serde_json::from_str::<serde_json::Value>(&t).unwrap(),
            other => panic!("expected pong text frame, got {:?}", other),
        };
        assert_eq!(pong_reply["command"], "pong");

        // Spawn mock provider responder loop.
        let provider_task = tokio::spawn(async move {
            while let Some(Ok(msg)) = ws.next().await {
                if let Message::Text(t) = msg {
                    let v: serde_json::Value = serde_json::from_str(&t).unwrap();
                    let cmd = v["command"].as_str().unwrap();
                    let id = v["id"].as_i64().unwrap_or(0);
                    match cmd {
                        "get-version-info" => {
                            let reply = serde_json::json!({
                                "command": "response",
                                "id": id,
                                "data": {
                                    "versions": {
                                        "hardware_version": "iPhone10,6",
                                        "software_name": "iPhone OS",
                                        "software_version": "16.7.2",
                                        "software_build_id": "20H115",
                                        "unique_device_id": "TEST-UUID",
                                        "serial_number": "TESTSERIAL"
                                    }
                                }
                            });
                            ws.send(Message::Text(reply.to_string())).await.unwrap();
                        }
                        "get-validation-data" => {
                            let reply = serde_json::json!({
                                "command": "response",
                                "id": id,
                                "data": { "error": "No account had a valid registration" }
                            });
                            ws.send(Message::Text(reply.to_string())).await.unwrap();
                        }
                        _ => {}
                    }
                }
            }
        });

        // 3. Call internal bridge for get-version-info -> 200 OK with versions JSON.
        let internal_addr = internal_url.strip_prefix("http://").unwrap();
        let mut c1 = tokio::net::TcpStream::connect(internal_addr).await.unwrap();
        let req1 = format!(
            "POST /api/v1/bridge/get-version-info HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            internal_token
        );
        c1.write_all(req1.as_bytes()).await.unwrap();
        let mut r1 = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut c1, &mut r1)
            .await
            .unwrap();
        assert!(r1.starts_with("HTTP/1.1 200"), "got: {}", r1);
        let body1 = r1.split_once("\r\n\r\n").unwrap().1;
        let v1: serde_json::Value = serde_json::from_str(body1).unwrap();
        let versions = &v1["versions"];
        assert_eq!(versions["hardware_version"], "iPhone10,6");
        assert_eq!(versions["software_name"], "iPhone OS");
        assert_eq!(versions["software_version"], "16.7.2");
        assert_eq!(versions["software_build_id"], "20H115");
        assert_eq!(versions["serial_number"], hub.mac_identity.serial_number.as_str());
        assert_eq!(versions["unique_device_id"], hub.mac_identity.unique_device_id.as_str());
        assert!(!body1.contains("TESTSERIAL") && !body1.contains("TEST-UUID"), "got: {}", body1);

        // 4. Call public bridge for get-validation-data -> provider error becomes HTTP 502.
        let mut c2 = tokio::net::TcpStream::connect(pub_addr).await.unwrap();
        let req2 = format!(
            "POST /api/v1/bridge/get-validation-data HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            issued_code
        );
        c2.write_all(req2.as_bytes()).await.unwrap();
        let mut r2 = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut c2, &mut r2)
            .await
            .unwrap();
        assert!(r2.starts_with("HTTP/1.1 502"), "got: {}", r2);
        assert!(r2.contains("No account had a valid registration"), "got: {}", r2);

        // 5. Wrong bearer code on public bridge -> 404.
        let mut c3 = tokio::net::TcpStream::connect(pub_addr).await.unwrap();
        c3.write_all(
            b"POST /api/v1/bridge/get-version-info HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer WWWW-XXXX-YYYY-ZZZZ\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut r3 = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut c3, &mut r3)
            .await
            .unwrap();
        assert!(r3.starts_with("HTTP/1.1 404"), "got: {}", r3);

        provider_task.abort();
        server_task.abort();
        let _ = fs::remove_dir_all(&dir);
    }
}
