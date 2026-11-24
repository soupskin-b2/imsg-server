use crate::config::{Config, WakeupConfig};
use crate::proto::{
    bye_reason_name, read_frame, read_frame_max, write_frame, Frame, ACK_TIMEOUT_S, BYE_AUTH_FAILED,
    BYE_BAD_VERSION, BYE_PROTOCOL_ERROR, BYE_REPLACED, BYE_SERVER_SHUTDOWN, FALLBACK_INTERVAL_S,
    FRAME_HELLO, MEDIA_CHUNK_LEN, PONG_TIMEOUT_S, PROBE_SERVER_IDLE_S, PROTOCOL_VERSION, ROLE_MAIN,
    ROLE_MEDIA, ROLE_PAIR, ROLE_PROBE, MAX_HANDSHAKE_PAYLOAD_LEN,
};
use crate::media::MediaStore;
use crate::relay::RelayHub;
use crate::state::ClientState;
use anyhow::{anyhow, Context, Result};
use log::{debug, info, warn};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

const HANDSHAKE_TIMEOUT_S: u64 = 15;

#[derive(Debug)]
pub struct IncomingClientMsg {
    pub client_id: String,
    pub seq: u64,
    pub body: Vec<u8>,
}

#[derive(Debug)]
enum ConnCmd {
    SendMsg { seq: u64, body: Vec<u8> },
    Replaced,
    #[allow(dead_code)]
    Shutdown,
}

struct ActiveConn {
    generation: u64,
    cmd_tx: mpsc::Sender<ConnCmd>,
}

struct ClientSlot {
    state: ClientState,
    active: Option<ActiveConn>,
}

struct HubInner {
    next_gen: u64,
    slots: HashMap<String, ClientSlot>,
    last_wakeup: HashMap<String, Instant>,
    /// Stale clients already warned about (once per run).
    stale_warned: std::collections::HashSet<String>,
}

/// A client not connected for this long gets no new messages queued (see `deliver_all`).
const STALE_CLIENT_DAYS: u64 = 90;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// "2026-08-01 (113 days ago)"-style, for logs.
fn fmt_ago(ms: u64) -> String {
    if ms == 0 {
        return "never".to_string();
    }
    let days = now_ms().saturating_sub(ms) / (24 * 60 * 60 * 1000);
    format!("{} days ago", days)
}

pub struct Hub {
    state_dir: PathBuf,
    config_path: PathBuf,
    auth_entries: Mutex<Vec<(String, [u8; 32])>>,
    pair_lock: Mutex<()>,
    wakeup: Option<WakeupConfig>,
    connect_tx: broadcast::Sender<String>,
    inner: Mutex<HubInner>,
    pub media: Arc<MediaStore>,
}

struct MainRegistration {
    generation: u64,
    server_last_rx_seq: u64,
    pending: Vec<(u64, Vec<u8>)>,
    /// Our epoch for the WELCOME, if the client speaks epochs.
    epoch: Option<u64>,
}

impl Hub {
    pub fn new(cfg: &Config) -> Result<Self> {
        let mut auth_entries = Vec::with_capacity(cfg.clients.len());
        let mut slots = HashMap::new();
        for c in &cfg.clients {
            let hash = c.token_hash_bytes()?;
            let mut state = ClientState::load_or_default(&cfg.state_dir, &c.id)?;
            if state.last_seen_ms == 0 {
                // From before last_seen was kept: count from now.
                state.last_seen_ms = now_ms();
            }
            auth_entries.push((c.id.clone(), hash));
            slots.insert(
                c.id.clone(),
                ClientSlot {
                    state,
                    active: None,
                },
            );
        }
        let (connect_tx, _) = broadcast::channel(64);
        let media = Arc::new(MediaStore::new(
            &cfg.state_dir,
            cfg.media.ffmpeg.as_deref(),
            cfg.media.retention_days,
        )?);
        Ok(Self {
            media,
            state_dir: cfg.state_dir.clone(),
            config_path: cfg.path.clone(),
            auth_entries: Mutex::new(auth_entries),
            pair_lock: Mutex::new(()),
            wakeup: cfg.wakeup.clone(),
            connect_tx,
            inner: Mutex::new(HubInner {
                next_gen: 1,
                slots,
                last_wakeup: HashMap::new(),
                stale_warned: std::collections::HashSet::new(),
            }),
        })
    }

    pub fn client_ids(&self) -> Vec<String> {
        let entries = self.auth_entries.lock().expect("auth mutex poisoned");
        entries.iter().map(|(id, _)| id.clone()).collect()
    }

    pub fn subscribe_connects(&self) -> broadcast::Receiver<String> {
        self.connect_tx.subscribe()
    }

    pub fn connected_client_ids(&self) -> Vec<String> {
        let inner = self.inner.lock().expect("hub mutex poisoned");
        inner
            .slots
            .iter()
            .filter_map(|(id, slot)| slot.active.as_ref().map(|_| id.clone()))
            .collect()
    }

    /// Delivers a body only to clients with an active main connection (avoids queueing stale
    /// status updates into offline outboxes or triggering wakeups).
    pub async fn deliver_connected(&self, body: Vec<u8>) {
        let ids = self.connected_client_ids();
        for id in ids {
            if let Err(e) = self.deliver(&id, body.clone()).await {
                warn!("failed to deliver status to client '{}': {:#}", id, e);
            }
        }
    }

    /// Checks a one-time pairing code; on success adds a new client and returns (id, token).
    pub fn pair(&self, code: &[u8]) -> Result<Option<(String, String)>> {
        let _guard = self.pair_lock.lock().expect("pair mutex poisoned");
        if !crate::pairing::consume(&self.state_dir, code)? {
            return Ok(None);
        }
        let id = format!("phone-{}", hex::encode(rand::random::<[u8; 4]>()));
        let added = crate::config::append_client(&self.config_path, &id)?;
        let hash_bytes: [u8; 32] = hex::decode(&added.token_sha256)?
            .try_into()
            .map_err(|_| anyhow!("bad token hash length"))?;
        let state = ClientState::load_or_default(&self.state_dir, &id)?;
        self.inner
            .lock()
            .expect("hub mutex poisoned")
            .slots
            .insert(id.clone(), ClientSlot { state, active: None });
        self.auth_entries
            .lock()
            .expect("auth mutex poisoned")
            .push((id.clone(), hash_bytes));
        Ok(Some((added.id, added.token_hex)))
    }

    /// Constant-time token verification against all configured clients.
    pub fn authenticate(&self, token_bytes: &[u8]) -> Option<String> {
        let digest = Sha256::digest(token_bytes);
        let mut matched: Option<String> = None;
        let entries = self.auth_entries.lock().expect("auth mutex poisoned");
        for (id, expected) in entries.iter() {
            if bool::from(digest.as_slice().ct_eq(expected)) {
                matched = Some(id.clone());
            }
        }
        matched
    }

    /// Assigns the next seq, persists to the client's outbox, and forwards to the active main connection if attached.
    pub async fn deliver(&self, client_id: &str, body: Vec<u8>) -> Result<u64> {
        let (seq, active_tx) = {
            let mut inner = self.inner.lock().expect("hub mutex poisoned");
            let slot = inner
                .slots
                .get_mut(client_id)
                .ok_or_else(|| anyhow!("unknown client '{}'", client_id))?;
            let (seq, dropped) = slot.state.enqueue_bounded(&body);
            if dropped > 0 {
                warn!(
                    "client '{}': {} unread messages queued, dropped the {} oldest (it hasn't connected since {})",
                    client_id,
                    slot.state.outbox.len(),
                    dropped,
                    fmt_ago(slot.state.last_seen_ms)
                );
            }
            slot.state.save(&self.state_dir, client_id)?;
            let tx = slot.active.as_ref().map(|a| a.cmd_tx.clone());
            (seq, tx)
        };

        match active_tx {
            Some(tx) => {
                if tx.send(ConnCmd::SendMsg { seq, body }).await.is_err() {
                    debug!(
                        "client '{}': active connection closed while delivering seq {}",
                        client_id, seq
                    );
                    self.trigger_wakeup(client_id);
                }
            }
            None => {
                debug!(
                    "client '{}': offline; queued seq {} in outbox",
                    client_id, seq
                );
                self.trigger_wakeup(client_id);
            }
        }
        Ok(seq)
    }

    /// Delivers a body to every configured client that isn't stale: one that hasn't connected
    /// for STALE_CLIENT_DAYS is most likely a phone that was paired again under a new id (or is
    /// gone), and queueing every message for it only grows its state file.
    pub async fn deliver_all(&self, body: Vec<u8>) -> Result<()> {
        let ids = self.client_ids();
        let now = now_ms();
        let stale_ms = STALE_CLIENT_DAYS * 24 * 60 * 60 * 1000;
        for id in ids {
            let last_seen = {
                let inner = self.inner.lock().expect("hub mutex poisoned");
                inner.slots.get(&id).map(|s| (s.state.last_seen_ms, s.active.is_some()))
            };
            if let Some((seen, active)) = last_seen {
                if !active && seen != 0 && now.saturating_sub(seen) > stale_ms {
                    let mut inner = self.inner.lock().expect("hub mutex poisoned");
                    if inner.stale_warned.insert(id.clone()) {
                        warn!(
                            "client '{}' hasn't connected for over {} days (since {}); not queueing messages for it. \
                             Remove its [[clients]] entry from config.toml if it's gone.",
                            id,
                            STALE_CLIENT_DAYS,
                            fmt_ago(seen)
                        );
                    }
                    continue;
                }
            }
            if let Err(e) = self.deliver(&id, body.clone()).await {
                warn!("failed to deliver message to client '{}': {:#}", id, e);
            }
        }
        Ok(())
    }

    fn register_main(
        &self,
        client_id: &str,
        client_last_rx_seq: u64,
        epochs: Option<(u64, u64)>,
        cmd_tx: mpsc::Sender<ConnCmd>,
    ) -> Result<(MainRegistration, Option<mpsc::Sender<ConnCmd>>)> {
        let mut inner = self.inner.lock().expect("hub mutex poisoned");
        let generation = inner.next_gen;
        inner.next_gen += 1;

        let slot = inner
            .slots
            .get_mut(client_id)
            .ok_or_else(|| anyhow!("unknown client '{}'", client_id))?;

        let old_tx = slot
            .active
            .replace(ActiveConn { generation, cmd_tx })
            .map(|old| old.cmd_tx);

        // Persisted below (rarely: only once an hour is enough to know it's alive).
        let now = now_ms();
        let mut dirty = now.saturating_sub(slot.state.last_seen_ms) > 60 * 60 * 1000;
        slot.state.last_seen_ms = now;
        let mut client_last_rx_seq = client_last_rx_seq;
        let mut epoch = None;
        if let Some((client_epoch, seen_epoch)) = epochs {
            let (ours, made) = slot.state.ensure_epoch();
            dirty |= made;
            epoch = Some(ours);
            if client_epoch != 0 && client_epoch != slot.state.client_epoch {
                // A new client state (app data cleared, state file lost) numbers its messages
                // from 1 again: without this they'd all be dropped as duplicates of old seqs.
                if slot.state.client_epoch != 0 && slot.state.last_rx_seq != 0 {
                    warn!(
                        "client '{}': its state is new (epoch {:016x}, was {:016x}); taking its messages from seq 1 (was {})",
                        client_id, client_epoch, slot.state.client_epoch, slot.state.last_rx_seq
                    );
                    slot.state.last_rx_seq = 0;
                }
                slot.state.client_epoch = client_epoch;
                dirty = true;
            }
            if seen_epoch != 0 && seen_epoch != ours && client_last_rx_seq != 0 {
                // Its last_rx_seq counts another (older) state of ours: it ACKs nothing here.
                warn!(
                    "client '{}': last_rx_seq {} is from another server state (epoch {:016x}, ours {:016x}); resending everything unACKed",
                    client_id, client_last_rx_seq, seen_epoch, ours
                );
                client_last_rx_seq = 0;
            }
        }

        // Implicit ACK of everything up to client's last_rx_seq.
        if slot.state.ack_up_to(client_last_rx_seq) > 0 {
            dirty = true;
        }
        // Persisted before the WELCOME, so the epoch it carries is the one we keep.
        if dirty {
            slot.state.save(&self.state_dir, client_id)?;
        }

        let server_last_rx_seq = slot.state.last_rx_seq;
        let pending = slot.state.pending_after(client_last_rx_seq)?;

        Ok((
            MainRegistration {
                generation,
                server_last_rx_seq,
                pending,
                epoch,
            },
            old_tx,
        ))
    }

    fn on_ack(&self, client_id: &str, ack_seq: u64) -> Result<bool> {
        let mut inner = self.inner.lock().expect("hub mutex poisoned");
        let slot = inner
            .slots
            .get_mut(client_id)
            .ok_or_else(|| anyhow!("unknown client '{}'", client_id))?;
        if slot.state.ack_up_to(ack_seq) > 0 {
            slot.state.save(&self.state_dir, client_id)?;
        }
        Ok(slot.state.is_outbox_empty())
    }

    fn on_incoming_msg(&self, client_id: &str, seq: u64) -> Result<(u64, bool)> {
        let mut inner = self.inner.lock().expect("hub mutex poisoned");
        let slot = inner
            .slots
            .get_mut(client_id)
            .ok_or_else(|| anyhow!("unknown client '{}'", client_id))?;

        if seq <= slot.state.last_rx_seq {
            debug!(
                "client '{}': duplicate MSG seq {} (last_rx_seq={}), dropping",
                client_id, seq, slot.state.last_rx_seq
            );
            return Ok((slot.state.last_rx_seq, false));
        }

        if seq > slot.state.last_rx_seq + 1 {
            warn!(
                "client '{}': incoming MSG seq gap (expected {}, got {}); accepting",
                client_id,
                slot.state.last_rx_seq + 1,
                seq
            );
        }

        slot.state.last_rx_seq = seq;
        // Persist BEFORE sending ACK.
        slot.state.save(&self.state_dir, client_id)?;
        Ok((seq, true))
    }

    fn detach_main(&self, client_id: &str, generation: u64) {
        let mut inner = self.inner.lock().expect("hub mutex poisoned");
        if let Some(slot) = inner.slots.get_mut(client_id) {
            if slot.active.as_ref().map(|a| a.generation) == Some(generation) {
                slot.active = None;
                // Seen until now (a phone can stay on one connection for days); kept on disk so
                // a restart doesn't think it's been away since it connected.
                slot.state.last_seen_ms = now_ms();
                if let Err(e) = slot.state.save(&self.state_dir, client_id) {
                    warn!("client '{}': failed to save state on disconnect: {:#}", client_id, e);
                }
            }
        }
    }

    fn trigger_wakeup(&self, client_id: &str) {
        let Some(cfg) = &self.wakeup else {
            return;
        };
        if cfg.command.is_empty() {
            return;
        }
        let now = Instant::now();
        let min_interval = Duration::from_secs(cfg.min_interval_s);
        {
            let mut inner = self.inner.lock().expect("hub mutex poisoned");
            if let Some(&last) = inner.last_wakeup.get(client_id) {
                if now.saturating_duration_since(last) < min_interval {
                    debug!(
                        "client '{}': wakeup rate-limited ({:?} < {:?})",
                        client_id,
                        now.saturating_duration_since(last),
                        min_interval
                    );
                    return;
                }
            }
            inner.last_wakeup.insert(client_id.to_string(), now);
        }

        let program = cfg.command[0].replace("{client_id}", client_id);
        let args: Vec<String> = cfg.command[1..]
            .iter()
            .map(|a| a.replace("{client_id}", client_id))
            .collect();
        let cid = client_id.to_string();

        tokio::spawn(async move {
            info!(
                "client '{}': running wakeup command: {} {:?}",
                cid, program, args
            );
            match tokio::process::Command::new(&program).args(&args).status().await {
                Ok(status) => {
                    if !status.success() {
                        warn!(
                            "client '{}': wakeup command exited with {}",
                            cid, status
                        );
                    }
                }
                Err(e) => {
                    warn!("client '{}': failed to spawn wakeup command: {}", cid, e);
                }
            }
        });
    }
}

pub fn build_tls_acceptor(cfg: &Config) -> Result<TlsAcceptor> {
    // Explicitly install aws_lc_rs crypto provider to avoid provider-selection panics.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cert_file = File::open(&cfg.cert_path)
        .with_context(|| format!("failed to open cert {}", cfg.cert_path.display()))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse cert PEM {}", cfg.cert_path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", cfg.cert_path.display());
    }

    let key_file = File::open(&cfg.key_path)
        .with_context(|| format!("failed to open key {}", cfg.key_path.display()))?;
    let mut key_reader = BufReader::new(key_file);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .with_context(|| format!("failed to parse key PEM {}", cfg.key_path.display()))?
        .ok_or_else(|| anyhow!("no private key found in {}", cfg.key_path.display()))?;

    let versions: &[&rustls::SupportedProtocolVersion] = if cfg.tls12_fallback {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };

    let server_config = rustls::ServerConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to configure rustls ServerConfig")?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

pub async fn run_listeners(
    cfg: &Config,
    hub: Arc<Hub>,
    relay: Arc<RelayHub>,
    incoming_tx: mpsc::Sender<IncomingClientMsg>,
) -> Result<()> {
    let acceptor = build_tls_acceptor(cfg)?;
    let mut join_handles = Vec::new();

    for addr in &cfg.listen_addrs {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| {
                format!(
                    "failed to bind {} (another service may already be using this port)",
                    addr
                )
            })?;
        let local = listener.local_addr()?;
        info!(
            "listening on {} (tls12_fallback={}, built-in relay enabled)",
            local, cfg.tls12_fallback
        );

        let acceptor = acceptor.clone();
        let hub = Arc::clone(&hub);
        let relay = Arc::clone(&relay);
        let incoming_tx = incoming_tx.clone();

        join_handles.push(tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let acceptor = acceptor.clone();
                        let hub = Arc::clone(&hub);
                        let relay = Arc::clone(&relay);
                        let incoming_tx = incoming_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_tcp_conn(
                                stream,
                                peer,
                                acceptor,
                                hub,
                                relay,
                                incoming_tx,
                            )
                            .await
                            {
                                debug!("connection {} ended: {:#}", peer, e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("accept error on {}: {}", local, e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }));
    }

    for h in join_handles {
        let _ = h.await;
    }
    Ok(())
}

/// AsyncRead/AsyncWrite wrapper that yields one already-peeked byte before delegating to `inner`.
pub struct PrefixedStream<S> {
    first: Option<u8>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(first: u8, inner: S) -> Self {
        Self {
            first: Some(first),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(byte) = self.first.take() {
            if buf.remaining() > 0 {
                buf.put_slice(&[byte]);
                return Poll::Ready(Ok(()));
            } else {
                self.first = Some(byte);
                return Poll::Ready(Ok(()));
            }
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn handle_tcp_conn(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    hub: Arc<Hub>,
    relay: Arc<RelayHub>,
    incoming_tx: mpsc::Sender<IncomingClientMsg>,
) -> Result<()> {
    // Spec §2: Set TCP_NODELAY and leave OS TCP keepalives disabled (default off).
    stream.set_nodelay(true)?;

    let mut tls_stream = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_S),
        acceptor.accept(stream),
    )
    .await
    .map_err(|_| anyhow!("TLS handshake timed out"))??;

    // Sniff the first decrypted byte to multiplex the phone push protocol (HELLO = 0x01)
    // and the built-in HTTP/1.1 registration relay (ASCII uppercase method: GET, POST, ...).
    let mut first = [0u8; 1];
    let n = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_S),
        tls_stream.read(&mut first),
    )
    .await
    .map_err(|_| anyhow!("initial byte timed out"))??;
    if n == 0 {
        return Ok(());
    }

    if first[0].is_ascii_uppercase() {
        crate::relay::enable_keepalive(tls_stream.get_ref().0, peer);
    }
    let prefixed = PrefixedStream::new(first[0], tls_stream);
    if first[0] == FRAME_HELLO {
        handle_stream(prefixed, peer, hub, incoming_tx).await
    } else if first[0].is_ascii_uppercase() {
        relay.handle_http_conn(prefixed, peer).await
    } else {
        debug!("{} sent unexpected leading byte 0x{:02x}; closing", peer, first[0]);
        Ok(())
    }
}

async fn handle_stream<S>(
    mut stream: S,
    peer: SocketAddr,
    hub: Arc<Hub>,
    incoming_tx: mpsc::Sender<IncomingClientMsg>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let first = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_S),
        read_frame_max(&mut stream, MAX_HANDSHAKE_PAYLOAD_LEN),
    )
    .await
    .map_err(|_| anyhow!("HELLO timed out"))??;

    let Some(Frame::Hello {
        version,
        role,
        token,
        last_rx_seq,
        interval_s,
        epochs,
    }) = first
    else {
        let _ = write_frame(&mut stream, &Frame::Bye { reason: BYE_PROTOCOL_ERROR }).await;
        anyhow::bail!("expected HELLO frame from {}", peer);
    };

    if version != PROTOCOL_VERSION {
        warn!("{} sent unsupported protocol version {}", peer, version);
        let _ = write_frame(&mut stream, &Frame::Bye { reason: BYE_BAD_VERSION }).await;
        return Ok(());
    }

    if role == ROLE_PAIR {
        match hub.pair(&token) {
            Ok(Some((client_id, token_hex))) => {
                info!("paired new client '{}' from {}", client_id, peer);
                write_frame(
                    &mut stream,
                    &Frame::Paired {
                        client_id,
                        token: token_hex,
                    },
                )
                .await?;
            }
            Ok(None) => {
                warn!("{} sent a wrong or expired pairing code", peer);
                let _ = write_frame(&mut stream, &Frame::Bye { reason: BYE_AUTH_FAILED }).await;
            }
            Err(e) => {
                warn!("pairing {} failed: {:#}", peer, e);
                let _ = write_frame(&mut stream, &Frame::Bye { reason: BYE_AUTH_FAILED }).await;
            }
        }
        return Ok(());
    }

    let Some(client_id) = hub.authenticate(&token) else {
        warn!("{} failed authentication (role={})", peer, role);
        let _ = write_frame(&mut stream, &Frame::Bye { reason: BYE_AUTH_FAILED }).await;
        return Ok(());
    };

    match role {
        ROLE_PROBE => {
            debug!("client '{}' probe connected from {}", client_id, peer);
            handle_probe(stream, &client_id, peer).await
        }
        ROLE_MEDIA => {
            debug!("client '{}' media connection from {}", client_id, peer);
            handle_media(stream, &client_id, Arc::clone(&hub.media)).await
        }
        ROLE_MAIN => {
            info!(
                "client '{}' main connected from {} (last_rx_seq={}, interval_s={})",
                client_id, peer, last_rx_seq, interval_s
            );
            handle_main(stream, &client_id, peer, last_rx_seq, epochs, interval_s, hub, incoming_tx).await
        }
        other => {
            warn!("client '{}' sent invalid role {}", client_id, other);
            let _ = write_frame(&mut stream, &Frame::Bye { reason: BYE_PROTOCOL_ERROR }).await;
            Ok(())
        }
    }
}

async fn handle_probe<S>(mut stream: S, client_id: &str, peer: SocketAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_frame(&mut stream, &Frame::Welcome { last_rx_seq: 0, epoch: None }).await?;

    let idle_limit = Duration::from_secs(PROBE_SERVER_IDLE_S);
    loop {
        let next = match tokio::time::timeout(idle_limit, read_frame_max(&mut stream, MAX_HANDSHAKE_PAYLOAD_LEN)).await {
            Ok(Ok(Some(frame))) => frame,
            Ok(Ok(None)) => {
                debug!("client '{}' probe {} EOF", client_id, peer);
                break;
            }
            Ok(Err(e)) => {
                debug!("client '{}' probe {} read error: {:#}", client_id, peer, e);
                break;
            }
            Err(_) => {
                debug!(
                    "client '{}' probe {} exceeded idle cap ({}s)",
                    client_id, peer, PROBE_SERVER_IDLE_S
                );
                break;
            }
        };

        match next {
            Frame::Ping { nonce } => {
                write_frame(&mut stream, &Frame::Pong { nonce }).await?;
            }
            Frame::Bye { reason } => {
                debug!(
                    "client '{}' probe {} sent BYE ({})",
                    client_id,
                    peer,
                    bye_reason_name(reason)
                );
                break;
            }
            other => {
                warn!(
                    "client '{}' probe {} sent unexpected frame {:?}",
                    client_id, peer, other
                );
                let _ = write_frame(&mut stream, &Frame::Bye { reason: BYE_PROTOCOL_ERROR }).await;
                break;
            }
        }
    }
    Ok(())
}

/// How long a media connection may sit idle between requests.
const MEDIA_IDLE_S: u64 = 120;

struct UploadInProgress {
    id: String,
    total: u64,
    received: u64,
    tmp: PathBuf,
    file: tokio::fs::File,
}

/// ROLE_MEDIA: serves MEDIA_GET downloads and MEDIA_PUT uploads, one request at a time.
async fn handle_media<S>(mut stream: S, client_id: &str, media: Arc<MediaStore>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

    write_frame(&mut stream, &Frame::Welcome { last_rx_seq: 0, epoch: None }).await?;
    let mut upload: Option<UploadInProgress> = None;
    let result: Result<()> = async {
        loop {
            let frame = match tokio::time::timeout(
                Duration::from_secs(MEDIA_IDLE_S),
                read_frame(&mut stream),
            )
            .await
            {
                Ok(Ok(Some(f))) => f,
                Ok(Ok(None)) | Err(_) => return Ok(()),
                Ok(Err(e)) => return Err(e),
            };
            match frame {
                Frame::MediaGet { id, full, offset } => {
                    let variant = match media.variant(&id, full).await {
                        Ok(v) => v,
                        Err(e) if crate::media::is_try_later(&e) => {
                            // MEDIA_ERR would make the phone give up on the attachment for good
                            // ("couldn't download"); a closed connection makes it try again later.
                            warn!(
                                "client '{}' MEDIA_GET {} (full={}) failed for now; closing so the phone retries: {:#}",
                                client_id, id, full, e
                            );
                            return Ok(());
                        }
                        Err(e) => {
                            warn!("client '{}' MEDIA_GET {} (full={}) failed: {:#}", client_id, id, full, e);
                            write_frame(&mut stream, &Frame::MediaErr { message: format!("{:#}", e) }).await?;
                            continue;
                        }
                    };
                    let mut file = tokio::fs::File::open(&variant.path).await?;
                    let mut pos = offset.min(variant.len);
                    file.seek(std::io::SeekFrom::Start(pos)).await?;
                    let mut buf = vec![0u8; MEDIA_CHUNK_LEN];
                    loop {
                        let want = ((variant.len - pos) as usize).min(MEDIA_CHUNK_LEN);
                        file.read_exact(&mut buf[..want]).await?;
                        write_frame(
                            &mut stream,
                            &Frame::MediaData {
                                total: variant.len,
                                offset: pos,
                                mime: variant.mime.clone(),
                                name: variant.name.clone(),
                                data: buf[..want].to_vec(),
                            },
                        )
                        .await?;
                        pos += want as u64;
                        if pos >= variant.len {
                            break;
                        }
                    }
                    debug!(
                        "client '{}' fetched {} (full={}, {} bytes from {})",
                        client_id, id, full, variant.len, offset
                    );
                }
                Frame::MediaPut { id, offset, total, data } => {
                    let err = |m: String| Frame::MediaErr { message: m };
                    if total > media.max_upload_bytes() {
                        write_frame(&mut stream, &err("attachment is too large".into())).await?;
                        continue;
                    }
                    if offset == 0 {
                        if let Some(old) = upload.take() {
                            let _ = tokio::fs::remove_file(&old.tmp).await;
                        }
                        let path = match media.upload_path(&id) {
                            Ok(p) => p,
                            Err(e) => {
                                write_frame(&mut stream, &err(format!("{:#}", e))).await?;
                                continue;
                            }
                        };
                        let tmp = path.with_extension("part");
                        let file = tokio::fs::File::create(&tmp).await?;
                        upload = Some(UploadInProgress { id: id.clone(), total, received: 0, tmp, file });
                    }
                    let Some(up) = upload.as_mut().filter(|u| u.id == id && u.received == offset && u.total == total) else {
                        write_frame(&mut stream, &err("upload out of order; start again".into())).await?;
                        continue;
                    };
                    if up.received + data.len() as u64 > total {
                        let _ = tokio::fs::remove_file(&up.tmp).await;
                        upload = None;
                        write_frame(&mut stream, &err("upload longer than announced".into())).await?;
                        continue;
                    }
                    up.file.write_all(&data).await?;
                    up.received += data.len() as u64;
                    if up.received == total {
                        let up = upload.take().expect("upload present");
                        let mut file = up.file;
                        file.flush().await?;
                        file.sync_all().await?;
                        drop(file);
                        tokio::fs::rename(&up.tmp, media.upload_path(&up.id)?).await?;
                        info!("client '{}' uploaded {} ({} bytes)", client_id, up.id, total);
                        write_frame(&mut stream, &Frame::MediaPutAck { id: up.id, received: total }).await?;
                    }
                }
                Frame::Ping { nonce } => {
                    write_frame(&mut stream, &Frame::Pong { nonce }).await?;
                }
                Frame::Bye { .. } => return Ok(()),
                other => {
                    warn!("client '{}' media connection sent unexpected frame {:?}", client_id, other.frame_type());
                    let _ = write_frame(&mut stream, &Frame::Bye { reason: BYE_PROTOCOL_ERROR }).await;
                    return Ok(());
                }
            }
        }
    }
    .await;
    if let Some(up) = upload {
        let _ = tokio::fs::remove_file(&up.tmp).await;
    }
    result
}

fn idle_timeout_for(interval_s: u16) -> Duration {
    let iv = if interval_s == 0 {
        FALLBACK_INTERVAL_S
    } else {
        interval_s
    };
    // 1.5 * interval_s + PONG_TIMEOUT (10s), exact in milliseconds.
    Duration::from_millis((iv as u64) * 1500 + PONG_TIMEOUT_S * 1000)
}

async fn handle_main<S>(
    stream: S,
    client_id: &str,
    peer: SocketAddr,
    client_last_rx_seq: u64,
    epochs: Option<(u64, u64)>,
    initial_interval_s: u16,
    hub: Arc<Hub>,
    incoming_tx: mpsc::Sender<IncomingClientMsg>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<ConnCmd>(256);
    let (reg, old_tx) = hub.register_main(client_id, client_last_rx_seq, epochs, cmd_tx)?;

    if let Some(old) = old_tx {
        info!(
            "client '{}': replacing previous main connection (new gen={})",
            client_id, reg.generation
        );
        let _ = old.try_send(ConnCmd::Replaced);
    }

    let (mut read_half, mut write_half) = tokio::io::split(stream);

    // Dedicated reader task so read_exact never sits inside tokio::select!.
    let (in_tx, mut in_rx) = mpsc::channel::<Result<Frame>>(64);
    let reader_handle = tokio::spawn(async move {
        loop {
            match read_frame(&mut read_half).await {
                Ok(Some(frame)) => {
                    if in_tx.send(Ok(frame)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = in_tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });

    // Dedicated writer task owns the write half and drains outbound frames.
    let (out_tx, mut out_rx) = mpsc::channel::<Frame>(256);
    let writer_handle = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if write_frame(&mut write_half, &frame).await.is_err() {
                break;
            }
        }
    });

    let mut ack_deadline: Option<Instant> = None;
    let mut interval_s = if initial_interval_s == 0 {
        FALLBACK_INTERVAL_S
    } else {
        initial_interval_s
    };
    let mut idle_deadline = Instant::now() + idle_timeout_for(interval_s);
    let mut ack_timed_out = false;
    let mut flush_writer_gracefully = false;

    // Send WELCOME and replay unACKed outgoing messages.
    let send_ok = async {
        out_tx
            .send(Frame::Welcome {
                last_rx_seq: reg.server_last_rx_seq,
                epoch: reg.epoch,
            })
            .await
            .is_ok()
    }
    .await;

    if send_ok {
        let _ = hub.connect_tx.send(client_id.to_string());
        let mut resend_failed = false;
        for (seq, body) in reg.pending {
            if out_tx.send(Frame::Msg { seq, body }).await.is_err() {
                resend_failed = true;
                break;
            }
            if ack_deadline.is_none() {
                ack_deadline = Some(Instant::now() + Duration::from_secs(ACK_TIMEOUT_S));
            }
        }

        if !resend_failed {
            loop {
                let ack_sleep = async {
                    match ack_deadline {
                        Some(d) => tokio::time::sleep_until(d).await,
                        None => std::future::pending::<()>().await,
                    }
                };
                let idle_sleep = tokio::time::sleep_until(idle_deadline);

                tokio::select! {
                    maybe_frame = in_rx.recv() => {
                        match maybe_frame {
                            Some(Ok(frame)) => {
                                idle_deadline = Instant::now() + idle_timeout_for(interval_s);
                                match frame {
                                    Frame::Ping { nonce } => {
                                        if out_tx.send(Frame::Pong { nonce }).await.is_err() {
                                            break;
                                        }
                                    }
                                    Frame::SetInterval { interval_s: new_iv } => {
                                        interval_s = if new_iv == 0 { FALLBACK_INTERVAL_S } else { new_iv };
                                        idle_deadline = Instant::now() + idle_timeout_for(interval_s);
                                        info!(
                                            "client '{}' updated interval_s={}",
                                            client_id, interval_s
                                        );
                                    }
                                    Frame::Ack { seq } => {
                                        match hub.on_ack(client_id, seq) {
                                            Ok(outbox_empty) => {
                                                if outbox_empty {
                                                    ack_deadline = None;
                                                } else {
                                                    ack_deadline = Some(Instant::now() + Duration::from_secs(ACK_TIMEOUT_S));
                                                }
                                            }
                                            Err(e) => {
                                                warn!("client '{}' ACK state error: {:#}", client_id, e);
                                                break;
                                            }
                                        }
                                    }
                                    Frame::Msg { seq, body } => {
                                        match hub.on_incoming_msg(client_id, seq) {
                                            Ok((ack_seq, should_process)) => {
                                                if out_tx.send(Frame::Ack { seq: ack_seq }).await.is_err() {
                                                    break;
                                                }
                                                if should_process {
                                                    let msg = IncomingClientMsg {
                                                        client_id: client_id.to_string(),
                                                        seq,
                                                        body,
                                                    };
                                                    if incoming_tx.send(msg).await.is_err() {
                                                        warn!("backend incoming channel closed");
                                                        break;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                warn!("client '{}' incoming MSG persist error: {:#}", client_id, e);
                                                break;
                                            }
                                        }
                                    }
                                    Frame::Bye { reason } => {
                                        info!(
                                            "client '{}' {} sent BYE ({})",
                                            client_id, peer, bye_reason_name(reason)
                                        );
                                        break;
                                    }
                                    other => {
                                        warn!(
                                            "client '{}' {} sent unexpected frame {:?}",
                                            client_id, peer, other
                                        );
                                        let _ = out_tx.send(Frame::Bye { reason: BYE_PROTOCOL_ERROR }).await;
                                        flush_writer_gracefully = true;
                                        break;
                                    }
                                }
                            }
                            Some(Err(e)) => {
                                debug!("client '{}' {} read error: {:#}", client_id, peer, e);
                                break;
                            }
                            None => {
                                debug!("client '{}' {} closed stream", client_id, peer);
                                break;
                            }
                        }
                    }

                    maybe_cmd = cmd_rx.recv() => {
                        match maybe_cmd {
                            Some(ConnCmd::SendMsg { seq, body }) => {
                                if out_tx.send(Frame::Msg { seq, body }).await.is_err() {
                                    break;
                                }
                                if ack_deadline.is_none() {
                                    ack_deadline = Some(Instant::now() + Duration::from_secs(ACK_TIMEOUT_S));
                                }
                            }
                            Some(ConnCmd::Replaced) => {
                                info!("client '{}' {} replaced by newer connection", client_id, peer);
                                let _ = out_tx.send(Frame::Bye { reason: BYE_REPLACED }).await;
                                flush_writer_gracefully = true;
                                break;
                            }
                            Some(ConnCmd::Shutdown) => {
                                let _ = out_tx.send(Frame::Bye { reason: BYE_SERVER_SHUTDOWN }).await;
                                flush_writer_gracefully = true;
                                break;
                            }
                            None => break,
                        }
                    }

                    _ = ack_sleep => {
                        warn!(
                            "client '{}' {} ACK timeout ({}s); marking connection dead",
                            client_id, peer, ACK_TIMEOUT_S
                        );
                        ack_timed_out = true;
                        break;
                    }

                    _ = idle_sleep => {
                        warn!(
                            "client '{}' {} idle timeout (interval_s={}); marking connection dead",
                            client_id, peer, interval_s
                        );
                        break;
                    }
                }
            }
        }
    }

    hub.detach_main(client_id, reg.generation);

    drop(out_tx);
    if flush_writer_gracefully {
        let _ = tokio::time::timeout(Duration::from_secs(2), writer_handle).await;
    } else {
        writer_handle.abort();
    }
    reader_handle.abort();

    if ack_timed_out {
        hub.trigger_wakeup(client_id);
    }

    info!(
        "client '{}' main disconnected (gen={}, peer={})",
        client_id, reg.generation, peer
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn prefixed_stream_replays_first_byte_and_passes_writes() {
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(b"ET /health HTTP/1.1\r\n").await.unwrap();
        client.shutdown().await.unwrap();

        let mut prefixed = PrefixedStream::new(b'G', server);
        let mut out = String::new();
        prefixed.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "GET /health HTTP/1.1\r\n");
    }

    /// MEDIA_ERR makes the phone give up on an attachment for good, so it is only for failures
    /// that would happen again; Apple not being reachable closes the connection instead.
    #[tokio::test]
    async fn media_get_answers_permanent_failures_and_closes_on_retryable_ones() {
        let dir = std::env::temp_dir().join(format!("imsg-push-media-{}", uuid::Uuid::new_v4()));
        let media = Arc::new(MediaStore::new(&dir, Some("/nonexistent/ffmpeg"), 1).unwrap());
        let att = rustpush::Attachment {
            a_type: rustpush::AttachmentType::MMCS(rustpush::MMCSFile {
                signature: vec![1; 21],
                object: "o".into(),
                url: "https://example.invalid/o".into(),
                key: vec![2; 32],
                size: 10,
            }),
            part: 0,
            uti_type: "public.jpeg".into(),
            mime: "image/jpeg".into(),
            name: "IMG_0001.jpg".into(),
            iris: false,
        };
        let r = media.register_incoming(&att, false, false).unwrap();
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let task = tokio::spawn({
            let media = Arc::clone(&media);
            async move { handle_media(server, "c", media).await }
        });
        assert!(matches!(read_frame(&mut client).await.unwrap(), Some(Frame::Welcome { .. })));

        write_frame(&mut client, &Frame::MediaGet { id: "nope".into(), full: false, offset: 0 }).await.unwrap();
        match read_frame(&mut client).await.unwrap() {
            Some(Frame::MediaErr { message }) => assert!(message.contains("unknown attachment"), "{}", message),
            other => panic!("expected MEDIA_ERR, got {:?}", other.map(|f| f.frame_type())),
        }

        write_frame(&mut client, &Frame::MediaGet { id: r.media_id.clone(), full: false, offset: 0 }).await.unwrap();
        assert!(read_frame(&mut client).await.unwrap().is_none(), "expected the connection to close");
        task.await.unwrap().unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }
}
