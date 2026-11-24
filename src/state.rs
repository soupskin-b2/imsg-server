use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientState {
    /// Last assigned outgoing sequence number (0 before first message; first message is 1).
    pub tx_seq: u64,
    /// Last delivered/accepted incoming sequence number from the client.
    pub last_rx_seq: u64,
    /// Unacknowledged outgoing message bodies (base64-encoded), keyed by seq.
    #[serde(default)]
    pub outbox: BTreeMap<u64, String>,
    /// Random id of this state's seq numbering, sent in WELCOME; 0 until first needed. A wiped
    /// state gets a new one, which tells the client our seqs start at 1 again.
    #[serde(default)]
    pub epoch: u64,
    /// The client's epoch as of its last HELLO (0: never sent one).
    #[serde(default)]
    pub client_epoch: u64,
    /// When the client last opened a main connection (ms since the epoch; 0: unknown).
    #[serde(default)]
    pub last_seen_ms: u64,
}

/// Most messages kept for a client that isn't taking them; beyond this the oldest are dropped.
/// A phone that's away (or a client left behind by pairing again) must not grow the state file
/// without bound: it's rewritten and synced on every message.
pub const MAX_OUTBOX: usize = 5000;
/// Most bytes (base64) kept in one outbox, for the same reason.
pub const MAX_OUTBOX_BYTES: usize = 64 * 1024 * 1024;

impl ClientState {
    pub fn file_path(state_dir: &Path, client_id: &str) -> PathBuf {
        state_dir.join(format!("{}.json", client_id))
    }

    pub fn load_or_default(state_dir: &Path, client_id: &str) -> Result<Self> {
        let path = Self::file_path(state_dir, client_id);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read client state {}", path.display()))?;
        let state: ClientState = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse client state {}", path.display()))?;
        Ok(state)
    }

    /// Atomically persists the state via a temp file + rename.
    pub fn save(&self, state_dir: &Path, client_id: &str) -> Result<()> {
        fs::create_dir_all(state_dir)
            .with_context(|| format!("failed to create state dir {}", state_dir.display()))?;
        let final_path = Self::file_path(state_dir, client_id);
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = state_dir.join(format!(
            ".{}.json.tmp.{}.{}",
            client_id,
            std::process::id(),
            n
        ));

        let json = serde_json::to_vec_pretty(self)?;
        {
            let mut f = File::create(&tmp_path)
                .with_context(|| format!("failed to create temp state {}", tmp_path.display()))?;
            f.write_all(&json)?;
            f.sync_all()?;
        }

        fs::rename(&tmp_path, &final_path).with_context(|| {
            format!(
                "failed to rename {} -> {}",
                tmp_path.display(),
                final_path.display()
            )
        })?;
        Ok(())
    }

    /// Queues `body` as the next seq. Returns it and how many old messages were dropped to stay
    /// within MAX_OUTBOX / MAX_OUTBOX_BYTES.
    pub fn enqueue_bounded(&mut self, body: &[u8]) -> (u64, usize) {
        self.tx_seq += 1;
        let seq = self.tx_seq;
        self.outbox.insert(seq, BASE64.encode(body));
        let mut dropped = 0;
        while self.outbox.len() > MAX_OUTBOX {
            self.outbox.pop_first();
            dropped += 1;
        }
        if self.outbox.len() > 1 {
            let mut bytes: usize = self.outbox.values().map(String::len).sum();
            while bytes > MAX_OUTBOX_BYTES && self.outbox.len() > 1 {
                if let Some((_, v)) = self.outbox.pop_first() {
                    bytes -= v.len();
                    dropped += 1;
                }
            }
        }
        (seq, dropped)
    }

    pub fn enqueue(&mut self, body: &[u8]) -> u64 {
        self.enqueue_bounded(body).0
    }

    pub fn ack_up_to(&mut self, seq: u64) -> usize {
        let before = self.outbox.len();
        self.outbox.retain(|&k, _| k > seq);
        before - self.outbox.len()
    }

    pub fn pending_after(&self, last_rx_seq: u64) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut out = Vec::new();
        for (&seq, b64) in self.outbox.range((last_rx_seq.saturating_add(1))..) {
            let bytes = BASE64
                .decode(b64)
                .with_context(|| format!("invalid base64 in outbox for seq {}", seq))?;
            out.push((seq, bytes));
        }
        Ok(out)
    }

    pub fn is_outbox_empty(&self) -> bool {
        self.outbox.is_empty()
    }

    /// Our epoch, made (random, nonzero) the first time; true in `.1` if it was just made.
    pub fn ensure_epoch(&mut self) -> (u64, bool) {
        if self.epoch != 0 {
            return (self.epoch, false);
        }
        while self.epoch == 0 {
            self.epoch = rand::random();
        }
        (self.epoch, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbox_is_bounded() {
        let mut st = ClientState::default();
        let mut dropped = 0;
        for _ in 0..MAX_OUTBOX + 10 {
            dropped += st.enqueue_bounded(b"x").1;
        }
        assert_eq!(dropped, 10);
        assert_eq!(st.outbox.len(), MAX_OUTBOX);
        assert_eq!(*st.outbox.keys().next().unwrap(), 11);
        assert_eq!(st.tx_seq, (MAX_OUTBOX + 10) as u64);

        let mut big = ClientState::default();
        let chunk = vec![0u8; 3 * 1024 * 1024]; // 4 MiB as base64
        for _ in 0..20 {
            big.enqueue_bounded(&chunk);
        }
        let bytes: usize = big.outbox.values().map(String::len).sum();
        assert!(bytes <= MAX_OUTBOX_BYTES && big.outbox.len() == 16, "{} msgs", big.outbox.len());
    }

    #[test]
    fn atomic_save_and_outbox_ops() {
        let dir = std::env::temp_dir().join(format!(
            "imsg_state_test_{}_{}",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);

        let mut st = ClientState::load_or_default(&dir, "phone1").unwrap();
        assert_eq!(st.tx_seq, 0);
        assert_eq!(st.last_rx_seq, 0);

        let s1 = st.enqueue(b"hello");
        let s2 = st.enqueue(b"world");
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        st.last_rx_seq = 5;
        st.save(&dir, "phone1").unwrap();

        // Overwrite existing file atomically
        st.ack_up_to(1);
        st.save(&dir, "phone1").unwrap();

        let loaded = ClientState::load_or_default(&dir, "phone1").unwrap();
        assert_eq!(loaded.tx_seq, 2);
        assert_eq!(loaded.last_rx_seq, 5);
        let pending = loaded.pending_after(0).unwrap();
        assert_eq!(pending, vec![(2, b"world".to_vec())]);
        assert!(loaded.pending_after(2).unwrap().is_empty());

        let _ = fs::remove_dir_all(&dir);
    }
}
