//! One-time pairing codes.
//!
//! `imsg-server pair` writes `state_dir/pairing.json` with the code's SHA-256. When a phone
//! connects with ROLE_PAIR, the running server checks the code, deletes the file, and issues the
//! phone its own token. A code expires after 15 minutes and is burned after 5 wrong attempts.

use anyhow::{Context, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

pub const CODE_DIGITS: usize = 12;
pub const TTL_S: u64 = 15 * 60;
pub const MAX_FAILURES: u32 = 5;

#[derive(Serialize, Deserialize)]
struct Pending {
    code_sha256: String,
    expires_at: u64,
    failures: u32,
}

fn path(state_dir: &Path) -> PathBuf {
    state_dir.join("pairing.json")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn digits_only(input: &[u8]) -> String {
    input.iter().filter(|b| b.is_ascii_digit()).map(|&b| b as char).collect()
}

fn hash(code: &str) -> String {
    hex::encode(Sha256::digest(code.as_bytes()))
}

/// Groups a code for display: `1234 5678 9012`.
pub fn format_code(code: &str) -> String {
    code.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Creates a new code (replacing any pending one) and returns it.
pub fn create(state_dir: &Path) -> Result<String> {
    fs::create_dir_all(state_dir)
        .with_context(|| format!("failed to create {}", state_dir.display()))?;
    let mut rng = rand::thread_rng();
    let code: String = (0..CODE_DIGITS)
        .map(|_| char::from(b'0' + rng.gen_range(0..10u8)))
        .collect();
    let pending = Pending {
        code_sha256: hash(&code),
        expires_at: now() + TTL_S,
        failures: 0,
    };
    save(state_dir, &pending)?;
    Ok(code)
}

fn save(state_dir: &Path, pending: &Pending) -> Result<()> {
    let p = path(state_dir);
    let tmp = p.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec(pending)?)?;
    crate::config::restrict_permissions(&tmp);
    fs::rename(&tmp, &p)?;
    Ok(())
}

/// Checks a presented code. A correct code is consumed; a wrong one counts as a failure.
/// Callers must serialize calls (the server holds a lock).
pub fn consume(state_dir: &Path, presented: &[u8]) -> Result<bool> {
    let p = path(state_dir);
    let Ok(raw) = fs::read(&p) else {
        return Ok(false);
    };
    let Ok(mut pending) = serde_json::from_slice::<Pending>(&raw) else {
        let _ = fs::remove_file(&p);
        return Ok(false);
    };
    if now() >= pending.expires_at {
        let _ = fs::remove_file(&p);
        return Ok(false);
    }
    let presented = hash(&digits_only(presented));
    if bool::from(presented.as_bytes().ct_eq(pending.code_sha256.as_bytes())) {
        fs::remove_file(&p).with_context(|| format!("failed to remove {}", p.display()))?;
        return Ok(true);
    }
    pending.failures += 1;
    if pending.failures >= MAX_FAILURES {
        let _ = fs::remove_file(&p);
    } else {
        save(state_dir, &pending)?;
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("imsg-pair-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn correct_code_is_single_use() {
        let d = temp_dir("single");
        let code = create(&d).unwrap();
        assert_eq!(code.len(), CODE_DIGITS);
        // Separators typed on the phone are ignored.
        assert!(consume(&d, format_code(&code).as_bytes()).unwrap());
        assert!(!consume(&d, code.as_bytes()).unwrap());
    }

    #[test]
    fn wrong_codes_burn_the_code() {
        let d = temp_dir("burn");
        let code = create(&d).unwrap();
        for _ in 0..MAX_FAILURES {
            assert!(!consume(&d, b"000000000000x").unwrap());
        }
        assert!(!consume(&d, code.as_bytes()).unwrap());
    }

    #[test]
    fn expired_code_is_rejected() {
        let d = temp_dir("expired");
        let code = create(&d).unwrap();
        let mut pending: Pending = serde_json::from_slice(&fs::read(path(&d)).unwrap()).unwrap();
        pending.expires_at = 1;
        save(&d, &pending).unwrap();
        assert!(!consume(&d, code.as_bytes()).unwrap());
    }

    #[test]
    fn format_groups_by_four() {
        assert_eq!(format_code("123456789012"), "1234 5678 9012");
    }
}
