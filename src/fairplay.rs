//! FairPlay certificates for Albert device activation, loaded at runtime from `<apple_dir>/fairplay/`.
//!
//! Each `<name>.crt` holds a certificate chain (leaf first, then intermediates, ending at Apple
//! Root CA), PEM or concatenated DER. Its private key sits next to it as `<name>.key` or
//! `<name>.pem` (PEM or DER). Activation picks one pair at random. The certs are only needed to
//! activate a new device; an already activated install keeps working without them.

use anyhow::{bail, Context, Result};
use log::{info, warn};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

const KEY_EXTS: &[&str] = &["key", "pem"];

static LOADED: AtomicUsize = AtomicUsize::new(0);

/// The certs directory inside `apple_dir`.
pub fn dir(apple_dir: &Path) -> PathBuf {
    apple_dir.join("fairplay")
}

/// Number of FairPlay pairs handed to rustpush by [`install`].
pub fn loaded() -> usize {
    LOADED.load(Ordering::Relaxed)
}

/// Loads every pair in `dir` and hands them to rustpush. A missing or empty directory is fine
/// (returns 0); a malformed pair is an error.
pub fn install(dir: &Path) -> Result<usize> {
    let pairs = load_dir(dir)?;
    let n = pairs.len();
    if n == 0 {
        info!(
            "no FairPlay certs in {}; activating a new device will fail until you add some",
            dir.display()
        );
        return Ok(0);
    }
    if rustpush::set_fairplay_keys(pairs) {
        LOADED.store(n, Ordering::Relaxed);
        info!("loaded {} FairPlay cert pair(s) from {}", n, dir.display());
    }
    Ok(n)
}

/// Returns `(DER cert chain, DER private key)` pairs, sorted by file name.
pub fn load_dir(dir: &Path) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("failed to read {}", dir.display())),
    };
    let mut certs: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map_or(false, |x| x == "crt"))
        .collect();
    certs.sort();

    let mut pairs = Vec::with_capacity(certs.len());
    for crt in certs {
        let key = KEY_EXTS
            .iter()
            .map(|ext| crt.with_extension(ext))
            .find(|p| p.is_file())
            .with_context(|| {
                format!("{}: no matching .key or .pem private key", crt.display())
            })?;
        let pair = load_pair(&crt, &key)
            .with_context(|| format!("invalid FairPlay pair {}", crt.display()))?;
        pairs.push(pair);
    }
    Ok(pairs)
}

fn load_pair(crt: &Path, key_path: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let chain = parse_chain(&fs::read(crt)?)?;
    let key = parse_key(&fs::read(key_path)?)
        .with_context(|| format!("cannot read private key {}", key_path.display()))?;
    if !chain[0].public_key()?.public_eq(&key) {
        bail!("private key {} does not match the leaf certificate", key_path.display());
    }
    for pair in chain.windows(2) {
        if pair[1].issued(&pair[0]) != openssl::x509::X509VerifyResult::OK {
            bail!("certificates are out of order: each must be issued by the next one");
        }
    }
    let last = chain.last().unwrap();
    if last.issued(last) != openssl::x509::X509VerifyResult::OK {
        warn!(
            "{}: chain does not end at a self-signed root (Apple Root CA); Albert will likely reject it",
            crt.display()
        );
    }
    let mut der = Vec::new();
    for cert in &chain {
        der.extend_from_slice(&cert.to_der()?);
    }
    Ok((der, key.private_key_to_der()?))
}

fn parse_chain(data: &[u8]) -> Result<Vec<X509>> {
    let chain = if data.windows(10).any(|w| w == b"-----BEGIN") {
        X509::stack_from_pem(data)?
    } else {
        split_der(data)?
            .into_iter()
            .map(X509::from_der)
            .collect::<Result<Vec<X509>, _>>()?
    };
    if chain.is_empty() {
        bail!("no certificates found");
    }
    Ok(chain)
}

fn parse_key(data: &[u8]) -> Result<PKey<Private>> {
    if data.windows(10).any(|w| w == b"-----BEGIN") {
        Ok(PKey::private_key_from_pem(data)?)
    } else {
        Ok(PKey::private_key_from_der(data)?)
    }
}

/// Splits concatenated DER `SEQUENCE`s.
fn split_der(data: &[u8]) -> Result<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i] != 0x30 || i + 2 > data.len() {
            bail!("not a DER certificate at byte {}", i);
        }
        let first = data[i + 1] as usize;
        let (len, hdr) = if first & 0x80 == 0 {
            (first, 2)
        } else {
            let n = first & 0x7f;
            if n == 0 || n > 4 || i + 2 + n > data.len() {
                bail!("bad DER length at byte {}", i);
            }
            let len = data[i + 2..i + 2 + n]
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | *b as usize);
            (len, 2 + n)
        };
        let end = i + hdr + len;
        if end > data.len() {
            bail!("truncated DER certificate at byte {}", i);
        }
        out.push(&data[i..end]);
        i = end;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509NameBuilder};

    fn make_cert(cn: &str, key: &PKey<Private>, issuer: Option<(&X509, &PKey<Private>)>) -> X509 {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_pubkey(key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
        match issuer {
            Some((ica, ikey)) => {
                b.set_issuer_name(ica.subject_name()).unwrap();
                b.sign(ikey, MessageDigest::sha256()).unwrap();
            }
            None => {
                b.set_issuer_name(&name).unwrap();
                b.sign(key, MessageDigest::sha256()).unwrap();
            }
        }
        b.build()
    }

    fn rsa() -> PKey<Private> {
        PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap()
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "imsg_fairplay_{}_{}_{}",
            tag,
            std::process::id(),
            rand::random::<u32>()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    struct Chain {
        certs: Vec<X509>,
        leaf_key: PKey<Private>,
    }

    fn chain() -> Chain {
        let root_key = rsa();
        let root = make_cert("Root", &root_key, None);
        let mid_key = rsa();
        let mid = make_cert("Mid", &mid_key, Some((&root, &root_key)));
        let leaf_key = rsa();
        let leaf = make_cert("Leaf", &leaf_key, Some((&mid, &mid_key)));
        Chain {
            certs: vec![leaf, mid, root],
            leaf_key,
        }
    }

    fn der_chain(c: &Chain) -> Vec<u8> {
        c.certs.iter().flat_map(|x| x.to_der().unwrap()).collect()
    }

    #[test]
    fn missing_dir_is_empty() {
        let d = std::env::temp_dir().join("imsg_fairplay_does_not_exist");
        assert!(load_dir(&d).unwrap().is_empty());
    }

    #[test]
    fn loads_pem_and_der_pairs() {
        let d = temp_dir("ok");
        let a = chain();
        let b = chain();
        // a: PEM chain + PEM key; b: DER chain + DER key named .pem (rustpush's upstream layout).
        let pem: Vec<u8> = a.certs.iter().flat_map(|x| x.to_pem().unwrap()).collect();
        fs::write(d.join("a.crt"), pem).unwrap();
        fs::write(d.join("a.key"), a.leaf_key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        fs::write(d.join("b.crt"), der_chain(&b)).unwrap();
        fs::write(d.join("b.pem"), b.leaf_key.private_key_to_der().unwrap()).unwrap();
        fs::write(d.join("README.txt"), "ignored").unwrap();

        let pairs = load_dir(&d).unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, der_chain(&a));
        assert_eq!(pairs[0].1, a.leaf_key.private_key_to_der().unwrap());
        assert_eq!(pairs[1].0, der_chain(&b));
        assert_eq!(pairs[1].1, b.leaf_key.private_key_to_der().unwrap());
        // Keys must be loadable the way rustpush loads them.
        PKey::private_key_from_der(&pairs[0].1).unwrap();
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_bad_pairs() {
        let c = chain();

        let d = temp_dir("nokey");
        fs::write(d.join("x.crt"), der_chain(&c)).unwrap();
        assert!(format!("{:#}", load_dir(&d).unwrap_err()).contains("no matching"));
        let _ = fs::remove_dir_all(&d);

        let d = temp_dir("mismatch");
        fs::write(d.join("x.crt"), der_chain(&c)).unwrap();
        fs::write(d.join("x.key"), rsa().private_key_to_der().unwrap()).unwrap();
        assert!(format!("{:#}", load_dir(&d).unwrap_err()).contains("does not match"));
        let _ = fs::remove_dir_all(&d);

        let d = temp_dir("order");
        let swapped: Vec<u8> = [&c.certs[0], &c.certs[2], &c.certs[1]]
            .iter()
            .flat_map(|x| x.to_der().unwrap())
            .collect();
        fs::write(d.join("x.crt"), swapped).unwrap();
        fs::write(d.join("x.key"), c.leaf_key.private_key_to_der().unwrap()).unwrap();
        assert!(format!("{:#}", load_dir(&d).unwrap_err()).contains("out of order"));
        let _ = fs::remove_dir_all(&d);

        let d = temp_dir("truncated");
        let mut der = der_chain(&c);
        der.truncate(der.len() - 5);
        fs::write(d.join("x.crt"), der).unwrap();
        fs::write(d.join("x.key"), c.leaf_key.private_key_to_der().unwrap()).unwrap();
        assert!(format!("{:#}", load_dir(&d).unwrap_err()).contains("truncated"));
        let _ = fs::remove_dir_all(&d);
    }
}
