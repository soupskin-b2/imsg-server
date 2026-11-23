use anyhow::{bail, Context, Result};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Host name phones connect to; must match the TLS certificate.
    pub server_name: String,
    pub listen_addrs: Vec<String>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub state_dir: PathBuf,
    pub apple_dir: PathBuf,
    #[serde(default = "default_true")]
    pub tls12_fallback: bool,
    #[serde(default)]
    pub preferred_handle: Option<String>,
    #[serde(default)]
    pub wakeup: Option<WakeupConfig>,
    /// Legacy `[relay]` section (ignored; imsg-server always uses its built-in relay).
    #[serde(default)]
    pub relay: Option<LegacyRelayConfig>,
    #[serde(default)]
    pub renewal: RenewalConfig,
    #[serde(default)]
    pub clients: Vec<ClientConfig>,
    /// Where this config was loaded from (paired phones are appended here).
    #[serde(skip)]
    pub path: PathBuf,
}

fn default_true() -> bool {
    true
}

/// Kept only so older config.toml files still parse cleanly when upgrading to the built-in relay.
#[derive(Debug, Clone, Deserialize)]
pub struct LegacyRelayConfig {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
}

/// Automatic phone-number renewal settings.
#[derive(Debug, Clone, Deserialize)]
pub struct RenewalConfig {
    /// Start proactive phone-number renewal this many days before the auth certificate expires.
    #[serde(default = "default_renewal_lead_days")]
    pub lead_days: u64,
}

impl Default for RenewalConfig {
    fn default() -> Self {
        Self {
            lead_days: default_renewal_lead_days(),
        }
    }
}

fn default_renewal_lead_days() -> u64 {
    7
}

#[derive(Debug, Clone, Deserialize)]
pub struct WakeupConfig {
    /// Command and arguments to run; `{client_id}` is replaced with the client ID.
    pub command: Vec<String>,
    /// Minimum seconds between wakeup invocations per client.
    #[serde(default = "default_wakeup_min_interval_s")]
    pub min_interval_s: u64,
}

fn default_wakeup_min_interval_s() -> u64 {
    300
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub id: String,
    /// Lowercase hex SHA-256 of the wire token (ASCII bytes of the hex token string).
    pub token_sha256: String,
}

impl ClientConfig {
    pub fn token_hash_bytes(&self) -> Result<[u8; 32]> {
        let bytes = hex::decode(self.token_sha256.trim())
            .with_context(|| format!("invalid hex in token_sha256 for client '{}'", self.id))?;
        if bytes.len() != 32 {
            bail!(
                "token_sha256 for client '{}' must be 32 bytes (64 hex chars), got {}",
                self.id,
                bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path).with_context(|| {
            format!(
                "failed to read {} (create it with `imsg-server init`)",
                path.display()
            )
        })?;
        let mut cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("failed to parse TOML config {}", path.display()))?;
        if cfg.listen_addrs.is_empty() {
            bail!("listen_addrs must contain at least one address");
        }
        for c in &cfg.clients {
            c.token_hash_bytes()?;
        }
        cfg.path = path.to_path_buf();
        Ok(cfg)
    }

    /// What to type on the phone: `host` for port 443, otherwise `host:port`.
    pub fn phone_address(&self) -> String {
        let port = self
            .listen_addrs
            .first()
            .and_then(|a| a.rsplit_once(':'))
            .map(|(_, p)| p.to_string())
            .unwrap_or_else(|| "443".to_string());
        if port == "443" {
            self.server_name.clone()
        } else {
            format!("{}:{}", self.server_name, port)
        }
    }
}

pub struct InitArgs {
    pub domain: String,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub listen: String,
    pub renewal_lead_days: u64,
}

/// Writes a fresh config.toml. Refuses to overwrite an existing one.
pub fn init(config_path: &Path, args: &InitArgs) -> Result<()> {
    if config_path.exists() {
        bail!("{} already exists; edit it instead", config_path.display());
    }
    let domain = args.domain.trim();
    if domain.is_empty() || domain.contains(['/', ':', ' ']) {
        bail!("--domain must be a bare host name like imsg.example.com");
    }
    let live = Path::new("/etc/letsencrypt/live").join(domain);
    let cert = args.cert.clone().unwrap_or_else(|| live.join("fullchain.pem"));
    let key = args.key.clone().unwrap_or_else(|| live.join("privkey.pem"));
    let base = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(base)?;
    let text = format!(
        r#"# imsg-server configuration

# Host name phones and the jailbroken iPhone relay provider connect to.
# Must match the TLS certificate below.
server_name = "{domain}"
listen_addrs = ["{listen}"]

# TLS certificate chain and private key (PEM), from a public CA such as Let's Encrypt.
cert_path = "{cert}"
key_path = "{key}"

# Message state and Apple credentials. Keep both private.
state_dir = "{state}"
apple_dir = "{apple}"

# Automatic phone-number renewal (sends an SMS to Apple's registration gateway).
[renewal]
lead_days = {lead_days}

# Paired phones are added below by `imsg-server pair`.
"#,
        domain = domain,
        listen = args.listen,
        cert = toml_path(&cert),
        key = toml_path(&key),
        state = toml_path(&base.join("state")),
        apple = toml_path(&base.join("apple")),
        lead_days = args.renewal_lead_days,
    );
    fs::write(config_path, text)
        .with_context(|| format!("failed to write {}", config_path.display()))?;
    restrict_permissions(config_path);
    Config::load(config_path)?;
    Ok(())
}

fn toml_path(p: &Path) -> String {
    // Forward slashes keep TOML strings clean on Windows and Unix.
    p.to_string_lossy().replace('\\', "/")
}

/// Best effort: make a secrets file readable by its owner only.
pub fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

pub struct AddedClient {
    pub id: String,
    pub token_hex: String,
    pub token_sha256: String,
}

/// Generates a random token for a new client and appends a `[[clients]]` block to config.toml.
pub fn append_client(config_path: &Path, client_id: &str) -> Result<AddedClient> {
    let mut raw_token = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw_token);
    let token_hex = hex::encode(raw_token);
    // On the wire, the client sends the ASCII bytes of the hex token string.
    let token_sha256 = hex::encode(Sha256::digest(token_hex.as_bytes()));

    let existing_text = fs::read_to_string(config_path)?;
    let prefix = if existing_text.ends_with('\n') { "\n" } else { "\n\n" };
    let block = format!(
        "{prefix}[[clients]]\nid = \"{client_id}\"\ntoken_sha256 = \"{token_sha256}\"\n"
    );
    let mut file = OpenOptions::new()
        .append(true)
        .open(config_path)
        .with_context(|| format!("failed to open {} for appending", config_path.display()))?;
    file.write_all(block.as_bytes())?;
    file.sync_all()?;
    Config::load(config_path)?;

    Ok(AddedClient {
        id: client_id.to_string(),
        token_hex,
        token_sha256,
    })
}
