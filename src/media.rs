//! Attachment storage and conversion.
//!
//! Incoming attachments are downloaded from Apple once, kept under `<state_dir>/media/<id>/`, and
//! turned into two variants the phone fetches over a ROLE_MEDIA connection:
//! * `preview`: small enough to store in the phone's MMS database and play on Android 8.1
//!   (JPEG/PNG at most 640 px, 240p H.264 MP4, AAC audio);
//! * `full`: the original size, in a format the phone can open (HEIC becomes JPEG, HEVC becomes
//!   H.264), fetched only when the user saves the attachment.
//!
//! Outgoing attachments arrive as uploads under `<state_dir>/media/up/` and are converted to what
//! iPhones expect (AMR becomes AAC, 3GP/H.263 becomes H.264 MP4) before going to Apple.

use crate::body::{
    InAttachment, ATTACH_AUDIO, ATTACH_FILE, ATTACH_IMAGE, ATTACH_STICKER, ATTACH_VCARD,
    ATTACH_VIDEO, ATTACH_VOICE,
};
use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info, warn};
use rustpush::{APSConnection, Attachment, AttachmentType, MMCSFile, PushError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use tokio::sync::Semaphore;
use uuid::Uuid;

/// Longest edge of a photo preview.
const PREVIEW_IMAGE_PX: u32 = 640;
/// Longest edge of a sticker / Genmoji preview (kept as PNG with transparency).
const PREVIEW_STICKER_PX: u32 = 320;
/// Short edge of a video preview.
const PREVIEW_VIDEO_PX: u32 = 240;
/// Animated GIFs up to this size are passed through unchanged as their own preview.
const GIF_PASSTHROUGH_BYTES: u64 = 1_500_000;
/// Longest edge of a full-size video (when it has to be re-encoded for the phone).
const FULL_VIDEO_MAX_PX: u32 = 1080;
const MAX_UPLOAD_BYTES: u64 = 100 * 1024 * 1024;
const CONVERT_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Tries of one download from Apple when it fails in a way worth trying again (a missed APS
/// answer, a network error); the phone retries later on top of that.
const DOWNLOAD_ATTEMPTS: u32 = 3;
const UPLOAD_RETENTION: Duration = Duration::from_secs(24 * 3600);
const PRUNE_INTERVAL: Duration = Duration::from_secs(6 * 3600);

/// A failure that may well not happen again (Apple not reachable yet, an APS answer that didn't
/// come, a network error), as opposed to one that will (an unknown attachment, a file ffmpeg can't
/// convert). The phone gives up on an attachment for good when it gets MEDIA_ERR, so these are
/// answered by closing the media connection instead, which makes it try again later.
#[derive(Debug)]
pub struct TryLater(pub String);

impl std::fmt::Display for TryLater {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TryLater {}

/// Whether `e` (from [`MediaStore::variant`]) is worth retrying later.
pub fn is_try_later(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.is::<TryLater>())
}

/// Whether a rustpush download error is likely to go away on its own.
fn transient(e: &PushError) -> bool {
    match e {
        PushError::SendTimedOut
        | PushError::NotConnected
        | PushError::RequestError(_)
        | PushError::IoError(_)
        | PushError::TLSError(_)
        | PushError::ConnectionClosed(_)
        | PushError::APSSendError(_)
        | PushError::ResourceTimeout => true,
        PushError::StatusError(s) => s.is_server_error() || s.as_u16() == 429,
        _ => false,
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Meta {
    name: String,
    mime: String,
    uti: String,
    kind: u8,
    created_ms: u64,
    size: u64,
    /// How to fetch the original from Apple again (kept until the original is on disk).
    #[serde(default)]
    attachment: Option<StoredAttachment>,
}

/// A copy of rustpush's `Attachment` that survives JSON. rustpush's own serde writes its byte
/// fields with `serialize_bytes` (a JSON number array) but reads them back only as plist data,
/// so an `Attachment` written to meta.json could never be loaded again: every incoming photo,
/// video and voice message failed with "invalid type: sequence, expected a byte array". The
/// JSON shape is the same as before, so meta.json files written by older versions load too.
#[derive(Clone, Serialize, Deserialize)]
struct StoredAttachment {
    a_type: StoredAttachmentType,
    part: u64,
    uti_type: String,
    mime: String,
    name: String,
    iris: bool,
}

#[derive(Clone, Serialize, Deserialize)]
enum StoredAttachmentType {
    Inline(Vec<u8>),
    MMCS(StoredMmcsFile),
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredMmcsFile {
    signature: Vec<u8>,
    object: String,
    url: String,
    key: Vec<u8>,
    size: usize,
}

impl From<&Attachment> for StoredAttachment {
    fn from(a: &Attachment) -> Self {
        Self {
            a_type: match &a.a_type {
                AttachmentType::Inline(data) => StoredAttachmentType::Inline(data.clone()),
                AttachmentType::MMCS(m) => StoredAttachmentType::MMCS(StoredMmcsFile {
                    signature: m.signature.clone(),
                    object: m.object.clone(),
                    url: m.url.clone(),
                    key: m.key.clone(),
                    size: m.size,
                }),
            },
            part: a.part,
            uti_type: a.uti_type.clone(),
            mime: a.mime.clone(),
            name: a.name.clone(),
            iris: a.iris,
        }
    }
}

impl StoredAttachment {
    fn to_attachment(&self) -> Attachment {
        Attachment {
            a_type: match &self.a_type {
                StoredAttachmentType::Inline(data) => AttachmentType::Inline(data.clone()),
                StoredAttachmentType::MMCS(m) => AttachmentType::MMCS(MMCSFile {
                    signature: m.signature.clone(),
                    object: m.object.clone(),
                    url: m.url.clone(),
                    key: m.key.clone(),
                    size: m.size,
                }),
            },
            part: self.part,
            uti_type: self.uti_type.clone(),
            mime: self.mime.clone(),
            name: self.name.clone(),
            iris: self.iris,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VariantInfo {
    mime: String,
    name: String,
}

/// A file ready to send to the phone.
#[derive(Debug, Clone)]
pub struct Variant {
    pub path: PathBuf,
    pub mime: String,
    pub name: String,
    pub len: u64,
}

/// An upload converted for Apple.
#[derive(Debug, Clone)]
pub struct Outgoing {
    pub path: PathBuf,
    pub name: String,
    pub mime: String,
    pub uti: String,
}

pub struct MediaStore {
    dir: PathBuf,
    ffmpeg: String,
    ffprobe: String,
    heif_dec: Option<String>,
    retention: Duration,
    aps: RwLock<Option<APSConnection>>,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    convert: Semaphore,
    pruner_started: std::sync::Once,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Media and upload ids are generated UUIDs; refuse anything that could leave the media folder.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn ext_of(name: &str) -> String {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default()
}

fn stem_of(name: &str) -> String {
    let stem = Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("attachment");
    let clean: String = stem
        .chars()
        .map(|c| if c == '/' || c == '\\' || c.is_control() { '_' } else { c })
        .collect();
    if clean.trim().is_empty() {
        "attachment".to_string()
    } else {
        clean
    }
}

fn is_heif(mime: &str, uti: &str, name: &str) -> bool {
    let m = mime.to_ascii_lowercase();
    m.contains("heic")
        || m.contains("heif")
        || uti.contains("heic")
        || uti.contains("heif")
        || matches!(ext_of(name).as_str(), "heic" | "heif" | "heics")
}

/// What kind of attachment this is, from Apple's MIME type, UTI and file name.
pub fn classify(mime: &str, uti: &str, name: &str, voice: bool, sticker: bool) -> u8 {
    let m = mime.to_ascii_lowercase();
    let ext = ext_of(name);
    if m.starts_with("image/")
        || is_heif(mime, uti, name)
        || matches!(ext.as_str(), "jpg" | "jpeg" | "png" | "gif" | "webp" | "tif" | "tiff" | "bmp")
    {
        return if sticker { ATTACH_STICKER } else { ATTACH_IMAGE };
    }
    if m.starts_with("video/")
        || uti == "com.apple.quicktime-movie"
        || matches!(ext.as_str(), "mov" | "mp4" | "m4v" | "3gp")
    {
        return ATTACH_VIDEO;
    }
    if m.starts_with("audio/")
        || uti == "com.apple.coreaudio-format"
        || matches!(ext.as_str(), "caf" | "m4a" | "mp3" | "aac" | "amr" | "wav" | "aiff")
    {
        return if voice || ext == "caf" { ATTACH_VOICE } else { ATTACH_AUDIO };
    }
    if m.contains("vcard") || uti == "public.vcard" || ext == "vcf" {
        return ATTACH_VCARD;
    }
    ATTACH_FILE
}

/// UTI Apple expects for a MIME type we send.
pub fn uti_for_mime(mime: &str) -> &'static str {
    match mime {
        "image/jpeg" => "public.jpeg",
        "image/png" => "public.png",
        "image/gif" => "com.compuserve.gif",
        "video/mp4" => "public.mpeg-4",
        "audio/mp4" => "public.mpeg-4-audio",
        "text/vcard" | "text/x-vcard" => "public.vcard",
        "text/plain" => "public.plain-text",
        _ => "public.data",
    }
}

fn which(cmd: &str) -> Option<String> {
    if cmd.contains('/') {
        return Path::new(cmd).is_file().then(|| cmd.to_string());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(cmd))
        .find(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
}

impl MediaStore {
    pub fn new(state_dir: &Path, ffmpeg: Option<&str>, retention_days: u64) -> Result<Self> {
        let dir = state_dir.join("media");
        fs::create_dir_all(dir.join("up"))
            .with_context(|| format!("failed to create {}", dir.display()))?;
        let ffmpeg = ffmpeg.unwrap_or("ffmpeg").to_string();
        let ffprobe = match ffmpeg.rsplit_once("ffmpeg") {
            Some((head, tail)) => format!("{}ffprobe{}", head, tail),
            None => "ffprobe".to_string(),
        };
        if which(&ffmpeg).is_none() || which(&ffprobe).is_none() {
            warn!(
                "{} / {} not found: photos, videos and audio will arrive as placeholders \
                 (install the ffmpeg package)",
                ffmpeg, ffprobe
            );
        }
        let heif_dec = which("heif-dec").or_else(|| which("heif-convert"));
        if heif_dec.is_none() {
            warn!(
                "heif-dec not found: iPhone photos (HEIC) are decoded with ffmpeg, which before 8.1 \
                 shows only one 512 px tile of each (install libheif-examples)"
            );
        }
        Ok(Self {
            dir,
            ffmpeg,
            ffprobe,
            heif_dec,
            retention: Duration::from_secs(retention_days.max(1) * 86_400),
            aps: RwLock::new(None),
            locks: Mutex::new(HashMap::new()),
            convert: Semaphore::new(2),
            pruner_started: std::sync::Once::new(),
        })
    }

    /// Gives the store the live APS connection it needs to download originals from Apple.
    pub fn set_aps(self: &Arc<Self>, conn: APSConnection) {
        *self.aps.write().unwrap() = Some(conn);
        let me = Arc::clone(self);
        self.pruner_started.call_once(move || {
            tokio::spawn(async move {
                loop {
                    me.prune();
                    tokio::time::sleep(PRUNE_INTERVAL).await;
                }
            });
        });
    }

    fn entry_dir(&self, id: &str) -> PathBuf {
        self.dir.join(id)
    }

    fn lock_for(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.locks.lock().unwrap();
        locks.retain(|_, l| Arc::strong_count(l) > 1);
        Arc::clone(locks.entry(key.to_string()).or_default())
    }

    fn read_meta(&self, id: &str) -> Result<Meta> {
        let path = self.entry_dir(id).join("meta.json");
        let raw = fs::read(&path).map_err(|_| anyhow!("unknown attachment"))?;
        Ok(serde_json::from_slice(&raw)?)
    }

    fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec(value)?)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Records an incoming attachment and starts preparing its preview in the background.
    pub fn register_incoming(
        self: &Arc<Self>,
        att: &Attachment,
        voice: bool,
        sticker: bool,
    ) -> Result<InAttachment> {
        let id = Uuid::new_v4().to_string();
        let dir = self.entry_dir(&id);
        fs::create_dir_all(&dir)?;
        let kind = classify(&att.mime, &att.uti_type, &att.name, voice, sticker);
        let name = if att.name.trim().is_empty() {
            "attachment".to_string()
        } else {
            att.name.clone()
        };
        // Inline attachments (voice messages and other small files) arrive with the message:
        // keep the bytes as the original right away instead of in meta.json.
        let attachment = match &att.a_type {
            AttachmentType::Inline(data) => {
                let tmp = dir.join("original.part");
                fs::write(&tmp, data)?;
                fs::rename(&tmp, dir.join("original"))?;
                None
            }
            AttachmentType::MMCS(_) => Some(StoredAttachment::from(att)),
        };
        let meta = Meta {
            name: name.clone(),
            mime: att.mime.clone(),
            uti: att.uti_type.clone(),
            kind,
            created_ms: now_ms(),
            size: att.get_size() as u64,
            attachment,
        };
        Self::write_json(&dir.join("meta.json"), &meta)?;
        if kind != ATTACH_FILE {
            let me = Arc::clone(self);
            let id2 = id.clone();
            tokio::spawn(async move {
                if let Err(e) = me.variant(&id2, false).await {
                    warn!("preparing preview for attachment {} failed: {:#}", id2, e);
                }
            });
        }
        Ok(InAttachment {
            media_id: id,
            kind,
            name,
            size: meta.size,
        })
    }

    /// Records a local file (echo test mode) as if it had arrived from Apple.
    pub fn register_local(
        self: &Arc<Self>,
        src: &Path,
        name: &str,
        mime: &str,
    ) -> Result<InAttachment> {
        let id = Uuid::new_v4().to_string();
        let dir = self.entry_dir(&id);
        fs::create_dir_all(&dir)?;
        fs::copy(src, dir.join("original"))?;
        let kind = classify(mime, "", name, false, false);
        let meta = Meta {
            name: name.to_string(),
            mime: mime.to_string(),
            uti: String::new(),
            kind,
            created_ms: now_ms(),
            size: fs::metadata(src)?.len(),
            attachment: None,
        };
        Self::write_json(&dir.join("meta.json"), &meta)?;
        Ok(InAttachment {
            media_id: id,
            kind,
            name: name.to_string(),
            size: meta.size,
        })
    }

    /// The preview (`full == false`) or full-size file for `id`, downloading and converting it on
    /// first use. Concurrent callers for the same file wait for one conversion.
    pub async fn variant(&self, id: &str, full: bool) -> Result<Variant> {
        if !valid_id(id) {
            bail!("bad attachment id");
        }
        let which = if full { "full" } else { "preview" };
        let lock = self.lock_for(&format!("{}/{}", id, which));
        let _guard = lock.lock().await;

        let dir = self.entry_dir(id);
        let info_path = dir.join(format!("{}.json", which));
        let data_path = dir.join(which);
        if let (Ok(raw), Ok(md)) = (fs::read(&info_path), fs::metadata(&data_path)) {
            if let Ok(info) = serde_json::from_slice::<VariantInfo>(&raw) {
                return Ok(Variant {
                    path: data_path,
                    mime: info.mime,
                    name: info.name,
                    len: md.len(),
                });
            }
        }

        let meta = self.read_meta(id)?;
        let original = self.ensure_original(id, &meta).await?;
        let info = if full {
            self.make_full(&meta, &original, &data_path).await?
        } else {
            self.make_preview(&meta, &original, &data_path).await?
        };
        Self::write_json(&info_path, &info)?;
        let len = fs::metadata(&data_path)?.len();
        info!(
            "attachment {} {} ready: {} {} ({} bytes)",
            id, which, info.mime, info.name, len
        );
        Ok(Variant {
            path: data_path,
            mime: info.mime,
            name: info.name,
            len,
        })
    }

    async fn ensure_original(&self, id: &str, meta: &Meta) -> Result<PathBuf> {
        let lock = self.lock_for(&format!("{}/original", id));
        let _guard = lock.lock().await;
        let path = self.entry_dir(id).join("original");
        if path.exists() {
            return Ok(path);
        }
        let att = meta
            .attachment
            .as_ref()
            .ok_or_else(|| anyhow!("attachment is no longer available"))?
            .to_attachment();
        let tmp = path.with_extension("part");
        match &att.a_type {
            AttachmentType::Inline(data) => fs::write(&tmp, data)?,
            AttachmentType::MMCS(_) => {
                let mut attempt = 1;
                loop {
                    let conn = self
                        .aps
                        .read()
                        .unwrap()
                        .clone()
                        .ok_or_else(|| anyhow::Error::new(TryLater("not connected to Apple yet".into())))?;
                    let started = std::time::Instant::now();
                    match Self::download_once(&att, &conn, &tmp).await {
                        Ok(()) => {
                            info!(
                                "downloaded attachment {} from Apple ({} bytes) in {:?}",
                                id,
                                fs::metadata(&tmp).map(|m| m.len()).unwrap_or(0),
                                started.elapsed()
                            );
                            break;
                        }
                        Err(e) => {
                            let _ = fs::remove_file(&tmp);
                            let again = is_try_later(&e);
                            if !again || attempt >= DOWNLOAD_ATTEMPTS {
                                return Err(e);
                            }
                            warn!(
                                "download of attachment {} from Apple failed (try {} of {}), trying again: {:#}",
                                id, attempt, DOWNLOAD_ATTEMPTS, e
                            );
                            tokio::time::sleep(Duration::from_secs(2 * attempt as u64)).await;
                            attempt += 1;
                        }
                    }
                }
            }
        }
        fs::rename(&tmp, &path)?;
        Ok(path)
    }

    /// One download of an MMCS attachment into `tmp`.
    async fn download_once(att: &Attachment, conn: &APSConnection, tmp: &Path) -> Result<()> {
        let file = fs::File::create(tmp)?;
        let mut writer = BufWriter::new(file);
        match tokio::time::timeout(DOWNLOAD_TIMEOUT, att.get_attachment(conn, &mut writer, |_, _| {})).await {
            Err(_) => return Err(TryLater("download from Apple timed out".into()).into()),
            Ok(Err(e)) if transient(&e) => {
                return Err(TryLater(format!("download from Apple failed: {} ({:?})", e, e)).into())
            }
            Ok(Err(e)) => bail!("download from Apple failed: {} ({:?})", e, e),
            Ok(Ok(())) => {}
        }
        writer.flush()?;
        Ok(())
    }

    async fn run(&self, prog: &str, args: &[String]) -> Result<Vec<u8>> {
        let _permit = self.convert.acquire().await?;
        debug!("running {} {:?}", prog, args);
        let child = Command::new(prog)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("failed to start {}", prog))?;
        let out = tokio::time::timeout(CONVERT_TIMEOUT, child.wait_with_output())
            .await
            .map_err(|_| anyhow!("{} timed out", prog))??;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let tail: String = err.lines().rev().take(4).collect::<Vec<_>>().join(" | ");
            bail!("{} failed ({}): {}", prog, out.status, tail);
        }
        Ok(out.stdout)
    }

    async fn ffmpeg(&self, args: Vec<String>) -> Result<()> {
        let mut full = vec![
            "-hide_banner".to_string(),
            "-loglevel".to_string(),
            "error".to_string(),
            "-nostdin".to_string(),
            "-y".to_string(),
        ];
        full.extend(args);
        self.run(&self.ffmpeg, &full).await.map(|_| ())
    }

    async fn probe(&self, input: &Path) -> Result<Probe> {
        let out = self
            .run(
                &self.ffprobe,
                &[
                    "-v".into(),
                    "error".into(),
                    "-show_entries".into(),
                    "stream=codec_type,codec_name,pix_fmt,width,height,color_transfer".into(),
                    "-of".into(),
                    "json".into(),
                    input.to_string_lossy().into_owned(),
                ],
            )
            .await?;
        Ok(Probe::parse(&out))
    }

    /// HEIC/HEIF to a PNG the scaling step can read; `None` if neither decoder managed (ffmpeg
    /// then tries the original). iPhone photos are grids of 512 px HEVC tiles: libheif puts them
    /// together and rotates the result. ffmpeg 8.1+ does too, but only for a plain decode: with
    /// `-vf` on the same command it refuses ("Simple and complex filtering cannot be used
    /// together"), which failed every photo preview. ffmpeg 7.1 (Debian 13) ignores the grid and
    /// gives one tile, so heif-dec is the one to have.
    async fn decode_heif(&self, input: &Path, work: &Path) -> Option<PathBuf> {
        if let Some(png) = self.decode_heif_libheif(input, work).await {
            return Some(png);
        }
        let out = work.join("grid.png");
        let res = self
            .ffmpeg(vec![
                "-i".into(),
                input.to_string_lossy().into_owned(),
                "-frames:v".into(),
                "1".into(),
                out.to_string_lossy().into_owned(),
            ])
            .await;
        match res {
            Ok(()) if out.exists() => Some(out),
            Ok(()) => None,
            Err(e) => {
                warn!("decoding HEIC with ffmpeg failed: {:#}", e);
                None
            }
        }
    }

    /// HEIC/HEIF to PNG with libheif's heif-dec; `None` if it is not installed or failed.
    async fn decode_heif_libheif(&self, input: &Path, work: &Path) -> Option<PathBuf> {
        let tool = self.heif_dec.as_ref()?;
        let out = work.join("decoded.png");
        let res = self
            .run(
                tool,
                &[
                    input.to_string_lossy().into_owned(),
                    out.to_string_lossy().into_owned(),
                ],
            )
            .await;
        if let Err(e) = res {
            warn!("{} failed: {:#}", tool, e);
            return None;
        }
        if out.exists() {
            return Some(out);
        }
        // Some versions number the output when the file holds several images.
        fs::read_dir(work)
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map_or(false, |n| n.starts_with("decoded") && n.ends_with(".png"))
            })
    }

    fn work_dir(&self, out: &Path) -> Result<PathBuf> {
        let work = out.with_extension("work");
        let _ = fs::remove_dir_all(&work);
        fs::create_dir_all(&work)?;
        Ok(work)
    }

    async fn make_preview(&self, meta: &Meta, original: &Path, out: &Path) -> Result<VariantInfo> {
        let stem = stem_of(&meta.name);
        let work = self.work_dir(out)?;
        let res: Result<VariantInfo> = async {
            match meta.kind {
                ATTACH_IMAGE | ATTACH_STICKER => {
                    let size = fs::metadata(original)?.len();
                    let heif = is_heif(&meta.mime, &meta.uti, &meta.name);
                    let mut input = original.to_path_buf();
                    if heif {
                        if let Some(png) = self.decode_heif(original, &work).await {
                            input = png;
                        }
                    }
                    let probe = self.probe(&input).await.unwrap_or_default();
                    if !heif && probe.video_codec.as_deref() == Some("gif") && size <= GIF_PASSTHROUGH_BYTES
                    {
                        fs::copy(original, out)?;
                        return Ok(VariantInfo {
                            mime: "image/gif".into(),
                            name: format!("{}.gif", stem),
                        });
                    }
                    let sticker = meta.kind == ATTACH_STICKER;
                    let px = if sticker { PREVIEW_STICKER_PX } else { PREVIEW_IMAGE_PX };
                    let png = sticker || probe.has_alpha();
                    let tmp = work.join(if png { "out.png" } else { "out.jpg" });
                    let mut args = vec![
                        "-i".into(),
                        input.to_string_lossy().into_owned(),
                        "-frames:v".into(),
                        "1".into(),
                        "-vf".into(),
                        format!(
                            "scale='min({px},iw)':'min({px},ih)':force_original_aspect_ratio=decrease"
                        ),
                    ];
                    if !png {
                        args.extend(["-pix_fmt".into(), "yuvj420p".into(), "-q:v".into(), "5".into()]);
                    }
                    args.push(tmp.to_string_lossy().into_owned());
                    self.ffmpeg(args).await?;
                    fs::rename(&tmp, out)?;
                    Ok(if png {
                        VariantInfo { mime: "image/png".into(), name: format!("{}.png", stem) }
                    } else {
                        VariantInfo { mime: "image/jpeg".into(), name: format!("{}.jpg", stem) }
                    })
                }
                ATTACH_VIDEO => {
                    let probe = self.probe(original).await.unwrap_or_default();
                    let tmp = work.join("out.mp4");
                    let px = PREVIEW_VIDEO_PX;
                    let scale = format!(
                        "scale=w='if(gte(iw,ih),-2,min({px},iw))':h='if(gte(iw,ih),min({px},ih),-2)'"
                    );
                    self.ffmpeg(video_args(original, &tmp, &probe, &scale, "28", "500k", "baseline", "3.0", "64k"))
                        .await?;
                    fs::rename(&tmp, out)?;
                    Ok(VariantInfo { mime: "video/mp4".into(), name: format!("{}.mp4", stem) })
                }
                ATTACH_AUDIO | ATTACH_VOICE => {
                    let tmp = work.join("out.m4a");
                    self.ffmpeg(audio_args(original, &tmp, "48k")).await?;
                    fs::rename(&tmp, out)?;
                    let name = if meta.kind == ATTACH_VOICE {
                        "Voice message.m4a".to_string()
                    } else {
                        format!("{}.m4a", stem)
                    };
                    Ok(VariantInfo { mime: "audio/mp4".into(), name })
                }
                ATTACH_VCARD => {
                    fs::copy(original, out)?;
                    Ok(VariantInfo { mime: "text/x-vCard".into(), name: format!("{}.vcf", stem) })
                }
                _ => bail!("this attachment has no preview"),
            }
        }
        .await;
        let _ = fs::remove_dir_all(&work);
        res
    }

    async fn make_full(&self, meta: &Meta, original: &Path, out: &Path) -> Result<VariantInfo> {
        let stem = stem_of(&meta.name);
        let ext = ext_of(&meta.name);
        let work = self.work_dir(out)?;
        let res: Result<VariantInfo> = async {
            let passthrough = || -> Result<VariantInfo> {
                fs::copy(original, out)?;
                Ok(VariantInfo { mime: meta.mime.clone(), name: meta.name.clone() })
            };
            match meta.kind {
                ATTACH_IMAGE | ATTACH_STICKER => {
                    if !is_heif(&meta.mime, &meta.uti, &meta.name)
                        && matches!(ext.as_str(), "jpg" | "jpeg" | "png" | "gif")
                    {
                        return passthrough();
                    }
                    let mut input = original.to_path_buf();
                    if is_heif(&meta.mime, &meta.uti, &meta.name) {
                        if let Some(png) = self.decode_heif(original, &work).await {
                            input = png;
                        }
                    }
                    let probe = self.probe(&input).await.unwrap_or_default();
                    let png = meta.kind == ATTACH_STICKER || probe.has_alpha();
                    let tmp = work.join(if png { "out.png" } else { "out.jpg" });
                    let mut args = vec!["-i".into(), input.to_string_lossy().into_owned(), "-frames:v".into(), "1".into()];
                    if !png {
                        args.extend(["-pix_fmt".into(), "yuvj420p".into(), "-q:v".into(), "2".into()]);
                    }
                    args.push(tmp.to_string_lossy().into_owned());
                    self.ffmpeg(args).await?;
                    fs::rename(&tmp, out)?;
                    Ok(if png {
                        VariantInfo { mime: "image/png".into(), name: format!("{}.png", stem) }
                    } else {
                        VariantInfo { mime: "image/jpeg".into(), name: format!("{}.jpg", stem) }
                    })
                }
                ATTACH_VIDEO => {
                    let probe = self.probe(original).await.unwrap_or_default();
                    let tmp = work.join("out.mp4");
                    let small = probe.width.max(probe.height) <= FULL_VIDEO_MAX_PX;
                    if probe.video_codec.as_deref() == Some("h264") && small && !probe.is_hdr() {
                        // Already playable: just move it into an MP4 container.
                        self.ffmpeg(vec![
                            "-i".into(), original.to_string_lossy().into_owned(),
                            "-map".into(), "0:v:0".into(), "-map".into(), "0:a:0?".into(),
                            "-c".into(), "copy".into(), "-movflags".into(), "+faststart".into(),
                            tmp.to_string_lossy().into_owned(),
                        ])
                        .await?;
                    } else {
                        let px = FULL_VIDEO_MAX_PX;
                        let scale = format!(
                            "scale=w='if(gte(iw,ih),min({px},iw),-2)':h='if(gte(iw,ih),-2,min({px},ih))'"
                        );
                        self.ffmpeg(video_args(original, &tmp, &probe, &scale, "23", "4M", "main", "4.0", "128k"))
                            .await?;
                    }
                    fs::rename(&tmp, out)?;
                    Ok(VariantInfo { mime: "video/mp4".into(), name: format!("{}.mp4", stem) })
                }
                ATTACH_AUDIO | ATTACH_VOICE => {
                    if matches!(ext.as_str(), "m4a" | "mp3" | "aac" | "amr") {
                        return passthrough();
                    }
                    let tmp = work.join("out.m4a");
                    self.ffmpeg(audio_args(original, &tmp, "128k")).await?;
                    fs::rename(&tmp, out)?;
                    let name = if meta.kind == ATTACH_VOICE {
                        "Voice message.m4a".to_string()
                    } else {
                        format!("{}.m4a", stem)
                    };
                    Ok(VariantInfo { mime: "audio/mp4".into(), name })
                }
                _ => passthrough(),
            }
        }
        .await;
        let _ = fs::remove_dir_all(&work);
        res
    }

    /// Where upload `id` is stored (it must be a valid id).
    pub fn upload_path(&self, id: &str) -> Result<PathBuf> {
        if !valid_id(id) {
            bail!("bad upload id");
        }
        Ok(self.dir.join("up").join(id))
    }

    pub fn max_upload_bytes(&self) -> u64 {
        MAX_UPLOAD_BYTES
    }

    /// Converts upload `upload_id` into something an iPhone shows inline.
    pub async fn prepare_outgoing(&self, upload_id: &str, name: &str, mime: &str) -> Result<Outgoing> {
        let src = self.upload_path(upload_id)?;
        if !src.is_file() {
            bail!("attachment upload {} is missing", upload_id);
        }
        let mime = mime.to_ascii_lowercase();
        let stem = stem_of(name);
        let out_with = |ext: &str| src.with_extension(format!("out.{}", ext));
        let (path, name, mime) = match mime.as_str() {
            "image/jpeg" | "image/jpg" => (src.clone(), format!("{}.jpg", stem), "image/jpeg".to_string()),
            "image/png" => (src.clone(), format!("{}.png", stem), mime.clone()),
            "image/gif" => (src.clone(), format!("{}.gif", stem), mime.clone()),
            m if m.starts_with("image/") => {
                let out = out_with("jpg");
                self.ffmpeg(vec![
                    "-i".into(), src.to_string_lossy().into_owned(), "-frames:v".into(), "1".into(),
                    "-pix_fmt".into(), "yuvj420p".into(), "-q:v".into(), "3".into(),
                    out.to_string_lossy().into_owned(),
                ])
                .await?;
                (out, format!("{}.jpg", stem), "image/jpeg".to_string())
            }
            m if m.starts_with("video/") => {
                let out = out_with("mp4");
                let probe = self.probe(&src).await.unwrap_or_default();
                self.ffmpeg(video_args(&src, &out, &probe, "scale=trunc(iw/2)*2:trunc(ih/2)*2", "23", "2M", "high", "4.0", "96k"))
                    .await?;
                (out, format!("{}.mp4", stem), "video/mp4".to_string())
            }
            m if m.starts_with("audio/") && m != "audio/mp4" && m != "audio/mpeg" => {
                let out = out_with("m4a");
                self.ffmpeg(audio_args(&src, &out, "64k")).await?;
                (out, format!("{}.m4a", stem), "audio/mp4".to_string())
            }
            m if m.contains("vcard") => (src.clone(), format!("{}.vcf", stem), "text/vcard".to_string()),
            _ => (src.clone(), name.to_string(), mime.clone()),
        };
        let uti = uti_for_mime(&mime).to_string();
        Ok(Outgoing { path, name, mime, uti })
    }

    /// Deletes upload `id` and anything converted from it.
    pub fn remove_upload(&self, id: &str) {
        let Ok(src) = self.upload_path(id) else { return };
        let up = self.dir.join("up");
        if let Ok(entries) = fs::read_dir(&up) {
            for e in entries.filter_map(|e| e.ok()) {
                let n = e.file_name();
                let n = n.to_string_lossy();
                if n == id || n.starts_with(&format!("{}.", id)) {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
        let _ = fs::remove_file(src);
    }

    /// Deletes attachments older than the retention period and stale uploads.
    fn prune(&self) {
        let now = SystemTime::now();
        let mut removed = 0usize;
        if let Ok(entries) = fs::read_dir(&self.dir) {
            for e in entries.filter_map(|e| e.ok()) {
                let path = e.path();
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
                if name == "up" || !path.is_dir() {
                    continue;
                }
                let age = fs::metadata(path.join("meta.json"))
                    .or_else(|_| fs::metadata(&path))
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| now.duration_since(t).ok())
                    .unwrap_or_default();
                if age > self.retention && fs::remove_dir_all(&path).is_ok() {
                    removed += 1;
                }
            }
        }
        if let Ok(entries) = fs::read_dir(self.dir.join("up")) {
            for e in entries.filter_map(|e| e.ok()) {
                let old = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| now.duration_since(t).ok())
                    .map_or(false, |a| a > UPLOAD_RETENTION);
                if old && fs::remove_file(e.path()).is_ok() {
                    removed += 1;
                }
            }
        }
        if removed > 0 {
            info!("pruned {} old attachments/uploads", removed);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn video_args(
    input: &Path,
    out: &Path,
    probe: &Probe,
    scale: &str,
    crf: &str,
    maxrate: &str,
    profile: &str,
    level: &str,
    audio_rate: &str,
) -> Vec<String> {
    // iPhone HDR (HLG / PQ) video looks washed out when squeezed into 8-bit SDR; tone-map it.
    let vf = if probe.is_hdr() {
        format!(
            "zscale=t=linear:npl=100,format=gbrpf32le,zscale=p=bt709,tonemap=hable:desat=0,\
             zscale=t=bt709:m=bt709:r=tv,format=yuv420p,{}",
            scale
        )
    } else {
        format!("{},format=yuv420p", scale)
    };
    let bufsize = match maxrate.strip_suffix('k') {
        Some(n) => format!("{}k", n.parse::<u32>().unwrap_or(500) * 2),
        None => maxrate
            .strip_suffix('M')
            .map(|n| format!("{}M", n.parse::<u32>().unwrap_or(2) * 2))
            .unwrap_or_else(|| maxrate.to_string()),
    };
    vec![
        "-i".into(), input.to_string_lossy().into_owned(),
        "-map".into(), "0:v:0".into(), "-map".into(), "0:a:0?".into(),
        "-vf".into(), vf,
        "-fpsmax".into(), "30".into(),
        "-c:v".into(), "libx264".into(), "-preset".into(), "veryfast".into(),
        "-profile:v".into(), profile.into(), "-level".into(), level.into(),
        "-crf".into(), crf.into(), "-maxrate".into(), maxrate.into(), "-bufsize".into(), bufsize,
        "-c:a".into(), "aac".into(), "-b:a".into(), audio_rate.into(), "-ac".into(), "2".into(),
        "-movflags".into(), "+faststart".into(),
        out.to_string_lossy().into_owned(),
    ]
}

fn audio_args(input: &Path, out: &Path, rate: &str) -> Vec<String> {
    vec![
        "-i".into(), input.to_string_lossy().into_owned(),
        "-vn".into(), "-c:a".into(), "aac".into(), "-b:a".into(), rate.into(),
        "-movflags".into(), "+faststart".into(),
        out.to_string_lossy().into_owned(),
    ]
}

#[derive(Debug, Default, Clone)]
struct Probe {
    video_codec: Option<String>,
    pix_fmt: Option<String>,
    width: u32,
    height: u32,
    color_transfer: Option<String>,
}

impl Probe {
    fn parse(json: &[u8]) -> Probe {
        let mut p = Probe::default();
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(json) else { return p };
        let Some(streams) = v.get("streams").and_then(|s| s.as_array()) else { return p };
        if let Some(s) = streams
            .iter()
            .find(|s| s.get("codec_type").and_then(|t| t.as_str()) == Some("video"))
        {
            let st = |k: &str| s.get(k).and_then(|x| x.as_str()).map(str::to_string);
            p.video_codec = st("codec_name");
            p.pix_fmt = st("pix_fmt");
            p.color_transfer = st("color_transfer");
            p.width = s.get("width").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            p.height = s.get("height").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
        }
        p
    }

    fn has_alpha(&self) -> bool {
        self.pix_fmt.as_deref().map_or(false, |f| {
            f.starts_with("rgba")
                || f.starts_with("bgra")
                || f.starts_with("argb")
                || f.starts_with("abgr")
                || f.starts_with("ya")
                || f.starts_with("yuva")
                || f.starts_with("gbrap")
        })
    }

    fn is_hdr(&self) -> bool {
        matches!(
            self.color_transfer.as_deref(),
            Some("arib-std-b67") | Some("smpte2084")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_apple_attachments() {
        assert_eq!(classify("image/heic", "public.heic", "IMG_1.HEIC", false, false), ATTACH_IMAGE);
        assert_eq!(classify("image/heic", "public.heic", "s.heic", false, true), ATTACH_STICKER);
        assert_eq!(classify("video/quicktime", "com.apple.quicktime-movie", "IMG_2.MOV", false, false), ATTACH_VIDEO);
        assert_eq!(classify("audio/x-caf", "com.apple.coreaudio-format", "Audio Message.caf", true, false), ATTACH_VOICE);
        assert_eq!(classify("audio/mpeg", "public.mp3", "song.mp3", false, false), ATTACH_AUDIO);
        assert_eq!(classify("text/vcard", "public.vcard", "Sam.vcf", false, false), ATTACH_VCARD);
        assert_eq!(classify("application/pdf", "com.adobe.pdf", "a.pdf", false, false), ATTACH_FILE);
        assert_eq!(classify("", "", "photo.jpeg", false, false), ATTACH_IMAGE);
    }

    #[test]
    fn ids_cannot_escape() {
        assert!(valid_id("0b9c0c6e-3c0e-4c55-9a39-5d1b0e1f2a3b"));
        assert!(!valid_id("../etc"));
        assert!(!valid_id(""));
        assert!(!valid_id("a/b"));
    }

    #[test]
    fn probe_parses_ffprobe_json() {
        let p = Probe::parse(br#"{"streams":[{"codec_type":"audio","codec_name":"aac"},{"codec_type":"video","codec_name":"hevc","pix_fmt":"yuv420p10le","width":1920,"height":1080,"color_transfer":"arib-std-b67"}]}"#);
        assert_eq!(p.video_codec.as_deref(), Some("hevc"));
        assert!(p.is_hdr());
        assert!(!p.has_alpha());
        assert_eq!(p.width, 1920);
        let png = Probe::parse(br#"{"streams":[{"codec_type":"video","codec_name":"png","pix_fmt":"rgba"}]}"#);
        assert!(png.has_alpha());
    }

    fn sample_attachment(a_type: AttachmentType) -> Attachment {
        Attachment {
            a_type,
            part: 0,
            uti_type: "com.apple.coreaudio-format".into(),
            mime: "audio/x-caf".into(),
            name: "Audio Message.caf".into(),
            iris: false,
        }
    }

    fn sample_mmcs() -> AttachmentType {
        AttachmentType::MMCS(MMCSFile {
            signature: vec![9; 21],
            object: "obj".into(),
            url: "https://example.invalid/obj".into(),
            key: vec![7; 32],
            size: 3,
        })
    }

    fn temp_store() -> (Arc<MediaStore>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("imsg-media-test-{}", Uuid::new_v4()));
        (Arc::new(MediaStore::new(&dir, None, 30).unwrap()), dir)
    }

    #[test]
    fn meta_with_attachment_round_trips() {
        for a_type in [AttachmentType::Inline(vec![1, 2, 3]), sample_mmcs()] {
            let meta = Meta {
                name: "Audio Message.caf".into(),
                mime: "audio/x-caf".into(),
                uti: "com.apple.coreaudio-format".into(),
                kind: ATTACH_VOICE,
                created_ms: 1,
                size: 3,
                attachment: Some(StoredAttachment::from(&sample_attachment(a_type))),
            };
            let raw = serde_json::to_vec(&meta).unwrap();
            let back: Meta = serde_json::from_slice(&raw).expect("meta.json must load again");
            let att = back.attachment.unwrap().to_attachment();
            assert_eq!(att.name, "Audio Message.caf");
            match att.a_type {
                AttachmentType::Inline(d) => assert_eq!(d, vec![1, 2, 3]),
                AttachmentType::MMCS(m) => {
                    assert_eq!(m.signature, vec![9; 21]);
                    assert_eq!(m.key, vec![7; 32]);
                    assert_eq!(m.url, "https://example.invalid/obj");
                }
            }
        }
    }

    /// meta.json files written before the fix (rustpush's `Attachment` straight through
    /// serde_json) still load, so attachments already on the server can be fetched again.
    #[test]
    fn legacy_meta_json_loads() {
        #[derive(Serialize)]
        struct LegacyMeta {
            name: String,
            mime: String,
            uti: String,
            kind: u8,
            created_ms: u64,
            size: u64,
            attachment: Option<Attachment>,
        }
        for a_type in [AttachmentType::Inline(vec![4, 5]), sample_mmcs()] {
            let legacy = LegacyMeta {
                name: "IMG_1.HEIC".into(),
                mime: "image/heic".into(),
                uti: "public.heic".into(),
                kind: ATTACH_IMAGE,
                created_ms: 1,
                size: 3,
                attachment: Some(sample_attachment(a_type)),
            };
            // What the old code read back, and why every attachment failed:
            let old = serde_json::to_vec(&legacy.attachment).unwrap();
            assert!(serde_json::from_slice::<Option<Attachment>>(&old).is_err());
            let raw = serde_json::to_vec(&legacy).unwrap();
            let meta: Meta = serde_json::from_slice(&raw).expect("legacy meta.json must load");
            match meta.attachment.unwrap().to_attachment().a_type {
                AttachmentType::Inline(d) => assert_eq!(d, vec![4, 5]),
                AttachmentType::MMCS(m) => assert_eq!(m.key, vec![7; 32]),
            }
        }
    }

    /// An MMCS attachment's meta loads again: fetching it gets as far as needing Apple.
    #[tokio::test]
    async fn mmcs_attachment_meta_is_usable() {
        let (store, dir) = temp_store();
        let att = sample_attachment(sample_mmcs());
        let r = store.register_incoming(&att, true, false).unwrap();
        assert_eq!(r.kind, ATTACH_VOICE);
        let err = store.variant(&r.media_id, false).await.unwrap_err();
        assert!(format!("{:#}", err).contains("not connected to Apple"), "{:#}", err);
        assert!(is_try_later(&err), "the phone must retry this, not give up: {:#}", err);
        let unknown = store.variant("0b9c0c6e-3c0e-4c55-9a39-5d1b0e1f2a3b", false).await.unwrap_err();
        assert!(!is_try_later(&unknown), "{:#}", unknown);
        let _ = fs::remove_dir_all(dir);
    }

    /// An iPhone voice message (inline `Audio Message.caf`, Opus 24 kHz mono in CAF, as iOS
    /// 12.2+ sends it) becomes an AAC preview and full file with the real ffmpeg.
    #[tokio::test]
    async fn inline_voice_message_converts() {
        if which("ffmpeg").is_none() || which("ffprobe").is_none() {
            eprintln!("ffmpeg not installed; skipping");
            return;
        }
        let caf = include_bytes!("../testdata/audio_message_opus.caf").to_vec();
        let (store, dir) = temp_store();
        let att = sample_attachment(AttachmentType::Inline(caf.clone()));
        let r = store.register_incoming(&att, true, false).unwrap();
        assert_eq!(r.kind, ATTACH_VOICE);
        assert_eq!(r.size, caf.len() as u64);
        let meta = store.read_meta(&r.media_id).unwrap();
        assert!(meta.attachment.is_none(), "inline bytes go to the original, not meta.json");
        assert_eq!(fs::read(dir.join("media").join(&r.media_id).join("original")).unwrap(), caf);
        for full in [false, true] {
            let v = store.variant(&r.media_id, full).await.unwrap();
            assert_eq!(v.mime, "audio/mp4");
            assert_eq!(v.name, "Voice message.m4a");
            assert!(v.len > 1000, "converted file is {} bytes", v.len);
            let probe = Command::new("ffprobe")
                .args(["-v", "error", "-show_entries", "stream=codec_name", "-of", "csv=p=0"])
                .arg(&v.path)
                .output()
                .await
                .unwrap();
            let out = String::from_utf8_lossy(&probe.stdout);
            assert!(out.contains("aac"), "{}", out);
        }
        let _ = fs::remove_dir_all(dir);
    }

    fn ffmpeg_version() -> Option<(u32, u32)> {
        let out = std::process::Command::new("ffmpeg").arg("-version").output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let v = text.split_whitespace().nth(2)?.trim_start_matches('n');
        let mut parts = v.split(|c: char| !c.is_ascii_digit());
        Some((parts.next()?.parse().ok()?, parts.next().and_then(|m| m.parse().ok()).unwrap_or(0)))
    }

    async fn image_size(path: &Path) -> (u32, u32) {
        let out = Command::new("ffprobe")
            .args(["-v", "error", "-show_entries", "stream=width,height", "-of", "csv=p=0"])
            .arg(path)
            .output()
            .await
            .unwrap();
        let s = String::from_utf8_lossy(&out.stdout);
        let (w, h) = s.trim().split_once(',').unwrap();
        (w.parse().unwrap(), h.parse().unwrap())
    }

    /// An iPhone-style photo (HEIC made of 256 px tiles, 768x512 in all) gets a preview and a
    /// full-size JPEG of the whole picture. With ffmpeg 8.1+ and no heif-dec, the preview used to
    /// fail outright ("Simple and complex filtering cannot be used together").
    #[tokio::test]
    async fn tiled_heic_photo_converts() {
        if which("ffmpeg").is_none() || which("ffprobe").is_none() {
            eprintln!("ffmpeg not installed; skipping");
            return;
        }
        let heic = include_bytes!("../testdata/tiled_photo.heic").to_vec();
        let ffmpeg_joins_tiles = ffmpeg_version().map_or(false, |v| v >= (8, 1));
        for libheif in [true, false] {
            let dir = std::env::temp_dir().join(format!("imsg-media-test-{}", Uuid::new_v4()));
            let mut store = MediaStore::new(&dir, None, 30).unwrap();
            if !libheif {
                store.heif_dec = None;
            } else if store.heif_dec.is_none() {
                eprintln!("heif-dec not installed; testing ffmpeg only");
                continue;
            }
            let store = Arc::new(store);
            let att = Attachment {
                a_type: AttachmentType::Inline(heic.clone()),
                part: 0,
                uti_type: "public.heic".into(),
                mime: "image/heic".into(),
                name: "IMG_0001.HEIC".into(),
                iris: false,
            };
            let r = store.register_incoming(&att, false, false).unwrap();
            assert_eq!(r.kind, ATTACH_IMAGE);
            for full in [false, true] {
                let v = store
                    .variant(&r.media_id, full)
                    .await
                    .unwrap_or_else(|e| panic!("libheif={} full={}: {:#}", libheif, full, e));
                assert_eq!(v.mime, "image/jpeg");
                assert_eq!(v.name, "IMG_0001.jpg");
                if libheif || ffmpeg_joins_tiles {
                    let (w, h) = image_size(&v.path).await;
                    if full {
                        assert_eq!((w, h), (768, 512), "libheif={}", libheif);
                    } else {
                        assert!(w == 640 && (426..=427).contains(&h), "libheif={}: {}x{}", libheif, w, h);
                    }
                }
            }
            let _ = fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn stems_are_safe() {
        assert_eq!(stem_of("IMG_0001.HEIC"), "IMG_0001");
        assert_eq!(stem_of(""), "attachment");
    }
}
