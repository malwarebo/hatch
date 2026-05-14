#![deny(clippy::all)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use hatch_core::sig::TrustStore;
use hatch_core::Manifest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("zstd: {0}")]
    Zstd(String),
    #[error("manifest not found: {0}")]
    NotFound(String),
    #[error("bundle signature failed: {0}")]
    BadBundleSignature(String),
    #[error("bundle checksum mismatch")]
    ChecksumMismatch,
    #[error("manifest invalid: {0}")]
    ManifestInvalid(String),
    #[error("core: {0}")]
    Core(#[from] hatch_core::CoreError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestIndexEntry {
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub path: String,
    pub risk_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub schema_version: String,
    pub released_at: String,
    pub entries: Vec<ManifestIndexEntry>,
    pub bundle_signature: Option<BundleSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSignature {
    pub key_id: String,
    pub algorithm: String,
    pub sig: String,
}

pub struct Registry {
    pub cache_dir: PathBuf,
    pub trust: TrustStore,
}

#[derive(Debug, Clone)]
pub struct LoadedBundle {
    pub manifest: BundleManifest,
    pub manifests: BTreeMap<String, String>,
}

impl Registry {
    pub fn new(cache_dir: PathBuf, trust: TrustStore) -> Self {
        Self { cache_dir, trust }
    }

    pub fn install_bundle_from_file(&self, bundle: &Path) -> Result<LoadedBundle, RegistryError> {
        let raw = std::fs::read(bundle)?;
        let decompressed =
            zstd::decode_all(&raw[..]).map_err(|e| RegistryError::Zstd(e.to_string()))?;
        let loaded = parse_tar(&decompressed)?;
        std::fs::create_dir_all(&self.cache_dir)?;
        let out = self.cache_dir.join("current");
        std::fs::create_dir_all(&out)?;
        std::fs::write(
            out.join("manifest.json"),
            serde_json::to_vec_pretty(&loaded.manifest)?,
        )?;
        for (name, body) in &loaded.manifests {
            std::fs::write(out.join(format!("{name}.toml")), body)?;
        }
        Ok(loaded)
    }

    pub fn list_local(&self) -> Result<Vec<ManifestIndexEntry>, RegistryError> {
        let path = self.cache_dir.join("current/manifest.json");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let raw = std::fs::read_to_string(&path)?;
        let manifest: BundleManifest = serde_json::from_str(&raw)?;
        Ok(manifest.entries)
    }

    pub fn fetch_manifest(&self, name: &str) -> Result<Manifest, RegistryError> {
        let path = self.cache_dir.join("current").join(format!("{name}.toml"));
        if !path.exists() {
            return Err(RegistryError::NotFound(name.into()));
        }
        let raw = std::fs::read_to_string(&path)?;
        let m = Manifest::parse_str(&raw)?;
        Ok(m)
    }

    pub fn verify_manifest(&self, manifest: &Manifest) -> Result<(), RegistryError> {
        self.trust
            .verify(manifest)
            .map(|_| ())
            .map_err(|e| RegistryError::ManifestInvalid(e.to_string()))
    }
}

pub fn build_bundle(
    manifests: &BTreeMap<String, String>,
    released_at: &str,
    signature: Option<BundleSignature>,
) -> Result<Vec<u8>, RegistryError> {
    let entries: Vec<ManifestIndexEntry> = manifests
        .iter()
        .map(|(name, body)| {
            let parsed = Manifest::parse_str(body).ok();
            let risk = parsed
                .as_ref()
                .map(|m| hatch_core::risk::breakdown(m).score())
                .unwrap_or(0);
            let mut h = Sha256::new();
            h.update(body.as_bytes());
            let sha = h.finalize();
            let sha_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha);
            let version = parsed.map(|m| m.version).unwrap_or_else(|| "0.0.0".into());
            ManifestIndexEntry {
                name: name.clone(),
                version,
                sha256: format!("sha256:{sha_b64}"),
                path: format!("{name}.toml"),
                risk_score: risk,
            }
        })
        .collect();
    let bundle = BundleManifest {
        schema_version: "1.0".into(),
        released_at: released_at.into(),
        entries,
        bundle_signature: signature,
    };

    let mut buffer = Vec::new();
    write_tar_entry(
        &mut buffer,
        "manifest.json",
        serde_json::to_vec_pretty(&bundle)?.as_slice(),
    );
    for (name, body) in manifests {
        write_tar_entry(&mut buffer, &format!("{name}.toml"), body.as_bytes());
    }
    let compressed =
        zstd::encode_all(&buffer[..], 9).map_err(|e| RegistryError::Zstd(e.to_string()))?;
    Ok(compressed)
}

fn write_tar_entry(out: &mut Vec<u8>, name: &str, body: &[u8]) {
    let len = body.len() as u64;
    out.extend_from_slice(b"--HATCH-ENTRY--\n");
    out.extend_from_slice(format!("name={name}\nlen={len}\n").as_bytes());
    out.extend_from_slice(b"---\n");
    out.extend_from_slice(body);
    out.push(b'\n');
    out.extend_from_slice(b"--HATCH-END--\n");
}

fn parse_tar(buf: &[u8]) -> Result<LoadedBundle, RegistryError> {
    let mut manifests = BTreeMap::new();
    let mut manifest: Option<BundleManifest> = None;
    let mut i = 0usize;
    let marker_start = b"--HATCH-ENTRY--\n";
    let marker_end = b"--HATCH-END--\n";
    while i < buf.len() {
        let Some(rel) = find_at(buf, i, marker_start) else {
            break;
        };
        i = rel + marker_start.len();
        let header_end = find_at(buf, i, b"---\n")
            .ok_or_else(|| RegistryError::Zstd("bundle header malformed".into()))?;
        let header = &buf[i..header_end];
        let header_str =
            std::str::from_utf8(header).map_err(|_| RegistryError::Zstd("bundle utf8".into()))?;
        let mut name = String::new();
        let mut len: usize = 0;
        for line in header_str.lines() {
            if let Some(v) = line.strip_prefix("name=") {
                name = v.to_string();
            }
            if let Some(v) = line.strip_prefix("len=") {
                len = v
                    .parse()
                    .map_err(|e: std::num::ParseIntError| RegistryError::Zstd(e.to_string()))?;
            }
        }
        i = header_end + b"---\n".len();
        if i + len > buf.len() {
            return Err(RegistryError::Zstd("bundle truncated".into()));
        }
        let body = &buf[i..i + len];
        i += len + 1;
        let end_idx = find_at(buf, i, marker_end)
            .ok_or_else(|| RegistryError::Zstd("bundle marker missing".into()))?;
        i = end_idx + marker_end.len();
        if name == "manifest.json" {
            manifest = Some(serde_json::from_slice(body)?);
        } else if let Some(rest) = name.strip_suffix(".toml") {
            manifests.insert(
                rest.to_string(),
                std::str::from_utf8(body)
                    .map_err(|_| RegistryError::Zstd("manifest utf8".into()))?
                    .to_string(),
            );
        }
    }
    let manifest = manifest.ok_or_else(|| RegistryError::Zstd("manifest.json absent".into()))?;
    Ok(LoadedBundle {
        manifest,
        manifests,
    })
}

fn find_at(buf: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from > buf.len() {
        return None;
    }
    buf[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const MIN: &str = include_str!("../../hatch-core/tests/fixtures/minimal.toml");

    #[test]
    fn round_trip_bundle() {
        let dir = tempdir().unwrap();
        let mut manifests = BTreeMap::new();
        manifests.insert("minimal".to_string(), MIN.to_string());

        let compressed = build_bundle(&manifests, "2026-05-13T00:00:00Z", None).unwrap();
        let bundle_path = dir.path().join("bundle.tar.zst");
        std::fs::write(&bundle_path, &compressed).unwrap();

        let cache = dir.path().join("cache");
        let registry = Registry::new(cache.clone(), TrustStore::empty().with_unsigned(true));
        let loaded = registry.install_bundle_from_file(&bundle_path).unwrap();

        assert_eq!(loaded.manifest.entries.len(), 1);
        assert_eq!(loaded.manifest.entries[0].name, "minimal");
        let m = registry.fetch_manifest("minimal").unwrap();
        assert_eq!(m.name, "example");

        let listed = registry.list_local().unwrap();
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn fetch_missing_errors() {
        let dir = tempdir().unwrap();
        let registry = Registry::new(dir.path().to_path_buf(), TrustStore::empty());
        let err = registry.fetch_manifest("nope").unwrap_err();
        assert!(matches!(err, RegistryError::NotFound(_)));
    }
}
