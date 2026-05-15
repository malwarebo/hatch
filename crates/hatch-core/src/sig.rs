use base64::Engine as _;
use ed25519_dalek::{
    Signature as Ed25519Sig, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use thiserror::Error;

use crate::manifest::Manifest;

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("manifest is unsigned")]
    Unsigned,
    #[error("unknown key id: {0}")]
    UnknownKey(String),
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid key length: expected {expected}, got {got}")]
    KeyLength { expected: usize, got: usize },
    #[error("invalid signature length: expected {expected}, got {got}")]
    SigLength { expected: usize, got: usize },
    #[error("signature verification failed")]
    BadSignature,
    #[error("canonicalisation error: {0}")]
    Canonical(String),
}

pub struct TrustStore {
    pub keys: Vec<(String, [u8; PUBLIC_KEY_LENGTH])>,
    pub revoked: Vec<String>,
    pub allow_unsigned: bool,
}

impl TrustStore {
    pub fn empty() -> Self {
        Self {
            keys: Vec::new(),
            revoked: Vec::new(),
            allow_unsigned: false,
        }
    }

    pub fn with_unsigned(mut self, allow: bool) -> Self {
        self.allow_unsigned = allow;
        self
    }

    pub fn add_key(mut self, key_id: impl Into<String>, b64: &str) -> Result<Self, SignatureError> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64))?;
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(SignatureError::KeyLength {
                expected: PUBLIC_KEY_LENGTH,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; PUBLIC_KEY_LENGTH];
        arr.copy_from_slice(&bytes);
        self.keys.push((key_id.into(), arr));
        Ok(self)
    }

    pub fn revoke(mut self, key_id: impl Into<String>) -> Self {
        self.revoked.push(key_id.into());
        self
    }

    pub fn verify(&self, manifest: &Manifest) -> Result<VerifyResult, SignatureError> {
        let Some(sig) = manifest.signature.as_ref() else {
            return if self.allow_unsigned {
                Ok(VerifyResult::Unsigned)
            } else {
                Err(SignatureError::Unsigned)
            };
        };

        if sig.algorithm != "ed25519" {
            return Err(SignatureError::UnsupportedAlgorithm(sig.algorithm.clone()));
        }
        if self.revoked.iter().any(|k| k == &sig.key_id) {
            return Err(SignatureError::UnknownKey(sig.key_id.clone()));
        }
        let pk_bytes = self
            .keys
            .iter()
            .find(|(id, _)| id == &sig.key_id)
            .map(|(_, k)| *k)
            .ok_or_else(|| SignatureError::UnknownKey(sig.key_id.clone()))?;

        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sig.sig)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&sig.sig))?;
        if sig_bytes.len() != SIGNATURE_LENGTH {
            return Err(SignatureError::SigLength {
                expected: SIGNATURE_LENGTH,
                got: sig_bytes.len(),
            });
        }
        let mut s = [0u8; SIGNATURE_LENGTH];
        s.copy_from_slice(&sig_bytes);
        let signature = Ed25519Sig::from_bytes(&s);

        let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| SignatureError::KeyLength {
            expected: PUBLIC_KEY_LENGTH,
            got: pk_bytes.len(),
        })?;

        let canon = canonicalize(manifest)?;
        vk.verify(&canon, &signature)
            .map_err(|_| SignatureError::BadSignature)?;
        Ok(VerifyResult::Verified {
            key_id: sig.key_id.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub enum VerifyResult {
    Verified { key_id: String },
    Unsigned,
}

pub fn canonicalize(manifest: &Manifest) -> Result<Vec<u8>, SignatureError> {
    let mut clone = manifest.clone();
    clone.signature = None;
    serde_json::to_vec(&clone).map_err(|e| SignatureError::Canonical(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Manifest, Signature};
    use ed25519_dalek::{Signer, SigningKey};

    const MIN: &str = include_str!("../tests/fixtures/minimal.toml");

    fn random_signing_key() -> SigningKey {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).expect("entropy");
        SigningKey::from_bytes(&secret)
    }

    #[test]
    fn unsigned_rejected_by_default() {
        let m = Manifest::parse_str(MIN).unwrap();
        let store = TrustStore::empty();
        assert!(matches!(store.verify(&m), Err(SignatureError::Unsigned)));
    }

    #[test]
    fn unsigned_accepted_when_allowed() {
        let m = Manifest::parse_str(MIN).unwrap();
        let store = TrustStore::empty().with_unsigned(true);
        assert!(matches!(store.verify(&m), Ok(VerifyResult::Unsigned)));
    }

    #[test]
    fn signed_round_trip() {
        let sk = random_signing_key();
        let pk = sk.verifying_key();
        let pk_b64 = base64::engine::general_purpose::STANDARD.encode(pk.to_bytes());

        let mut m = Manifest::parse_str(MIN).unwrap();
        let canon = canonicalize(&m).unwrap();
        let signature = sk.sign(&canon);
        m.signature = Some(Signature {
            key_id: "test".into(),
            algorithm: "ed25519".into(),
            sig: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            signed_at: "2026-05-01T00:00:00Z".into(),
        });

        let store = TrustStore::empty().add_key("test", &pk_b64).unwrap();
        let res = store.verify(&m).unwrap();
        assert!(matches!(res, VerifyResult::Verified { .. }));
    }

    #[test]
    fn tampering_breaks_signature() {
        let sk = random_signing_key();
        let pk = sk.verifying_key();
        let pk_b64 = base64::engine::general_purpose::STANDARD.encode(pk.to_bytes());

        let mut m = Manifest::parse_str(MIN).unwrap();
        let canon = canonicalize(&m).unwrap();
        let signature = sk.sign(&canon);
        m.signature = Some(Signature {
            key_id: "test".into(),
            algorithm: "ed25519".into(),
            sig: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            signed_at: "2026-05-01T00:00:00Z".into(),
        });

        m.description = "tampered".into();
        let store = TrustStore::empty().add_key("test", &pk_b64).unwrap();
        assert!(matches!(
            store.verify(&m),
            Err(SignatureError::BadSignature)
        ));
    }
}
