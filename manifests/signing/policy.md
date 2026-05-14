# Signing policy

Two-tier key infrastructure:

- **Master key**: ed25519. Generated offline. Stored on a hardware token
  (Yubikey or equivalent). Used only to sign delegated keys. Rotation:
  every five years.
- **Delegated CI signing key**: ed25519. Lives encrypted as a GitHub Actions
  secret. Used to sign each release bundle. Rotation: every six months.
  Each delegated key is itself signed by the master key.

## Trust store distribution

Every hatch release bundles the current master public key plus the most
recent two delegated public keys. The daemon refuses signatures from keys
not in the bundled trust store.

## Revocation

Revoked keys move to `pubkeys/revoked/`. New hatch releases ship the
revocation list. The daemon rejects any signature by a revoked key
regardless of age.

## Per-release signing

1. CI builds `manifests-<date>.tar.zst`.
2. CI computes its SHA-256.
3. CI signs the hash with the delegated key, embedding the signature into
   the bundle's `manifest.json` under `bundle_signature`.
4. CI publishes both `manifests-<date>.tar.zst` and a detached
   `manifests-<date>.tar.zst.sig` to GitHub Releases.
5. `hatch registry update` downloads both, verifies the detached signature
   against the bundled trust store, then unpacks.
