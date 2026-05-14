# hatch fuzzing

These targets use [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
and require nightly Rust.

```bash
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run fuzz_manifest_parse
cargo +nightly fuzz run fuzz_jsonrpc_parse
cargo +nightly fuzz run fuzz_cel_compile
cargo +nightly fuzz run fuzz_sni_parse
cargo +nightly fuzz run fuzz_audit_replay
```

CI runs each target for one hour nightly. Corpus lives under
`fuzz/corpus/`.
