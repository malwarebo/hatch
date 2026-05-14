#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        for line in s.lines() {
            let _: Result<hatch_audit::AuditEvent, _> = serde_json::from_str(line);
        }
    }
});
