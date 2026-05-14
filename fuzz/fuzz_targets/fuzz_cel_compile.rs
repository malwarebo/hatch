#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(p) = hatch_protocol::cel::Program::compile(s) {
            let ctx = hatch_protocol::cel::Context::new();
            let _ = p.run(&ctx);
        }
    }
});
