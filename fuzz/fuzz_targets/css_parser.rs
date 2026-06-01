#![no_main]

use citadel_parser::{parse_css, security::SecurityContext};
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

// Fuzz the CSS parser: arbitrary bytes -> parse_css must never panic or hit UB.
fuzz_target!(|data: &[u8]| {
    if let Ok(css) = std::str::from_utf8(data) {
        if css.len() > 100_000 {
            return; // bound resource use
        }
        let ctx = Arc::new(SecurityContext::new(10));
        let _ = parse_css(css, ctx);
    }
});
