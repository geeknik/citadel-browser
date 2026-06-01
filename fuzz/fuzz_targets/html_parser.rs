#![no_main]
//! Fuzz testing for the HTML parser, focused on security: script injection,
//! deep nesting, malformed markup, entity handling, and memory-exhaustion input.

use citadel_parser::{parse_html, security::SecurityContext};
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

// The parser must never panic or hit UB at any strictness level; rejecting
// malicious/malformed input gracefully is fine. libFuzzer catches panics.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // Own the (possibly lossy) string so it outlives the parse calls below.
    let html = String::from_utf8_lossy(data);
    if html.len() > 50_000 {
        return; // bound resource use / timeouts
    }
    for max_depth in [5usize, 10, 20] {
        let ctx = Arc::new(SecurityContext::new(max_depth));
        let _ = parse_html(&html, ctx);
    }
});
