#![no_main]

use citadel_networking::request::{Method, Request};
use libfuzzer_sys::fuzz_target;

// Fuzz request construction: arbitrary input as a URL plus header setting must
// never panic or hit UB (HTTPS-only enforcement / validation lives in
// Request::new and the with_* builders).
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if s.len() > 10_000 {
            return; // bound resource use
        }
        if let Ok(req) = Request::new(Method::GET, s) {
            let _ = req.with_header("X-Fuzz", "1");
        }
    }
});
