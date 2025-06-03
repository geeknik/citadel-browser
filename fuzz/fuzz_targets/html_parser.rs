#![no_main]

use libfuzzer_sys::fuzz_target;
use parser::html::parse_html;
use parser::security::SecurityContext;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    // Try to convert bytes to a UTF-8 string
    if let Ok(html_str) = std::str::from_utf8(data) {
        // Limit input size to prevent excessive resource usage
        if html_str.len() > 10_000 {
            return;
        }

        // Create a security context for parsing
        let security_context = Arc::new(SecurityContext::default());

        // Attempt to parse the HTML string
        let _ = parse_html(html_str, security_context);
        // The fuzzer will look for panics, crashes, or other undefined behavior
    }
}); 