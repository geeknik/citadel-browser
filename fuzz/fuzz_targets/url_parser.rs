#![no_main]

use libfuzzer_sys::fuzz_target;
use parser::url::UrlParser;

fuzz_target!(|data: &[u8]| {
    // Try to convert bytes to a UTF-8 string
    if let Ok(url_str) = std::str::from_utf8(data) {
        // Limit input size to prevent excessive resource usage
        if url_str.len() > 10_000 {
            return;
        }

        // Attempt to parse the URL string
        let parser = UrlParser::new();
        let _ = parser.parse(url_str);
        // The fuzzer will look for panics, crashes, or other undefined behavior
    }
}); 