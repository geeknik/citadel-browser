#![no_main]

use libfuzzer_sys::fuzz_target;
use parser::css::CssParser;

fuzz_target!(|data: &[u8]| {
    // Try to convert bytes to a UTF-8 string
    if let Ok(css_str) = std::str::from_utf8(data) {
        // Limit input size to prevent excessive resource usage
        if css_str.len() > 10_000 {
            return;
        }

        // Attempt to parse the CSS string
        let mut parser = CssParser::new(css_str);
        let _ = parser.parse();
        // The fuzzer will look for panics, crashes, or other undefined behavior
    }
}); 