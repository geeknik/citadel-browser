#![no_main]

use libfuzzer_sys::fuzz_target;
use parser::javascript::JsParser;

fuzz_target!(|data: &[u8]| {
    // Try to convert bytes to a UTF-8 string
    if let Ok(js_str) = std::str::from_utf8(data) {
        // Attempt to parse the JavaScript string
        let mut parser = JsParser::new(js_str);
        let _ = parser.parse();
        // The fuzzer will look for panics, crashes, or other undefined behavior
    }
}); 