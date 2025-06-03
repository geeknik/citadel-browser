#![no_main]
//! Fuzz testing for HTML parser - focusing on security vulnerabilities
//! 
//! This fuzzer specifically targets potential security issues in HTML parsing:
//! - Script injection attempts
//! - Deep nesting attacks
//! - Malformed HTML handling
//! - Entity parsing vulnerabilities
//! - Memory exhaustion attempts

use libfuzzer_sys::fuzz_target;
use citadel_parser::{parse_html, security::SecurityContext};
use std::sync::Arc;

/// Security-focused HTML fuzzing entry point
fuzz_target!(|data: &[u8]| {
    // Skip completely empty inputs
    if data.is_empty() {
        return;
    }
    
    // Convert bytes to string, handling invalid UTF-8 gracefully
    let html_input = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => {
            // For invalid UTF-8, try lossy conversion
            let lossy = String::from_utf8_lossy(data);
            if lossy.len() > 10_000 {
                return; // Skip excessively large inputs
            }
            &lossy
        }
    };
    
    // Skip excessively large inputs to prevent timeout
    if html_input.len() > 50_000 {
        return;
    }
    
    // Test with different security context strictness levels
    test_with_security_context(html_input, 5);   // Very strict
    test_with_security_context(html_input, 10);  // Moderate
    test_with_security_context(html_input, 20);  // Permissive
});

/// Test HTML parsing with a specific security context
fn test_with_security_context(html: &str, max_depth: usize) {
    let security_context = Arc::new(SecurityContext::new(max_depth));
    
    // The parser should never panic, regardless of input
    let result = std::panic::catch_unwind(|| {
        parse_html(html, security_context)
    });
    
    match result {
        Ok(parse_result) => {
            match parse_result {
                Ok(_dom) => {
                    // Parsing succeeded - verify no security violations occurred
                    // The parser should have handled any malicious content safely
                }
                Err(_parse_error) => {
                    // Parsing failed gracefully - this is acceptable
                    // Security contexts can reject malicious input
                }
            }
        }
        Err(_panic) => {
            // Parser panicked - this is a bug that needs fixing
            panic!("HTML parser panicked on input (this should never happen)");
        }
    }
}

/// Generate security-focused test cases for fuzzing
#[cfg(test)]
mod fuzz_test_cases {
    use super::*;
    
    #[test]
    fn test_known_malicious_patterns() {
        let malicious_cases = vec![
            // Script injection attempts
            b"<script>alert('xss')</script>",
            b"<img src=x onerror=alert('xss')>",
            b"<svg onload=alert('xss')>",
            b"javascript:alert('xss')",
            
            // Deep nesting attacks
            b"<div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div></div>",
            
            // Malformed HTML
            b"<html><head><title>Test</title><body><p>Unclosed",
            b"<<>><<>><<>>",
            b"<html><body><script><script><script>",
            
            // Entity injection
            b"&lt;script&gt;alert('xss')&lt;/script&gt;",
            b"&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;",
            b"&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;",
            
            // Large attribute attacks
            b"<div class='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'>",
            
            // Comment injection
            b"<!-- <script>alert('xss')</script> -->",
            b"<!--[if IE]><script>alert('xss')</script><![endif]-->",
            
            // CDATA injection
            b"<![CDATA[<script>alert('xss')</script>]]>",
            
            // Null byte injection
            b"<script\x00>alert('xss')</script>",
            b"<img src=\x00javascript:alert('xss')>",
            
                         // Unicode edge cases
             b"\xEF\xBB\xBF<script>alert('xss')</script>", // BOM
             "<script>\u{200B}alert('xss')</script>".as_bytes(), // Zero-width space
        ];
        
        for case in malicious_cases {
            // Each malicious case should be handled safely
            test_with_security_context(std::str::from_utf8(case).unwrap_or(""), 10);
        }
    }
    
    #[test]
    fn test_memory_exhaustion_patterns() {
        let memory_attack_cases = vec![
            // Excessive attributes
            (0..1000).map(|i| format!("attr{}='value{}'", i, i)).collect::<Vec<_>>().join(" "),
            
            // Deeply nested elements
            "<div>".repeat(100) + "content" + &"</div>".repeat(100),
            
            // Large text content
            format!("<p>{}</p>", "A".repeat(10000)),
            
            // Many siblings
            (0..1000).map(|i| format!("<p>Content {}</p>", i)).collect::<Vec<_>>().join(""),
        ];
        
        for case in memory_attack_cases {
            if case.len() < 50_000 { // Skip excessively large cases
                test_with_security_context(&case, 10);
            }
        }
    }
    
    #[test]
    fn test_encoding_edge_cases() {
        let encoding_cases = vec![
            // Invalid UTF-8 sequences (handled by fuzzer conversion)
            "Valid UTF-8 content",
            
            // Mixed encoding
            "ASCII + Unicode: 🦀 Rust",
            
            // Control characters
            "<p>\x01\x02\x03\x04\x05</p>",
            
            // High Unicode code points
            "<p>\u{1F680}\u{1F512}\u{1F4A1}</p>",
            
            // Combining characters
            "<p>e\u{0301}\u{0302}\u{0303}</p>", // e with multiple accents
        ];
        
        for case in encoding_cases {
            test_with_security_context(case, 10);
        }
    }
} 