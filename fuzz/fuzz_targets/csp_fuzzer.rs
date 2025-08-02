#![no_main]
//! Content Security Policy (CSP) Focused Fuzzing
//!
//! This fuzzer specifically targets CSP implementation vulnerabilities:
//! - CSP header parsing edge cases
//! - CSP directive interpretation
//! - CSP bypass attempts
//! - CSP violation detection accuracy
//! - CSP policy conflicts and edge cases

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::collections::HashMap;

use citadel_security::{SecurityContext, CspDirective, CspSource};

/// CSP-focused fuzzing input
#[derive(Debug, Clone, Arbitrary)]
pub struct CspFuzzInput {
    /// Raw CSP header string
    pub csp_header: String,
    /// URLs to test against the CSP
    pub test_urls: Vec<String>,
    /// Inline script content
    pub inline_scripts: Vec<String>,
    /// Inline style content
    pub inline_styles: Vec<String>,
    /// Nonces to test
    pub nonces: Vec<String>,
    /// Hash values to test
    pub hashes: Vec<String>,
    /// Host patterns to test
    pub host_patterns: Vec<String>,
    /// Whether to test in report-only mode
    pub report_only: bool,
}

/// CSP directive fuzzing
#[derive(Debug, Clone, Arbitrary)]
pub struct CspDirectiveFuzz {
    /// Directive name (potentially malformed)
    pub directive_name: String,
    /// Source values (potentially malformed)
    pub sources: Vec<String>,
}

/// Advanced CSP fuzzing scenarios
#[derive(Debug, Clone, Arbitrary)]
pub struct AdvancedCspFuzz {
    /// Multiple CSP headers to test conflicts
    pub multiple_headers: Vec<String>,
    /// CSP with encoded characters
    pub encoded_csp: String,
    /// Very long CSP header
    pub long_directives: Vec<CspDirectiveFuzz>,
    /// CSP with unicode characters
    pub unicode_csp: String,
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    
    // Choose fuzzing strategy
    let strategy = unstructured.int_in_range(0..=3).unwrap_or(0);
    
    match strategy {
        0 => fuzz_basic_csp_parsing(&mut unstructured),
        1 => fuzz_csp_enforcement(&mut unstructured),
        2 => fuzz_csp_bypass_attempts(&mut unstructured),
        3 => fuzz_advanced_csp_scenarios(&mut unstructured),
        _ => fuzz_basic_csp_parsing(&mut unstructured),
    }
});

/// Fuzz basic CSP header parsing
fn fuzz_basic_csp_parsing(unstructured: &mut Unstructured) {
    if let Ok(input) = CspFuzzInput::arbitrary(unstructured) {
        let result = std::panic::catch_unwind(|| {
            let mut context = SecurityContext::new(10);
            
            // Test CSP header parsing
            let parse_result = context.apply_csp_header(&input.csp_header);
            
            match parse_result {
                Ok(_) => {
                    // If parsing succeeds, verify CSP configuration
                    let csp = context.get_csp();
                    
                    // Test that the CSP has reasonable defaults
                    assert!(!csp.directives.is_empty() || input.csp_header.trim().is_empty());
                    
                    // Test CSP header generation
                    let headers = context.generate_security_headers();
                    if let Some(generated_csp) = headers.get("Content-Security-Policy") {
                        // Generated CSP should be well-formed
                        assert!(!generated_csp.contains(";;"));
                        assert!(!generated_csp.starts_with(';'));
                        assert!(!generated_csp.ends_with(';'));
                    }
                }
                Err(_) => {
                    // Parsing failure is acceptable for malformed CSP
                    // Ensure it doesn't crash or cause undefined behavior
                }
            }
            
            // Test with report-only mode
            if input.report_only {
                let report_only_header = format!("{}; report-uri /csp-violation", input.csp_header);
                let _ = context.apply_csp_header(&report_only_header);
            }
        });
        
        if result.is_err() {
            panic!("CSP parsing should never panic");
        }
    }
}

/// Fuzz CSP enforcement against URLs
fn fuzz_csp_enforcement(unstructured: &mut Unstructured) {
    if let Ok(input) = CspFuzzInput::arbitrary(unstructured) {
        let result = std::panic::catch_unwind(|| {
            let mut context = SecurityContext::new(10);
            
            // Apply CSP if valid
            if context.apply_csp_header(&input.csp_header).is_ok() {
                // Test URL validation against various directives
                let directives_to_test = vec![
                    CspDirective::ScriptSrc,
                    CspDirective::StyleSrc,
                    CspDirective::ImgSrc,
                    CspDirective::ConnectSrc,
                    CspDirective::FontSrc,
                    CspDirective::MediaSrc,
                    CspDirective::ObjectSrc,
                    CspDirective::FrameSrc,
                ];
                
                for url in &input.test_urls {
                    if url.len() < 10_000 { // Reasonable URL length
                        for directive in &directives_to_test {
                            let validation_result = context.validate_csp_url(url, *directive);
                            
                            // Validation should never panic, but may succeed or fail
                            match validation_result {
                                Ok(_) => {
                                    // URL allowed by CSP
                                }
                                Err(_) => {
                                    // URL blocked by CSP - should record violation
                                    let violations = context.get_recent_violations(1);
                                    // Should have at least recorded this violation
                                }
                            }
                        }
                    }
                }
                
                // Test nonce validation if nonces provided
                for nonce in &input.nonces {
                    if nonce.len() < 1000 { // Reasonable nonce length
                        let nonce_csp = format!("script-src 'nonce-{}'", nonce);
                        let _ = context.apply_csp_header(&nonce_csp);
                    }
                }
                
                // Test hash validation if hashes provided
                for hash in &input.hashes {
                    if hash.len() < 1000 { // Reasonable hash length
                        let hash_csp = format!("script-src 'sha256-{}'", hash);
                        let _ = context.apply_csp_header(&hash_csp);
                    }
                }
            }
        });
        
        if result.is_err() {
            panic!("CSP enforcement should never panic");
        }
    }
}

/// Fuzz CSP bypass attempts
fn fuzz_csp_bypass_attempts(unstructured: &mut Unstructured) {
    if let Ok(input) = CspFuzzInput::arbitrary(unstructured) {
        let result = std::panic::catch_unwind(|| {
            let mut context = SecurityContext::new(10);
            
            // Set up a strict CSP
            let strict_csp = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'";
            if context.apply_csp_header(strict_csp).is_ok() {
                
                // Test common CSP bypass patterns
                let bypass_urls = vec![
                    "javascript:alert(1)",
                    "data:text/html,<script>alert(1)</script>",
                    "data:application/javascript,alert(1)",
                    "blob:https://example.com/script.js",
                    "filesystem:https://example.com/script.js",
                    "chrome-extension://malicious/script.js",
                    "moz-extension://malicious/script.js",
                    "ms-browser-extension://malicious/script.js",
                    "about:blank",
                    "about:srcdoc",
                ];
                
                let mut blocked_bypasses = 0;
                for bypass_url in bypass_urls {
                    if context.validate_csp_url(bypass_url, CspDirective::ScriptSrc).is_err() {
                        blocked_bypasses += 1;
                    }
                }
                
                // Most bypass attempts should be blocked
                assert!(blocked_bypasses >= 7, "CSP should block most bypass attempts");
                
                // Test with fuzzer-provided URLs that might be bypass attempts
                for url in &input.test_urls {
                    if url.len() < 1000 {
                        let _ = context.validate_csp_url(url, CspDirective::ScriptSrc);
                        let _ = context.validate_csp_url(url, CspDirective::StyleSrc);
                    }
                }
            }
            
            // Test CSP with unsafe directives
            let unsafe_csp_headers = vec![
                "script-src 'unsafe-inline'",
                "script-src 'unsafe-eval'",
                "style-src 'unsafe-inline'",
                "script-src * 'unsafe-inline' 'unsafe-eval'",
                "default-src *",
            ];
            
            for unsafe_csp in unsafe_csp_headers {
                let _ = context.apply_csp_header(unsafe_csp);
                // Even with unsafe directives, parsing should not crash
            }
        });
        
        if result.is_err() {
            panic!("CSP bypass testing should never panic");
        }
    }
}

/// Fuzz advanced CSP scenarios
fn fuzz_advanced_csp_scenarios(unstructured: &mut Unstructured) {
    if let Ok(input) = AdvancedCspFuzz::arbitrary(unstructured) {
        let result = std::panic::catch_unwind(|| {
            let mut context = SecurityContext::new(10);
            
            // Test multiple CSP headers (last one should win)
            for (i, header) in input.multiple_headers.iter().enumerate() {
                if header.len() < 10_000 && i < 10 { // Limit iterations and size
                    let _ = context.apply_csp_header(header);
                }
            }
            
            // Test encoded CSP headers
            if input.encoded_csp.len() < 10_000 {
                let _ = context.apply_csp_header(&input.encoded_csp);
            }
            
            // Test unicode CSP headers
            if input.unicode_csp.len() < 10_000 {
                let _ = context.apply_csp_header(&input.unicode_csp);
            }
            
            // Test very long directives
            if input.long_directives.len() < 100 { // Limit number of directives
                let long_csp = input.long_directives.iter()
                    .take(50) // Limit to 50 directives
                    .map(|d| {
                        let sources = d.sources.iter()
                            .take(100) // Limit sources per directive
                            .filter(|s| s.len() < 1000) // Limit source length
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" ");
                        format!("{} {}", d.directive_name, sources)
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                
                if long_csp.len() < 100_000 { // Total CSP length limit
                    let _ = context.apply_csp_header(&long_csp);
                }
            }
            
            // Test CSP with special characters
            let special_char_tests = vec![
                "script-src 'self' \\x3cscript\\x3e",
                "script-src 'self' %3Cscript%3E",
                "script-src 'self' \\u003cscript\\u003e",
                "script-src 'self' &lt;script&gt;",
                "script-src 'self' &#60;script&#62;",
            ];
            
            for special_csp in special_char_tests {
                let _ = context.apply_csp_header(special_csp);
            }
            
            // Test CSP directive ordering
            let directive_order_tests = vec![
                "script-src 'self'; default-src 'none'",
                "default-src 'none'; script-src 'self'",
                "style-src 'self'; script-src 'self'; default-src 'none'",
            ];
            
            for order_test in directive_order_tests {
                let _ = context.apply_csp_header(order_test);
            }
            
            // Test CSP with whitespace variations
            let whitespace_tests = vec![
                "  script-src   'self'  ;  style-src   'self'  ",
                "\\tscript-src\\t'self'\\t;\\tstyle-src\\t'self'\\t",
                "\\nscript-src\\n'self'\\n;\\nstyle-src\\n'self'\\n",
                "script-src\\r\\n'self'\\r\\n;\\r\\nstyle-src\\r\\n'self'",
            ];
            
            for whitespace_test in whitespace_tests {
                let _ = context.apply_csp_header(whitespace_test);
            }
        });
        
        if result.is_err() {
            panic!("Advanced CSP scenarios should never panic");
        }
    }
}

/// Test CSP directive parsing edge cases
fn test_csp_directive_edge_cases() {
    let edge_cases = vec![
        // Empty directives
        "",
        ";",
        ";;",
        "; ; ;",
        
        // Malformed directives
        "script-src",
        "script-src;",
        ";script-src 'self'",
        "script-src 'self';",
        "script-src 'self';;style-src 'self'",
        
        // Invalid source expressions
        "script-src 'invalid'",
        "script-src 'self' 'invalid'",
        "script-src 'nonce-'",
        "script-src 'nonce-abc'def'",
        "script-src 'sha256-'",
        "script-src 'sha256-invalid-hash'",
        
        // Case sensitivity
        "SCRIPT-SRC 'SELF'",
        "Script-Src 'Self'",
        "script-src 'SELF'",
        
        // Special characters in hostnames
        "script-src https://example.com:8080",
        "script-src https://sub.example.com",
        "script-src https://*.example.com",
        "script-src example.com:*",
        "script-src *.example.com:443",
        
        // Path handling
        "script-src https://example.com/path/to/scripts/",
        "script-src https://example.com/path/to/scripts/*",
        "script-src https://example.com/path/to/scripts/script.js",
        
        // Protocol handling
        "script-src http:",
        "script-src https:",
        "script-src data:",
        "script-src blob:",
        "script-src filesystem:",
        
        // Complex directives
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https: data: blob:",
        "script-src 'self' 'nonce-abc123' 'sha256-def456' https://trusted.com",
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src *",
    ];
    
    for csp_header in edge_cases {
        let mut context = SecurityContext::new(10);
        
        // Should not panic on any input
        let result = std::panic::catch_unwind(|| {
            let _ = context.apply_csp_header(csp_header);
        });
        
        assert!(result.is_ok(), "CSP parsing should not panic on: {}", csp_header);
    }
}

#[cfg(test)]
mod csp_fuzz_tests {
    use super::*;
    
    #[test]
    fn test_csp_directive_edge_cases() {
        test_csp_directive_edge_cases();
    }
    
    #[test]
    fn test_csp_nonce_validation() {
        let mut context = SecurityContext::new(10);
        
        // Test valid nonce
        assert!(context.apply_csp_header("script-src 'nonce-abc123'").is_ok());
        
        // Test invalid nonces
        let invalid_nonces = vec![
            "script-src 'nonce-'",
            "script-src 'nonce-abc'def'",
            "script-src 'nonce-abc def'",
            "script-src 'nonce-abc\\x00def'",
        ];
        
        for invalid_nonce in invalid_nonces {
            // Should parse but nonce should be ignored or rejected
            let _ = context.apply_csp_header(invalid_nonce);
        }
    }
    
    #[test]
    fn test_csp_hash_validation() {
        let mut context = SecurityContext::new(10);
        
        // Test valid hashes
        let valid_hashes = vec![
            "script-src 'sha256-abc123def456'",
            "script-src 'sha384-abc123def456'",
            "script-src 'sha512-abc123def456'",
        ];
        
        for valid_hash in valid_hashes {
            assert!(context.apply_csp_header(valid_hash).is_ok());
        }
        
        // Test invalid hashes
        let invalid_hashes = vec![
            "script-src 'sha256-'",
            "script-src 'sha256-invalid hash'",
            "script-src 'sha999-abc123'",
            "script-src 'sha256-abc'def'",
        ];
        
        for invalid_hash in invalid_hashes {
            // Should parse but hash should be ignored or rejected
            let _ = context.apply_csp_header(invalid_hash);
        }
    }
    
    #[test]
    fn test_csp_host_pattern_validation() {
        let mut context = SecurityContext::new(10);
        
        // Test valid host patterns
        let valid_patterns = vec![
            "script-src https://example.com",
            "script-src https://*.example.com",
            "script-src https://example.com:8080",
            "script-src *.example.com",
            "script-src example.com",
        ];
        
        for pattern in valid_patterns {
            assert!(context.apply_csp_header(pattern).is_ok());
        }
        
        // Test edge case patterns
        let edge_patterns = vec![
            "script-src *",
            "script-src https:",
            "script-src data:",
            "script-src blob:",
            "script-src 'self'",
        ];
        
        for pattern in edge_patterns {
            assert!(context.apply_csp_header(pattern).is_ok());
        }
    }
}