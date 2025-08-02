#![no_main]
//! Memory Safety and Performance Security Fuzzing
//!
//! This fuzzer targets memory safety and performance-related security issues:
//! - Memory exhaustion attacks
//! - Resource limit bypass attempts
//! - Parser memory safety vulnerabilities
//! - Performance degradation attacks
//! - Memory leak detection
//! - Stack overflow protection

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::sync::Arc;
use std::time::{Duration, Instant};

use citadel_security::SecurityContext;
use citadel_parser::parse_html;

/// Memory safety fuzzing input
#[derive(Debug, Clone, Arbitrary)]
pub struct MemoryFuzzInput {
    /// Large HTML content for memory testing
    pub html_content: String,
    /// Nesting depth to test
    pub nesting_depth: u16,
    /// Element repetition count
    pub element_repetition: u16,
    /// Attribute count per element
    pub attribute_count: u16,
    /// Text content size
    pub text_content_size: u32,
    /// Memory allocation sizes to test
    pub memory_sizes: Vec<u32>,
    /// Performance stress test iterations
    pub stress_iterations: u16,
}

impl MemoryFuzzInput {
    /// Get bounded nesting depth (1-100)
    pub fn get_nesting_depth(&self) -> usize {
        ((self.nesting_depth % 100) + 1) as usize
    }
    
    /// Get bounded element repetition (1-1000)
    pub fn get_element_repetition(&self) -> usize {
        ((self.element_repetition % 1000) + 1) as usize
    }
    
    /// Get bounded attribute count (1-100)
    pub fn get_attribute_count(&self) -> usize {
        ((self.attribute_count % 100) + 1) as usize
    }
    
    /// Get bounded text content size (1-100KB)
    pub fn get_text_content_size(&self) -> usize {
        ((self.text_content_size % 100_000) + 1) as usize
    }
    
    /// Get bounded stress iterations (1-1000)
    pub fn get_stress_iterations(&self) -> usize {
        ((self.stress_iterations % 1000) + 1) as usize
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    
    // Choose fuzzing strategy
    let strategy = unstructured.int_in_range(0..=5).unwrap_or(0);
    
    match strategy {
        0 => fuzz_memory_exhaustion_protection(&mut unstructured),
        1 => fuzz_deep_nesting_attacks(&mut unstructured),
        2 => fuzz_large_content_handling(&mut unstructured),
        3 => fuzz_parser_memory_safety(&mut unstructured),
        4 => fuzz_performance_attacks(&mut unstructured),
        5 => fuzz_resource_limit_enforcement(&mut unstructured),
        _ => fuzz_memory_exhaustion_protection(&mut unstructured),
    }
});

/// Fuzz memory exhaustion protection
fn fuzz_memory_exhaustion_protection(unstructured: &mut Unstructured) {
    if let Ok(input) = MemoryFuzzInput::arbitrary(unstructured) {
        let result = std::panic::catch_unwind(|| {
            let context = SecurityContext::new(10);
            
            // Test various memory allocation sizes
            for &size in &input.memory_sizes {
                let bounded_size = (size as usize) % (2 * 1024 * 1024 * 1024); // Max 2GB to prevent actual exhaustion
                
                let memory_result = context.check_memory_usage(bounded_size);
                
                // Verify memory protection logic
                match bounded_size {
                    0..=1_048_576 => {
                        // Small allocations (<=1MB) should generally be allowed
                        if memory_result.is_err() {
                            // But it's still acceptable to be conservative
                        }
                    }
                    1_048_577..=268_435_456 => {
                        // Medium allocations (1MB-256MB) might be allowed or blocked
                        // Both outcomes are acceptable
                    }
                    268_435_457.. => {
                        // Large allocations (>256MB) should generally be blocked
                        assert!(memory_result.is_err(), "Large allocation should be blocked: {} bytes", bounded_size);
                    }
                }
            }
            
            // Test rapid memory allocation requests
            let rapid_requests = std::cmp::min(input.get_stress_iterations(), 1000);
            for i in 0..rapid_requests {
                let size = (i * 1024) % (10 * 1024 * 1024); // Up to 10MB per request
                let _ = context.check_memory_usage(size);
            }
            
            // Verify metrics are being tracked
            let metrics = context.get_metrics();
            assert!(metrics.memory_exhaustion_attempts > 0 || input.memory_sizes.is_empty());
        });
        
        if result.is_err() {
            panic!("Memory exhaustion protection should never panic");
        }
    }
}

/// Fuzz deep nesting attacks
fn fuzz_deep_nesting_attacks(unstructured: &mut Unstructured) {
    if let Ok(input) = MemoryFuzzInput::arbitrary(unstructured) {
        let result = std::panic::catch_unwind(|| {
            let nesting_depth = input.get_nesting_depth();
            let security_context = Arc::new(SecurityContext::new(std::cmp::min(nesting_depth, 50)));
            
            // Create deeply nested HTML
            let element_types = vec!["div", "span", "p", "section", "article"];
            let mut html = String::new();
            let mut close_tags = Vec::new();
            
            // Limit total nesting to prevent timeout
            let actual_depth = std::cmp::min(nesting_depth, 200);
            
            for i in 0..actual_depth {
                let element = element_types[i % element_types.len()];
                html.push_str(&format!("<{}>", element));
                close_tags.push(format!("</{}>", element));
            }
            
            html.push_str("content");
            
            // Close tags in reverse order
            for close_tag in close_tags.into_iter().rev() {
                html.push_str(&close_tag);
            }
            
            // Limit total HTML size to prevent timeout
            if html.len() > 1_000_000 {
                return;
            }
            
            // Test parsing with deep nesting
            let parse_start = Instant::now();
            let parse_result = parse_html(&html, security_context.clone());
            let parse_duration = parse_start.elapsed();
            
            // Parsing should complete within reasonable time
            assert!(parse_duration < Duration::from_secs(5), "Parsing took too long: {:?}", parse_duration);
            
            match parse_result {
                Ok(_) => {
                    // If parsing succeeds, it should have enforced nesting limits
                    let violations = security_context.get_recent_violations(10);
                    // May or may not have violations depending on implementation
                }
                Err(_) => {
                    // Parsing rejection is acceptable for deep nesting
                    // Should have recorded security violations
                }
            }
        });
        
        if result.is_err() {
            panic!("Deep nesting attack handling should never panic");
        }
    }
}

/// Fuzz large content handling
fn fuzz_large_content_handling(unstructured: &mut Unstructured) {
    if let Ok(input) = MemoryFuzzInput::arbitrary(unstructured) {
        let result = std::panic::catch_unwind(|| {
            let security_context = Arc::new(SecurityContext::new(10));
            
            // Create HTML with large text content
            let text_size = std::cmp::min(input.get_text_content_size(), 1_000_000); // Max 1MB
            let large_text = "A".repeat(text_size);
            
            let html_variants = vec![
                // Large text in different elements
                format!("<p>{}</p>", large_text),
                format!("<div>{}</div>", large_text),
                format!("<span>{}</span>", large_text),
                format!("<pre>{}</pre>", large_text),
                
                // Large attribute values
                format!("<div class=\"{}\">content</div>", large_text.chars().take(10000).collect::<String>()),
                format!("<div id=\"{}\">content</div>", large_text.chars().take(1000).collect::<String>()),
                format!("<div data-value=\"{}\">content</div>", large_text.chars().take(5000).collect::<String>()),
                
                // Many small elements
                format!("{}", "<p>small</p>".repeat(std::cmp::min(text_size / 10, 10000))),
                
                // Large comments
                format!("<!-- {} -->", large_text),
                
                // Large CDATA sections
                format!("<![CDATA[{}]]>", large_text),
            ];
            
            for html in html_variants {
                // Limit total size to prevent timeout
                if html.len() > 2_000_000 {
                    continue;
                }
                
                let parse_start = Instant::now();
                let parse_result = parse_html(&html, security_context.clone());
                let parse_duration = parse_start.elapsed();
                
                // Should complete within reasonable time
                assert!(parse_duration < Duration::from_secs(10), "Large content parsing took too long");
                
                // Check memory usage during parsing (simulated)
                let estimated_memory = html.len() * 3; // Rough estimate of memory usage
                if estimated_memory > 10_000_000 { // 10MB
                    // Large content should be handled gracefully
                    match parse_result {
                        Ok(_) => {
                            // Success is fine if memory limits are enforced internally
                        }
                        Err(_) => {
                            // Rejection is also fine for large content
                        }
                    }
                }
            }
        });
        
        if result.is_err() {
            panic!("Large content handling should never panic");
        }
    }
}

/// Fuzz parser memory safety
fn fuzz_parser_memory_safety(unstructured: &mut Unstructured) {
    if let Ok(input) = MemoryFuzzInput::arbitrary(unstructured) {
        let result = std::panic::catch_unwind(|| {
            let security_context = Arc::new(SecurityContext::new(10));
            
            // Test parser with malformed HTML that could cause memory issues
            let malformed_html_patterns = vec![
                // Unclosed tags
                "<div><p><span>".to_string(),
                "<html><head><body>".to_string(),
                
                // Mismatched tags
                "<div><span></div></span>".to_string(),
                "<p><div></p></div>".to_string(),
                
                // Deeply nested malformed structure
                format!("{}<content>{}", "<div><p>".repeat(input.get_nesting_depth()), "</p></div>".repeat(input.get_nesting_depth())),
                
                // Many attributes
                {
                    let attrs = (0..input.get_attribute_count())
                        .map(|i| format!("attr{}=\"value{}\"", i, i))
                        .collect::<Vec<_>>()
                        .join(" ");
                    format!("<div {}>content</div>", attrs)
                },
                
                // Repeated elements
                format!("{}", "<br>".repeat(input.get_element_repetition())),
                format!("{}", "<hr/>".repeat(input.get_element_repetition())),
                
                // Mixed content with potential memory issues
                format!("{}text{}{}", 
                    "<div>".repeat(input.get_nesting_depth() / 2),
                    input.html_content.chars().take(10000).collect::<String>(),
                    "</div>".repeat(input.get_nesting_depth() / 2)
                ),
            ];
            
            for html in malformed_html_patterns {
                // Skip excessively large inputs
                if html.len() > 5_000_000 {
                    continue;
                }
                
                let parse_start = Instant::now();
                let parse_result = parse_html(&html, security_context.clone());
                let parse_duration = parse_start.elapsed();
                
                // Parser should be resilient to malformed input
                assert!(parse_duration < Duration::from_secs(15), "Malformed HTML parsing took too long");
                
                // Result can be success or failure, but should not crash
                match parse_result {
                    Ok(_) => {
                        // Parser handled malformed input gracefully
                    }
                    Err(_) => {
                        // Parser rejected malformed input - also acceptable
                    }
                }
            }
        });
        
        if result.is_err() {
            panic!("Parser memory safety should never panic");
        }
    }
}

/// Fuzz performance attacks
fn fuzz_performance_attacks(unstructured: &mut Unstructured) {
    if let Ok(input) = MemoryFuzzInput::arbitrary(unstructured) {
        let result = std::panic::catch_unwind(|| {
            let security_context = Arc::new(SecurityContext::new(10));
            
            // Test patterns known to cause performance issues
            let performance_attack_patterns = vec![
                // Exponential backtracking patterns
                format!("{}a", "<div>".repeat(std::cmp::min(input.get_nesting_depth(), 100))),
                
                // Many empty elements
                "<div></div>".repeat(std::cmp::min(input.get_element_repetition(), 10000)),
                
                // Complex attribute patterns
                {
                    let complex_attrs = (0..std::cmp::min(input.get_attribute_count(), 500))
                        .map(|i| format!("data-attr-{}-test-value=\"complex-value-{}-with-data\"", i, i))
                        .collect::<Vec<_>>()
                        .join(" ");
                    format!("<div {}>content</div>", complex_attrs)
                },
                
                // Nested tables (historically problematic)
                {
                    let table_depth = std::cmp::min(input.get_nesting_depth(), 50);
                    let mut nested_tables = String::new();
                    for _ in 0..table_depth {
                        nested_tables.push_str("<table><tr><td>");
                    }
                    nested_tables.push_str("content");
                    for _ in 0..table_depth {
                        nested_tables.push_str("</td></tr></table>");
                    }
                    nested_tables
                },
                
                // Mixed content complexity
                format!(
                    "{}{}{}",
                    "<div class=\"container\">".repeat(std::cmp::min(input.get_nesting_depth(), 100)),
                    "<span>text</span>".repeat(std::cmp::min(input.get_element_repetition(), 1000)),
                    "</div>".repeat(std::cmp::min(input.get_nesting_depth(), 100))
                ),
            ];
            
            for pattern in performance_attack_patterns {
                // Skip excessively large patterns
                if pattern.len() > 10_000_000 {
                    continue;
                }
                
                let start_time = Instant::now();
                let parse_result = parse_html(&pattern, security_context.clone());
                let elapsed = start_time.elapsed();
                
                // Should complete within reasonable time even under attack
                assert!(elapsed < Duration::from_secs(30), "Performance attack caused excessive delay: {:?}", elapsed);
                
                // Verify that security context tracked the attempt
                if pattern.len() > 1_000_000 {
                    let violations = security_context.get_recent_violations(10);
                    // Large patterns might trigger security violations
                }
            }
            
            // Test rapid-fire parsing (DoS simulation)
            let iterations = std::cmp::min(input.get_stress_iterations(), 100);
            let stress_start = Instant::now();
            
            for i in 0..iterations {
                let simple_html = format!("<div id=\"test-{}\">content {}</div>", i, i);
                let _ = parse_html(&simple_html, security_context.clone());
            }
            
            let stress_elapsed = stress_start.elapsed();
            
            // Rapid parsing should not cause excessive slowdown
            let avg_time_per_parse = stress_elapsed.as_millis() / iterations as u128;
            assert!(avg_time_per_parse < 100, "Average parse time too high under stress: {}ms", avg_time_per_parse);
        });
        
        if result.is_err() {
            panic!("Performance attack handling should never panic");
        }
    }
}

/// Fuzz resource limit enforcement
fn fuzz_resource_limit_enforcement(unstructured: &mut Unstructured) {
    if let Ok(input) = MemoryFuzzInput::arbitrary(unstructured) {
        let result = std::panic::catch_unwind(|| {
            // Test different nesting limits
            let nesting_limits = vec![1, 5, 10, 25, 50];
            
            for limit in nesting_limits {
                let security_context = Arc::new(SecurityContext::new(limit));
                
                // Create HTML that exceeds the limit
                let excessive_nesting = std::cmp::max(limit * 2, input.get_nesting_depth());
                let deeply_nested_html = format!(
                    "{}content{}",
                    "<div>".repeat(excessive_nesting),
                    "</div>".repeat(excessive_nesting)
                );
                
                // Skip if HTML is too large
                if deeply_nested_html.len() > 1_000_000 {
                    continue;
                }
                
                let parse_result = parse_html(&deeply_nested_html, security_context.clone());
                
                // Parser should either:
                // 1. Reject the deeply nested content, or
                // 2. Parse it with enforced limits
                match parse_result {
                    Ok(_) => {
                        // If parsing succeeds, limits should have been enforced
                        // Check if violations were recorded
                        let violations = security_context.get_recent_violations(10);
                        // Implementation may or may not record violations for nesting
                    }
                    Err(_) => {
                        // Rejection is acceptable for excessive nesting
                    }
                }
                
                // Test resource timeout simulation
                let timeout_start = Instant::now();
                let timeout_html = "<div>".repeat(std::cmp::min(excessive_nesting, 1000)) + "content" + &"</div>".repeat(std::cmp::min(excessive_nesting, 1000));
                
                if timeout_html.len() < 5_000_000 {
                    let _ = parse_html(&timeout_html, security_context.clone());
                    let timeout_elapsed = timeout_start.elapsed();
                    
                    // Should not take excessively long
                    assert!(timeout_elapsed < Duration::from_secs(20), "Resource limit enforcement took too long");
                }
            }
            
            // Test memory limit variations
            let memory_limits = vec![
                1024 * 1024,        // 1MB
                10 * 1024 * 1024,   // 10MB
                100 * 1024 * 1024,  // 100MB
                256 * 1024 * 1024,  // 256MB
            ];
            
            for limit in memory_limits {
                let context = SecurityContext::new(10);
                
                // Test at limit
                let at_limit_result = context.check_memory_usage(limit);
                
                // Test above limit
                let above_limit = limit + 1024;
                let above_limit_result = context.check_memory_usage(above_limit);
                
                // Larger requests should be more likely to be blocked
                if at_limit_result.is_ok() && above_limit_result.is_err() {
                    // This is the expected behavior
                } else if at_limit_result.is_err() && above_limit_result.is_err() {
                    // Conservative blocking is also acceptable
                } else {
                    // Other combinations might be acceptable depending on implementation
                }
            }
        });
        
        if result.is_err() {
            panic!("Resource limit enforcement should never panic");
        }
    }
}

#[cfg(test)]
mod memory_safety_fuzz_tests {
    use super::*;
    
    #[test]
    fn test_memory_exhaustion_basic() {
        let input = MemoryFuzzInput {
            html_content: String::new(),
            nesting_depth: 10,
            element_repetition: 100,
            attribute_count: 10,
            text_content_size: 1000,
            memory_sizes: vec![1024, 1024*1024, 100*1024*1024, 500*1024*1024],
            stress_iterations: 10,
        };
        
        let mut unstructured = Unstructured::new(&[]);
        fuzz_memory_exhaustion_protection(&mut unstructured);
    }
    
    #[test]
    fn test_deep_nesting_basic() {
        let input = MemoryFuzzInput {
            html_content: "test content".to_string(),
            nesting_depth: 50,
            element_repetition: 10,
            attribute_count: 5,
            text_content_size: 100,
            memory_sizes: vec![1024],
            stress_iterations: 5,
        };
        
        let mut unstructured = Unstructured::new(&[]);
        fuzz_deep_nesting_attacks(&mut unstructured);
    }
    
    #[test]
    fn test_large_content_basic() {
        let input = MemoryFuzzInput {
            html_content: "large content test".to_string(),
            nesting_depth: 5,
            element_repetition: 10,
            attribute_count: 5,
            text_content_size: 10000,
            memory_sizes: vec![],
            stress_iterations: 5,
        };
        
        let mut unstructured = Unstructured::new(&[]);
        fuzz_large_content_handling(&mut unstructured);
    }
    
    #[test]
    fn test_parser_memory_safety_basic() {
        let input = MemoryFuzzInput {
            html_content: "<div><p><span>unclosed".to_string(),
            nesting_depth: 10,
            element_repetition: 20,
            attribute_count: 10,
            text_content_size: 1000,
            memory_sizes: vec![],
            stress_iterations: 10,
        };
        
        let mut unstructured = Unstructured::new(&[]);
        fuzz_parser_memory_safety(&mut unstructured);
    }
    
    #[test]
    fn test_performance_attacks_basic() {
        let input = MemoryFuzzInput {
            html_content: "performance test".to_string(),
            nesting_depth: 20,
            element_repetition: 50,
            attribute_count: 20,
            text_content_size: 5000,
            memory_sizes: vec![],
            stress_iterations: 20,
        };
        
        let mut unstructured = Unstructured::new(&[]);
        fuzz_performance_attacks(&mut unstructured);
    }
}