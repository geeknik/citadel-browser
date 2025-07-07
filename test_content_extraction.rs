#!/usr/bin/env cargo script

//! Test script to verify page content extraction is working correctly
//! 
//! Run with: cargo run --bin test_content_extraction

use std::sync::Arc;
use std::fs;

// Import the parser crate components
use citadel_parser::{parse_html, Dom};
use citadel_security::context::SecurityContext as ParserSecurityContext;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging to see our debug output
    env_logger::init();
    
    println!("🧪 Testing Citadel Browser Content Extraction");
    println!("==============================================");
    
    // Read our test HTML file
    let html_content = fs::read_to_string("test_page_content.html")?;
    println!("📄 Loaded test HTML: {} bytes", html_content.len());
    
    // Create security context for parsing
    let parser_security_context = Arc::new(ParserSecurityContext::new(15));
    
    // Parse the HTML using citadel-parser
    println!("🔍 Parsing HTML with citadel-parser...");
    let dom = parse_html(&html_content, parser_security_context)?;
    println!("✅ DOM parsing completed successfully");
    
    // Extract title
    let title = dom.get_title();
    println!("📑 Extracted title: '{}'", title);
    
    // Extract content
    let content = dom.get_text_content();
    println!("📝 Extracted content: {} characters", content.len());
    
    // Display content preview
    println!("\n📖 Content Preview:");
    println!("{}", "=".repeat(50));
    if content.len() > 500 {
        println!("{}...", &content[..500]);
        println!("(truncated - showing first 500 characters)");
    } else {
        println!("{}", content);
    }
    println!("{}", "=".repeat(50));
    
    // Verify key content is present
    let mut tests_passed = 0;
    let mut tests_total = 0;
    
    // Test 1: Title extraction
    tests_total += 1;
    if title == "Test Page for Citadel Browser" {
        println!("✅ Test 1 PASSED: Title extraction");
        tests_passed += 1;
    } else {
        println!("❌ Test 1 FAILED: Expected 'Test Page for Citadel Browser', got '{}'", title);
    }
    
    // Test 2: Content contains expected text
    tests_total += 1;
    if content.contains("Welcome to Citadel Browser Test Page") {
        println!("✅ Test 2 PASSED: Main heading present");
        tests_passed += 1;
    } else {
        println!("❌ Test 2 FAILED: Main heading not found in content");
    }
    
    // Test 3: Security features mentioned
    tests_total += 1;
    if content.contains("privacy-first browser") {
        println!("✅ Test 3 PASSED: Privacy description present");
        tests_passed += 1;
    } else {
        println!("❌ Test 3 FAILED: Privacy description not found");
    }
    
    // Test 4: Script content should be filtered out
    tests_total += 1;
    if !content.contains("alert(") && !content.contains("console.log") {
        println!("✅ Test 4 PASSED: Script content properly filtered");
        tests_passed += 1;
    } else {
        println!("❌ Test 4 FAILED: Script content not filtered (security risk!)");
    }
    
    // Test 5: List items are extracted
    tests_total += 1;
    if content.contains("Advanced privacy protection") && content.contains("Memory safety through Rust") {
        println!("✅ Test 5 PASSED: List content extracted");
        tests_passed += 1;
    } else {
        println!("❌ Test 5 FAILED: List content missing");
    }
    
    // Summary
    println!("\n🎯 Test Results: {}/{} tests passed", tests_passed, tests_total);
    
    if tests_passed == tests_total {
        println!("🎉 ALL TESTS PASSED! Content extraction is working correctly.");
        println!("✅ The browser should now be able to display page content properly.");
    } else {
        println!("⚠️  Some tests failed. Content extraction needs attention.");
        return Err("Content extraction tests failed".into());
    }
    
    println!("\n💡 You can now test the browser by running: cargo run --bin citadel-browser");
    println!("   Try loading a simple webpage to see if content displays correctly.");
    
    Ok(())
}