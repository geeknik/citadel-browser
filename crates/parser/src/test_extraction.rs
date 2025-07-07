/// Test module for verifying content extraction functionality
use std::sync::Arc;
use crate::{parse_html, Dom};
use crate::security::SecurityContext;

/// Test HTML content extraction with a realistic page
pub fn test_page_content_extraction() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Testing Citadel Browser Content Extraction");
    println!("==============================================");
    
    // Sample HTML content similar to what a real page might have
    let html_content = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test Page for Citadel Browser</title>
</head>
<body>
    <header>
        <h1>Welcome to Citadel Browser Test Page</h1>
        <nav>
            <ul>
                <li><a href="#about">About</a></li>
                <li><a href="#features">Features</a></li>
                <li><a href="#security">Security</a></li>
            </ul>
        </nav>
    </header>
    
    <main>
        <section id="about">
            <h2>About Citadel Browser</h2>
            <p>Citadel Browser is a privacy-first browser built with Rust. It prioritizes user security and privacy above all else.</p>
            <p>This test page helps verify that content extraction and display are working correctly.</p>
        </section>
        
        <section id="features">
            <h2>Key Features</h2>
            <ul>
                <li>Advanced privacy protection</li>
                <li>Security-first architecture</li>
                <li>Modern Rust implementation</li>
                <li>Enhanced anti-fingerprinting</li>
            </ul>
        </section>
        
        <section id="security">
            <h2>Security Benefits</h2>
            <p>Our security model includes:</p>
            <ol>
                <li>Memory safety through Rust</li>
                <li>Sandboxed execution environments</li>
                <li>Comprehensive content filtering</li>
                <li>Zero-knowledge virtual machine</li>
            </ol>
        </section>
    </main>
    
    <footer>
        <p>&copy; 2024 Citadel Browser Project. Built for privacy and security.</p>
    </footer>
    
    <!-- This script should be filtered out for security -->
    <script>
        console.log("This script should be filtered by security policies");
        alert("This alert should not appear");
    </script>
</body>
</html>"#;
    
    println!("📄 Testing HTML: {} bytes", html_content.len());
    
    // Create security context for parsing
    let parser_security_context = Arc::new(SecurityContext::new(15));
    
    // Parse the HTML using citadel-parser
    println!("🔍 Parsing HTML with citadel-parser...");
    let dom = parse_html(html_content, parser_security_context)?;
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
    
    Ok(())
}