#!/usr/bin/env rust-script

//! Test script to analyze the content extraction pipeline
//! 
//! This script tests the exact path content takes from HTML to UI display
//! to identify where content might be getting lost.

use std::sync::Arc;

// Mock the key functions to test content flow
fn mock_extract_content_enhanced(html: &str) -> String {
    let mut content = String::new();
    let mut in_tag = false;
    let mut in_script = false;
    let mut in_style = false;
    let mut in_noscript = false;
    let mut tag_name = String::new();
    
    let html_lower = html.to_lowercase();
    
    for (i, ch) in html.char_indices() {
        if ch == '<' {
            in_tag = true;
            tag_name.clear();
            
            // Check what tag we're entering
            let remaining = &html_lower[i..];
            if remaining.starts_with("<script") {
                in_script = true;
            } else if remaining.starts_with("<style") {
                in_style = true;
            } else if remaining.starts_with("<noscript") {
                in_noscript = true;
            }
        } else if ch == '>' && in_tag {
            in_tag = false;
            
            // Check if we're exiting certain tags
            if tag_name == "/script" {
                in_script = false;
            } else if tag_name == "/style" {
                in_style = false;
            } else if tag_name == "/noscript" {
                in_noscript = false;
            }
            
            tag_name.clear();
        } else if in_tag {
            // Build tag name for closing tag detection
            if ch.is_ascii_alphabetic() || ch == '/' {
                tag_name.push(ch);
            }
        } else if !in_tag && !in_script && !in_style && !in_noscript {
            content.push(ch);
        }
    }
    
    // Clean up the content more thoroughly
    content = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<&str>>()
        .join("\n")
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
        .trim()
        .to_string();
    
    // Decode common HTML entities
    content = content
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ");
    
    content
}

fn test_content_extraction() {
    println!("=== Testing Content Extraction Pipeline ===\n");
    
    // Test cases representing different types of web content
    let test_cases = vec![
        (
            "Simple HTML",
            r#"<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
    <h1>Hello World</h1>
    <p>This is a test paragraph.</p>
</body>
</html>"#
        ),
        (
            "Complex HTML with scripts",
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Complex Page</title>
    <script>console.log('hidden');</script>
    <style>body { color: red; }</style>
</head>
<body>
    <h1>Main Content</h1>
    <p>First paragraph with <strong>bold text</strong>.</p>
    <script>alert('more hidden');</script>
    <p>Second paragraph.</p>
</body>
</html>"#
        ),
        (
            "Whitespace heavy HTML",
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Whitespace Test</title>
</head>
<body>
    
    
    <h1>   Title with spaces   </h1>
    
    <p>
        Paragraph with
        line breaks and    multiple spaces.
    </p>
    
    
</body>
</html>"#
        ),
        (
            "X.com-like content",
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>X - Social Media</title>
    <script>var config = {};</script>
</head>
<body>
    <div id="react-root">
        <article>
            <div class="tweet-content">
                <p>This is a tweet with <a href="#">links</a></p>
                <p>And multiple paragraphs</p>
            </div>
        </article>
    </div>
</body>
</html>"#
        ),
    ];
    
    for (name, html) in test_cases {
        println!("--- Testing: {} ---", name);
        println!("Input HTML ({} chars):", html.len());
        println!("{}", html.chars().take(100).collect::<String>());
        if html.len() > 100 {
            println!("...");
        }
        println!();
        
        let extracted = mock_extract_content_enhanced(html);
        
        println!("Extracted content ({} chars):", extracted.len());
        if extracted.is_empty() {
            println!("❌ EMPTY - This would show 'No readable content found'");
        } else {
            println!("✅ Content extracted:");
            println!("'{}'", extracted);
        }
        println!();
        
        // Analyze what happened
        if extracted.trim().is_empty() {
            println!("🔍 ANALYSIS: Content extraction resulted in empty string");
            println!("This would trigger the 'No readable content found' UI path");
        } else if extracted.len() < 10 {
            println!("🔍 ANALYSIS: Very short content - might not be meaningful");
        } else {
            println!("🔍 ANALYSIS: Content extraction successful");
        }
        
        println!("\n" + "=".repeat(60) + "\n");
    }
}

fn test_ui_display_logic() {
    println!("=== Testing UI Display Logic ===\n");
    
    let test_contents = vec![
        ("", "Empty string"),
        ("   ", "Whitespace only"),
        ("Hello", "Simple text"),
        ("Hello\n\nWorld", "Text with newlines"),
        ("   Hello World   ", "Text with surrounding whitespace"),
    ];
    
    for (content, description) in test_contents {
        println!("Testing: {} - '{}'", description, content);
        
        // This is the UI logic condition
        if content.trim().is_empty() {
            println!("❌ UI would show: 'No readable content found'");
        } else {
            println!("✅ UI would show content in scrollable area");
        }
        println!();
    }
}

fn main() {
    test_content_extraction();
    test_ui_display_logic();
    
    println!("=== CONCLUSION ===");
    println!("If you're seeing 'No readable content found' in the browser,");
    println!("it's likely because the content extraction is producing empty strings");
    println!("after the aggressive whitespace normalization process.");
    println!();
    println!("Recommended fix: Reduce the aggressiveness of content cleaning");
    println!("and add debug logging to track content through the pipeline.");
}