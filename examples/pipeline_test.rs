use std::sync::Arc;
use citadel_security::SecurityContext;
use citadel_parser::html;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing Citadel Browser Core Pipeline...");

    // Initialize security context
    let security_context = Arc::new(SecurityContext::default());

    // Test HTML parsing
    let test_html = r#"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Page</title>
    </head>
    <body>
        <h1>Hello World!</h1>
        <p>This is a test page for Citadel Browser.</p>
    </body>
    </html>
    "#;

    println!("Parsing HTML...");
    let dom = html::parse_html(test_html, security_context)?;

    println!("✅ HTML parsing successful!");
    println!("DOM root element: {:?}", dom.root());

    // Test CSS parsing
    let test_css = r#"
    body {
        font-family: Arial, sans-serif;
        margin: 0;
        padding: 20px;
    }
    h1 {
        color: #333;
        font-size: 2em;
    }
    p {
        color: #666;
        line-height: 1.5;
    }
    "#;

    println!("Parsing CSS...");
    let stylesheet = citadel_parser::css::parse_css(test_css, security_context.clone())?;

    println!("✅ CSS parsing successful!");
    println!("Parsed {} style rules", stylesheet.len());

    println!("\n🎉 Core pipeline test completed successfully!");
    println!("The browser engine components are working correctly.");

    Ok(())
}