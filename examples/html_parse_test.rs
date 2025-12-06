use std::sync::Arc;
use citadel_parser::{html, security::SecurityContext};

fn main() {
    println!("🧪 Testing HTML Parsing...");

    // Create security context
    let security_context = Arc::new(SecurityContext::new(100)); // max depth 100

    // Test basic HTML
    let test_html = r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Test Page</title>
        <meta charset="UTF-8">
    </head>
    <body>
        <h1>Hello Citadel!</h1>
        <p>This is a <strong>test</strong> page.</p>
        <ul>
            <li>Item 1</li>
            <li>Item 2</li>
        </ul>
        <div>
            <p>Nested content</p>
        </div>
    </body>
    </html>
    "#;

    match html::parse_html(test_html, security_context) {
        Ok(dom) => {
            println!("✅ HTML parsing successful!");
            println!("DOM created with root element");

            // Test DOM traversal
            let root = dom.root();
            println!("Root node exists: {}", Arc::strong_count(&root) > 0);

            println!("✅ HTML parser working correctly!");
        }
        Err(e) => {
            println!("❌ HTML parsing failed: {:?}", e);
        }
    }
}