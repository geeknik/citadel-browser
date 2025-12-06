use std::sync::Arc;
use citadel_parser::{html, security::SecurityContext};

fn main() {
    println!("🌐 Testing HTML parsing with real-world content...");

    // Real HTML from example.com (compact version)
    let real_html = r#"
    <!doctype html>
    <html lang="en">
    <head>
        <title>Example Domain</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {
                background: #eee;
                width: 60vw;
                margin: 15vh auto;
                font-family: system-ui, sans-serif
            }
            h1 {
                font-size: 1.5em
            }
            div {
                opacity: 0.8
            }
            a:link, a:visited {
                color: #348
            }
        </style>
    </head>
    <body>
        <div>
            <h1>Example Domain</h1>
            <p>This domain is for use in documentation examples without needing permission. Avoid use in operations.</p>
            <p><a href="https://iana.org/domains/example">Learn more</a></p>
        </div>
    </body>
    </html>
    "#;

    // Create security context
    let security_context = Arc::new(SecurityContext::new(100));

    match html::parse_html(real_html, security_context) {
        Ok(dom) => {
            println!("✅ Real HTML parsing successful!");

            // Test DOM traversal
            let root = dom.root();
            println!("Root node exists: {}", Arc::strong_count(&root) > 0);

            // Extract title
            let title = dom.get_title();
            println!("Page title: {}", title);

            // Extract text content
            let text_content = dom.get_text_content();
            println!("Text content ({} chars): {}", text_content.len(), text_content);

            // Test element selection
            let headings = dom.get_elements_by_tag_name("h1");
            println!("Found {} h1 elements", headings.len());

            let links = dom.get_elements_by_tag_name("a");
            println!("Found {} link elements", links.len());

            // Test ID and class selection
            let element_by_id = dom.get_element_by_id("nonexistent");
            println!("Non-existent ID search: {:?}", element_by_id.is_some());

            // Count total elements
            let element_count = dom.count_elements();
            println!("Total DOM elements: {}", element_count);

            println!("✅ Real HTML parser test completed successfully!");
        }
        Err(e) => {
            println!("❌ Real HTML parsing failed: {:?}", e);
        }
    }
}