//! HTML parsing implementation for Citadel, focusing on security and privacy.
//!
//! This module uses kuchiki (built on html5ever) for reliable HTML parsing
//! with proper TreeSink implementation, while preserving Citadel's security
//! and privacy features.

use std::sync::Arc;
use std::io;

use kuchiki::parse_html as kuchiki_parse_html;
use kuchiki::traits::TendrilSink;

use crate::dom::Dom;
use crate::security::SecurityContext;
use crate::metrics::DocumentMetrics;
use crate::error::ParserError;

mod converter;  // Module for converting kuchiki DOM to Citadel DOM

/// Parse an HTML string into a Citadel DOM tree
///
/// This function uses kuchiki for reliable HTML parsing, then converts
/// the resulting DOM to Citadel's internal DOM representation while
/// applying security policies.
pub fn parse_html(
    html: &str,
    security_context: Arc<SecurityContext>,
) -> Result<Dom, ParserError> {
    tracing::debug!("🔍 Starting HTML parsing with {} characters", html.len());

    // Parse HTML using kuchiki (built on html5ever with proper TreeSink)
    // kuchiki's one() method returns NodeRef directly, not a Result
    let kuchiki_document = kuchiki_parse_html().one(html);
    tracing::debug!("✅ Kuchiki HTML parsing successful");

    // Convert kuchiki DOM to Citadel DOM with security filtering
    let metrics = Arc::new(DocumentMetrics::new());
    let citadel_dom = converter::kuchiki_to_citadel_dom(kuchiki_document, security_context, metrics)?;

    tracing::debug!("✅ HTML parsing complete - Citadel DOM created");
    Ok(citadel_dom)
}

/// Parses an HTML document from a reader
///
/// Similar to parse_html but works with any Read source
pub fn parse_html_from_reader<R: io::Read>(
    mut input: R,
    security_context: Arc<SecurityContext>,
) -> Result<Dom, ParserError> {
    tracing::debug!("🔍 Starting HTML parsing from reader");

    // Read input into a buffer first
    let mut buffer = Vec::new();
    if let Err(e) = input.read_to_end(&mut buffer) {
        return Err(ParserError::IoError(e.to_string()));
    }

    // Convert to string for parsing
    let html_string = match String::from_utf8(buffer.clone()) {
        Ok(s) => s,
        Err(_e) => {
            tracing::warn!("⚠️ HTML contains invalid UTF-8, attempting lossy conversion");
            String::from_utf8_lossy(&buffer).into_owned()
        }
    };

    // Parse the HTML string
    parse_html(&html_string, security_context)
}

/// Parse HTML fragments (partial HTML without full document structure)
///
/// Useful for parsing snippets, innerHTML, or dynamic content
pub fn parse_html_fragment(
    fragment: &str,
    security_context: Arc<SecurityContext>,
) -> Result<Dom, ParserError> {
    tracing::debug!("🔍 Parsing HTML fragment with {} characters", fragment.len());

    // For fragments, wrap in minimal HTML structure if needed
    let html_to_parse = if fragment.trim().starts_with("<html") ||
                           fragment.trim().starts_with("<!DOCTYPE") {
        fragment.to_string()
    } else {
        format!("<!DOCTYPE html><html><body>{}</body></html>", fragment)
    };

    parse_html(&html_to_parse, security_context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityContext;

    #[test]
    fn test_basic_html_parsing() {
        let security_context = Arc::new(SecurityContext::new(100));
        let html = r#"
        <!DOCTYPE html>
        <html>
        <head><title>Test</title></head>
        <body>
            <h1>Hello World</h1>
            <p>This is a test.</p>
        </body>
        </html>
        "#;

        let result = parse_html(html, security_context);
        assert!(result.is_ok(), "HTML parsing should succeed");

        let dom = result.unwrap();
        let title = dom.get_title();
        assert_eq!(title, "Test");

        let text_content = dom.get_text_content();
        assert!(text_content.contains("Hello World"));
        assert!(text_content.contains("This is a test"));
    }

    #[test]
    fn test_malformed_html_parsing() {
        let security_context = Arc::new(SecurityContext::new(100));
        let html = r#"
        <html>
        <head><title>Malformed</title>
        <body>
            <p>Unclosed paragraph
            <div>Nested content</div>
            <img src="test.jpg">
        "#;

        let result = parse_html(html, security_context);
        assert!(result.is_ok(), "Even malformed HTML should parse");

        let dom = result.unwrap();
        let title = dom.get_title();
        assert_eq!(title, "Malformed");
    }

    #[test]
    fn test_security_filtering() {
        let security_context = Arc::new(SecurityContext::new(100));
        let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <p>Safe content</p>
            <script>alert('xss')</script>
            <iframe src="javascript:evil()"></iframe>
        </body>
        </html>
        "#;

        let result = parse_html(html, security_context);
        assert!(result.is_ok(), "HTML with scripts should parse but be filtered");

        let dom = result.unwrap();
        let text_content = dom.get_text_content();

        // Safe content should be present
        assert!(text_content.contains("Safe content"));

        // Scripts should be filtered out (not in text content)
        assert!(!text_content.contains("alert('xss')"));
        assert!(!text_content.contains("javascript:evil()"));
    }

    #[test]
    fn test_fragment_parsing() {
        let security_context = Arc::new(SecurityContext::new(100));
        let fragment = r#"
            <div class="container">
                <h2>Fragment Title</h2>
                <p>Fragment content</p>
            </div>
        "#;

        let result = parse_html_fragment(fragment, security_context);
        assert!(result.is_ok(), "Fragment parsing should succeed");

        let dom = result.unwrap();
        let text_content = dom.get_text_content();
        assert!(text_content.contains("Fragment Title"));
        assert!(text_content.contains("Fragment content"));
    }
}