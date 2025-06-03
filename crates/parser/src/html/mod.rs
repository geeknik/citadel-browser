//! HTML parsing implementation for Citadel, focusing on security and privacy.

mod tree_sink;

// Re-export necessary types from html5ever
use html5ever::{parse_document, tendril::TendrilSink};

use crate::dom::Dom;
use crate::security::SecurityContext;
use std::sync::Arc;
use std::default::Default;
use std::io::Cursor;
use crate::metrics::DocumentMetrics;
use crate::error::ParserError;

/// Parse an HTML string into a DOM tree
pub fn parse_html(
    html: &str,
    security_context: Arc<SecurityContext>,
) -> Result<Dom, ParserError> {
    let metrics = Arc::new(DocumentMetrics::new());
    let html_sink = tree_sink::create_html_sink(security_context, metrics);
    
    // Use TendrilSink trait to parse HTML
    let parser = parse_document(html_sink, Default::default());
    
    // Parse the HTML - parser.one() returns (Dom, QuirksMode) directly, not a Result
    let (dom, _quirks_mode) = parser.one(html);
    Ok(dom)
}

/// Parses an HTML document from a reader
pub fn parse_html_from_reader<R: std::io::Read>(
    mut input: R,
    security_context: Arc<SecurityContext>,
) -> Result<Dom, ParserError> {
    let metrics = Arc::new(DocumentMetrics::new());
    let html_sink = tree_sink::create_html_sink(security_context, metrics);
    
    // Read input into a buffer first
    let mut buffer = Vec::new();
    if let Err(e) = input.read_to_end(&mut buffer) {
        return Err(ParserError::IoError(e.to_string()));
    }
    let mut cursor = Cursor::new(buffer);

    // Use parse_document from html5ever, providing our custom sink
    let dom_result = parse_document(html_sink, Default::default())
        .from_utf8()
        .read_from(&mut cursor);

    // Handle potential errors from read_from
    match dom_result {
        Ok((dom, _)) => Ok(dom),
        Err(e) => Err(ParserError::HtmlParseError(e.to_string())),
    }
} 