//! Converter from kuchiki DOM to Citadel DOM
//!
//! This module handles the conversion from kuchiki's DOM representation
//! to Citadel's internal DOM representation while applying security
//! filtering and preserving privacy features.

use std::sync::Arc;
use kuchiki::{NodeRef, NodeData as KuchikiNodeData, ElementData, Attributes};
use html5ever::{QualName, ns, namespace_url, LocalName};
use kuchiki::traits::TendrilSink;

use crate::dom::{Dom, Node, NodeData, NodeHandle, Element, Attribute, NodeBuilder};
use crate::security::SecurityContext;
use crate::metrics::{DocumentMetrics};
use crate::dom::metrics::DomMetrics;

/// Convert a kuchiki DOM to Citadel DOM with security filtering
pub fn kuchiki_to_citadel_dom(
    kuchiki_document: NodeRef,
    security_context: Arc<SecurityContext>,
    metrics: Arc<DocumentMetrics>,
) -> Result<Dom, crate::error::ParserError> {
    tracing::debug!("🔄 Starting kuchiki to Citadel DOM conversion");

    // Create Citadel DOM
    let mut citadel_dom = Dom::new();

    // Create node builder with security context
    let dom_metrics = Arc::new(DomMetrics::new());
    let node_builder = Arc::new(NodeBuilder::new(dom_metrics, security_context.clone()));

    // Convert the root node and its children
    let root_handle = citadel_dom.root();
    convert_node_recursive(
        &kuchiki_document,
        &mut citadel_dom,
        &node_builder,
        &security_context,
        root_handle,
        0,
        &metrics
    )?;

    tracing::debug!("✅ DOM conversion complete");
    Ok(citadel_dom)
}

/// Recursively convert kuchiki nodes to Citadel DOM nodes
fn convert_node_recursive(
    kuchiki_node: &NodeRef,
    citadel_dom: &mut Dom,
    node_builder: &Arc<NodeBuilder>,
    security_context: &Arc<SecurityContext>,
    parent_handle: NodeHandle,
    depth: usize,
    _metrics: &DocumentMetrics,
) -> Result<(), crate::error::ParserError> {
    // Prevent deep recursion attacks
    if depth > security_context.max_nesting_depth() {
        tracing::warn!("⚠️ Maximum DOM depth exceeded, stopping recursion at depth {}", depth);
        return Ok(());
    }

    let citadel_node = match kuchiki_node.data() {
        KuchikiNodeData::Element(ref element_data) => {
            convert_element_node(
                element_data,
                node_builder,
                security_context,
                kuchiki_node,
            )?
        }
        KuchikiNodeData::Text(ref text) => {
            let text_content = text.borrow();
            Some(create_text_node(&text_content, node_builder))
        }
        KuchikiNodeData::Comment(ref comment) => {
            let comment_content = comment.borrow();
            Some(create_comment_node(&comment_content, node_builder))
        }
        KuchikiNodeData::Document(_) => {
            // Document node - no need to create a corresponding Citadel node
            None
        }
        KuchikiNodeData::Doctype(ref doctype) => {
            Some(create_doctype_node(doctype, node_builder))
        }
        // Skip processing instructions - kuchiki doesn't expose them directly
        _ => {
            None
        }
    };

    // If we created a node, add it to the parent
    if let Some(node_handle) = citadel_node {
        citadel_dom.append_child(&parent_handle, node_handle.clone());

        // Recursively process children
        for child in kuchiki_node.children() {
            convert_node_recursive(
                &child,
                citadel_dom,
                node_builder,
                security_context,
                node_handle.clone(),
                depth + 1,
                _metrics,
            )?;
        }
    } else if matches!(kuchiki_node.data(), KuchikiNodeData::Document(_)) {
        // For document nodes, just process children directly
        for child in kuchiki_node.children() {
            convert_node_recursive(
                &child,
                citadel_dom,
                node_builder,
                security_context,
                parent_handle.clone(),
                depth + 1,
                _metrics,
            )?;
        }
    } else {
        // Blocked element: drop entire subtree to avoid leaking script/style contents
        tracing::debug!("🚫 Dropping blocked node and its children");
    }

    Ok(())
}

/// Convert a kuchiki element to Citadel DOM element
fn convert_element_node(
    element_data: &ElementData,
    node_builder: &Arc<NodeBuilder>,
    security_context: &Arc<SecurityContext>,
    _kuchiki_node: &NodeRef,
) -> Result<Option<NodeHandle>, crate::error::ParserError> {
    let tag_name = element_data.name.local.as_ref();

    // Check if element is allowed by security policy
    if !security_context.is_element_allowed(tag_name) {
        tracing::debug!("🚫 Element <{}> blocked by security policy", tag_name);
        return Ok(None);
    }

    // Convert attributes with security filtering
    let attributes = convert_attributes(&element_data.attributes.borrow(), security_context)?;

    // Create QualName for the element using our own html5ever types
    let qual_name = QualName::new(
        None, // prefix
        ns!(html), // namespace
        LocalName::from(tag_name),
    );

    // Create the Citadel element node
    match node_builder.create_element_node(qual_name, attributes) {
        Ok(node_handle) => {
            tracing::debug!("✅ Created element node <{}>", tag_name);
            Ok(Some(node_handle))
        }
        Err(e) => {
            tracing::warn!("⚠️ Failed to create element node <{}>: {}", tag_name, e);
            // Create a safe fallback element instead of failing
            let safe_element = Element::new(
                QualName::new(None, ns!(html), LocalName::from("div")),
                Vec::new(),
            );
            let node_data = NodeData::Element(safe_element);
            Ok(Some(Node::create_new(node_data)))
        }
    }
}

/// Convert kuchiki attributes to Citadel attributes with security filtering
fn convert_attributes(
    kuchiki_attrs: &Attributes,
    security_context: &Arc<SecurityContext>,
) -> Result<Vec<Attribute>, crate::error::ParserError> {
    let mut citadel_attrs = Vec::new();

    // kuchiki uses an iterator-based approach for attributes
    for attr in kuchiki_attrs.map.iter() {
        let (local_name, html_attr) = attr;
        let attr_name = local_name.local.as_ref();
        let attr_value = html_attr.value.as_ref();

        // Check if attribute is allowed
        if security_context.is_attribute_allowed(attr_name) {
            // Additional security checks for certain attributes
            if is_safe_attribute_value(attr_name, attr_value, security_context) {
                let qual_name = QualName::new(
                    None, // prefix
                    ns!(), // namespace
                    LocalName::from(attr_name),
                );

                citadel_attrs.push(Attribute {
                    name: qual_name,
                    value: attr_value.to_string(),
                });

                tracing::debug!("✅ Allowed attribute: {}=\"{}\"", attr_name, attr_value);
            } else {
                tracing::debug!("🚫 Blocked attribute value: {}=\"{}\"", attr_name, attr_value);
            }
        } else {
            tracing::debug!("🚫 Blocked attribute: {}", attr_name);
        }
    }

    Ok(citadel_attrs)
}

/// Check if an attribute value is safe according to security policies
fn is_safe_attribute_value(
    attr_name: &str,
    attr_value: &str,
    _security_context: &Arc<SecurityContext>,
) -> bool {
    match attr_name.to_lowercase().as_str() {
        "href" | "src" | "action" | "formaction" => {
            // Check for dangerous URLs
            !attr_value.to_lowercase().starts_with("javascript:") &&
            !attr_value.to_lowercase().starts_with("data:") &&
            !attr_value.to_lowercase().starts_with("vbscript:")
        }
        "onclick" | "onload" | "onerror" | "onmouseover" | "onfocus" | "onblur" => {
            // Block all event handlers
            false
        }
        "style" => {
            // Check CSS for dangerous content
            !attr_value.to_lowercase().contains("javascript:") &&
            !attr_value.to_lowercase().contains("expression(")
        }
        "id" | "class" | "name" | "title" | "alt" | "placeholder" => {
            // Safe attributes
            true
        }
        _ => {
            // Default to allowing if not specifically dangerous
            !attr_value.to_lowercase().contains("javascript:") &&
            !attr_value.to_lowercase().contains("vbscript:")
        }
    }
}

/// Create a text node
fn create_text_node(text: &str, node_builder: &Arc<NodeBuilder>) -> NodeHandle {
    // Trim and sanitize text content
    let sanitized_text = sanitize_text(text);
    node_builder.text_node(sanitized_text)
}

/// Create a comment node
fn create_comment_node(comment: &str, node_builder: &Arc<NodeBuilder>) -> NodeHandle {
    node_builder.comment(comment.to_string())
}

/// Create a doctype node (simplified)
fn create_doctype_node(doctype: &kuchiki::Doctype, node_builder: &Arc<NodeBuilder>) -> NodeHandle {
    // For simplicity, just use the name and ignore public/system IDs
    node_builder.doctype(
        doctype.name.to_string(),
        String::new(),
        String::new(),
    )
}

/// Sanitize text content
fn sanitize_text(text: &str) -> String {
    // Basic text sanitization
    // In a full implementation, this could include:
    // - Null byte removal
    // - Control character normalization
    // - Unicode normalization

    text.chars()
        .filter(|c| *c != '\0' && !c.is_control() || *c == '\n' || *c == '\t')
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityContext;
    use kuchiki::parse_html as kuchiki_parse_html;

    #[test]
    fn test_kuchiki_to_citadel_conversion() {
        let security_context = Arc::new(SecurityContext::new(100));
        let metrics = Arc::new(DocumentMetrics::new());

        let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Test Document</title>
        </head>
        <body>
            <h1>Hello World</h1>
            <p>This is a <strong>test</strong> paragraph.</p>
            <!-- This is a comment -->
        </body>
        </html>
        "#;

        let kuchiki_doc = kuchiki_parse_html().one(html);
        let citadel_dom = kuchiki_to_citadel_dom(kuchiki_doc, security_context, metrics).unwrap();

        assert_eq!(citadel_dom.get_title(), "Test Document");
        let text = citadel_dom.get_text_content();
        assert!(text.contains("Hello World"));
        assert!(text.contains("test"));
    }

    #[test]
    fn test_security_filtering_in_conversion() {
        let security_context = Arc::new(SecurityContext::new(100));
        let metrics = Arc::new(DocumentMetrics::new());

        let html = r#"
        <html>
        <body>
            <p>Safe content</p>
            <script>alert('xss')</script>
            <img src="javascript:evil()" onerror="alert('xss')">
            <a href="javascript:malicious()">Bad link</a>
            <a href="https://example.com">Good link</a>
        </body>
        </html>
        "#;

        let kuchiki_doc = kuchiki_parse_html().one(html);
        let citadel_dom = kuchiki_to_citadel_dom(kuchiki_doc, security_context, metrics).unwrap();

        let text = citadel_dom.get_text_content();

        // Safe content should be present
        assert!(text.contains("Safe content"));
        assert!(text.contains("Good link"));

        // Script content should be filtered out
        assert!(!text.contains("alert('xss')"));
        assert!(!text.contains("malicious()"));
    }

    #[test]
    fn test_attribute_filtering() {
        let security_context = Arc::new(SecurityContext::new(100));
        let metrics = Arc::new(DocumentMetrics::new());

        let html = r#"
        <html>
        <body>
            <div id="test" class="container" style="color: red;" onclick="alert('xss')"
                 data-safe="value" data-danger="javascript:evil()">
                Content
            </div>
        </body>
        </html>
        "#;

        let kuchiki_doc = kuchiki_parse_html().one(html);
        let citadel_dom = kuchiki_to_citadel_dom(kuchiki_doc, security_context, metrics).unwrap();

        // Find the div element
        if let Some(div_handle) = citadel_dom.get_element_by_id("test") {
            if let Ok(div_node) = div_handle.read() {
                if let crate::dom::node::NodeData::Element(element) = &div_node.data {
                    // Check that safe attributes are preserved
                    assert!(element.attributes.iter().any(|a| a.name.local.as_ref() == "id"));
                    assert!(element.attributes.iter().any(|a| a.name.local.as_ref() == "class"));

                    // Check that dangerous attributes are filtered
                    assert!(!element.attributes.iter().any(|a| a.name.local.as_ref() == "onclick"));

                    // Check data attributes - safe ones should remain, dangerous ones filtered
                    let data_attrs: Vec<_> = element.attributes.iter()
                        .filter(|a| a.name.local.as_ref().starts_with("data-"))
                        .collect();

                    assert!(data_attrs.iter().any(|a| a.name.local.as_ref() == "data-safe"));
                    assert!(!data_attrs.iter().any(|a| a.name.local.as_ref() == "data-danger"));
                }
            }
        }
    }
}
