//! The Document Object Model (DOM) representation for Citadel.
//!
//! This module defines the core structures like Node, Element, and Attribute,
//! along with builders and metrics collection, emphasizing privacy and security.

// Declare submodules
pub mod error;
pub mod metrics;
pub mod node;

// Re-export key types for easier access from outside the dom module
pub use error::DomError;
pub use metrics::DomMetrics;
pub use node::{Attribute, Element, Node, NodeBuilder, NodeHandle, NodeData};

use std::sync::Arc;
use citadel_security::context::SecurityContext;

/// Represents the top-level DOM structure for a parsed document.
#[derive(Debug)]
pub struct Dom {
    /// The root node of the document (often the <html> element).
    pub document_node_handle: NodeHandle, // Using the Arc<RwLock<Node>> type alias
    /// Metrics collected during the parsing and DOM construction process.
    pub metrics: Arc<DomMetrics>,
    /// The security context applied during DOM construction.
    pub security_context: Arc<SecurityContext>,
    // Potentially add QuirksMode or other document-level properties here
}

impl Dom {
    /// Creates a new, empty DOM with a root document node.
    pub fn new() -> Self {
        // Create metrics and a root document node
        let metrics = Arc::new(DomMetrics::new());
        let security_context = Arc::new(SecurityContext::new(10));
        let root_node_data = NodeData::Document;
        let root_node = Node::new(root_node_data);
        let root_handle = Arc::new(std::sync::RwLock::new(root_node));

        Self {
            document_node_handle: root_handle,
            metrics,
            security_context,
        }
    }

    /// Get the root document node handle.
    pub fn root(&self) -> NodeHandle {
        self.document_node_handle.clone()
    }

    /// Appends a child node to a parent node.
    pub fn append_child(&mut self, parent: &NodeHandle, child: NodeHandle) {
        if let Ok(mut parent_node) = parent.write() {
            parent_node.children.push(child);
            self.metrics.increment_elements_created();
        }
    }

    /// Appends text content to a parent node.
    pub fn append_text(&mut self, parent: &NodeHandle, text: String) {
        if let Ok(mut parent_node) = parent.write() {
            let text_node = crate::dom::node::Node::create_new(
                crate::dom::node::NodeData::Text(text.clone())
            );
            parent_node.children.push(text_node);
            self.metrics.add_text_content(text.len());
        }
    }

    /// Inserts a new node before a specific sibling.
    pub fn insert_before(&mut self, _sibling: &NodeHandle, new_node: NodeHandle) {
        // This is a simplified implementation - in a full DOM, we'd need to:
        // 1. Find the parent of the sibling
        // 2. Find the index of the sibling in parent's children
        // 3. Insert the new node at that index
        // For now, we'll just append to the document root as a fallback
        self.append_child(&self.document_node_handle.clone(), new_node);
    }

    /// Inserts text content before a specific sibling.
    pub fn insert_text_before(&mut self, _sibling: &NodeHandle, text: &str) {
        // Similar to insert_before, this is simplified
        self.append_text(&self.document_node_handle.clone(), text.to_string());
    }

    /// Removes a node from its parent.
    pub fn remove_node(&mut self, node_to_remove: &NodeHandle) {
        // This is a simplified implementation - in a full DOM, we'd need to:
        // 1. Find the parent of the node
        // 2. Remove the node from parent's children vector
        // For now, we'll just mark it as removed (no-op)
        // In practice, when the node goes out of scope, it will be deallocated
        let _ = node_to_remove; // Acknowledge the parameter
    }

    /// Moves all children from one node to another.
    pub fn reparent_children(&mut self, source: &NodeHandle, target: &NodeHandle) {
        if let (Ok(mut source_node), Ok(mut target_node)) = (source.write(), target.write()) {
            // Move all children from source to target
            target_node.children.append(&mut source_node.children);
        }
    }

    /// Gets read access to a node.
    pub fn get_node<'a>(&self, handle: &'a NodeHandle) -> Option<std::sync::RwLockReadGuard<'a, Node>> {
        handle.read().ok()
    }

    /// Gets write access to a node.
    pub fn get_node_mut<'a>(&self, handle: &'a NodeHandle) -> Option<std::sync::RwLockWriteGuard<'a, Node>> {
        handle.write().ok()
    }
    
    /// Creates a document wrapper from this DOM
    pub fn into_document(self) -> crate::Document {
        // For now, this simply extracts the document node
        // In the future, we might want to wrap it with additional document-specific APIs
        let node = self.document_node_handle.read().ok()
            .expect("Failed to get read lock on document node")
            .clone();
        node
    }

    /// Get the title of the document by searching for <title> tag
    pub fn get_title(&self) -> String {
        self.extract_title_recursive(&self.document_node_handle)
    }

    /// Get the text content of the entire document
    pub fn get_text_content(&self) -> String {
        tracing::info!("🔍 DOM::get_text_content() called");
        
        let raw_content = self.extract_text_recursive(&self.document_node_handle);
        
        // Debug logging
        if raw_content.is_empty() {
            tracing::warn!("🔍 DOM text extraction: Raw content is empty - investigating DOM structure");
            
            // Debug: Examine the document structure when text extraction fails
            if let Ok(root_node) = self.document_node_handle.read() {
                tracing::info!("  🌳 Document root has {} children", root_node.children.len());
                
                for (i, child) in root_node.children.iter().enumerate() {
                    if let Ok(child_node) = child.read() {
                        match &child_node.data {
                            crate::dom::node::NodeData::Element(element) => {
                                tracing::info!("    Child {}: <{}> with {} children", i, element.local_name(), child_node.children.len());
                                
                                if element.local_name() == "html" {
                                    tracing::info!("      🎯 Found HTML! Examining its structure...");
                                    for (j, html_child) in child_node.children.iter().enumerate() {
                                        if let Ok(html_child_node) = html_child.read() {
                                            match &html_child_node.data {
                                                crate::dom::node::NodeData::Element(he) => {
                                                    tracing::info!("        HTML child {}: <{}> with {} children", j, he.local_name(), html_child_node.children.len());
                                                }
                                                crate::dom::node::NodeData::Text(t) => {
                                                    tracing::info!("        HTML child {}: TEXT '{}' ({} chars)", j, t.trim(), t.len());
                                                }
                                                _ => {
                                                    tracing::info!("        HTML child {}: Other", j);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            crate::dom::node::NodeData::Text(text) => {
                                tracing::info!("    Child {}: TEXT '{}' ({} chars)", i, text.trim(), text.len());
                            }
                            _ => {
                                tracing::info!("    Child {}: Other node type", i);
                            }
                        }
                    }
                }
            }
        } else {
            tracing::info!("🔍 DOM text extraction: Raw content {} chars: '{}'", raw_content.len(), 
                if raw_content.len() > 100 { &format!("{}...", &raw_content[..100]) } else { &raw_content });
        }
        
        // Clean up the extracted content
        // Replace multiple spaces with single spaces
        let cleaned = raw_content
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ");
            
        // Replace multiple newlines with double newlines for paragraph spacing
        let final_content = cleaned
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .collect::<Vec<&str>>()
            .join("\n\n");
            
        tracing::info!("🔍 DOM text extraction: Final content {} chars", final_content.len());
        if final_content.len() > 0 {
            let preview = if final_content.len() > 200 {
                format!("{}...", &final_content[..200])
            } else {
                final_content.clone()
            };
            tracing::info!("📚 Final content preview: '{}'", preview);
        }
        
        final_content
    }

    /// Recursively extract title from DOM tree
    fn extract_title_recursive(&self, node_handle: &NodeHandle) -> String {
        if let Ok(node) = node_handle.read() {
            // Check if this is a title element
            if let crate::dom::node::NodeData::Element(element) = &node.data {
                if element.local_name() == "title" {
                    // Extract ALL text content from title element's children
                    let mut title_text = String::new();
                    for child in &node.children {
                        title_text.push_str(&self.extract_text_recursive(child));
                    }
                    return title_text.trim().to_string();
                }
            }
            
            // Recursively search children
            for child in &node.children {
                let title = self.extract_title_recursive(child);
                if !title.is_empty() {
                    return title;
                }
            }
        }
        String::new()
    }

    /// Recursively extract all text content from DOM tree
    fn extract_text_recursive(&self, node_handle: &NodeHandle) -> String {
        let mut text_content = String::new();
        
        if let Ok(node) = node_handle.read() {
            match &node.data {
                crate::dom::node::NodeData::Text(text) => {
                    // Add the text content, trimming excessive whitespace
                    let trimmed_text = text.trim();
                    if !trimmed_text.is_empty() {
                        tracing::debug!("📄 Found text node: '{}' ({} chars)", trimmed_text, trimmed_text.len());
                        text_content.push_str(trimmed_text);
                        text_content.push(' '); // Add space after text nodes
                    }
                }
                crate::dom::node::NodeData::Element(element) => {
                    // Skip script and style elements
                    let tag_name = element.local_name();
                    if tag_name != "script" && tag_name != "style" {
                        tracing::debug!("🏷️ Processing element <{}> with {} children", tag_name, node.children.len());
                        
                        // Check if this is a block element that should have spacing
                        let is_block_element = matches!(tag_name, 
                            "div" | "p" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | 
                            "section" | "article" | "header" | "footer" | "main" | 
                            "aside" | "nav" | "blockquote" | "pre" | "address" |
                            "li" | "dt" | "dd" | "td" | "th" | "tr"
                        );
                        
                        let content_before = text_content.len();
                        
                        // Add text content from children
                        for child in &node.children {
                            text_content.push_str(&self.extract_text_recursive(child));
                        }
                        
                        let content_after = text_content.len();
                        if content_after > content_before {
                            tracing::debug!("  ✅ Element <{}> contributed {} chars", tag_name, content_after - content_before);
                        } else {
                            tracing::debug!("  ⚠️ Element <{}> contributed no text", tag_name);
                        }
                        
                        // Add spacing after block elements
                        if is_block_element && !text_content.is_empty() && !text_content.ends_with('\n') {
                            text_content.push('\n');
                        }
                    } else {
                        tracing::debug!("🚫 Skipping {} element (blocked)", tag_name);
                    }
                }
                _ => {
                    tracing::debug!("🔄 Processing other node type with {} children", node.children.len());
                    // For other node types, check children
                    for child in &node.children {
                        text_content.push_str(&self.extract_text_recursive(child));
                    }
                }
            }
        } else {
            tracing::warn!("⚠️ Failed to read node in extract_text_recursive");
        }
        
        text_content
    }

    /// Get the metrics for this DOM
    pub fn get_metrics(&self) -> &DomMetrics {
        &self.metrics
    }
}

// Example of creating a minimal DOM (e.g., for testing or empty documents)
#[allow(dead_code)] // Keep function for potential use even if not called directly here
fn create_minimal_dom() -> Result<Dom, DomError> {
    let dom = Dom::new();
    let _metrics = dom.metrics.clone();
    let _security_context = dom.security_context.clone();
    
    // You could add elements to the DOM here if needed
    Ok(dom)
}

// Potentially re-export or define common DOM interfaces/traits here 