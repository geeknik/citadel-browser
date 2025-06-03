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
        let security_context = Arc::new(SecurityContext::new());
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
    pub fn insert_before(&mut self, sibling: &NodeHandle, new_node: NodeHandle) {
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
        self.extract_text_recursive(&self.document_node_handle)
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
                    text_content.push_str(text);
                    // Don't add extra spaces - let natural HTML spacing handle this
                }
                crate::dom::node::NodeData::Element(element) => {
                    // Skip script and style elements
                    let tag_name = element.local_name();
                    if tag_name != "script" && tag_name != "style" {
                        // Add text content from children
                        for child in &node.children {
                            text_content.push_str(&self.extract_text_recursive(child));
                        }
                    }
                }
                _ => {
                    // For other node types, check children
                    for child in &node.children {
                        text_content.push_str(&self.extract_text_recursive(child));
                    }
                }
            }
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
    let metrics = dom.metrics.clone();
    let security_context = dom.security_context.clone();
    
    // You could add elements to the DOM here if needed
    Ok(dom)
}

// Potentially re-export or define common DOM interfaces/traits here 