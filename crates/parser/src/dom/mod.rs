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
    pub fn append_child(&mut self, _parent: &NodeHandle, _child: NodeHandle) {
        // TODO: Implement logic using locks
        self.metrics.increment_elements_created();
    }

    /// Appends text content to a parent node.
    pub fn append_text(&mut self, _parent: &NodeHandle, text: String) {
        // TODO: Implement logic to create/append text node using locks
        self.metrics.add_text_content(text.len());
    }

    /// Inserts a new node before a specific sibling.
    pub fn insert_before(&mut self, _sibling: &NodeHandle, _new_node: NodeHandle) {
        // TODO: Implement logic using locks
        self.metrics.increment_elements_created();
    }

    /// Inserts text content before a specific sibling.
    pub fn insert_text_before(&mut self, _sibling: &NodeHandle, text: &str) {
        // TODO: Implement logic to create/insert text node using locks
         self.metrics.add_text_content(text.len());
    }

    /// Removes a node from its parent.
    pub fn remove_node(&mut self, _node: &NodeHandle) {
         // TODO: Implement logic using locks
    }

    /// Moves all children from one node to another.
    pub fn reparent_children(&mut self, _node: &NodeHandle, _new_parent: &NodeHandle) {
        // TODO: Implement logic using locks
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