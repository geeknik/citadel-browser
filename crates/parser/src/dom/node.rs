//! Defines the core Node structure and associated builders for the DOM.

use std::sync::{Arc, RwLock};
use std::sync::atomic::AtomicUsize;
use std::fmt;
use html5ever::QualName;
use html5ever::tendril::StrTendril;
use crate::dom::metrics::DomMetrics;
use crate::dom::error::DomError;
// Use our local SecurityContext implementation
use crate::security::SecurityContext;

// Alias for the type used in html5ever
use html5ever::Attribute as HtmlAttribute;

/// Represents a single attribute (name-value pair).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub name: QualName,
    pub value: String,
}

impl From<HtmlAttribute> for Attribute {
    fn from(attr: HtmlAttribute) -> Self {
        Attribute {
            name: attr.name,
            value: attr.value.to_string(),
        }
    }
}

/// Represents an HTML element within the DOM.
#[derive(Debug, Clone)]
pub struct Element {
    pub name: QualName,
    pub attributes: Vec<Attribute>,
}

impl Element {
    pub fn new(name: QualName, attributes: Vec<Attribute>) -> Self {
        Self { name, attributes }
    }

    /// Helper to get the local name as a string slice.
    pub fn local_name(&self) -> &str {
        &self.name.local
    }
}

/// Represents the different types of nodes in the DOM
#[derive(Debug, Clone)]
pub enum NodeData {
    /// The document root
    Document,
    /// An HTML element
    Element(Element),
    /// A text node
    Text(String),
    /// A comment node
    Comment(String),
    /// A doctype declaration
    Doctype {
        name: String,
        public_id: String,
        system_id: String,
    },
    /// A processing instruction
    ProcessingInstruction {
        target: String,
        data: String,
    },
}

/// Represents a node in the DOM tree.
#[derive(Debug, Clone)]
pub struct Node {
    /// The actual node data
    pub data: NodeData,
    /// Child nodes
    pub children: Vec<Arc<RwLock<Node>>>,
}

impl Node {
    /// Create a new node with the given data
    pub fn new(data: NodeData) -> Self {
        Self {
            data,
            children: Vec::new(),
        }
    }

    /// Create a new node and wrap it in Arc<RwLock>
    pub fn create_new(data: NodeData) -> Arc<RwLock<Node>> {
        Arc::new(RwLock::new(Self::new(data)))
    }

    /// Check if this node is an element
    pub fn is_element(&self) -> bool {
        matches!(self.data, NodeData::Element(_))
    }

    /// Get element attributes if this is an element node
    pub fn element_attributes(&self) -> Option<&Vec<Attribute>> {
        match &self.data {
            NodeData::Element(elem) => Some(&elem.attributes),
            _ => None,
        }
    }

    /// Get mutable element attributes if this is an element node
    pub fn element_attributes_mut(&mut self) -> Option<&mut Vec<Attribute>> {
        match &mut self.data {
            NodeData::Element(elem) => Some(&mut elem.attributes),
            _ => None,
        }
    }
}

/// Builder pattern for creating DOM nodes safely, integrating security checks.
pub struct NodeBuilder {
    metrics: Arc<DomMetrics>,
    security_context: Arc<SecurityContext>,
}

impl NodeBuilder {
    /// Creates a new NodeBuilder.
    pub fn new(metrics: Arc<DomMetrics>, security_context: Arc<SecurityContext>) -> Self {
        Self {
            metrics,
            security_context,
        }
    }

    /// Create a new element node, applying security policies.
    pub fn create_element_node(&self, name: QualName, attrs: Vec<Attribute>) -> Result<Arc<RwLock<Node>>, DomError> {
        let element = Element::new(name, attrs);
        let local_name = element.local_name().to_string();

        // If not allowed, block it
        if !self.security_context.is_element_allowed(&local_name) {
            self.metrics.increment_elements_blocked();
            return Err(DomError::BlockedElement { element_name: local_name });
        }

        let node = Arc::new(RwLock::new(Node {
            data: NodeData::Element(element),
            children: Vec::new(),
        }));

        self.metrics.increment_elements_created();
        Ok(node)
    }

    /// Creates a new text node
    pub fn create_text_node(&self, text: String) -> Arc<RwLock<Node>> {
        Node::create_new(NodeData::Text(text))
    }

    /// Creates a new comment node
    pub fn create_comment_node(&self, text: String) -> Arc<RwLock<Node>> {
        Node::create_new(NodeData::Comment(text))
    }

    /// Creates a comment node
    pub fn comment(&self, text: String) -> Arc<RwLock<Node>> {
        self.create_comment_node(text)
    }

    /// Creates a processing instruction node
    pub fn processing_instruction(&self, target: String, data: String) -> Arc<RwLock<Node>> {
        Node::create_new(NodeData::ProcessingInstruction { target, data })
    }

    /// Creates a new doctype node
    pub fn create_doctype_node(&self, name: String, public_id: String, system_id: String) -> Arc<RwLock<Node>> {
        Node::create_new(NodeData::Doctype { name, public_id, system_id })
    }
}

// Type alias for node handles
pub type NodeHandle = Arc<RwLock<Node>>;

#[cfg(test)]
mod tests {
    use super::*;
    use html5ever::{namespace_url, ns, local_name};
    
    #[test]
    fn test_element_creation() {
        let metrics = Arc::new(DomMetrics::new());
        let security_context = Arc::new(SecurityContext::new(100));
        let builder = NodeBuilder::new(metrics, security_context);
        
        let name = QualName::new(None, ns!(html), local_name!("div"));
        let attrs = vec![];
        
        let node = builder.create_element_node(name, attrs).unwrap();
        let node_guard = node.read().unwrap();
        if let NodeData::Element(element) = &node_guard.data {
            assert_eq!(element.local_name(), "div");
        } else {
            panic!("Expected Element node");
        }
    }
    
    #[test]
    fn test_blocked_element() {
        let metrics = Arc::new(DomMetrics::new());
        let security_context = Arc::new(SecurityContext::new(100));
        let builder = NodeBuilder::new(metrics, security_context);
        
        let name = QualName::new(None, ns!(html), local_name!("script"));
        let attrs = vec![];
        
        let result = builder.create_element_node(name, attrs);
        assert!(matches!(result, Err(DomError::BlockedElement { .. })));
    }
} 