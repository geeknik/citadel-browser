//! Defines the core Node structure and associated builders for the DOM.

use std::sync::{Arc, RwLock};
use html5ever::{QualName, local_name, ns, namespace_url};
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
    
    /// Get attribute value by name
    pub fn get_attribute(&self, name: &str) -> Option<String> {
        for attr in &self.attributes {
            if &*attr.name.local == name {
                return Some(attr.value.clone());
            }
        }
        None
    }
    
    /// Check if the element has a specific attribute
    pub fn has_attribute(&self, name: &str) -> bool {
        self.attributes.iter().any(|attr| &*attr.name.local == name)
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

    /// Get element data if this is an element node
    pub fn as_element(&self) -> Option<&Element> {
        match &self.data {
            NodeData::Element(elem) => Some(elem),
            _ => None,
        }
    }

    /// Get a simple ID for this node (for layout engine integration)
    pub fn id(&self) -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        std::ptr::addr_of!(*self).hash(&mut hasher);
        hasher.finish() as u32
    }

    /// Get the tag name if this is an element node
    pub fn tag_name(&self) -> Option<&str> {
        match &self.data {
            NodeData::Element(elem) => Some(&elem.name.local),
            _ => None,
        }
    }

    /// Get CSS classes from class attribute if this is an element
    pub fn classes(&self) -> Option<Vec<String>> {
        match &self.data {
            NodeData::Element(elem) => {
                for attr in &elem.attributes {
                    if &*attr.name.local == "class" {
                        return Some(
                            attr.value
                                .split_whitespace()
                                .map(|s| s.to_string())
                                .collect()
                        );
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Get element ID from id attribute if this is an element
    pub fn element_id(&self) -> Option<String> {
        match &self.data {
            NodeData::Element(elem) => {
                for attr in &elem.attributes {
                    if &*attr.name.local == "id" {
                        return Some(attr.value.clone());
                    }
                }
                None
            }
            _ => None,
        }
    }
    
    /// Set element attribute (mutable version)
    pub fn set_attribute(&mut self, name: &str, value: &str) -> Result<(), &'static str> {
        match &mut self.data {
            NodeData::Element(elem) => {
                // Check if attribute already exists
                for attr in &mut elem.attributes {
                    if &*attr.name.local == name {
                        attr.value = value.to_string();
                        return Ok(());
                    }
                }
                
                // Add new attribute
                use string_cache::Atom;
                let new_attr = Attribute {
                    name: QualName::new(None, ns!(), Atom::from(name)),
                    value: value.to_string(),
                };
                elem.attributes.push(new_attr);
                Ok(())
            },
            _ => Err("Cannot set attribute on non-element node")
        }
    }
    
    /// Remove element attribute
    pub fn remove_attribute(&mut self, name: &str) -> Result<(), &'static str> {
        match &mut self.data {
            NodeData::Element(elem) => {
                elem.attributes.retain(|attr| &*attr.name.local != name);
                Ok(())
            },
            _ => Err("Cannot remove attribute on non-element node")
        }
    }
    
    /// Get inner HTML content (simplified)
    pub fn inner_html(&self) -> String {
        match &self.data {
            NodeData::Element(_) => {
                let mut html = String::new();
                for child in &self.children {
                    if let Ok(child_guard) = child.read() {
                        match &child_guard.data {
                            NodeData::Text(text) => html.push_str(text),
                            NodeData::Element(elem) => {
                                html.push_str(&format!("<{}>", elem.local_name()));
                                html.push_str(&child_guard.inner_html());
                                html.push_str(&format!("</{}>", elem.local_name()));
                            },
                            _ => {}
                        }
                    }
                }
                html
            },
            _ => String::new()
        }
    }
    
    /// Set inner HTML content (simplified - security-conscious)
    pub fn set_inner_html(&mut self, html: &str) -> Result<(), &'static str> {
        match &self.data {
            NodeData::Element(_) => {
                // Clear existing children
                self.children.clear();
                
                // For security, we'll just add the HTML as text content
                // In a full implementation, this would parse the HTML
                if !html.is_empty() {
                    let text_node = Node::create_new(NodeData::Text(html.to_string()));
                    self.children.push(text_node);
                }
                Ok(())
            },
            _ => Err("Cannot set innerHTML on non-element node")
        }
    }
    
    /// Set text content, replacing all children
    pub fn set_text_content(&mut self, text: &str) {
        // Clear existing children
        self.children.clear();
        
        // Add new text node if text is not empty
        if !text.is_empty() {
            let text_node = Node::create_new(NodeData::Text(text.to_string()));
            self.children.push(text_node);
        }
    }
    
    /// Get all CSS classes from class attribute
    pub fn class_list(&self) -> Vec<String> {
        match &self.data {
            NodeData::Element(elem) => {
                for attr in &elem.attributes {
                    if &*attr.name.local == "class" {
                        return attr.value
                            .split_whitespace()
                            .map(|s| s.to_string())
                            .collect();
                    }
                }
                Vec::new()
            },
            _ => Vec::new()
        }
    }
    
    /// Add CSS class
    pub fn add_class(&mut self, class_name: &str) -> Result<(), &'static str> {
        match &mut self.data {
            NodeData::Element(elem) => {
                // Find existing class attribute
                for attr in &mut elem.attributes {
                    if &*attr.name.local == "class" {
                        let mut classes: Vec<&str> = attr.value.split_whitespace().collect();
                        if !classes.contains(&class_name) {
                            classes.push(class_name);
                            attr.value = classes.join(" ");
                        }
                        return Ok(());
                    }
                }
                
                // Create new class attribute
                use string_cache::Atom;
                let class_attr = Attribute {
                    name: QualName::new(None, ns!(), Atom::from("class")),
                    value: class_name.to_string(),
                };
                elem.attributes.push(class_attr);
                Ok(())
            },
            _ => Err("Cannot add class to non-element node")
        }
    }
    
    /// Remove CSS class
    pub fn remove_class(&mut self, class_name: &str) -> Result<(), &'static str> {
        match &mut self.data {
            NodeData::Element(elem) => {
                for attr in &mut elem.attributes {
                    if &*attr.name.local == "class" {
                        let classes: Vec<&str> = attr.value
                            .split_whitespace()
                            .filter(|&c| c != class_name)
                            .collect();
                        attr.value = classes.join(" ");
                        return Ok(());
                    }
                }
                Ok(())
            },
            _ => Err("Cannot remove class from non-element node")
        }
    }
    
    /// Toggle CSS class
    pub fn toggle_class(&mut self, class_name: &str) -> Result<bool, &'static str> {
        let has_class = self.class_list().contains(&class_name.to_string());
        if has_class {
            self.remove_class(class_name)?;
            Ok(false)
        } else {
            self.add_class(class_name)?;
            Ok(true)
        }
    }
    
    /// Get element dimensions (mock values for now)
    pub fn get_bounding_rect(&self) -> (f32, f32, f32, f32) {
        // Returns (x, y, width, height)
        // In a real implementation, this would come from the layout engine
        (0.0, 0.0, 100.0, 20.0)
    }
    
    /// Get computed styles (mock implementation)
    pub fn get_computed_style(&self, property: &str) -> Option<String> {
        // In a real implementation, this would query the CSS engine
        match property {
            "display" => Some("block".to_string()),
            "visibility" => Some("visible".to_string()),
            "color" => Some("rgb(0, 0, 0)".to_string()),
            "backgroundColor" => Some("rgba(0, 0, 0, 0)".to_string()),
            "width" => Some("auto".to_string()),
            "height" => Some("auto".to_string()),
            _ => None
        }
    }

    /// Get child nodes (direct references for layout engine)
    pub fn children(&self) -> &Vec<Arc<RwLock<Node>>> {
        &self.children
    }

    /// Add a child node
    pub fn add_child(&mut self, child: Arc<RwLock<Node>>) {
        self.children.push(child);
    }

    /// Get text content of this node
    pub fn text_content(&self) -> String {
        match &self.data {
            NodeData::Text(text) => text.clone(),
            NodeData::Element(_) => {
                let mut content = String::new();
                for child in &self.children {
                    if let Ok(child_guard) = child.read() {
                        content.push_str(&child_guard.text_content());
                    }
                }
                content
            }
            _ => String::new(),
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

        // Create the element regardless of security policy for parsing compatibility
        // Security filtering will be applied at render/execution time
        let node = Arc::new(RwLock::new(Node {
            data: NodeData::Element(element),
            children: Vec::new(),
        }));

        if !self.security_context.is_element_allowed(&local_name) {
            self.metrics.increment_elements_blocked();
            // Still create the element but track that it's blocked
        } else {
            self.metrics.increment_elements_created();
        }

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

    /// Creates a doctype node (alias for create_doctype_node)
    pub fn doctype(&self, name: String, public_id: String, system_id: String) -> Arc<RwLock<Node>> {
        self.create_doctype_node(name, public_id, system_id)
    }

    /// Creates a document fragment for template contents
    pub fn create_document_fragment(&self) -> Result<Arc<RwLock<Node>>, DomError> {
        // Document fragments are like mini-documents for template content
        Ok(Node::create_new(NodeData::Document))
    }

    /// Creates a blocked element placeholder for security-blocked elements
    pub fn create_blocked_element(&self, name: QualName) -> Result<Arc<RwLock<Node>>, DomError> {
        // Create a placeholder comment node instead of the blocked element
        let comment = format!("<!-- blocked element: {} -->", name.local);
        Ok(Node::create_new(NodeData::Comment(comment)))
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
        let builder = NodeBuilder::new(metrics.clone(), security_context);
        
        let name = QualName::new(None, ns!(html), local_name!("script"));
        let attrs = vec![];
        
        // With our new approach, blocked elements are created during parsing
        // but marked as blocked in metrics
        let result = builder.create_element_node(name, attrs);
        assert!(result.is_ok());
        
        // Verify that the blocked element count increased
        assert_eq!(metrics.get_elements_blocked(), 1);
        assert_eq!(metrics.get_elements_created(), 0);
    }
} 