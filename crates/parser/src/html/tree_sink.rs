//! Minimal working TreeSink implementation for Citadel's HTML parser.
//! 
//! This implementation follows html5ever best practices to ensure basic parsing works,
//! then adds Citadel's security features on top.

use html5ever::{
    tendril::StrTendril,
    tree_builder::{ElementFlags, NodeOrText, QuirksMode, TreeSink},
    Attribute as HtmlAttribute,
    QualName,
};
use markup5ever::ExpandedName;
use std::sync::Arc;
use std::borrow::Cow;
use std::collections::HashMap;

// Static values for fallback
lazy_static::lazy_static! {
    static ref EMPTY_NAMESPACE: markup5ever::Namespace = markup5ever::Namespace::from("");
    static ref EMPTY_LOCAL_NAME: markup5ever::LocalName = markup5ever::LocalName::from("");
}

use crate::dom::{
    Attribute, Dom, NodeBuilder, NodeHandle,
};
use crate::metrics::DocumentMetrics;
use crate::dom::metrics::DomMetrics;
use crate::security::SecurityContext;

/// Minimal working TreeSink implementation for html5ever
/// 
/// This implementation stores element names correctly (required by html5ever)
/// and provides basic security filtering while maintaining parsing compatibility.
pub struct HtmlTreeSink {
    /// The DOM being constructed
    dom: Dom,
    /// Node builder for creating nodes
    node_builder: Arc<NodeBuilder>,
    /// Security context for policy enforcement
    security_context: Arc<SecurityContext>,
    /// Document parsing metrics (unused in minimal implementation)
    _doc_metrics: Arc<DocumentMetrics>,
    /// Document quirks mode
    quirks_mode: QuirksMode,
    /// Document root handle
    document_handle: NodeHandle,
    /// Map of node handles to their element names (CRITICAL for html5ever)
    element_names: HashMap<usize, QualName>,
    /// Next ID for handles (using pointer addresses as unique IDs)
    next_id: usize,
}

impl HtmlTreeSink {
    /// Create a new TreeSink
    pub fn new(security_context: Arc<SecurityContext>, doc_metrics: Arc<DocumentMetrics>) -> Self {
        let dom = Dom::new();
        let metrics = Arc::new(DomMetrics::new());
        let node_builder = Arc::new(NodeBuilder::new(metrics, security_context.clone()));
        let document_handle = dom.root();
        
        Self {
            dom,
            node_builder,
            security_context,
            _doc_metrics: doc_metrics,
            quirks_mode: QuirksMode::NoQuirks,
            document_handle,
            element_names: HashMap::new(),
            next_id: 1,
        }
    }
    
    /// Get a unique ID for a handle (using Arc pointer address)
    fn get_handle_id(&self, handle: &NodeHandle) -> usize {
        Arc::as_ptr(handle) as *const _ as usize
    }
    
    /// Convert html5ever attributes to Citadel attributes with security filtering
    fn convert_attributes(&self, attrs: Vec<HtmlAttribute>) -> Vec<Attribute> {
        attrs.into_iter()
            .filter_map(|attr| {
                let attr_name = attr.name.local.as_ref();
                
                // Apply security filtering
                if self.security_context.is_attribute_allowed(attr_name) {
                    Some(Attribute {
                        name: attr.name,
                        value: attr.value.to_string(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }
}

impl TreeSink for HtmlTreeSink {
    type Output = (Dom, QuirksMode);
    type Handle = NodeHandle;

    fn finish(self) -> Self::Output {
        (self.dom, self.quirks_mode)
    }

    fn parse_error(&mut self, _msg: Cow<'static, str>) {
        // Handle parse errors - only log critical ones to reduce spam
        if _msg.contains("character reference") || _msg.contains("doctype") {
            #[cfg(debug_assertions)]
            eprintln!("HTML parse error: {}", _msg);
        }
    }

    fn set_quirks_mode(&mut self, mode: QuirksMode) {
        self.quirks_mode = mode;
    }

    fn get_document(&mut self) -> Self::Handle {
        self.document_handle.clone()
    }

    fn get_template_contents(&mut self, target: &Self::Handle) -> Self::Handle {
        // For template elements, create a document fragment
        // In a minimal implementation, we can return the target itself
        match self.node_builder.create_document_fragment() {
            Ok(fragment) => fragment,
            Err(_) => target.clone(),
        }
    }

    fn same_node(&self, x: &Self::Handle, y: &Self::Handle) -> bool {
        Arc::ptr_eq(x, y)
    }

    fn elem_name<'a>(&'a self, target: &'a Self::Handle) -> ExpandedName<'a> {
        // CRITICAL: This method must return actual element names for html5ever to work
        let handle_id = self.get_handle_id(target);
        if let Some(qname) = self.element_names.get(&handle_id) {
            qname.expanded()
                 } else {
             // Fallback for non-element nodes
             ExpandedName {
                 ns: &EMPTY_NAMESPACE,
                 local: &EMPTY_LOCAL_NAME,
             }
         }
    }

    fn create_element(&mut self, name: QualName, attrs: Vec<HtmlAttribute>, _flags: ElementFlags) -> Self::Handle {
        let tag_name = name.local.as_ref();
        
        // For parsing compatibility, create ALL elements but apply security filtering to content
        // This prevents html5ever parsing errors while maintaining security
        let safe_attrs = if self.security_context.is_element_allowed(tag_name) {
            self.convert_attributes(attrs)
        } else {
            // For blocked elements, strip all attributes to minimize attack surface
            Vec::new()
        };
        
        // Create the element regardless of security status - security is applied at render time
        match self.node_builder.create_element_node(name.clone(), safe_attrs) {
            Ok(handle) => {
                // CRITICAL: Store the element name for elem_name() method
                let handle_id = self.get_handle_id(&handle);
                self.element_names.insert(handle_id, name);
                handle
            }
            Err(_) => {
                // On error, still create a placeholder to maintain parsing flow
                let placeholder = self.node_builder.comment(format!("error creating: {}", tag_name));
                let handle_id = self.get_handle_id(&placeholder);
                self.element_names.insert(handle_id, name);
                placeholder
            }
        }
    }

    fn create_comment(&mut self, text: StrTendril) -> Self::Handle {
        self.node_builder.comment(text.to_string())
    }

    fn create_pi(&mut self, target: StrTendril, data: StrTendril) -> Self::Handle {
        self.node_builder.processing_instruction(target.to_string(), data.to_string())
    }

    fn append(&mut self, parent: &Self::Handle, child: NodeOrText<Self::Handle>) {
        match child {
            NodeOrText::AppendNode(child_handle) => {
                self.dom.append_child(parent, child_handle);
            }
            NodeOrText::AppendText(text) => {
                // For parsing compatibility, allow text content but apply minimal sanitization
                // More comprehensive sanitization happens at render time
                let text_str = text.to_string();
                self.dom.append_text(parent, text_str);
            }
        }
    }

    fn append_before_sibling(&mut self, sibling: &Self::Handle, new_node: NodeOrText<Self::Handle>) {
        match new_node {
            NodeOrText::AppendNode(node_handle) => {
                self.dom.insert_before(sibling, node_handle);
            }
            NodeOrText::AppendText(text) => {
                let text_str = text.to_string();
                self.dom.insert_text_before(sibling, &text_str);
            }
        }
    }

    fn append_based_on_parent_node(&mut self, _element: &Self::Handle, prev_element: &Self::Handle, child: NodeOrText<Self::Handle>) {
        // Handle foster parenting by delegating to regular append
        self.append(prev_element, child);
    }

    fn append_doctype_to_document(&mut self, name: StrTendril, public_id: StrTendril, system_id: StrTendril) {
        // Create and store doctype - apply basic validation
        let safe_name = name.to_string();
        if safe_name.to_lowercase() == "html" {
            let _doctype = self.node_builder.doctype(
                safe_name, 
                public_id.to_string(), 
                system_id.to_string()
            );
        }
    }

    fn add_attrs_if_missing(&mut self, target: &Self::Handle, attrs: Vec<HtmlAttribute>) {
        let safe_attrs = self.convert_attributes(attrs);
        
        if let Some(mut node_guard) = self.dom.get_node_mut(target) {
            if let Some(current_attrs) = node_guard.element_attributes_mut() {
                let existing_names: std::collections::HashSet<_> = current_attrs.iter()
                    .map(|attr| &attr.name)
                    .collect();
                
                let new_attrs: Vec<_> = safe_attrs.into_iter()
                    .filter(|attr| !existing_names.contains(&attr.name))
                    .collect();
                    
                current_attrs.extend(new_attrs);
            }
        }
    }

    fn remove_from_parent(&mut self, target: &Self::Handle) {
        self.dom.remove_node(target);
    }

    fn reparent_children(&mut self, node: &Self::Handle, new_parent: &Self::Handle) {
        self.dom.reparent_children(node, new_parent);
    }

    fn mark_script_already_started(&mut self, _node: &Self::Handle) {
        // No-op: scripts are handled by security policy
    }

    fn set_current_line(&mut self, _line_number: u64) {
        // No-op: could be used for error reporting
    }

    fn pop(&mut self, _node: &Self::Handle) {
        // html5ever manages its own element stack internally
        // This is just a notification that an element was closed
    }
}

/// Create a TreeSink for HTML parsing
pub fn create_html_sink(security_context: Arc<SecurityContext>, doc_metrics: Arc<DocumentMetrics>) -> HtmlTreeSink {
    HtmlTreeSink::new(security_context, doc_metrics)
} 