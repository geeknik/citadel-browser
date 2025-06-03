//! Implementation of html5ever's TreeSink trait for building Citadel's DOM.

use html5ever::{
    // Remove parse_document
    tendril::StrTendril,
    tree_builder::{NodeOrText, QuirksMode, TreeSink, ElementFlags},
    Attribute as HtmlAttribute,
    QualName,
};
// Use markup5ever for Namespace
use markup5ever::Namespace;
// Remove RwLock
use std::sync::Arc;
use std::borrow::Cow;
use string_cache::Atom as StrAtom;

use crate::dom::{
    Attribute, Dom, DomError, NodeBuilder, NodeHandle,
    // SafeNodeHandle is defined locally below, remove this import
    // SafeNodeHandle, 
};
use crate::metrics::DocumentMetrics;
use crate::dom::metrics::DomMetrics;
use crate::security::SecurityContext;

// Create static namespace and atom instances to solve lifetime problems
lazy_static::lazy_static! {
    static ref HTML_NAMESPACE: markup5ever::Namespace = markup5ever::Namespace::from("http://www.w3.org/1999/xhtml");
    static ref PLACEHOLDER_ATOM: markup5ever::LocalName = markup5ever::LocalName::from("placeholder");
    static ref BLOCKED_ATOM: markup5ever::LocalName = markup5ever::LocalName::from("#blocked");
}

/// Wrapper enum to handle nodes that might be blocked by security policy.
#[derive(Debug, Clone)]
pub enum SafeNodeHandle {
    Valid(NodeHandle), // Arc<RwLock<Node>>
    Blocked, // Represents a node that was prevented from being created
}

/// The TreeSink implementation for Citadel.
pub struct HtmlTreeSink {
    /// The DOM being built.
    dom: Dom,
    /// Builder responsible for creating nodes safely.
    node_builder: Arc<NodeBuilder>,
    /// Security context for policy enforcement.
    security_context: Arc<SecurityContext>,
    /// Stack of open elements.
    open_elements: Vec<SafeNodeHandle>,
    /// Document quirks mode.
    quirks_mode: QuirksMode,
    /// Metrics for the document being built
    doc_metrics: Arc<DocumentMetrics>,
}

impl HtmlTreeSink {
    /// Create a new tree sink with necessary contexts.
    pub fn new(security_context: Arc<SecurityContext>, doc_metrics: Arc<DocumentMetrics>) -> Self {
        let dom = Dom::new(); // Call simplified Dom::new()
        let metrics = Arc::new(DomMetrics::new());
        let node_builder = Arc::new(NodeBuilder::new(metrics, security_context.clone()));
        
        // Get the root node before we move dom
        let root_node = dom.root();
        
        HtmlTreeSink {
            dom,
            node_builder,
            open_elements: vec![SafeNodeHandle::Valid(root_node)], // Start with root
            security_context,
            doc_metrics, // Store metrics
            quirks_mode: QuirksMode::NoQuirks, // Initialize quirks mode
        }
    }
    
    /// Consume the tree sink and return the built DOM
    pub fn get_output(self) -> (Dom, QuirksMode) {
        (self.dom, self.quirks_mode)
    }

    /// Helper to get the current parent node handle (if valid).
    fn current_parent(&self) -> Option<&NodeHandle> {
        self.open_elements.last().and_then(|handle| match handle {
            SafeNodeHandle::Valid(nh) => Some(nh),
            SafeNodeHandle::Blocked => None, // Cannot append to a blocked node
        })
    }

    /// Helper to convert html5ever attributes to Citadel attributes.
    fn convert_attributes(&self, attrs: Vec<HtmlAttribute>) -> Vec<Attribute> {
        attrs.into_iter()
            .map(|attr| Attribute {
                name: attr.name,
                value: attr.value.to_string(),
            })
            .collect()
    }

    // Helper to append a node/text safely, checking handle validity
    fn append_child_to(&mut self, parent_handle: &SafeNodeHandle, child: NodeOrText<SafeNodeHandle>) {
        if let SafeNodeHandle::Valid(p_handle) = parent_handle {
            match child {
                NodeOrText::AppendNode(SafeNodeHandle::Valid(c_handle)) => {
                    self.dom.append_child(p_handle, c_handle.clone());
                    self.doc_metrics.increment_elements(); // Count valid elements
                }
                NodeOrText::AppendText(text) => {
                    // Check if text content is allowed or needs sanitization based on context
                    // For now, assume text is okay
                    self.dom.append_text(p_handle, text.to_string());
                    self.doc_metrics.add_text_content(text.len());
                }
                _ => { /* Ignore blocked children */ }
            }
        } else {
            // Cannot append to a blocked parent
            eprintln!("Attempted to append child to a blocked node");
        }
    }
}

impl TreeSink for HtmlTreeSink {
    type Output = (Dom, QuirksMode);
    type Handle = SafeNodeHandle;

    fn finish(self) -> Self::Output {
        (self.dom, self.quirks_mode)
    }

    fn parse_error(&mut self, msg: Cow<'static, str>) {
        // TODO: Integrate with a proper error reporting/logging system
        eprintln!("Parse error: {}", msg);
    }

    fn set_quirks_mode(&mut self, mode: QuirksMode) {
        self.quirks_mode = mode;
    }

    fn get_document(&mut self) -> Self::Handle {
        // Find the root #document node handle
        // Assuming the first element pushed is the root/document
        self.open_elements.first().cloned().unwrap_or_else(|| {
            // This case should ideally not happen if initialized correctly
            let root = self.dom.root();
            SafeNodeHandle::Valid(root)
        })
    }

    fn get_template_contents(&mut self, target: &Self::Handle) -> Self::Handle {
        // Handle <template> elements - potentially create a document fragment concept.
        // For now, treat like a normal element or block based on policy.
        match target {
            SafeNodeHandle::Valid(_) => self.get_document(), // Simplistic: return a new fragment root
            SafeNodeHandle::Blocked => SafeNodeHandle::Blocked,
        }
    }

    fn same_node(&self, handle1: &Self::Handle, handle2: &Self::Handle) -> bool {
        match (handle1, handle2) {
            (SafeNodeHandle::Valid(h1), SafeNodeHandle::Valid(h2)) => Arc::ptr_eq(h1, h2),
            (SafeNodeHandle::Blocked, SafeNodeHandle::Blocked) => true, // Consider blocked nodes equivalent?
            _ => false,
        }
    }

    fn elem_name<'a>(&'a self, target: &'a Self::Handle) -> markup5ever::ExpandedName<'a> {
        match target {
            SafeNodeHandle::Valid(_handle) => {
                markup5ever::ExpandedName {
                    ns: &HTML_NAMESPACE,
                    local: &PLACEHOLDER_ATOM,
                }
            }
            SafeNodeHandle::Blocked => {
                markup5ever::ExpandedName {
                    ns: &HTML_NAMESPACE,
                    local: &BLOCKED_ATOM,
                }
            }
        }
    }

    // --- Element Creation and Modification ---

    fn create_element(&mut self, name: QualName, attrs: Vec<HtmlAttribute>, _flags: ElementFlags) -> Self::Handle {
        let converted_attrs = self.convert_attributes(attrs);
        // Policy check: Is element allowed?
        if !self.security_context.is_element_allowed(name.local.as_ref()) {
            SafeNodeHandle::Blocked
        } else {
            // NodeBuilder handles security check and metrics
            match self.node_builder.create_element_node(name, converted_attrs) {
                Ok(handle) => {
                    SafeNodeHandle::Valid(handle)
                }
                Err(DomError::BlockedElement { .. }) => SafeNodeHandle::Blocked,
                Err(e) => {
                    eprintln!("Error creating element node: {:?}", e);
                    SafeNodeHandle::Blocked
                }
            }
        }
    }

    fn create_comment(&mut self, text: StrTendril) -> Self::Handle {
        // FIXME: Re-introduce policy check based on SecurityContext or passed-in config
        // if !self.config.allow_comments { 
        //     return SafeNodeHandle::Blocked;
        // }
        let node = self.node_builder.comment(text.to_string());
        SafeNodeHandle::Valid(node)
    }

    fn create_pi(&mut self, target: StrTendril, data: StrTendril) -> Self::Handle {
        // FIXME: Re-introduce policy check based on SecurityContext or passed-in config
        // if !self.config.allow_processing_instructions { 
        //     return SafeNodeHandle::Blocked;
        // }
        let node = self.node_builder.processing_instruction(target.to_string(), data.to_string());
        SafeNodeHandle::Valid(node)
    }

    fn append(&mut self, parent: &Self::Handle, child: NodeOrText<Self::Handle>) {
        // Prefix unused text variable
        let child_for_append = match child {
             NodeOrText::AppendText(text) => NodeOrText::AppendText(text),
             NodeOrText::AppendNode(handle) => NodeOrText::AppendNode(handle),
         };
        self.append_child_to(parent, child_for_append);
    }

    fn append_before_sibling(&mut self,
                             sibling: &Self::Handle,
                             new_node: NodeOrText<Self::Handle>) {
        // Extract valid handles
        let valid_sibling = match sibling {
            SafeNodeHandle::Valid(h) => Some(h),
            _ => None,
        };
        let valid_new_node_handle = match &new_node {
            NodeOrText::AppendNode(SafeNodeHandle::Valid(h)) => Some(h.clone()),
            _ => None,
        };
        let new_node_text = match &new_node {
            NodeOrText::AppendText(t) => Some(t.to_string()),
            _ => None,
        };

        if let Some(s_handle) = valid_sibling {
            if let Some(nn_handle) = valid_new_node_handle {
                self.dom.insert_before(s_handle, nn_handle);
                self.doc_metrics.increment_elements();
            } else if let Some(text) = new_node_text.clone() {
                self.dom.insert_text_before(s_handle, &text);
                self.doc_metrics.add_text_content(text.len());
            } else {
                // Ignore blocked new_node
            }
        } else {
            // Handle insert before blocked sibling
        }
    }

    fn append_based_on_parent_node(&mut self,
                                        element: &Self::Handle,
                                        prev_element: &Self::Handle,
                                        child: NodeOrText<Self::Handle>) {
        // Foster parenting / parent node logic is complex.
        // See: https://html.spec.whatwg.org/multipage/parsing.html#appropriate-place-for-inserting-a-node
        // For a secure parser, we might want to simplify or disallow scenarios requiring this.
        // Defaulting to standard append to the previous element for now.
        // FIXME: This needs careful security review and likely proper implementation.
        let _ = element; // Mark unused
        self.append(prev_element, child);
    }

    fn append_doctype_to_document(&mut self,
                                  name: StrTendril,
                                  public_id: StrTendril,
                                  system_id: StrTendril) {
        // Prefix unused variables
        let _name = name;
        let _public_id = public_id;
        let _system_id = system_id;
        // Security: DOCTYPEs can sometimes be used in DTD/XXE attacks if parsed insecurely.
        // html5ever doesn't parse external DTDs by default.
        // We might choose to ignore DOCTYPEs entirely for simplicity/security.
        // let handle = self.node_builder.doctype(name.to_string(), public_id.to_string(), system_id.to_string()).into();
        // Where should the doctype be appended? The DOM root needs a way to store it.
        // For now, just creating it, assuming NodeBuilder handles storage appropriately.
        // self.append(&self.get_document(), NodeOrText::AppendNode(handle)); // Needs DOM method
        // FIXME: Logic needs refinement, returning Blocked temporarily
        let _ = self.node_builder; // Avoid unused warning for node_builder if handle creation commented out
        // SafeNodeHandle::Blocked
    }

    // --- Stack Management ---

    fn add_attrs_if_missing(&mut self, target: &Self::Handle, attrs: Vec<HtmlAttribute>) {
        if let SafeNodeHandle::Valid(handle) = target {
            // Convert attributes once
            let attrs_to_add = self.convert_attributes(attrs);
            
            // Use a single mutable borrow
            if let Some(mut node_guard) = self.dom.get_node_mut(handle) {
                // If this is an element, we need to add attributes
                if let Some(current_attrs) = node_guard.element_attributes_mut() {
                    // Get current attribute names for filtering
                    let current_attr_names: Vec<&QualName> = current_attrs.iter()
                        .map(|attr| &attr.name)
                        .collect();
                        
                    // Filter out attributes that already exist
                    let filtered_attrs: Vec<Attribute> = attrs_to_add.into_iter()
                        .filter(|attr| !current_attr_names.contains(&&attr.name))
                        .collect();
                        
                    // Add the filtered attributes if any
                    if !filtered_attrs.is_empty() {
                        current_attrs.extend(filtered_attrs);
                    }
                }
            }
        }
    }

    fn remove_from_parent(&mut self, target: &Self::Handle) {
        // Prefix unused variable
        let _target = target;
        if let SafeNodeHandle::Valid(handle) = target {
            self.dom.remove_node(handle);
        }
    }

    fn reparent_children(&mut self, node: &Self::Handle, new_parent: &Self::Handle) {
         // Prefix unused variables
         let _node = node;
         let _new_parent = new_parent;
         if let (SafeNodeHandle::Valid(node_h), SafeNodeHandle::Valid(new_parent_h)) = (node, new_parent) {
            self.dom.reparent_children(node_h, new_parent_h);
        }
    }

    fn mark_script_already_started(&mut self, node: &Self::Handle) {
        // Prefix unused variable
        let _node = node;
        // Scripts are typically blocked by policy, but if allowed,
        // this flag might be relevant for execution control.
        // TODO: Implement if script execution is ever added.
    }

    fn set_current_line(&mut self, line_number: u64) {
        // Prefix unused variable
        let _line_number = line_number;
        // Store line number if needed for error reporting
    }

    // --- Required but potentially simpler implementations ---
    fn pop(&mut self, handle: &Self::Handle) -> () {
        // Parameter `handle` is unused for now, but required by trait
        let _ = handle;
        // Discard the popped value
        let _ = self.open_elements.pop().expect("Popped the root element?!");
    }
}

// Add From<NodeHandle> for SafeNodeHandle to simplify conversions
impl From<NodeHandle> for SafeNodeHandle {
    fn from(handle: NodeHandle) -> Self {
        SafeNodeHandle::Valid(handle)
    }
}

/// Create a new HtmlTreeSink for parsing
/// This is the public entry point to the tree sink implementation
pub fn create_html_sink(
    security_context: Arc<SecurityContext>,
    doc_metrics: Arc<DocumentMetrics>,
) -> HtmlTreeSink {
    HtmlTreeSink::new(security_context, doc_metrics)
} 