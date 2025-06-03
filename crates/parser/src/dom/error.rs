//! DOM specific errors for the Citadel parser crate.

#[derive(thiserror::Error, Debug)]
pub enum DomError {
    #[error("Attempted to create an element blocked by security policy: {element_name}")]
    BlockedElement { element_name: String },

    #[error("Invalid node operation: {0}")]
    InvalidOperation(String),

    #[error("Node not found: {0}")]
    NodeNotFound(String),

    #[error("Security violation: {0}")]
    SecurityViolation(String),

    // Add other DOM-specific errors as needed
} 