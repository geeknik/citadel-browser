//! Security specific errors for the Citadel browser engine.

#[derive(thiserror::Error, Debug, Clone)] // Clone might be useful
pub enum SecurityError {
    #[error("Invalid security configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Blocked resource access attempt: {resource_type} - {identifier}")]
    BlockedResource {
        resource_type: String,
        identifier: String,
    },

    #[error("Invalid URL scheme encountered: {scheme}")]
    InvalidScheme { scheme: String },

    #[error("Content Security Policy violation: {directive}")]
    CspViolation { directive: String },

    // Add other security-related errors
} 