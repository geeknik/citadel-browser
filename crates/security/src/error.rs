//! Security specific errors for the Citadel browser engine.
//!
//! This module defines comprehensive error types for all security-related
//! failures that can occur in the Citadel browser. Each error type provides
//! detailed context to help with debugging and security incident response.

use std::fmt;

/// Result type alias for security operations
pub type SecurityResult<T> = Result<T, SecurityError>;

/// Severity level for security errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecuritySeverity {
    /// Low severity - informational or minor policy violation
    Low,
    /// Medium severity - potential security issue requiring attention
    Medium,
    /// High severity - significant security violation
    High,
    /// Critical severity - immediate threat requiring intervention
    Critical,
}

impl fmt::Display for SecuritySeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecuritySeverity::Low => write!(f, "LOW"),
            SecuritySeverity::Medium => write!(f, "MEDIUM"),
            SecuritySeverity::High => write!(f, "HIGH"),
            SecuritySeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

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

    #[error("Memory exhaustion detected: requested {requested} bytes, limit {limit} bytes")]
    MemoryExhaustion { requested: usize, limit: usize },

    #[error("Suspicious activity detected: {activity_type} - {details}")]
    SuspiciousActivity {
        activity_type: String,
        details: String,
    },

    #[error("Network security violation: {violation_type} for host {host}")]
    NetworkSecurityViolation {
        violation_type: String,
        host: String,
    },

    #[error("Resource timeout exceeded: {resource} took longer than {timeout_ms}ms")]
    ResourceTimeout {
        resource: String,
        timeout_ms: u64,
    },

    #[error("Certificate validation failed for host {host}: {reason}")]
    CertificateValidationFailed {
        host: String,
        reason: String,
    },

    #[error("Mixed content detected: loading insecure {resource_type} from {url}")]
    MixedContent {
        resource_type: String,
        url: String,
    },

    #[error("Script execution blocked: {reason}")]
    ScriptExecutionBlocked { reason: String },

    #[error("DOM manipulation blocked: {operation} on {element}")]
    DomManipulationBlocked {
        operation: String,
        element: String,
    },

    #[error("Cross-origin request blocked: {request_type} to {target_origin}")]
    CrossOriginBlocked {
        request_type: String,
        target_origin: String,
    },

    #[error("Permission denied: {permission} access requested but not granted")]
    PermissionDenied { permission: String },

    #[error("Content type validation failed: expected {expected}, got {actual}")]
    ContentTypeValidationFailed {
        expected: String,
        actual: String,
    },

    #[error("Iframe security violation: {violation_type} for source {url}")]
    IframeSecurityViolation {
        violation_type: String,
        url: String,
    },

    #[error("WebSocket security violation: {reason} for connection to {url}")]
    WebSocketSecurityViolation {
        reason: String,
        url: String,
    },

    #[error("Service worker security violation: {violation} for script {script_url}")]
    ServiceWorkerSecurityViolation {
        violation: String,
        script_url: String,
    },

    #[error("Web API access blocked: {api} access denied due to {reason}")]
    WebApiAccessBlocked {
        api: String,
        reason: String,
    },

    #[error("Fingerprinting attempt detected: {method} blocked")]
    FingerprintingAttempt { method: String },

    #[error("Parser security violation: {parser_type} encountered {violation}")]
    ParserSecurityViolation {
        parser_type: String,
        violation: String,
    },

    #[error("Resource size limit exceeded: {resource_type} size {actual_size} exceeds limit {max_size}")]
    ResourceSizeLimitExceeded {
        resource_type: String,
        actual_size: usize,
        max_size: usize,
    },

    #[error("Security policy conflict: {policy1} conflicts with {policy2}")]
    SecurityPolicyConflict {
        policy1: String,
        policy2: String,
    },

    #[error("Cryptographic operation failed: {operation} - {reason}")]
    CryptographicFailure {
        operation: String,
        reason: String,
    },

    #[error("Sandbox violation: {operation} attempted outside sandbox boundaries")]
    SandboxViolation { operation: String },

    #[error("Security header validation failed: {header} has invalid value {value}")]
    SecurityHeaderValidationFailed {
        header: String,
        value: String,
    },

    #[error("CORS policy violation: {violation} for origin {origin}")]
    CorsViolation {
        violation: String,
        origin: String,
    },

    // Generic catch-all for other security-related errors
    #[error("Generic security error: {message}")]
    Generic { message: String },
}

impl SecurityError {
    /// Get the severity level of this security error
    pub fn severity(&self) -> SecuritySeverity {
        match self {
            // Critical severity errors - immediate threats
            SecurityError::ScriptExecutionBlocked { .. } => SecuritySeverity::Critical,
            SecurityError::SandboxViolation { .. } => SecuritySeverity::Critical,
            SecurityError::CryptographicFailure { .. } => SecuritySeverity::Critical,
            SecurityError::CertificateValidationFailed { .. } => SecuritySeverity::Critical,
            
            // High severity errors - significant security violations
            SecurityError::CspViolation { .. } => SecuritySeverity::High,
            SecurityError::CrossOriginBlocked { .. } => SecuritySeverity::High,
            SecurityError::MixedContent { .. } => SecuritySeverity::High,
            SecurityError::DomManipulationBlocked { .. } => SecuritySeverity::High,
            SecurityError::WebSocketSecurityViolation { .. } => SecuritySeverity::High,
            SecurityError::ServiceWorkerSecurityViolation { .. } => SecuritySeverity::High,
            SecurityError::IframeSecurityViolation { .. } => SecuritySeverity::High,
            SecurityError::CorsViolation { .. } => SecuritySeverity::High,
            SecurityError::ParserSecurityViolation { .. } => SecuritySeverity::High,
            
            // Medium severity errors - policy violations
            SecurityError::BlockedResource { .. } => SecuritySeverity::Medium,
            SecurityError::NetworkSecurityViolation { .. } => SecuritySeverity::Medium,
            SecurityError::PermissionDenied { .. } => SecuritySeverity::Medium,
            SecurityError::WebApiAccessBlocked { .. } => SecuritySeverity::Medium,
            SecurityError::FingerprintingAttempt { .. } => SecuritySeverity::Medium,
            SecurityError::ResourceSizeLimitExceeded { .. } => SecuritySeverity::Medium,
            SecurityError::SecurityHeaderValidationFailed { .. } => SecuritySeverity::Medium,
            
            // Low severity errors - informational or minor issues
            SecurityError::InvalidConfiguration { .. } => SecuritySeverity::Low,
            SecurityError::InvalidScheme { .. } => SecuritySeverity::Low,
            SecurityError::MemoryExhaustion { .. } => SecuritySeverity::Low,
            SecurityError::SuspiciousActivity { .. } => SecuritySeverity::Low,
            SecurityError::ResourceTimeout { .. } => SecuritySeverity::Low,
            SecurityError::ContentTypeValidationFailed { .. } => SecuritySeverity::Low,
            SecurityError::SecurityPolicyConflict { .. } => SecuritySeverity::Low,
            SecurityError::Generic { .. } => SecuritySeverity::Low,
        }
    }
    
    /// Check if this error should trigger an immediate security response
    pub fn requires_immediate_response(&self) -> bool {
        matches!(self.severity(), SecuritySeverity::Critical)
    }
    
    /// Check if this error should be reported to security monitoring
    pub fn should_report(&self) -> bool {
        matches!(self.severity(), SecuritySeverity::High | SecuritySeverity::Critical)
    }
    
    /// Get a short description suitable for logging
    pub fn short_description(&self) -> &'static str {
        match self {
            SecurityError::InvalidConfiguration { .. } => "invalid_config",
            SecurityError::BlockedResource { .. } => "blocked_resource",
            SecurityError::InvalidScheme { .. } => "invalid_scheme",
            SecurityError::CspViolation { .. } => "csp_violation",
            SecurityError::MemoryExhaustion { .. } => "memory_exhaustion",
            SecurityError::SuspiciousActivity { .. } => "suspicious_activity",
            SecurityError::NetworkSecurityViolation { .. } => "network_violation",
            SecurityError::ResourceTimeout { .. } => "resource_timeout",
            SecurityError::CertificateValidationFailed { .. } => "cert_validation_failed",
            SecurityError::MixedContent { .. } => "mixed_content",
            SecurityError::ScriptExecutionBlocked { .. } => "script_blocked",
            SecurityError::DomManipulationBlocked { .. } => "dom_blocked",
            SecurityError::CrossOriginBlocked { .. } => "cross_origin_blocked",
            SecurityError::PermissionDenied { .. } => "permission_denied",
            SecurityError::ContentTypeValidationFailed { .. } => "content_type_failed",
            SecurityError::IframeSecurityViolation { .. } => "iframe_violation",
            SecurityError::WebSocketSecurityViolation { .. } => "websocket_violation",
            SecurityError::ServiceWorkerSecurityViolation { .. } => "service_worker_violation",
            SecurityError::WebApiAccessBlocked { .. } => "web_api_blocked",
            SecurityError::FingerprintingAttempt { .. } => "fingerprinting_attempt",
            SecurityError::ParserSecurityViolation { .. } => "parser_violation",
            SecurityError::ResourceSizeLimitExceeded { .. } => "size_limit_exceeded",
            SecurityError::SecurityPolicyConflict { .. } => "policy_conflict",
            SecurityError::CryptographicFailure { .. } => "crypto_failure",
            SecurityError::SandboxViolation { .. } => "sandbox_violation",
            SecurityError::SecurityHeaderValidationFailed { .. } => "header_validation_failed",
            SecurityError::CorsViolation { .. } => "cors_violation",
            SecurityError::Generic { .. } => "generic_error",
        }
    }
    
    /// Get remediation advice for this error
    pub fn remediation_advice(&self) -> &'static str {
        match self {
            SecurityError::CspViolation { .. } => {
                "Review and update Content Security Policy directives to allow legitimate resources"
            }
            SecurityError::ScriptExecutionBlocked { .. } => {
                "Verify script sources and ensure they meet security policy requirements"
            }
            SecurityError::MixedContent { .. } => {
                "Ensure all resources are loaded over HTTPS to prevent mixed content warnings"
            }
            SecurityError::CertificateValidationFailed { .. } => {
                "Check certificate validity and trust chain for the target host"
            }
            SecurityError::CrossOriginBlocked { .. } => {
                "Configure CORS headers properly or use same-origin requests"
            }
            SecurityError::MemoryExhaustion { .. } => {
                "Reduce resource size or increase memory limits for this operation"
            }
            SecurityError::FingerprintingAttempt { .. } => {
                "Fingerprinting detected - this is expected behavior for privacy protection"
            }
            SecurityError::SandboxViolation { .. } => {
                "Critical sandbox breach detected - investigate immediately"
            }
            _ => "Review security policies and configuration for this resource or operation",
        }
    }
} 