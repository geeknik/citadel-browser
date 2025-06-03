use thiserror::Error;

/// NetworkError represents all possible errors that can occur within the networking layer
#[derive(Error, Debug)]
pub enum NetworkError {
    /// DNS resolution errors
    #[error("DNS resolution error: {0}")]
    DnsError(#[from] trust_dns_resolver::error::ResolveError),

    /// HTTP request errors
    #[error("HTTP request error: {0}")]
    HttpError(#[from] hyper::Error),

    /// TLS/SSL errors
    #[error("TLS/SSL error: {0}")]
    TlsError(String),

    /// Connection errors
    #[error("Connection error: {0}")]
    ConnectionError(String),

    /// URL parsing errors
    #[error("URL parsing error: {0}")]
    UrlError(#[from] url::ParseError),

    /// Timeout errors
    #[error("Request timed out after {0:?}")]
    TimeoutError(std::time::Duration),

    /// HTTPS enforcement error - attempt to use HTTP when HTTPS is enforced
    #[error("HTTPS enforcement error: {0}")]
    HttpsEnforcementError(String),

    /// Privacy violation error - attempt to use a feature that would compromise privacy
    #[error("Privacy violation: {0}")]
    PrivacyViolationError(String),

    /// Resource loading errors
    #[error("Resource loading error: {0}")]
    ResourceError(String),

    /// IO errors
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization errors
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Unknown or unclassified errors
    #[error("Unknown error: {0}")]
    UnknownError(String),
}

impl NetworkError {
    /// Returns true if the error is related to privacy protection
    pub fn is_privacy_related(&self) -> bool {
        matches!(
            self,
            NetworkError::PrivacyViolationError(_) | NetworkError::HttpsEnforcementError(_)
        )
    }

    /// Returns true if the error is likely temporary and the request could be retried
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            NetworkError::ConnectionError(_) |
            NetworkError::TimeoutError(_) |
            NetworkError::DnsError(_)
        )
    }
} 