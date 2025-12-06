use std::collections::HashMap;

use sha2::{Sha256, Sha384, Sha512, Digest};
use base64::{Engine as _, engine::general_purpose};
use url::Url;

use crate::error::NetworkError;
use crate::response::Response;

/// Supported integrity hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// Subresource integrity verification result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityResult {
    /// Integrity check passed
    Valid,
    /// Integrity check failed - content has been modified
    Invalid,
    /// No integrity information provided
    NotProvided,
    /// Unsupported hash algorithm
    UnsupportedAlgorithm,
    /// Malformed integrity attribute
    MalformedAttribute,
}

/// Content Security Policy violation types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CSPViolation {
    /// Script source not allowed
    ScriptSrc,
    /// Style source not allowed  
    StyleSrc,
    /// Image source not allowed
    ImgSrc,
    /// Font source not allowed
    FontSrc,
    /// Object source not allowed
    ObjectSrc,
    /// Media source not allowed
    MediaSrc,
    /// Frame source not allowed
    FrameSrc,
    /// Connect source not allowed
    ConnectSrc,
    /// Base URI not allowed
    BaseUri,
    /// Form action not allowed
    FormAction,
}

/// Content integrity and security validator
#[derive(Debug)]
pub struct IntegrityValidator {
    /// CSP policy directives
    csp_directives: HashMap<String, Vec<String>>,
    /// Whether to enforce strict CSP
    strict_csp: bool,
    /// Whether to require integrity for all resources
    require_integrity: bool,
}

impl IntegrityValidator {
    /// Create a new integrity validator
    pub fn new() -> Self {
        Self {
            csp_directives: HashMap::new(),
            strict_csp: false,
            require_integrity: false,
        }
    }

    /// Create validator with strict security settings
    pub fn strict() -> Self {
        let mut validator = Self::new();
        validator.strict_csp = true;
        validator.require_integrity = true;
        
        // Set default strict CSP
        validator.csp_directives.insert(
            "default-src".to_string(),
            vec!["'self'".to_string()]
        );
        validator.csp_directives.insert(
            "script-src".to_string(),
            vec!["'self'".to_string()]
        );
        validator.csp_directives.insert(
            "style-src".to_string(),
            vec!["'self'".to_string(), "'unsafe-inline'".to_string()]
        );
        validator.csp_directives.insert(
            "img-src".to_string(),
            vec!["'self'".to_string(), "data:".to_string()]
        );
        
        validator
    }

    /// Set CSP directives from a Content-Security-Policy header
    pub fn set_csp_from_header(&mut self, csp_header: &str) {
        self.csp_directives.clear();
        
        for directive in csp_header.split(';') {
            let directive = directive.trim();
            if let Some(space_pos) = directive.find(' ') {
                let name = directive[..space_pos].trim().to_string();
                let values: Vec<String> = directive[space_pos + 1..]
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
                
                self.csp_directives.insert(name, values);
            } else if !directive.is_empty() {
                // Directive without values (like 'upgrade-insecure-requests')
                self.csp_directives.insert(directive.to_string(), vec![]);
            }
        }
    }

    /// Add a CSP directive
    pub fn add_csp_directive(&mut self, directive: &str, values: Vec<&str>) {
        self.csp_directives.insert(
            directive.to_string(),
            values.into_iter().map(|s| s.to_string()).collect()
        );
    }

    /// Verify subresource integrity
    pub fn verify_integrity(&self, content: &[u8], integrity: &str) -> IntegrityResult {
        if integrity.is_empty() {
            return if self.require_integrity {
                IntegrityResult::Invalid
            } else {
                IntegrityResult::NotProvided
            };
        }

        // Parse integrity attribute (format: "algorithm-hash")
        for integrity_value in integrity.split_whitespace() {
            if let Some(dash_pos) = integrity_value.find('-') {
                let algorithm = &integrity_value[..dash_pos];
                let expected_hash = &integrity_value[dash_pos + 1..];

                let algorithm = match algorithm {
                    "sha256" => HashAlgorithm::Sha256,
                    "sha384" => HashAlgorithm::Sha384,
                    "sha512" => HashAlgorithm::Sha512,
                    _ => return IntegrityResult::UnsupportedAlgorithm,
                };

                if self.verify_hash(content, algorithm, expected_hash) {
                    return IntegrityResult::Valid;
                }
            } else {
                return IntegrityResult::MalformedAttribute;
            }
        }

        IntegrityResult::Invalid
    }

    /// Verify a hash against content
    fn verify_hash(&self, content: &[u8], algorithm: HashAlgorithm, expected_hash: &str) -> bool {
        let calculated_hash = match algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(content);
                general_purpose::STANDARD.encode(hasher.finalize())
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(content);
                general_purpose::STANDARD.encode(hasher.finalize())
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(content);
                general_purpose::STANDARD.encode(hasher.finalize())
            }
        };

        calculated_hash == expected_hash
    }

    /// Check if a URL is allowed by CSP for a given resource type
    pub fn check_csp_violation(&self, url: &Url, resource_type: &str) -> Option<CSPViolation> {
        let directive_name = match resource_type {
            "script" => "script-src",
            "style" => "style-src", 
            "image" => "img-src",
            "font" => "font-src",
            "object" => "object-src",
            "media" => "media-src",
            "frame" => "frame-src",
            "connect" => "connect-src",
            _ => "default-src",
        };

        // Check specific directive first, fallback to default-src
        let allowed_sources = self.csp_directives.get(directive_name)
            .or_else(|| self.csp_directives.get("default-src"));

        if let Some(sources) = allowed_sources {
            if self.is_url_allowed(url, sources) {
                None
            } else {
                Some(match resource_type {
                    "script" => CSPViolation::ScriptSrc,
                    "style" => CSPViolation::StyleSrc,
                    "image" => CSPViolation::ImgSrc,
                    "font" => CSPViolation::FontSrc,
                    "object" => CSPViolation::ObjectSrc,
                    "media" => CSPViolation::MediaSrc,
                    "frame" => CSPViolation::FrameSrc,
                    "connect" => CSPViolation::ConnectSrc,
                    _ => CSPViolation::ScriptSrc, // Default fallback
                })
            }
        } else if self.strict_csp {
            // In strict CSP mode, deny if no directive is set
            Some(CSPViolation::ScriptSrc)
        } else {
            // Allow if no CSP is set and not in strict mode
            None
        }
    }

    /// Check if a URL is allowed by the given CSP sources
    fn is_url_allowed(&self, url: &Url, sources: &[String]) -> bool {
        for source in sources {
            if self.matches_csp_source(url, source) {
                return true;
            }
        }
        false
    }

    /// Check if a URL matches a CSP source expression
    fn matches_csp_source(&self, url: &Url, source: &str) -> bool {
        match source {
            "'self'" => {
                // Would need the page origin to implement properly
                // For now, assume same-origin if scheme is https
                url.scheme() == "https"
            }
            "'unsafe-inline'" => {
                // This would apply to inline scripts/styles, not external resources
                false
            }
            "'unsafe-eval'" => {
                // This applies to eval(), not external resources
                false
            }
            "'none'" => false,
            _ if source.starts_with("data:") => {
                url.scheme() == "data"
            }
            _ if source.starts_with("https:") => {
                url.scheme() == "https"
            }
            _ if source.starts_with("http:") => {
                url.scheme() == "http"
            }
            _ if source.contains("://") => {
                // Full URL match
                url.as_str().starts_with(source)
            }
            _ => {
                // Host/domain match
                if let Some(host) = url.host_str() {
                    if let Some(domain) = source.strip_prefix("*.") {
                        // Wildcard subdomain match
                        host.ends_with(domain)
                    } else {
                        // Exact host match
                        host == source
                    }
                } else {
                    false
                }
            }
        }
    }

    /// Validate response content and headers for security issues
    pub fn validate_response(&self, response: &Response) -> Result<Vec<String>, NetworkError> {
        let mut warnings = Vec::new();

        // Check for missing security headers
        if response.header("content-security-policy").is_none() && self.strict_csp {
            warnings.push("Missing Content-Security-Policy header".to_string());
        }

        if response.header("x-content-type-options").is_none() {
            warnings.push("Missing X-Content-Type-Options header".to_string());
        }

        if response.header("x-frame-options").is_none() {
            warnings.push("Missing X-Frame-Options header".to_string());
        }

        if response.url().scheme() == "https"
            && response.header("strict-transport-security").is_none()
        {
            warnings.push("Missing Strict-Transport-Security header".to_string());
        }

        // Check for potentially dangerous content types
        if let Some(content_type) = response.content_type() {
            let ct = content_type.to_lowercase();
            if ct.contains("application/octet-stream") && response.url().path().ends_with(".js") {
                warnings.push("JavaScript served with generic binary content type".to_string());
            }
            
            if ct.contains("text/html") && response.url().path().ends_with(".js") {
                warnings.push("JavaScript file served with HTML content type".to_string());
            }
        }

        // Check for suspicious response patterns
        let body = response.body();
        if !body.is_empty() {
            let body_str = String::from_utf8_lossy(body);
            
            // Check for potential XSS payloads in responses
            if body_str.contains("<script") && !response.is_html() {
                warnings.push("Script tags found in non-HTML response".to_string());
            }
            
            // Check for potential data exfiltration patterns
            if body_str.contains("document.cookie") || body_str.contains("localStorage") {
                warnings.push("Potential sensitive data access detected".to_string());
            }
        }

        Ok(warnings)
    }

    /// Generate integrity hash for content
    pub fn generate_integrity(&self, content: &[u8], algorithm: HashAlgorithm) -> String {
        let hash = match algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(content);
                format!("sha256-{}", general_purpose::STANDARD.encode(hasher.finalize()))
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(content);
                format!("sha384-{}", general_purpose::STANDARD.encode(hasher.finalize()))
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(content);
                format!("sha512-{}", general_purpose::STANDARD.encode(hasher.finalize()))
            }
        };

        hash
    }

    /// Check if strict CSP mode is enabled
    pub fn is_strict(&self) -> bool {
        self.strict_csp
    }

    /// Check if integrity is required for all resources
    pub fn requires_integrity(&self) -> bool {
        self.require_integrity
    }
}

impl Default for IntegrityValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_integrity() {
        let validator = IntegrityValidator::new();
        let content = b"Hello, World!";
        
        // Generate integrity hash
        let integrity = validator.generate_integrity(content, HashAlgorithm::Sha256);
        
        // Verify the integrity
        let result = validator.verify_integrity(content, &integrity);
        assert_eq!(result, IntegrityResult::Valid);
    }

    #[test]
    fn test_invalid_integrity() {
        let validator = IntegrityValidator::new();
        let content = b"Hello, World!";
        let wrong_integrity = "sha256-wronghash";
        
        let result = validator.verify_integrity(content, wrong_integrity);
        assert_eq!(result, IntegrityResult::Invalid);
    }

    #[test]
    fn test_csp_self_policy() {
        let mut validator = IntegrityValidator::new();
        validator.add_csp_directive("script-src", vec!["'self'"]);
        
        let https_url = Url::parse("https://example.com/script.js").unwrap();
        let violation = validator.check_csp_violation(&https_url, "script");
        
        // Should be allowed for 'self' (simplified check)
        assert!(violation.is_none());
    }

    #[test]
    fn test_csp_violation() {
        let validator = IntegrityValidator::strict();
        
        let external_url = Url::parse("https://evil.com/script.js").unwrap();
        let violation = validator.check_csp_violation(&external_url, "script");
        
        // Should be blocked in strict mode
        assert!(violation.is_some());
    }

    #[test]
    fn test_malformed_integrity() {
        let validator = IntegrityValidator::new();
        let content = b"test";
        let malformed = "not-a-valid-integrity";
        
        let result = validator.verify_integrity(content, malformed);
        assert_eq!(result, IntegrityResult::MalformedAttribute);
    }

    #[test]
    fn test_unsupported_algorithm() {
        let validator = IntegrityValidator::new();
        let content = b"test";
        let unsupported = "md5-abcd1234";
        
        let result = validator.verify_integrity(content, unsupported);
        assert_eq!(result, IntegrityResult::UnsupportedAlgorithm);
    }

    #[test]
    fn test_csp_wildcard_domain() {
        let mut validator = IntegrityValidator::new();
        validator.add_csp_directive("script-src", vec!["*.example.com"]);
        
        let subdomain_url = Url::parse("https://cdn.example.com/script.js").unwrap();
        let violation = validator.check_csp_violation(&subdomain_url, "script");
        
        assert!(violation.is_none());
    }
}
