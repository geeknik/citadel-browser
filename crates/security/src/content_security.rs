//! Content Security Module
//!
//! Provides comprehensive content security protections including XSS prevention,
//! content sanitization, and security policy enforcement.

use std::collections::HashSet;
use crate::error::SecurityError;

/// Content security configuration
#[derive(Debug, Clone)]
pub struct ContentSecurityConfig {
    /// Enable XSS protection
    pub enable_xss_protection: bool,
    /// Enable script filtering
    pub enable_script_filtering: bool,
    /// Enable CSS filtering
    pub enable_css_filtering: bool,
    /// Allow inline scripts
    pub allow_inline_scripts: bool,
    /// Allow external resources
    pub allow_external_resources: bool,
}

impl Default for ContentSecurityConfig {
    fn default() -> Self {
        Self {
            enable_xss_protection: true,
            enable_script_filtering: true,
            enable_css_filtering: true,
            allow_inline_scripts: false,
            allow_external_resources: false,
        }
    }
}

/// Content security manager
pub struct ContentSecurityManager {
    config: ContentSecurityConfig,
    dangerous_tags: HashSet<String>,
    dangerous_attrs: HashSet<String>,
    dangerous_protocols: HashSet<String>,
}

impl ContentSecurityManager {
    /// Create a new content security manager
    pub fn new(config: ContentSecurityConfig) -> Self {
        let dangerous_tags = HashSet::from([
            "script".to_string(),
            "iframe".to_string(),
            "object".to_string(),
            "embed".to_string(),
            "form".to_string(),
            "input".to_string(),
            "textarea".to_string(),
            "button".to_string(),
            "select".to_string(),
            "link".to_string(),
            "meta".to_string(),
            "style".to_string(),
        ]);

        let dangerous_attrs = HashSet::from([
            "onclick".to_string(),
            "onload".to_string(),
            "onerror".to_string(),
            "onmouseover".to_string(),
            "onmouseout".to_string(),
            "onfocus".to_string(),
            "onblur".to_string(),
            "onchange".to_string(),
            "onsubmit".to_string(),
            "onreset".to_string(),
            "onkeydown".to_string(),
            "onkeyup".to_string(),
            "onkeypress".to_string(),
            "href".to_string(),
            "src".to_string(),
            "action".to_string(),
        ]);

        let dangerous_protocols = HashSet::from([
            "javascript:".to_string(),
            "vbscript:".to_string(),
            "data:text/html".to_string(),
            "data:text/javascript".to_string(),
        ]);

        Self {
            config,
            dangerous_tags,
            dangerous_attrs,
            dangerous_protocols,
        }
    }

    /// Sanitize HTML content
    pub fn sanitize_html(&self, html: &str) -> Result<String, SecurityError> {
        if !self.config.enable_xss_protection {
            return Ok(html.to_string());
        }

        // Basic HTML sanitization
        let mut sanitized = html.to_string();

        // Remove script tags
        for tag in &self.dangerous_tags {
            sanitized = sanitized.replace(&format!("<{} ", tag), &format!("<sanitized-{} ", tag));
            sanitized = sanitized.replace(&format!("<{}>", tag), &format!("<sanitized-{}>", tag));
            sanitized = sanitized.replace(&format!("</{}>", tag), &format!("</sanitized-{}>", tag));
        }

        // Remove dangerous attributes
        for attr in &self.dangerous_attrs {
            sanitized = sanitized.replace(&format!("{}=\"", attr), &format!("sanitized-{}=\"", attr));
            sanitized = sanitized.replace(&format!("{}='", attr), &format!("sanitized-{}='", attr));
        }

        // Remove dangerous protocols
        for protocol in &self.dangerous_protocols {
            sanitized = sanitized.replace(protocol, "sanitized:");
        }

        Ok(sanitized)
    }

    /// Check if URL is safe
    pub fn is_safe_url(&self, url: &str) -> bool {
        if self.config.allow_external_resources {
            return true;
        }

        for protocol in &self.dangerous_protocols {
            if url.to_lowercase().starts_with(protocol) {
                return false;
            }
        }

        true
    }

    /// Generate Content Security Policy header
    pub fn generate_csp_header(&self) -> String {
        let mut directives = vec![
            "default-src 'self'".to_string(),
            "script-src 'self'".to_string(),
            "style-src 'self'".to_string(),
            "img-src 'self' data:".to_string(),
            "font-src 'self'".to_string(),
            "connect-src 'self'".to_string(),
            "frame-ancestors 'none'".to_string(),
            "base-uri 'self'".to_string(),
            "form-action 'self'".to_string(),
        ];

        if self.config.allow_inline_scripts {
            directives.push("script-src 'self' 'unsafe-inline'".to_string());
        }

        directives.join("; ")
    }

    /// Validate CSS content
    pub fn validate_css(&self, css: &str) -> Result<String, SecurityError> {
        if !self.config.enable_css_filtering {
            return Ok(css.to_string());
        }

        // Basic CSS filtering
        let mut sanitized = css.to_string();

        // Remove dangerous CSS functions
        let dangerous_functions = vec![
            "expression(",
            "url(",
            "@import",
            "javascript:",
            "vbscript:",
        ];

        for function in dangerous_functions {
            sanitized = sanitized.replace(function, &format!("sanitized-{}", function));
        }

        Ok(sanitized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_sanitization() {
        let config = ContentSecurityConfig::default();
        let manager = ContentSecurityManager::new(config);

        let html = r#"<script>alert('xss')</script><div onclick="alert('xss')">Test</div>"#;
        let result = manager.sanitize_html(html).unwrap();

        assert!(!result.contains("<script"));
        assert!(!result.contains("onclick"));
        assert!(result.contains("sanitized-"));
    }

    #[test]
    fn test_url_safety() {
        let config = ContentSecurityConfig {
            allow_external_resources: false,
            ..Default::default()
        };
        let manager = ContentSecurityManager::new(config);

        assert!(!manager.is_safe_url("javascript:alert('xss')"));
        assert!(manager.is_safe_url("https://example.com"));
    }

    #[test]
    fn test_csp_generation() {
        let config = ContentSecurityConfig::default();
        let manager = ContentSecurityManager::new(config);

        let csp = manager.generate_csp_header();
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self'"));
    }
}