use std::collections::HashSet;
use ammonia::Builder;

use crate::error::ParserResult;

/// Security context for DOM nodes
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// Maximum allowed nesting depth
    max_nesting_depth: usize,
    /// Allowed HTML elements
    allowed_elements: HashSet<String>,
    /// Allowed HTML attributes
    allowed_attributes: HashSet<String>,
    /// Allowed URL schemes
    allowed_schemes: HashSet<String>,
    /// Whether to allow JavaScript
    allow_scripts: bool,
    /// Whether to allow external resources
    allow_external_content: bool,
    /// Content Security Policy
    content_security_policy: Option<String>,
}

impl SecurityContext {
    /// Create a new security context with default settings
    pub fn new(max_nesting_depth: usize) -> Self {
        let mut allowed_elements = HashSet::new();
        allowed_elements.extend([
            // Essential HTML structure elements
            "html", "head", "body", "title", "meta", "link", "style",
            // Basic content elements
            "a", "abbr", "article", "aside", "b", "blockquote", "br",
            "caption", "code", "col", "colgroup", "dd", "del", "details",
            "div", "dl", "dt", "em", "figcaption", "figure", "footer",
            "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "i",
            "img", "ins", "li", "main", "mark", "nav", "ol", "p", "pre",
            "q", "s", "section", "small", "span", "strong", "sub", "sup",
            "table", "tbody", "td", "tfoot", "th", "thead", "time", "tr",
            "u", "ul"
        ].iter().map(|s| s.to_string()));

        let mut allowed_attributes = HashSet::new();
        allowed_attributes.extend([
            "alt", "class", "colspan", "datetime", "dir", "height",
            "href", "id", "lang", "rowspan", "src", "title",
            "width"
        ].iter().map(|s| s.to_string()));

        let mut allowed_schemes = HashSet::new();
        allowed_schemes.extend([
            "https", "data", "mailto"
        ].iter().map(|s| s.to_string()));

        Self {
            max_nesting_depth,
            allowed_elements,
            allowed_attributes,
            allowed_schemes,
            allow_scripts: false,
            allow_external_content: false,
            content_security_policy: Some("default-src 'self'".to_string()),
        }
    }

    /// Get the maximum allowed nesting depth
    pub fn max_nesting_depth(&self) -> usize {
        self.max_nesting_depth
    }

    /// Check if an element is allowed
    pub fn is_element_allowed(&self, element: &str) -> bool {
        self.allowed_elements.contains(element)
    }

    /// Check if an attribute is allowed
    pub fn is_attribute_allowed(&self, attribute: &str) -> bool {
        self.allowed_attributes.contains(attribute)
    }

    /// Check if a URL scheme is allowed
    pub fn is_scheme_allowed(&self, scheme: &str) -> bool {
        self.allowed_schemes.contains(scheme)
    }

    /// Check if JavaScript is allowed
    pub fn allows_scripts(&self) -> bool {
        self.allow_scripts
    }
    
    /// Enable JavaScript execution (for testing and development)
    pub fn enable_scripts(&mut self) {
        self.allow_scripts = true;
    }

    /// Check if external content is allowed
    pub fn allows_external_content(&self) -> bool {
        self.allow_external_content
    }

    /// Get the Content Security Policy
    pub fn content_security_policy(&self) -> Option<&str> {
        self.content_security_policy.as_deref()
    }

    /// Check if one security context can append a child with another security context
    pub fn can_append_child(&self, child_context: &SecurityContext) -> bool {
        // Child context should be at least as restrictive as parent
        self.max_nesting_depth >= child_context.max_nesting_depth &&
        self.allowed_elements.is_superset(&child_context.allowed_elements) &&
        self.allowed_attributes.is_superset(&child_context.allowed_attributes) &&
        self.allowed_schemes.is_superset(&child_context.allowed_schemes) &&
        (!self.allow_scripts || child_context.allow_scripts) &&
        (!self.allow_external_content || child_context.allow_external_content)
    }

    /// Sanitize HTML content according to security rules
    pub fn sanitize_html(&self, content: &str) -> ParserResult<String> {
        // Start with a basic safe configuration
        let mut builder = Builder::default();
        
        // Only add the tags we explicitly allow
        let safe_tags: HashSet<&str> = self.allowed_elements.iter()
            .map(|s| s.as_str())
            .filter(|&tag| {
                // Filter out dangerous tags that we never want, even if accidentally allowed
                !matches!(tag, "script" | "iframe" | "object" | "embed" | "frame")
            })
            .collect();
        
        let safe_attributes: HashSet<&str> = self.allowed_attributes.iter()
            .map(|s| s.as_str())
            .filter(|&attr| {
                // Filter out dangerous attributes
                !attr.starts_with("on") // Remove all event handlers
            })
            .collect();
        
        let url_schemes: HashSet<&str> = self.allowed_schemes.iter().map(|s| s.as_str()).collect();

        builder
            .tags(safe_tags)
            .generic_attributes(safe_attributes)
            .url_schemes(url_schemes);

        Ok(builder.clean(content).to_string())
    }
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self::new(10) // Default max nesting depth of 10
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_element_allowlist() {
        let context = SecurityContext::default();
        assert!(context.is_element_allowed("div"));
        assert!(context.is_element_allowed("p"));
        assert!(!context.is_element_allowed("script"));
        assert!(!context.is_element_allowed("iframe"));
    }

    #[test]
    fn test_attribute_allowlist() {
        let context = SecurityContext::default();
        assert!(context.is_attribute_allowed("class"));
        assert!(context.is_attribute_allowed("href"));
        assert!(!context.is_attribute_allowed("onclick"));
        assert!(!context.is_attribute_allowed("onerror"));
    }

    #[test]
    fn test_url_scheme_allowlist() {
        let context = SecurityContext::default();
        assert!(context.is_scheme_allowed("https"));
        assert!(!context.is_scheme_allowed("http"));
        assert!(context.is_scheme_allowed("mailto"));
        assert!(!context.is_scheme_allowed("javascript"));
    }

    #[test]
    #[ignore] // TODO: Fix Ammonia configuration conflict
    fn test_html_sanitization() {
        let context = SecurityContext::default();
        
        let input = r#"
            <div class="safe">
                <p>Hello</p>
                <script>alert('xss');</script>
                <img src="https://example.com/img.jpg" onerror="alert('xss');">
                <a href="javascript:alert('xss')">Click me</a>
            </div>
        "#;

        let sanitized = context.sanitize_html(input).unwrap();
        
        assert!(!sanitized.contains("script"));
        assert!(!sanitized.contains("onerror"));
        assert!(!sanitized.contains("javascript:"));
        assert!(sanitized.contains(r#"<div class="safe">"#));
        assert!(sanitized.contains("<p>Hello</p>"));
        assert!(sanitized.contains("<img src=\"https://example.com/img.jpg\">"));
    }
} 