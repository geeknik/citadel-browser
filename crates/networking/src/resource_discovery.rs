use std::collections::HashMap;

use regex::Regex;
use url::Url;

use crate::error::NetworkError;
use crate::resource::ResourceType;

/// Reference to a resource found during parsing
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRef {
    /// The URL of the resource
    pub url: Url,
    /// The type of resource
    pub resource_type: ResourceType,
    /// Priority for loading (0 = highest priority)
    pub priority: u8,
    /// Whether this is a critical resource that blocks rendering
    pub is_critical: bool,
    /// Additional metadata about the resource
    pub metadata: HashMap<String, String>,
}

impl ResourceRef {
    /// Create a new resource reference
    pub fn new(url: Url, resource_type: ResourceType) -> Self {
        let priority = match resource_type {
            ResourceType::Html => 0,         // Highest priority
            ResourceType::Css => 1,          // High priority - blocks rendering
            ResourceType::Font => 2,         // Medium-high priority
            ResourceType::Script => 3,       // Medium priority
            ResourceType::Image => 4,        // Lower priority
            _ => 5,                          // Lowest priority
        };
        
        let is_critical = matches!(resource_type, ResourceType::Html | ResourceType::Css);
        
        Self {
            url,
            resource_type,
            priority,
            is_critical,
            metadata: HashMap::new(),
        }
    }
    
    /// Add metadata to the resource reference
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
    
    /// Set the priority of this resource
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }
    
    /// Mark this resource as critical or non-critical
    pub fn with_critical(mut self, is_critical: bool) -> Self {
        self.is_critical = is_critical;
        self
    }
}

/// Context for resource discovery
#[derive(Debug, Clone)]
pub struct ResourceContext {
    /// Base URL for resolving relative URLs
    pub base_url: Url,
    /// Whether to include non-critical resources
    pub include_non_critical: bool,
    /// Maximum number of resources to discover
    pub max_resources: Option<usize>,
    /// Resource types to include in discovery
    pub allowed_types: Option<Vec<ResourceType>>,
}

impl ResourceContext {
    /// Create a new resource context
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            include_non_critical: true,
            max_resources: Some(1000), // Reasonable limit
            allowed_types: None,
        }
    }
    
    /// Set whether to include non-critical resources
    pub fn include_non_critical(mut self, include: bool) -> Self {
        self.include_non_critical = include;
        self
    }
    
    /// Set the maximum number of resources to discover
    pub fn max_resources(mut self, max: Option<usize>) -> Self {
        self.max_resources = max;
        self
    }
    
    /// Set the allowed resource types
    pub fn allowed_types(mut self, types: Vec<ResourceType>) -> Self {
        self.allowed_types = Some(types);
        self
    }
}

/// Resource discovery engine that extracts resource references from HTML and CSS
#[derive(Debug)]
pub struct ResourceDiscovery {
    /// Compiled regex patterns for finding resources
    html_patterns: Vec<(Regex, ResourceType, bool)>, // (pattern, type, is_critical)
    css_patterns: Vec<(Regex, ResourceType, bool)>,
}

impl ResourceDiscovery {
    /// Create a new resource discovery engine
    pub fn new() -> Result<Self, NetworkError> {
        // HTML patterns for finding resources
        let html_patterns = vec![
            // Link tags for stylesheets
            (
                Regex::new(r#"<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\']([^"\']+)["\']"#)
                    .map_err(|e| NetworkError::ResourceError(format!("Regex error: {}", e)))?,
                ResourceType::Css,
                true, // CSS is critical
            ),
            // Alternative link pattern (href before rel)
            (
                Regex::new(r#"<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\']stylesheet["\']"#)
                    .map_err(|e| NetworkError::ResourceError(format!("Regex error: {}", e)))?,
                ResourceType::Css,
                true,
            ),
            // Script tags with src
            (
                Regex::new(r#"<script[^>]+src=["\']([^"\']+)["\']"#)
                    .map_err(|e| NetworkError::ResourceError(format!("Regex error: {}", e)))?,
                ResourceType::Script,
                false, // Scripts are not critical for initial render
            ),
            // Image tags
            (
                Regex::new(r#"<img[^>]+src=["\']([^"\']+)["\']"#)
                    .map_err(|e| NetworkError::ResourceError(format!("Regex error: {}", e)))?,
                ResourceType::Image,
                false, // Images are not critical
            ),
            // Link tags for preloading fonts
            (
                Regex::new(r#"<link[^>]+rel=["\']preload["\'][^>]+as=["\']font["\'][^>]+href=["\']([^"\']+)["\']"#)
                    .map_err(|e| NetworkError::ResourceError(format!("Regex error: {}", e)))?,
                ResourceType::Font,
                true, // Preloaded fonts are critical
            ),
            // Alternative font preload pattern
            (
                Regex::new(r#"<link[^>]+href=["\']([^"\']+)["\'][^>]+as=["\']font["\'][^>]+rel=["\']preload["\']"#)
                    .map_err(|e| NetworkError::ResourceError(format!("Regex error: {}", e)))?,
                ResourceType::Font,
                true,
            ),
        ];
        
        // CSS patterns for finding resources
        let css_patterns = vec![
            // @import statements
            (
                Regex::new(r#"@import\s+(?:url\()?["\']?([^"\')\s]+)["\']?\)?"#)
                    .map_err(|e| NetworkError::ResourceError(format!("Regex error: {}", e)))?,
                ResourceType::Css,
                true, // Imported CSS is critical
            ),
            // Font-face src urls
            (
                Regex::new(r#"@font-face[^}]*src:[^}]*url\(["\']?([^"\')\s]+)["\']?\)"#)
                    .map_err(|e| NetworkError::ResourceError(format!("Regex error: {}", e)))?,
                ResourceType::Font,
                true, // Fonts defined in CSS are critical
            ),
            // Background images
            (
                Regex::new(r#"background(?:-image)?:[^;}]*url\(["\']?([^"\')\s]+)["\']?\)"#)
                    .map_err(|e| NetworkError::ResourceError(format!("Regex error: {}", e)))?,
                ResourceType::Image,
                false, // Background images are not critical
            ),
            // General url() patterns in CSS
            (
                Regex::new(r#"url\(["\']?([^"\')\s]+)["\']?\)"#)
                    .map_err(|e| NetworkError::ResourceError(format!("Regex error: {}", e)))?,
                ResourceType::Other,
                false, // General resources are not critical
            ),
        ];
        
        Ok(Self {
            html_patterns,
            css_patterns,
        })
    }
    
    /// Discover resources from HTML content
    pub fn discover_from_html(
        &self,
        html: &str,
        context: &ResourceContext,
    ) -> Result<Vec<ResourceRef>, NetworkError> {
        let mut resources = Vec::new();
        let mut resource_count = 0;
        
        // Check resource limit
        let max_resources = context.max_resources.unwrap_or(usize::MAX);
        
        for (pattern, resource_type, is_critical) in &self.html_patterns {
            // Skip if this resource type is not allowed
            if let Some(ref allowed) = context.allowed_types {
                if !allowed.contains(resource_type) {
                    continue;
                }
            }
            
            // Skip non-critical resources if not requested
            if !context.include_non_critical && !is_critical {
                continue;
            }
            
            for captures in pattern.captures_iter(html) {
                if resource_count >= max_resources {
                    break;
                }
                
                if let Some(url_match) = captures.get(1) {
                    let url_str = url_match.as_str();
                    
                    // Resolve relative URLs
                    match self.resolve_url(url_str, &context.base_url) {
                        Ok(resolved_url) => {
                            // Skip data URLs and javascript URLs for security
                            if self.is_safe_url(&resolved_url) {
                                let resource_ref = ResourceRef::new(resolved_url, *resource_type)
                                    .with_critical(*is_critical);
                                
                                resources.push(resource_ref);
                                resource_count += 1;
                            }
                        }
                        Err(_) => {
                            // Skip invalid URLs
                            log::debug!("Skipping invalid URL in HTML: {}", url_str);
                        }
                    }
                }
            }
            
            if resource_count >= max_resources {
                break;
            }
        }
        
        Ok(resources)
    }
    
    /// Discover resources from CSS content
    pub fn discover_from_css(
        &self,
        css: &str,
        context: &ResourceContext,
    ) -> Result<Vec<ResourceRef>, NetworkError> {
        let mut resources = Vec::new();
        let mut resource_count = 0;
        
        // Check resource limit
        let max_resources = context.max_resources.unwrap_or(usize::MAX);
        
        for (pattern, resource_type, is_critical) in &self.css_patterns {
            // Skip if this resource type is not allowed
            if let Some(ref allowed) = context.allowed_types {
                if !allowed.contains(resource_type) {
                    continue;
                }
            }
            
            // Skip non-critical resources if not requested
            if !context.include_non_critical && !is_critical {
                continue;
            }
            
            for captures in pattern.captures_iter(css) {
                if resource_count >= max_resources {
                    break;
                }
                
                if let Some(url_match) = captures.get(1) {
                    let url_str = url_match.as_str();
                    
                    // Resolve relative URLs
                    match self.resolve_url(url_str, &context.base_url) {
                        Ok(resolved_url) => {
                            // Skip data URLs and javascript URLs for security
                            if self.is_safe_url(&resolved_url) {
                                let mut resource_ref = ResourceRef::new(resolved_url, *resource_type)
                                    .with_critical(*is_critical);
                                
                                // Add CSS-specific metadata
                                resource_ref = resource_ref.with_metadata("source", "css");
                                
                                resources.push(resource_ref);
                                resource_count += 1;
                            }
                        }
                        Err(_) => {
                            // Skip invalid URLs
                            log::debug!("Skipping invalid URL in CSS: {}", url_str);
                        }
                    }
                }
            }
            
            if resource_count >= max_resources {
                break;
            }
        }
        
        Ok(resources)
    }
    
    /// Discover resources from both HTML and embedded CSS
    pub fn discover_all(
        &self,
        html: &str,
        context: &ResourceContext,
    ) -> Result<Vec<ResourceRef>, NetworkError> {
        let mut all_resources = Vec::new();
        
        // First, discover resources from HTML
        let html_resources = self.discover_from_html(html, context)?;
        all_resources.extend(html_resources);
        
        // Then, extract inline CSS and discover resources from it
        let inline_css = self.extract_inline_css(html);
        for css_block in inline_css {
            let css_resources = self.discover_from_css(&css_block, context)?;
            all_resources.extend(css_resources);
        }
        
        // Remove duplicates and sort by priority
        self.deduplicate_and_sort(all_resources)
    }
    
    /// Extract inline CSS from HTML (style tags and style attributes)
    fn extract_inline_css(&self, html: &str) -> Vec<String> {
        let mut css_blocks = Vec::new();
        
        // Extract <style> tag contents
        if let Ok(style_regex) = Regex::new(r"<style[^>]*>(.*?)</style>") {
            for captures in style_regex.captures_iter(html) {
                if let Some(css_match) = captures.get(1) {
                    css_blocks.push(css_match.as_str().to_string());
                }
            }
        }
        
        // Extract style attribute contents
        if let Ok(style_attr_regex) = Regex::new(r#"style=["\']([^"\']*)["\']"#) {
            for captures in style_attr_regex.captures_iter(html) {
                if let Some(css_match) = captures.get(1) {
                    css_blocks.push(css_match.as_str().to_string());
                }
            }
        }
        
        css_blocks
    }
    
    /// Resolve a potentially relative URL against a base URL
    fn resolve_url(&self, url_str: &str, base_url: &Url) -> Result<Url, NetworkError> {
        // Handle absolute URLs
        if url_str.starts_with("http://") || url_str.starts_with("https://") {
            return Url::parse(url_str).map_err(NetworkError::UrlError);
        }
        
        // Handle protocol-relative URLs
        if url_str.starts_with("//") {
            let full_url = format!("{}:{}", base_url.scheme(), url_str);
            return Url::parse(&full_url).map_err(NetworkError::UrlError);
        }
        
        // Handle relative URLs
        base_url.join(url_str).map_err(NetworkError::UrlError)
    }
    
    /// Check if a URL is safe to load (no javascript: or data: schemes for security)
    fn is_safe_url(&self, url: &Url) -> bool {
        match url.scheme() {
            "https" | "http" => true,
            "data" => {
                // Only allow safe data URLs (images, fonts, etc.)
                if let Some(media_type) = url.path().split(',').next() {
                    media_type.starts_with("image/") || 
                    media_type.starts_with("font/") ||
                    media_type.starts_with("text/css")
                } else {
                    false
                }
            }
            _ => false, // Block javascript:, file:, and other potentially unsafe schemes
        }
    }
    
    /// Remove duplicates and sort resources by priority
    fn deduplicate_and_sort(&self, mut resources: Vec<ResourceRef>) -> Result<Vec<ResourceRef>, NetworkError> {
        // Remove duplicates based on URL
        resources.sort_by(|a, b| a.url.cmp(&b.url));
        resources.dedup_by(|a, b| a.url == b.url);
        
        // Sort by priority (lower number = higher priority)
        resources.sort_by(|a, b| {
            a.priority.cmp(&b.priority)
                .then_with(|| a.is_critical.cmp(&b.is_critical).reverse()) // Critical first
                .then_with(|| a.url.cmp(&b.url)) // Stable sort by URL
        });
        
        Ok(resources)
    }
}

impl Default for ResourceDiscovery {
    fn default() -> Self {
        Self::new().expect("Failed to create ResourceDiscovery with default patterns")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_resource_ref_creation() {
        let url = Url::parse("https://example.com/style.css").unwrap();
        let resource_ref = ResourceRef::new(url.clone(), ResourceType::Css);
        
        assert_eq!(resource_ref.url, url);
        assert_eq!(resource_ref.resource_type, ResourceType::Css);
        assert_eq!(resource_ref.priority, 1); // CSS should have high priority
        assert!(resource_ref.is_critical); // CSS should be critical
    }
    
    #[test]
    fn test_html_resource_discovery() {
        let discovery = ResourceDiscovery::new().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();
        let context = ResourceContext::new(base_url);
        
        let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <link rel="stylesheet" href="style.css">
            <script src="script.js"></script>
        </head>
        <body>
            <img src="image.png" alt="Test">
        </body>
        </html>
        "#;
        
        let resources = discovery.discover_from_html(html, &context).unwrap();
        
        // Should find CSS, script, and image
        assert!(resources.len() >= 3);
        
        // Check that we found the expected resources
        let css_found = resources.iter().any(|r| {
            r.url.path().ends_with("style.css") && r.resource_type == ResourceType::Css
        });
        let js_found = resources.iter().any(|r| {
            r.url.path().ends_with("script.js") && r.resource_type == ResourceType::Script
        });
        let img_found = resources.iter().any(|r| {
            r.url.path().ends_with("image.png") && r.resource_type == ResourceType::Image
        });
        
        assert!(css_found, "Should find CSS resource");
        assert!(js_found, "Should find JavaScript resource");
        assert!(img_found, "Should find image resource");
    }
    
    #[test]
    fn test_css_resource_discovery() {
        let discovery = ResourceDiscovery::new().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();
        let context = ResourceContext::new(base_url);
        
        let css = r#"
        @import url("imported.css");
        
        @font-face {
            font-family: 'CustomFont';
            src: url('fonts/custom.woff2') format('woff2');
        }
        
        .background {
            background-image: url("images/bg.jpg");
        }
        "#;
        
        let resources = discovery.discover_from_css(css, &context).unwrap();
        
        // Should find imported CSS, font, and background image
        assert!(resources.len() >= 3);
        
        // Check resource types
        let has_css = resources.iter().any(|r| r.resource_type == ResourceType::Css);
        let has_font = resources.iter().any(|r| r.resource_type == ResourceType::Font);
        let has_image = resources.iter().any(|r| r.resource_type == ResourceType::Image);
        
        assert!(has_css, "Should find imported CSS");
        assert!(has_font, "Should find font resource");
        assert!(has_image, "Should find background image");
    }
    
    #[test]
    fn test_resource_context_filtering() {
        let discovery = ResourceDiscovery::new().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();
        
        // Test with only critical resources
        let context = ResourceContext::new(base_url.clone())
            .include_non_critical(false);
        
        let html = r#"
        <html>
        <head>
            <link rel="stylesheet" href="style.css">
            <script src="script.js"></script>
        </head>
        <body>
            <img src="image.png" alt="Test">
        </body>
        </html>
        "#;
        
        let resources = discovery.discover_from_html(html, &context).unwrap();
        
        // Should only find critical resources (CSS), not scripts or images
        assert!(resources.iter().all(|r| r.is_critical));
        
        // Test with resource type filtering
        let context = ResourceContext::new(base_url)
            .allowed_types(vec![ResourceType::Css]);
        
        let resources = discovery.discover_from_html(html, &context).unwrap();
        
        // Should only find CSS resources
        assert!(resources.iter().all(|r| r.resource_type == ResourceType::Css));
    }
    
    #[test]
    fn test_url_resolution() {
        let discovery = ResourceDiscovery::new().unwrap();
        let base_url = Url::parse("https://example.com/path/page.html").unwrap();
        
        // Test relative URL resolution
        let relative_url = discovery.resolve_url("../style.css", &base_url).unwrap();
        assert_eq!(relative_url.as_str(), "https://example.com/style.css");
        
        // Test absolute URL
        let absolute_url = discovery.resolve_url("https://cdn.example.com/font.woff", &base_url).unwrap();
        assert_eq!(absolute_url.as_str(), "https://cdn.example.com/font.woff");
        
        // Test protocol-relative URL
        let protocol_relative = discovery.resolve_url("//cdn.example.com/script.js", &base_url).unwrap();
        assert_eq!(protocol_relative.as_str(), "https://cdn.example.com/script.js");
    }
    
    #[test]
    fn test_security_url_filtering() {
        let discovery = ResourceDiscovery::new().unwrap();
        
        // Safe URLs
        let https_url = Url::parse("https://example.com/style.css").unwrap();
        assert!(discovery.is_safe_url(&https_url));
        
        let http_url = Url::parse("http://example.com/style.css").unwrap();
        assert!(discovery.is_safe_url(&http_url));
        
        let data_image = Url::parse("data:image/png;base64,iVBORw0KGg").unwrap();
        assert!(discovery.is_safe_url(&data_image));
        
        // Unsafe URLs
        let javascript_url = Url::parse("javascript:alert('xss')").unwrap();
        assert!(!discovery.is_safe_url(&javascript_url));
        
        let file_url = Url::parse("file:///etc/passwd").unwrap();
        assert!(!discovery.is_safe_url(&file_url));
    }
}