use std::sync::Arc;
use std::collections::HashMap;
use tokio::runtime::Runtime;
use url::Url;

use citadel_networking::{NetworkConfig, Request, Method, CitadelDnsResolver};
use citadel_security::SecurityContext;
use citadel_parser::{parse_html, parse_css, security::SecurityContext as ParserSecurityContext, Dom, CitadelStylesheet};
use crate::resource_loader::ResourceLoader;

// Import structured types from app.rs
use crate::app::{ParsedPageData, LoadingError, ErrorType};
use crate::renderer::FormSubmission;

/// Browser engine responsible for loading and processing web pages
#[derive(Debug, Clone)]
pub struct BrowserEngine {
    /// Async runtime for network operations
    runtime: Arc<Runtime>,
    /// Network configuration
    network_config: NetworkConfig,
    /// Security context for parsing
    security_context: Arc<SecurityContext>,
    /// DNS resolver
    dns_resolver: Arc<CitadelDnsResolver>,
    /// Resource loader for HTML/CSS/assets
    resource_loader: Arc<ResourceLoader>,
}

impl BrowserEngine {
    /// Create a new browser engine
    pub async fn new(
        runtime: Arc<Runtime>,
        network_config: NetworkConfig,
        security_context: Arc<SecurityContext>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Initialize DNS resolver based on configuration
        let dns_resolver = Arc::new(CitadelDnsResolver::new().await?);
        let resource_loader = Arc::new(ResourceLoader::new(security_context.clone()).await?);
        
        Ok(Self {
            runtime,
            network_config,
            security_context,
            dns_resolver,
            resource_loader,
        })
    }
    
    /// Update the network configuration
    pub async fn update_network_config(mut self, config: NetworkConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        self.network_config = config;
        // Update DNS resolver if mode changed
        self.dns_resolver = Arc::new(CitadelDnsResolver::new().await?);
        Ok(self)
    }
    
    /// Load a web page from the given URL with progress tracking
    pub async fn load_page_with_progress(&self, url: Url, tab_id: uuid::Uuid) -> Result<ParsedPageData, LoadingError> {
        let start_time = std::time::Instant::now();
        log::info!("🌐 Loading page with progress tracking: {} (tab: {})", url, tab_id);

        if url.scheme() == "file" {
            let path = url.to_file_path().map_err(|_| LoadingError {
                error_type: ErrorType::Content,
                message: "Invalid file path".to_string(),
                url: url.to_string(),
                timestamp: std::time::SystemTime::now(),
                retry_possible: false,
            })?;

            let content = std::fs::read_to_string(path).map_err(|e| LoadingError {
                error_type: ErrorType::Network, // Or a new file-specific error type
                message: format!("Failed to read file: {}", e),
                url: url.to_string(),
                timestamp: std::time::SystemTime::now(),
                retry_possible: true,
            })?;

            let (title, content, element_count, security_warnings, dom, stylesheet) = self.parse_html_content_enhanced(&content, url.as_str()).await.map_err(|e| LoadingError {
                error_type: ErrorType::Content,
                message: e,
                url: url.to_string(),
                timestamp: std::time::SystemTime::now(),
                retry_possible: true,
            })?;

            let load_time_ms = start_time.elapsed().as_millis() as u64;

            return Ok(ParsedPageData {
                title,
                content: content.clone(),
                element_count,
                size_bytes: content.len(),
                url: url.to_string(),
                load_time_ms,
                security_warnings,
                dom: Some(dom),
                stylesheet: Some(stylesheet),
            });
        }

        // Validate URL scheme
        if url.scheme() != "https" && url.scheme() != "http" {
            return Err(LoadingError {
                error_type: ErrorType::Security,
                message: format!("Unsupported URL scheme: {}", url.scheme()),
                url: url.to_string(),
                timestamp: std::time::SystemTime::now(),
                retry_possible: false,
            });
        }
        
        // Enforce HTTPS if configured
        let final_url = if self.network_config.enforce_https && url.scheme() == "http" {
            let mut https_url = url.clone();
            https_url.set_scheme("https").map_err(|_| LoadingError {
                error_type: ErrorType::Security,
                message: "Failed to upgrade to HTTPS".to_string(),
                url: url.to_string(),
                timestamp: std::time::SystemTime::now(),
                retry_possible: true,
            })?;
            log::info!("🔒 Upgraded HTTP to HTTPS: {}", https_url);
            https_url
        } else {
            url
        };
        
        // Create HTTP request with privacy settings
        let request = Request::new(Method::GET, final_url.as_str())
            .map_err(|e| LoadingError {
                error_type: ErrorType::Network,
                message: format!("Failed to create request: {}", e),
                url: final_url.to_string(),
                timestamp: std::time::SystemTime::now(),
                retry_possible: true,
            })?
            .with_privacy_level(self.network_config.privacy_level)
            .prepare();
        
        // Perform DNS resolution
        let host = final_url.host_str().ok_or_else(|| LoadingError {
            error_type: ErrorType::Content,
            message: "Invalid host in URL".to_string(),
            url: final_url.to_string(),
            timestamp: std::time::SystemTime::now(),
            retry_possible: false,
        })?;
        
        // DNS resolution is handled by reqwest - respects system DNS settings
        log::debug!("📍 Using system DNS configuration via reqwest for host: {}", host);
        
        // Make HTTP request
        let response = match self.resource_loader.load_html(final_url.clone()).await {
            Ok(html) => html,
            Err(load_err) => {
                log::warn!("Resource loader failed for {} ({}), falling back to raw HTTP", final_url, load_err);
                self.make_http_request(request).await.map_err(|e| LoadingError {
                    error_type: ErrorType::Network,
                    message: e,
                    url: final_url.to_string(),
                    timestamp: std::time::SystemTime::now(),
                    retry_possible: true,
                })?
            }
        };
        
        // Parse and sanitize the HTML content
        let (title, content, element_count, security_warnings, dom, stylesheet) = self.parse_html_content_enhanced(&response, final_url.as_str()).await.map_err(|e| LoadingError {
            error_type: ErrorType::Content,
            message: e,
            url: final_url.to_string(),
            timestamp: std::time::SystemTime::now(),
            retry_possible: true,
        })?;
        
        let load_time_ms = start_time.elapsed().as_millis() as u64;
        
        log::info!("✅ Page loaded successfully in {}ms: {} elements, {} bytes", 
                   load_time_ms, element_count, response.len());
        
        Ok(ParsedPageData {
            title,
            content,
            element_count,
            size_bytes: response.len(),
            url: final_url.to_string(),
            load_time_ms,
            security_warnings,
            dom: Some(dom),
            stylesheet: Some(stylesheet),
        })
    }
    
    /// Load a web page from the given URL (legacy method)
    pub async fn load_page(&self, url: Url) -> Result<String, String> {
        log::info!("Loading page: {}", url);
        
        // Validate URL scheme
        if url.scheme() != "https" && url.scheme() != "http" {
            return Err(format!("Unsupported URL scheme: {}", url.scheme()));
        }
        
        // Enforce HTTPS if configured
        let final_url = if self.network_config.enforce_https && url.scheme() == "http" {
            let mut https_url = url.clone();
            https_url.set_scheme("https").map_err(|_| "Failed to upgrade to HTTPS")?;
            log::info!("Upgraded HTTP to HTTPS: {}", https_url);
            https_url
        } else {
            url
        };
        
        // Create HTTP request with privacy settings
        let request = Request::new(Method::GET, final_url.as_str())
            .map_err(|e| format!("Failed to create request: {}", e))?
            .with_privacy_level(self.network_config.privacy_level)
            .prepare();
        
        // DNS resolution is handled by reqwest - respects system DNS settings
        log::debug!("📍 Using system DNS configuration via reqwest");
        
        // Make HTTP request
        let response = match self.resource_loader.load_html(final_url.clone()).await {
            Ok(html) => html,
            Err(load_err) => {
                log::warn!("Resource loader failed for {} ({}), falling back to raw HTTP", final_url, load_err);
                self.make_http_request(request).await?
            }
        };
        
        // Parse and sanitize the HTML content
        let (title, content, element_count) = self.parse_html_content(&response, final_url.as_str()).await?;
        
        // For now, return a JSON-like string with the parsed data
        // TODO: Return a structured type instead
        let result = format!(
            "{{\"title\": \"{}\", \"content\": \"{}\", \"element_count\": {}, \"size_bytes\": {}, \"url\": \"{}\"}}",
            title.replace('"', "\\\""),
            content.chars().take(1000).collect::<String>().replace('"', "\\\""),
            element_count,
            response.len(),
            final_url
        );
        
        Ok(result)
    }
    
    /// Make an HTTP request using reqwest with privacy settings
    async fn make_http_request(&self, request: Request) -> Result<String, String> {
        // Build reqwest client with privacy settings
        let client = reqwest::Client::builder()
            .timeout(request.timeout().unwrap_or(std::time::Duration::from_secs(30)))
            .redirect(if request.follows_redirects() {
                reqwest::redirect::Policy::limited(request.get_max_redirects())
            } else {
                reqwest::redirect::Policy::none()
            })
            .user_agent(request.headers().get("User-Agent").unwrap_or(&"Citadel/1.0".to_string()))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
        
        // Build the request
        let mut req_builder = match request.method() {
            Method::GET => client.get(request.url().as_str()),
            Method::POST => client.post(request.url().as_str()),
            Method::PUT => client.put(request.url().as_str()),
            Method::DELETE => client.delete(request.url().as_str()),
            Method::HEAD => client.head(request.url().as_str()),
            _ => return Err("Unsupported HTTP method".to_string()),
        };
        
        // Add headers
        for (name, value) in request.headers() {
            req_builder = req_builder.header(name, value);
        }
        
        // Add body if present
        if let Some(body) = request.body() {
            req_builder = req_builder.body(body.to_vec());
        }
        
        // Execute the request
        let response = req_builder.send().await
            .map_err(|e| format!("HTTP request failed: {}", e))?;
        
        // Check response status
        if !response.status().is_success() {
            return Err(format!("HTTP error: {}", response.status()));
        }
        
        // Get response body
        let content = response.text().await
            .map_err(|e| format!("Failed to read response body: {}", e))?;
        
        log::info!("Successfully fetched {} bytes", content.len());
        Ok(content)
    }
    
    /// Parse HTML content with enhanced security and privacy protections
    async fn parse_html_content_enhanced(&self, html: &str, url: &str) -> Result<(String, String, usize, Vec<String>, Arc<Dom>, Arc<CitadelStylesheet>), String> {
        log::info!("🔧 Parsing HTML content for {}: {} bytes", url, html.len());
        
        let mut security_warnings = Vec::new();
        
        // Check for potentially dangerous content
        if html.to_lowercase().contains("<script") {
            security_warnings.push("JavaScript content detected and blocked".to_string());
        }
        if html.to_lowercase().contains("javascript:") {
            security_warnings.push("JavaScript URLs detected and sanitized".to_string());
        }
        if html.to_lowercase().contains("data:") {
            security_warnings.push("Data URLs detected - security review applied".to_string());
        }
        
        // Parse HTML using citadel-parser
        // Convert security context from citadel-security to citadel-parser format
        let parser_security_context = Arc::new(ParserSecurityContext::new(15)); // 15 max nesting depth
        
        log::info!("🔍 Starting HTML parsing for {} ({} bytes)", url, html.len());
        let dom = parse_html(html, parser_security_context)
            .map_err(|e| format!("HTML parsing failed: {}", e))?;
        log::info!("✅ DOM parsing completed successfully");
        
        // Debug: Check DOM structure
        let root = dom.root();
        let root_node = root.read().unwrap();
        log::info!("🌳 DOM root type: {:?}, children: {}", root_node.data, root_node.children().len());
        
        // Walk through first level of DOM to debug
        for (i, child_handle) in root_node.children().iter().enumerate() {
            let child = child_handle.read().unwrap();
            match &child.data {
                citadel_parser::dom::NodeData::Element(element) => {
                    log::info!("  └─ Child {}: <{}> with {} children", i, element.local_name(), child.children().len());
                    
                    if element.local_name() == "html" {
                        log::info!("    🎯 Found HTML element! Walking its children...");
                        for (j, html_child) in child.children().iter().enumerate() {
                            let html_child_node = html_child.read().unwrap();
                            match &html_child_node.data {
                                citadel_parser::dom::NodeData::Element(he) => {
                                    log::info!("      HTML child {}: <{}> with {} children", j, he.local_name(), html_child_node.children().len());
                                    
                                    if he.local_name() == "body" {
                                        log::info!("        🎯 Found BODY element! Sample of its children:");
                                        for (k, body_child) in html_child_node.children().iter().take(5).enumerate() {
                                            let body_child_node = body_child.read().unwrap();
                                            match &body_child_node.data {
                                                citadel_parser::dom::NodeData::Element(be) => {
                                                    log::info!("          Body child {}: <{}> with {} children", k, be.local_name(), body_child_node.children().len());
                                                }
                                                citadel_parser::dom::NodeData::Text(t) => {
                                                    log::info!("          Body child {}: TEXT '{}' ({} chars)", k, t.trim(), t.len());
                                                }
                                                _ => {
                                                    log::info!("          Body child {}: Other node type", k);
                                                }
                                            }
                                        }
                                        if html_child_node.children().len() > 5 {
                                            log::info!("          ... and {} more children", html_child_node.children().len() - 5);
                                        }
                                    }
                                }
                                citadel_parser::dom::NodeData::Text(t) => {
                                    log::info!("      HTML child {}: TEXT '{}' ({} chars)", j, t.trim(), t.len());
                                }
                                _ => {
                                    log::info!("      HTML child {}: Other node type", j);
                                }
                            }
                        }
                    }
                }
                citadel_parser::dom::NodeData::Text(t) => {
                    log::info!("  └─ Child {}: TEXT '{}' ({} chars)", i, t.trim(), t.len());
                }
                _ => {
                    log::info!("  └─ Child {}: {:?}", i, child.data);
                }
            }
        }
        
        // Extract page title from DOM
        let title = dom.get_title();
        log::info!("📄 Extracted title: '{}'", title);
        let title = if title.is_empty() {
            // Try to extract from URL as fallback
            if let Ok(parsed_url) = Url::parse(url) {
                parsed_url.host_str().unwrap_or("Unknown").to_string()
            } else {
                "Unknown Page".to_string()
            }
        } else {
            title
        };
        
        // Extract main text content for display from DOM
        let content = dom.get_text_content();
        log::info!("📝 Extracted content: {} characters", content.len());
        
        // Log a preview of the content for debugging (first 200 chars)
        if content.len() > 0 {
            let preview = if content.len() > 200 {
                format!("{}...", &content[..200])
            } else {
                content.clone()
            };
            log::info!("📖 Content preview: {}", preview);
        } else {
            log::warn!("⚠️  No content extracted from DOM!");
        }
        
        // Count elements (more sophisticated)
        let element_count = self.count_elements(html);
        
        // Extract and parse actual CSS from the webpage
        log::info!("🎨 Extracting CSS from website content");
        let extracted_css = self.extract_css_from_dom(&dom);
        log::info!("📋 Extracted {} bytes of CSS from DOM", extracted_css.len());
        
        // Create base CSS for proper rendering
        let base_css = r#"
            body { font-family: sans-serif; margin: 16px; color: #000000; background-color: #ffffff; }
            h1 { font-size: 24px; margin: 16px 0; color: #000000; font-weight: bold; }
            h2 { font-size: 22px; margin: 14px 0; color: #000000; font-weight: bold; }
            h3 { font-size: 20px; margin: 12px 0; color: #000000; font-weight: bold; }
            h4 { font-size: 18px; margin: 12px 0; color: #000000; font-weight: bold; }
            h5 { font-size: 16px; margin: 10px 0; color: #000000; font-weight: bold; }
            h6 { font-size: 14px; margin: 8px 0; color: #000000; font-weight: bold; }
            p { margin: 8px 0; color: #000000; line-height: 1.4; }
            a { color: #0066cc; text-decoration: underline; }
            ul, ol { margin: 8px 0; padding-left: 20px; }
            li { margin: 4px 0; }
            section { margin: 16px 0; }
            header { margin-bottom: 20px; }
            footer { margin-top: 20px; }
            strong, b { font-weight: bold; }
            em, i { font-style: italic; }
            blockquote { margin: 16px 0; padding-left: 16px; border-left: 4px solid #ccc; font-style: italic; }
            pre { background: #f5f5f5; padding: 10px; font-family: monospace; }
            .tagline { font-style: italic; }
            .quote { font-style: italic; color: #555; }
        "#;
        
        // Combine base CSS with extracted website CSS
        let combined_css = if extracted_css.is_empty() {
            log::info!("📝 Using base CSS only (no website CSS found)");
            base_css.to_string()
        } else {
            log::info!("🔗 Combining base CSS with extracted website CSS");
            format!("{}\n\n/* Extracted Website CSS */\n{}", base_css, extracted_css)
        };
        
        let parser_security_context_css = Arc::new(ParserSecurityContext::new(15));
        let stylesheet = parse_css(&combined_css, parser_security_context_css)
            .map_err(|e| format!("CSS parsing failed: {}", e))?;
        
        log::info!("✅ CSS parsing completed: {} rules parsed", stylesheet.rules.len());
        
        log::info!("✅ Successfully parsed page: {} elements, {} bytes, {} warnings", 
                   element_count, html.len(), security_warnings.len());
        
        Ok((title, content, element_count, security_warnings, Arc::new(dom), Arc::new(stylesheet)))
    }
    
    /// Parse HTML content with security and privacy protections (legacy method)
    async fn parse_html_content(&self, html: &str, url: &str) -> Result<(String, String, usize), String> {
        log::info!("Parsing HTML content for {}: {} bytes", url, html.len());
        
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
        
        log::info!("Successfully parsed page: {} elements, {} bytes", element_count, html.len());
        
        Ok((title, content, element_count))
    }
    
    /// Extract title from HTML content
    fn extract_title(&self, html: &str) -> Option<String> {
        // Simple regex-based title extraction
        if let Some(start) = html.find("<title>") {
            if let Some(end) = html[start + 7..].find("</title>") {
                let title = &html[start + 7..start + 7 + end];
                return Some(title.trim().to_string());
            }
        }
        None
    }
    
    /// Extract text content from HTML for basic display (legacy method)
    fn extract_content(&self, html: &str) -> String {
        let mut content = String::new();
        let mut in_tag = false;
        let mut in_script = false;
        let mut in_style = false;
        
        let html_lower = html.to_lowercase();
        
        for (i, ch) in html.char_indices() {
            if ch == '<' {
                in_tag = true;
                
                // Check if we're entering a script or style tag
                if html_lower[i..].starts_with("<script") {
                    in_script = true;
                } else if html_lower[i..].starts_with("<style") {
                    in_style = true;
                }
            } else if ch == '>' && in_tag {
                in_tag = false;
                
                // Check if we're exiting a script or style tag
                if in_script && html_lower[..i].ends_with("</script") {
                    in_script = false;
                } else if in_style && html_lower[..i].ends_with("</style") {
                    in_style = false;
                }
            } else if !in_tag && !in_script && !in_style {
                content.push(ch);
            }
        }
        
        // Clean up the content
        content = content
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ")
            .trim()
            .to_string();
        
        // Limit content length for display
        if content.len() > 2000 {
            content.truncate(1997);
            content.push_str("...");
        }
        
        content
    }
    
    /// Enhanced text content extraction with better filtering
    fn extract_content_enhanced(&self, html: &str) -> String {
        let mut content = String::new();
        let mut in_tag = false;
        let mut in_script = false;
        let mut in_style = false;
        let mut in_noscript = false;
        let mut tag_name = String::new();
        
        let html_lower = html.to_lowercase();
        
        for (i, ch) in html.char_indices() {
            if ch == '<' {
                in_tag = true;
                tag_name.clear();
                
                // Check what tag we're entering
                let remaining = &html_lower[i..];
                if remaining.starts_with("<script") {
                    in_script = true;
                } else if remaining.starts_with("<style") {
                    in_style = true;
                } else if remaining.starts_with("<noscript") {
                    in_noscript = true;
                }
            } else if ch == '>' && in_tag {
                in_tag = false;
                
                // Check if we're exiting certain tags
                if tag_name == "/script" {
                    in_script = false;
                } else if tag_name == "/style" {
                    in_style = false;
                } else if tag_name == "/noscript" {
                    in_noscript = false;
                }
                
                tag_name.clear();
            } else if in_tag {
                // Build tag name for closing tag detection
                if ch.is_ascii_alphabetic() || ch == '/' {
                    tag_name.push(ch);
                }
            } else if !in_tag && !in_script && !in_style && !in_noscript {
                content.push(ch);
            }
        }
        
        // Clean up the content more thoroughly
        content = content
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .collect::<Vec<&str>>()
            .join("\n")
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ")
            .trim()
            .to_string();
        
        // Decode common HTML entities
        content = content
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&nbsp;", " ");
        
        // Limit content length for display
        if content.len() > 3000 {
            content.truncate(2997);
            content.push_str("...");
        }
        
        content
    }
    
    /// Extract CSS from DOM - looks for <style> tags and <link> elements
    fn extract_css_from_dom(&self, dom: &Dom) -> String {
        let mut extracted_css = String::new();
        
        // Walk the DOM tree to find CSS
        self.extract_css_recursive(&dom.root(), &mut extracted_css);
        
        extracted_css
    }
    
    /// Recursively extract CSS from DOM nodes
    fn extract_css_recursive(&self, node_handle: &citadel_parser::dom::NodeHandle, css_accumulator: &mut String) {
        if let Ok(node) = node_handle.read() {
            match &node.data {
                citadel_parser::dom::NodeData::Element(element) => {
                    let tag_name = element.local_name();
                    
                    // Extract CSS from <style> tags
                    if tag_name == "style" {
                        log::info!("🎨 Found <style> tag, extracting CSS content");
                        // Get the text content of the style element
                        for child_handle in node.children() {
                            if let Ok(child_node) = child_handle.read() {
                                if let citadel_parser::dom::NodeData::Text(text) = &child_node.data {
                                    log::info!("📝 Extracted {} bytes of CSS from <style> tag", text.len());
                                    css_accumulator.push_str(text);
                                    css_accumulator.push('\n');
                                }
                            }
                        }
                    }
                    // TODO: Handle <link rel="stylesheet"> elements
                    // This would require making HTTP requests to fetch external stylesheets
                    else if tag_name == "link" {
                        if let Some(rel) = element.get_attribute("rel") {
                            if rel == "stylesheet" {
                                if let Some(href) = element.get_attribute("href") {
                                    log::info!("🔗 Found external stylesheet link: {} (not fetched in current implementation)", href);
                                    // TODO: Fetch external stylesheet
                                }
                            }
                        }
                    }
                    
                    // Recurse through children
                    for child_handle in node.children() {
                        self.extract_css_recursive(child_handle, css_accumulator);
                    }
                }
                _ => {
                    // Recurse through children for non-element nodes too
                    for child_handle in node.children() {
                        self.extract_css_recursive(child_handle, css_accumulator);
                    }
                }
            }
        }
    }

    /// Count HTML elements more accurately
    fn count_elements(&self, html: &str) -> usize {
        let mut count = 0;
        let mut in_tag = false;
        let mut is_closing_tag = false;
        
        for ch in html.chars() {
            match ch {
                '<' => {
                    in_tag = true;
                    is_closing_tag = false;
                }
                '>' => {
                    if in_tag && !is_closing_tag {
                        count += 1;
                    }
                    in_tag = false;
                }
                '/' if in_tag => {
                    // Check if this is at the beginning (closing tag) or end (self-closing)
                    is_closing_tag = true;
                }
                _ => {}
            }
        }
        
        count
    }
    
    /// Submit a form using the network layer
    pub async fn submit_form(&self, submission: FormSubmission) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        log::info!("📤 Submitting form to: {} (method: {})", submission.action, submission.method);
        
        // Validate submission action
        if submission.action == "#" {
            log::info!("🔄 Form submission to '#' - no navigation required");
            return Ok("#".to_string());
        }
        
        // Parse the target URL
        let target_url = Url::parse(&submission.action)
            .map_err(|e| format!("Invalid form action URL: {}", e))?;
        
        // Create request based on form method
        let method = match submission.method.as_str() {
            "POST" => Method::POST,
            "GET" => Method::GET,
            _ => {
                return Err(format!("Unsupported form method: {}", submission.method).into());
            }
        };
        
        let mut request = Request::new(method, target_url.as_str())
            .map_err(|e| format!("Failed to create request: {}", e))?;
        
        // Set security headers using builder pattern
        request = request
            .with_header("User-Agent", "Citadel Browser/0.0.1-alpha (Privacy-First)")
            .with_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .with_header("Accept-Language", "en-US,en;q=0.5")
            .with_header("DNT", "1") // Do Not Track
            .with_header("Sec-Fetch-Dest", "document")
            .with_header("Sec-Fetch-Mode", "navigate")
            .with_header("Sec-Fetch-Site", "same-origin");
        
        match submission.method.as_str() {
            "POST" => {
                // Encode form data as application/x-www-form-urlencoded
                let form_data = self.encode_form_data(&submission.data);
                request = request
                    .with_body(form_data.as_bytes())
                    .with_header("Content-Type", "application/x-www-form-urlencoded")
                    .with_header("Content-Length", &form_data.len().to_string());
                
                log::info!("📦 POST form data: {} bytes", form_data.len());
            }
            "GET" => {
                // Append form data as query parameters
                let query_string = self.encode_form_data(&submission.data);
                let mut url_with_query = target_url.clone();
                
                if !query_string.is_empty() {
                    if url_with_query.query().is_some() {
                        url_with_query.set_query(Some(&format!("{}?{}", url_with_query.query().unwrap(), query_string)));
                    } else {
                        url_with_query.set_query(Some(&query_string));
                    }
                }
                
                request = Request::new(Method::GET, url_with_query.as_str())
                    .map_err(|e| format!("Failed to create GET request: {}", e))?;
                log::info!("🔗 GET form submission with query: {} bytes", query_string.len());
            }
            _ => {
                return Err(format!("Unsupported form method: {}", submission.method).into());
            }
        }
        
        // Submit the form using the network layer
        log::info!("🌐 Sending form request to: {}", target_url);
        log::debug!("📑 Prepared {} request to {}", request.method(), request.url());
        
        // Form submission would be handled by the networking layer
        
        // Convert to reqwest format and execute
        // For now, just return the target URL as the implementation is simplified
        log::info!("🌐 Form submission prepared for: {}", target_url);
        
        // For this implementation, return the target URL
        // In a real implementation, we would execute the request and handle the response
        log::info!("✅ Form submission would be sent to: {}", target_url);
        
        Ok(target_url.to_string())
    }
    
    /// Encode form data as URL-encoded string
    fn encode_form_data(&self, data: &HashMap<String, String>) -> String {
        data.iter()
            .map(|(key, value)| {
                format!("{}={}", 
                    urlencoding::encode(key),
                    urlencoding::encode(value)
                )
            })
            .collect::<Vec<String>>()
            .join("&")
    }
    
    // Note: HTTP client creation moved to networking layer for proper abstraction
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        
        let result = rt.block_on(async {
            // Create a separate runtime for the BrowserEngine to own
            let engine_rt = tokio::runtime::Runtime::new().unwrap();
            let runtime = Arc::new(engine_rt);
            let network_config = NetworkConfig::default();
            let security_context = Arc::new(SecurityContext::new(10));
            
            BrowserEngine::new(runtime, network_config, security_context).await
        });
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_url_validation() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        
        let result = rt.block_on(async {
            // Create a separate runtime for the BrowserEngine to own
            let engine_rt = tokio::runtime::Runtime::new().unwrap();
            let runtime = Arc::new(engine_rt);
            let network_config = NetworkConfig::default();
            let security_context = Arc::new(SecurityContext::new(10));
            
            let engine = BrowserEngine::new(runtime, network_config, security_context).await?;
            
            // Test invalid URL scheme
            let invalid_url = Url::parse("ftp://example.com").unwrap();
            let load_result = engine.load_page_with_progress(invalid_url, uuid::Uuid::new_v4()).await;
            
            // Return both engine and load_result so we can drop engine outside the async context
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((engine, load_result))
        });
        
        let (engine, load_result) = result.unwrap();
        drop(engine); // Explicitly drop the engine (and its runtime) outside the async context
        
        assert!(load_result.is_err());
        
        if let Err(error) = load_result {
            assert_eq!(error.error_type, ErrorType::Security);
            assert!(error.message.contains("Unsupported URL scheme"));
        }
    }
}
