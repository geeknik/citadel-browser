use std::sync::Arc;
use tokio::runtime::Runtime;
use url::Url;

use citadel_networking::{NetworkConfig, Request, Method, CitadelDnsResolver};
use citadel_security::SecurityContext;
use citadel_parser::{parse_html, parse_css, security::SecurityContext as ParserSecurityContext, Dom, CitadelStylesheet};

// Import structured types from app.rs
use crate::app::{ParsedPageData, LoadingError, ErrorType};

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
        
        Ok(Self {
            runtime,
            network_config,
            security_context,
            dns_resolver,
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
        
        let _ip_addresses = self.dns_resolver.resolve(host).await
            .map_err(|e| LoadingError {
                error_type: ErrorType::Network,
                message: format!("DNS resolution failed: {}", e),
                url: final_url.to_string(),
                timestamp: std::time::SystemTime::now(),
                retry_possible: true,
            })?;
        
        // Make HTTP request
        let response = self.make_http_request(request).await.map_err(|e| LoadingError {
            error_type: ErrorType::Network,
            message: e,
            url: final_url.to_string(),
            timestamp: std::time::SystemTime::now(),
            retry_possible: true,
        })?;
        
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
        
        // Perform DNS resolution
        let host = final_url.host_str().ok_or("Invalid host in URL")?;
        let _ip_addresses = self.dns_resolver.resolve(host).await
            .map_err(|e| format!("DNS resolution failed: {}", e))?;
        
        // Make HTTP request
        let response = self.make_http_request(request).await?;
        
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
        
        // Create a basic stylesheet for now
        // TODO: Extract CSS from <style> tags and <link> elements
        let parser_security_context_css = Arc::new(ParserSecurityContext::new(15));
        let basic_css = r#"
            body { font-family: sans-serif; margin: 16px; }
            h1 { font-size: 24px; margin: 16px 0; }
            h2 { font-size: 22px; margin: 14px 0; }
            h3 { font-size: 20px; margin: 12px 0; }
            p { margin: 8px 0; }
            a { color: #0066cc; }
            ul, ol { margin: 8px 0; padding-left: 20px; }
        "#;
        
        let stylesheet = parse_css(basic_css, parser_security_context_css)
            .map_err(|e| format!("CSS parsing failed: {}", e))?;
        
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
    
    /// Count HTML elements more accurately
    fn count_elements(&self, html: &str) -> usize {
        let mut count = 0;
        let mut in_tag = false;
        let mut is_closing_tag = false;
        let mut is_self_closing = false;
        
        for ch in html.chars() {
            match ch {
                '<' => {
                    in_tag = true;
                    is_closing_tag = false;
                    is_self_closing = false;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[tokio::test]
    async fn test_engine_creation() {
        let runtime = Arc::new(Runtime::new().unwrap());
        let network_config = NetworkConfig::default();
        let security_context = Arc::new(SecurityContext::new());
        
        let engine = BrowserEngine::new(runtime, network_config, security_context).await;
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_url_validation() {
        let runtime = Arc::new(Runtime::new().unwrap());
        let network_config = NetworkConfig::default();
        let security_context = Arc::new(SecurityContext::new());
        
        let engine = BrowserEngine::new(runtime, network_config, security_context).await.unwrap();
        
        // Test invalid URL scheme
        let invalid_url = Url::parse("ftp://example.com").unwrap();
        let result = engine.load_page_with_progress(invalid_url, uuid::Uuid::new_v4()).await;
        assert!(result.is_err());
        
        if let Err(error) = result {
            assert_eq!(error.error_type, ErrorType::Security);
            assert!(error.message.contains("Unsupported URL scheme"));
        }
    }
}