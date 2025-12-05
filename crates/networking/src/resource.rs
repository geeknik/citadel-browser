use std::sync::Arc;
use std::time::Duration;

use hyper::{Body, Client, Request as HyperRequest, Response as HyperResponse};
use hyper::body::to_bytes;
use hyper::client::connect::HttpConnector;
use hyper_rustls::HttpsConnector;
use tokio::time::timeout;
use url::Url;

use crate::connection::{Connection, SecurityLevel};
use crate::dns::CitadelDnsResolver;
use crate::error::NetworkError;
use crate::request::{Method, Request};
use crate::response::Response;
use crate::NetworkConfig;

/// Resource types that can be fetched
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    /// HTML document
    Html,
    /// CSS stylesheet
    Css,
    /// JavaScript file
    Script,
    /// Image
    Image,
    /// Font
    Font,
    /// JSON data
    Json,
    /// XML data
    Xml,
    /// Plain text
    Text,
    /// Binary data
    Binary,
    /// Other/unknown type
    Other,
}

/// Detect potential tracking attempts in the response
fn detect_tracking_attempts(response: &mut Response) {
    // Simple detection based on URL patterns
    let tracking_patterns = [
        "google-analytics.com",
        "doubleclick.net",
        "facebook.com/tr",
        "connect.facebook.net",
        "googletagmanager.com",
        "analytics.",
        "tracker.",
        "tracking.",
        "metric.",
        "matomo.",
        "piwik.",
    ];
    
    let url = response.url().as_str().to_string();
    
    for pattern in tracking_patterns.iter() {
        if url.contains(pattern) {
            response.add_blocked_tracking(
                format!("Potential tracking URL detected: {}", pattern)
            );
        }
    }
}

/// Resource fetching client with privacy protections
pub struct Resource {
    /// HTTP client
    client: Client<HttpsConnector<HttpConnector>>,
    
    /// Connection manager
    connection: Connection,
    
    /// DNS resolver
    dns_resolver: Arc<CitadelDnsResolver>,
    
    /// Network configuration
    config: NetworkConfig,
}

impl Resource {
    /// Create a new resource fetcher with the specified configuration
    pub async fn new(config: NetworkConfig) -> Result<Self, NetworkError> {
        // Create the DNS resolver
        let dns_resolver = Arc::new(
            CitadelDnsResolver::with_mode(config.dns_mode.clone()).await?
        );
        
        // Create the connection manager
        let connection = Connection::new(
            Arc::clone(&dns_resolver),
            SecurityLevel::High,
        )?;
        
        // Create the HTTP client
        let client = Client::builder()
            .build(connection.connector().clone());
            
        Ok(Self {
            client,
            connection,
            dns_resolver,
            config,
        })
    }
    
    /// Fetch a resource with the provided request
    pub async fn fetch(&self, request: Request) -> Result<Response, NetworkError> {
        // Apply privacy enhancements based on current settings
        let prepared_request = if self.config.privacy_level == request.privacy_level() {
            // Use global privacy level
            request.prepare()
        } else {
            // Use request-specific privacy level
            request
        };
        
        // Get the timeout before converting the request
        let timeout_duration = prepared_request.timeout()
            .unwrap_or_else(|| Duration::from_secs(30));
            
        // Get the final URL and method before converting
        let final_url = prepared_request.url().clone();
        let method = prepared_request.method().clone();
            
        // Convert our Request to a hyper Request
        let hyper_request = self.to_hyper_request(prepared_request)?;
        
        // Execute the request with timeout
        let hyper_response = match timeout(
            timeout_duration,
            self.client.request(hyper_request)
        ).await {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => return Err(NetworkError::HttpError(e)),
            Err(_) => return Err(NetworkError::TimeoutError(timeout_duration)),
        };
        
        // Convert hyper Response to our Response
        self.parse_hyper_response(hyper_response, final_url, method).await
    }
    
    /// Convert our Request to a hyper Request
    fn to_hyper_request(&self, request: Request) -> Result<HyperRequest<Body>, NetworkError> {
        // Create a new builder
        let mut builder = HyperRequest::builder()
            .method(request.method().to_string().as_str())
            .uri(request.url().as_str());
            
        // Add headers
        for (name, value) in request.headers() {
            builder = builder.header(name, value);
        }
        
        // Set the body if present
        let body = match request.body() {
            Some(data) => Body::from(data.to_vec()),
            None => Body::empty(),
        };
        
        // Build the request
        builder.body(body)
            .map_err(|e| NetworkError::ConnectionError(format!("Failed to build request: {}", e)))
    }
    
    /// Convert a hyper Response to our Response
    async fn parse_hyper_response(
        &self,
        hyper_response: HyperResponse<Body>,
        url: Url,
        method: Method,
    ) -> Result<Response, NetworkError> {
        // Extract status code
        let status = hyper_response.status().as_u16();
        
        // Extract headers
        let headers = hyper_response.headers().iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    String::from_utf8_lossy(value.as_bytes()).to_string()
                )
            })
            .collect();
            
        // Extract body
        let body_bytes = to_bytes(hyper_response.into_body())
            .await
            .map_err(|e| NetworkError::ConnectionError(format!("Failed to read response body: {}", e)))?;
            
        // Create our Response
        let mut response = Response::new(
            status,
            headers,
            body_bytes,
            url,
            method,
        );
        
        // Check for and flag any tracking attempts based on response content
        detect_tracking_attempts(&mut response);
        
        Ok(response)
    }
    /// Determine the resource type from a response
    pub fn determine_resource_type(response: &Response) -> ResourceType {
        let content_type = match response.content_type() {
            Some(ct) => ct.to_lowercase(),
            None => return ResourceType::Other,
        };
        
        if content_type.contains("text/html") {
            ResourceType::Html
        } else if content_type.contains("text/css") {
            ResourceType::Css
        } else if content_type.contains("javascript") || content_type.contains("application/js") {
            ResourceType::Script
        } else if content_type.contains("image/") {
            ResourceType::Image
        } else if content_type.contains("font/") || content_type.contains("application/font") {
            ResourceType::Font
        } else if content_type.contains("application/json") {
            ResourceType::Json
        } else if content_type.contains("application/xml") || content_type.contains("text/xml") {
            ResourceType::Xml
        } else if content_type.contains("text/plain") {
            ResourceType::Text
        } else if content_type.contains("application/octet-stream") {
            ResourceType::Binary
        } else {
            ResourceType::Other
        }
    }
    
    /// Get the DNS resolver
    pub fn dns_resolver(&self) -> &CitadelDnsResolver {
        &self.dns_resolver
    }
    
    /// Get the connection manager
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
    
    /// Get the current network configuration
    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }
    
    /// Set a new network configuration
    pub async fn set_config(&mut self, config: NetworkConfig) -> Result<(), NetworkError> {
        // Update DNS mode if it changed
        if self.config.dns_mode != config.dns_mode {
            let dns_resolver = Arc::new(
                CitadelDnsResolver::with_mode(config.dns_mode.clone()).await?
            );
            
            // Create the new connection manager with the updated DNS resolver
            self.dns_resolver = dns_resolver;
            self.connection = Connection::new(
                Arc::clone(&self.dns_resolver),
                SecurityLevel::High,
            )?;
            
            // Recreate the HTTP client
            self.client = Client::builder()
                .build(self.connection.connector().clone());
        }
        
        // Update the configuration
        self.config = config;
        
        Ok(())
    }
    
    /// Helper method to fetch an HTML document
    pub async fn fetch_html(&self, url: &str) -> Result<Response, NetworkError> {
        let request = Request::new(Method::GET, url)?
            .with_header("Accept", "text/html,application/xhtml+xml")
            .prepare();
            
        self.fetch(request).await
    }
    
    /// Helper method to fetch JSON data
    pub async fn fetch_json(&self, url: &str) -> Result<Response, NetworkError> {
        let request = Request::new(Method::GET, url)?
            .with_header("Accept", "application/json")
            .prepare();
            
        self.fetch(request).await
    }
    
    /// Helper method to fetch a CSS stylesheet
    pub async fn fetch_css(&self, url: &str) -> Result<Response, NetworkError> {
        let request = Request::new(Method::GET, url)?
            .with_header("Accept", "text/css")
            .prepare();
            
        self.fetch(request).await
    }
    
    /// Helper method to fetch a JavaScript file
    pub async fn fetch_script(&self, url: &str) -> Result<Response, NetworkError> {
        let request = Request::new(Method::GET, url)?
            .with_header("Accept", "application/javascript,text/javascript")
            .prepare();
            
        self.fetch(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_resource_creation() {
        let config = NetworkConfig::default();
        let resource = Resource::new(config).await;
        assert!(resource.is_ok());
    }
} 
