use std::collections::HashMap;

use url::Url;
use bytes::Bytes;

use crate::error::NetworkError;
use crate::request::Method;

/// HTTP response status code categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCategory {
    /// 1xx - Informational
    Informational,
    /// 2xx - Success
    Success,
    /// 3xx - Redirection
    Redirection,
    /// 4xx - Client Error
    ClientError,
    /// 5xx - Server Error
    ServerError,
    /// Unknown status code
    Unknown,
}

/// HTTP response wrapper with privacy enhancements
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status code
    status: u16,
    
    /// Response headers
    headers: HashMap<String, String>,
    
    /// Response body
    body: Bytes,
    
    /// Final URL after any redirects
    url: Url,
    
    /// Original request method
    request_method: Method,
    
    /// Whether the response was from cache
    from_cache: bool,
    
    /// Tracking attempts detected and blocked
    tracking_blocked: Vec<String>,
}

impl Response {
    /// Creates a new Response object
    pub fn new(
        status: u16,
        headers: HashMap<String, String>,
        body: Bytes,
        url: Url,
        request_method: Method,
    ) -> Self {
        Self {
            status,
            headers,
            body,
            url,
            request_method,
            from_cache: false,
            tracking_blocked: Vec::new(),
        }
    }
    
    /// Set whether the response was served from cache
    pub fn set_from_cache(&mut self, from_cache: bool) {
        self.from_cache = from_cache;
    }
    
    /// Add a tracking attempt that was blocked
    pub fn add_blocked_tracking(&mut self, tracking_info: String) {
        self.tracking_blocked.push(tracking_info);
    }
    
    /// Get the HTTP status code
    pub fn status(&self) -> u16 {
        self.status
    }
    
    /// Get the HTTP status category
    pub fn status_category(&self) -> StatusCategory {
        match self.status {
            100..=199 => StatusCategory::Informational,
            200..=299 => StatusCategory::Success,
            300..=399 => StatusCategory::Redirection,
            400..=499 => StatusCategory::ClientError,
            500..=599 => StatusCategory::ServerError,
            _ => StatusCategory::Unknown,
        }
    }
    
    /// Check if the response was successful (2xx status code)
    pub fn is_success(&self) -> bool {
        self.status_category() == StatusCategory::Success
    }
    
    /// Check if the response is a redirection (3xx status code)
    pub fn is_redirection(&self) -> bool {
        self.status_category() == StatusCategory::Redirection
    }
    
    /// Check if the response is an error (4xx or 5xx status code)
    pub fn is_error(&self) -> bool {
        let category = self.status_category();
        category == StatusCategory::ClientError || category == StatusCategory::ServerError
    }
    
    /// Get all response headers
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }
    
    /// Get a specific header value
    pub fn header(&self, name: &str) -> Option<&String> {
        let name_lower = name.to_lowercase();
        self.headers.iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v)
    }
    
    /// Get the response body as bytes
    pub fn body(&self) -> &Bytes {
        &self.body
    }
    
    /// Get the response body as a string
    pub fn body_text(&self) -> Result<String, NetworkError> {
        String::from_utf8(self.body.to_vec())
            .map_err(|_| NetworkError::ResourceError("Failed to convert response body to string".to_string()))
    }
    
    /// Get the response body as JSON
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, NetworkError> {
        serde_json::from_slice(&self.body)
            .map_err(NetworkError::SerializationError)
    }
    
    /// Get the final URL (after any redirects)
    pub fn url(&self) -> &Url {
        &self.url
    }
    
    /// Get the original request method
    pub fn request_method(&self) -> &Method {
        &self.request_method
    }
    
    /// Check if the response was served from cache
    pub fn from_cache(&self) -> bool {
        self.from_cache
    }
    
    /// Get the list of blocked tracking attempts
    pub fn tracking_blocked(&self) -> &[String] {
        &self.tracking_blocked
    }
    
    /// Check if any tracking attempts were blocked
    pub fn had_tracking_blocked(&self) -> bool {
        !self.tracking_blocked.is_empty()
    }
    
    /// Get the content type of the response
    pub fn content_type(&self) -> Option<&String> {
        self.header("content-type")
    }
    
    /// Check if the response is HTML
    pub fn is_html(&self) -> bool {
        self.content_type()
            .map(|ct| ct.to_lowercase().contains("text/html"))
            .unwrap_or(false)
    }
    
    /// Check if the response is JSON
    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|ct| ct.to_lowercase().contains("application/json"))
            .unwrap_or(false)
    }
    
    /// Check if the response is an image
    pub fn is_image(&self) -> bool {
        self.content_type()
            .map(|ct| ct.to_lowercase().contains("image/"))
            .unwrap_or(false)
    }
    
    /// Check if the response is a script
    pub fn is_script(&self) -> bool {
        self.content_type()
            .map(|ct| {
                let ct = ct.to_lowercase();
                ct.contains("javascript") || 
                ct.contains("application/js") ||
                ct.contains("text/js")
            })
            .unwrap_or(false)
    }
    
    /// Check if the response is CSS
    pub fn is_css(&self) -> bool {
        self.content_type()
            .map(|ct| ct.to_lowercase().contains("text/css"))
            .unwrap_or(false)
    }
    
    /// Check for security headers and return warnings for missing ones
    pub fn security_header_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        
        // HTTPS-only security headers
        if self.url.scheme() == "https"
            && self.header("strict-transport-security").is_none()
        {
            warnings.push("Missing HSTS header".to_string());
        }
        
        // General security headers
        if self.is_html() {
            if self.header("content-security-policy").is_none() {
                warnings.push("Missing Content-Security-Policy header".to_string());
            }
            
            if self.header("x-content-type-options").is_none() {
                warnings.push("Missing X-Content-Type-Options header".to_string());
            }
            
            if self.header("x-frame-options").is_none() {
                warnings.push("Missing X-Frame-Options header".to_string());
            }
        }
        
        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::Method;
    
    fn create_test_response() -> Response {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/html; charset=utf-8".to_string());
        headers.insert("server".to_string(), "test-server".to_string());
        
        Response::new(
            200,
            headers,
            Bytes::from("<!DOCTYPE html><html><body>Test</body></html>"),
            Url::parse("https://example.com").unwrap(),
            Method::GET,
        )
    }
    
    #[test]
    fn test_response_status() {
        let response = create_test_response();
        assert_eq!(response.status(), 200);
        assert_eq!(response.status_category(), StatusCategory::Success);
        assert!(response.is_success());
        assert!(!response.is_error());
    }
    
    #[test]
    fn test_response_content_type() {
        let response = create_test_response();
        assert!(response.is_html());
        assert!(!response.is_json());
    }
    
    #[test]
    fn test_response_body() {
        let response = create_test_response();
        assert_eq!(
            response.body_text().unwrap(),
            "<!DOCTYPE html><html><body>Test</body></html>"
        );
    }
    
    #[test]
    fn test_security_headers() {
        let response = create_test_response();
        let warnings = response.security_header_warnings();
        assert!(warnings.contains(&"Missing Content-Security-Policy header".to_string()));
    }
} 
