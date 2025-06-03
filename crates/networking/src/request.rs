use std::collections::HashMap;
use std::time::Duration;

use rand::Rng;
use serde::Serialize;
use url::Url;

use crate::error::NetworkError;
use crate::PrivacyLevel;

/// Common HTTP methods supported by the Citadel browser
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Method {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    CONNECT,
    TRACE,
    PATCH,
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Method::GET => write!(f, "GET"),
            Method::POST => write!(f, "POST"),
            Method::PUT => write!(f, "PUT"),
            Method::DELETE => write!(f, "DELETE"),
            Method::HEAD => write!(f, "HEAD"),
            Method::OPTIONS => write!(f, "OPTIONS"),
            Method::CONNECT => write!(f, "CONNECT"),
            Method::TRACE => write!(f, "TRACE"),
            Method::PATCH => write!(f, "PATCH"),
        }
    }
}

/// Privacy-preserving HTTP request
#[derive(Debug, Clone)]
pub struct Request {
    /// HTTP method
    method: Method,
    
    /// Target URL
    url: Url,
    
    /// Request headers
    headers: HashMap<String, String>,
    
    /// Request body
    body: Option<Vec<u8>>,
    
    /// Request timeout
    timeout: Option<Duration>,
    
    /// Privacy level for this specific request
    privacy_level: PrivacyLevel,
    
    /// Whether to follow redirects
    follow_redirects: bool,
    
    /// Maximum number of redirects to follow
    max_redirects: usize,
}

impl Request {
    /// Create a new request with the specified method and URL
    pub fn new(method: Method, url: &str) -> Result<Self, NetworkError> {
        // Parse and validate the URL
        let url = Url::parse(url).map_err(NetworkError::UrlError)?;
        
        // Ensure HTTPS by default for privacy
        if url.scheme() != "https" && url.scheme() != "data" && url.scheme() != "about" {
            return Err(NetworkError::HttpsEnforcementError(
                format!("Non-HTTPS URL: {}. HTTPS is required for privacy and security.", url)
            ));
        }
        
        Ok(Self {
            method,
            url,
            headers: HashMap::new(),
            body: None,
            timeout: Some(Duration::from_secs(30)),
            privacy_level: PrivacyLevel::High,
            follow_redirects: true,
            max_redirects: 10,
        })
    }
    
    /// Set the request body
    pub fn with_body<T: AsRef<[u8]>>(mut self, body: T) -> Self {
        self.body = Some(body.as_ref().to_vec());
        self
    }
    
    /// Set the request body from a JSON-serializable type
    pub fn with_json<T: Serialize>(mut self, json: &T) -> Result<Self, NetworkError> {
        let body = serde_json::to_vec(json).map_err(NetworkError::SerializationError)?;
        self.body = Some(body);
        self.headers.insert("Content-Type".to_string(), "application/json".to_string());
        Ok(self)
    }
    
    /// Add a header to the request
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }
    
    /// Set the request timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
    
    /// Set the privacy level for this request
    pub fn with_privacy_level(mut self, level: PrivacyLevel) -> Self {
        self.privacy_level = level;
        self
    }
    
    /// Set whether to follow redirects
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }
    
    /// Set the maximum number of redirects to follow
    pub fn max_redirects(mut self, max: usize) -> Self {
        self.max_redirects = max;
        self
    }
    
    /// Prepare the request with privacy enhancements based on the configured privacy level
    pub fn prepare(mut self) -> Self {
        // Apply privacy enhancements based on the privacy level
        match self.privacy_level {
            PrivacyLevel::Maximum => {
                self.apply_maximum_privacy();
            },
            PrivacyLevel::High => {
                self.apply_high_privacy();
            },
            PrivacyLevel::Balanced => {
                self.apply_balanced_privacy();
            },
            PrivacyLevel::Custom => {
                // Custom privacy settings don't get automatic enhancements
            },
        }
        
        // Strip tracking parameters from URL regardless of privacy level
        self.strip_tracking_params();
        
        self
    }
    
    /// Apply maximum privacy enhancements
    fn apply_maximum_privacy(&mut self) {
        // Remove all non-essential headers that could be used for tracking
        self.headers.retain(|name, _| {
            let name_lower = name.to_lowercase();
            matches!(name_lower.as_str(), 
                "host" | "content-type" | "content-length" | 
                "accept" | "accept-encoding" | "connection"
            )
        });
        
        // Add randomized User-Agent
        self.headers.insert("User-Agent".to_string(), Self::generate_random_user_agent());
        
        // Add privacy-enhancing headers
        self.headers.insert("DNT".to_string(), "1".to_string());
        self.headers.insert("Sec-GPC".to_string(), "1".to_string());
        
        // Disable referrers entirely
        self.headers.insert("Referrer-Policy".to_string(), "no-referrer".to_string());
        
        // Disable cache for maximum privacy
        self.headers.insert("Cache-Control".to_string(), "no-store, max-age=0".to_string());
    }
    
    /// Apply high privacy enhancements (default)
    fn apply_high_privacy(&mut self) {
        // Remove potentially tracking headers
        let tracking_headers = [
            "x-forwarded-for", "x-real-ip", "cf-connecting-ip", 
            "via", "referer", "origin", "x-requested-with"
        ];
        
        for header in tracking_headers.iter() {
            self.headers.remove(*header);
        }
        
        // Add privacy-preserving headers
        self.headers.insert("DNT".to_string(), "1".to_string());
        self.headers.insert("Sec-GPC".to_string(), "1".to_string());
        
        // Set a generic User-Agent that doesn't leak too much info
        self.headers.insert("User-Agent".to_string(), Self::generate_generic_user_agent());
        
        // Strict referrer policy
        self.headers.insert("Referrer-Policy".to_string(), "strict-origin-when-cross-origin".to_string());
    }
    
    /// Apply balanced privacy enhancements
    fn apply_balanced_privacy(&mut self) {
        // Remove obvious tracking headers
        let tracking_headers = ["x-forwarded-for", "x-real-ip", "cf-connecting-ip"];
        
        for header in tracking_headers.iter() {
            self.headers.remove(*header);
        }
        
        // Add privacy request headers
        self.headers.insert("DNT".to_string(), "1".to_string());
        
        // Use a standard User-Agent if not set
        if !self.headers.contains_key("User-Agent") {
            self.headers.insert("User-Agent".to_string(), Self::generate_standard_user_agent());
        }
    }
    
    /// Strip common tracking parameters from the URL
    fn strip_tracking_params(&mut self) {
        let tracking_params = [
            "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
            "fbclid", "gclid", "msclkid", "mc_eid", "yclid", "_ga", "_gl",
            "ref", "referrer", "source", "xtor", "ICID", "dicbo", "fbcid",
        ];
        
        let pairs: Vec<(String, String)> = self.url.query_pairs()
            .filter(|(k, _)| !tracking_params.contains(&k.as_ref()))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
            
        // Clear query string and rebuild without tracking params
        self.url.set_query(None);
        
        if !pairs.is_empty() {
            let mut serializer = self.url.query_pairs_mut();
            for (key, value) in pairs {
                serializer.append_pair(&key, &value);
            }
        }
    }
    
    /// Generate a random User-Agent to prevent fingerprinting
    fn generate_random_user_agent() -> String {
        let mut rng = rand::thread_rng();
        
        // Choose a random browser and version
        let browsers = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/118.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0",
        ];
        
        browsers[rng.gen_range(0..browsers.len())].to_string()
    }
    
    /// Generate a generic User-Agent that doesn't reveal too much
    fn generate_generic_user_agent() -> String {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36".to_string()
    }
    
    /// Generate a more standard User-Agent for compatibility
    fn generate_standard_user_agent() -> String {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36".to_string()
    }
    
    // Getters
    
    /// Get the request method
    pub fn method(&self) -> &Method {
        &self.method
    }
    
    /// Get the request URL
    pub fn url(&self) -> &Url {
        &self.url
    }
    
    /// Get the request headers
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }
    
    /// Get the request body
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }
    
    /// Get the request timeout
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
    
    /// Get the privacy level
    pub fn privacy_level(&self) -> PrivacyLevel {
        self.privacy_level
    }
    
    /// Get whether to follow redirects
    pub fn follows_redirects(&self) -> bool {
        self.follow_redirects
    }
    
    /// Get the maximum number of redirects to follow
    pub fn get_max_redirects(&self) -> usize {
        self.max_redirects
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_request_creation() {
        let request = Request::new(Method::GET, "https://example.com").unwrap();
        assert_eq!(request.method(), &Method::GET);
        assert_eq!(request.url().as_str(), "https://example.com/");
    }
    
    #[test]
    fn test_https_enforcement() {
        let result = Request::new(Method::GET, "http://example.com");
        assert!(result.is_err());
        
        if let Err(NetworkError::HttpsEnforcementError(_)) = result {
            // Expected error
        } else {
            panic!("Expected HttpsEnforcementError");
        }
    }
    
    #[test]
    fn test_tracking_param_removal() {
        let request = Request::new(
            Method::GET, 
            "https://example.com/?id=123&utm_source=test&valid=true&fbclid=abc123"
        ).unwrap().prepare();
        
        let query = request.url().query().unwrap_or("");
        assert!(query.contains("id=123"));
        assert!(query.contains("valid=true"));
        assert!(!query.contains("utm_source"));
        assert!(!query.contains("fbclid"));
    }
    
    #[test]
    fn test_privacy_headers() {
        let request = Request::new(Method::GET, "https://example.com")
            .unwrap()
            .with_privacy_level(PrivacyLevel::Maximum)
            .prepare();
            
        assert!(request.headers().contains_key("DNT"));
        assert_eq!(request.headers().get("DNT").unwrap(), "1");
        assert!(request.headers().contains_key("Sec-GPC"));
        assert_eq!(request.headers().get("Sec-GPC").unwrap(), "1");
    }
} 