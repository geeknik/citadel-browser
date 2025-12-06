use std::sync::Arc;
use url::Url;
use citadel_networking::{ResourceManager, resource::ResourceType};
use citadel_security::SecurityContext;
use serde::{Deserialize, Serialize};

/// Error types for resource loading operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadingError {
    NetworkError(String),
    SecurityViolation(String),
    ParseError(String),
    NotFound(String),
    Timeout(String),
}

impl std::fmt::Display for LoadingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadingError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            LoadingError::SecurityViolation(msg) => write!(f, "Security violation: {}", msg),
            LoadingError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            LoadingError::NotFound(msg) => write!(f, "Not found: {}", msg),
            LoadingError::Timeout(msg) => write!(f, "Timeout: {}", msg),
        }
    }
}

impl std::error::Error for LoadingError {}

impl From<Box<dyn std::error::Error + Send + Sync>> for LoadingError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        LoadingError::NetworkError(err.to_string())
    }
}

/// Result of resource loading operation
#[derive(Debug, Clone)]
pub struct ResourceLoadResult {
    pub content: Vec<u8>,
    pub content_type: String,
    pub status_code: u16,
    pub headers: std::collections::HashMap<String, String>,
}

/// Configuration for web requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebRequestConfig {
    pub timeout: std::time::Duration,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub verify_ssl: bool,
    pub custom_headers: std::collections::HashMap<String, String>,
}

impl Default for WebRequestConfig {
    fn default() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(30),
            user_agent: "Citadel-Browser/1.0 (Security-First)".to_string(),
            follow_redirects: true,
            max_redirects: 5,
            verify_ssl: true,
            custom_headers: std::collections::HashMap::new(),
        }
    }
}

/// Resource loader for fetching web resources (HTML, CSS, JS, images, etc.)
pub struct ResourceLoader {
    /// Resource manager for caching and policy enforcement
    resource_manager: Arc<ResourceManager>,
    /// Security context for validation
    security_context: Arc<SecurityContext>,
    /// Current page URL for tracking
    current_url: Arc<std::sync::Mutex<Option<Url>>>,
    /// Current page title for tracking
    page_title: Arc<std::sync::Mutex<Option<String>>>,
}

impl std::fmt::Debug for ResourceLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceLoader")
            .field("resource_manager", &"ResourceManager")
            .field("security_context", &"SecurityContext")
            .finish()
    }
}

impl ResourceLoader {
    /// Create a new resource loader
    pub async fn new(security_context: Arc<SecurityContext>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let resource_manager = Arc::new(ResourceManager::new().await?);

        Ok(Self {
            resource_manager,
            security_context,
            current_url: Arc::new(std::sync::Mutex::new(None)),
            page_title: Arc::new(std::sync::Mutex::new(None)),
        })
    }
    
    /// Load a resource from the given URL
    pub async fn load_resource(&self, url: Url) -> Result<Vec<u8>, String> {
        // Use ResourceManager's fetch method which handles caching internally
        match self.resource_manager.fetch(url.as_str(), Some(ResourceType::Other)).await {
            Ok(response) => {
                log::info!("Successfully fetched resource: {} (status: {}, {} bytes)", 
                          url, response.status(), response.body().len());
                Ok(response.body().to_vec())
            }
            Err(e) => {
                log::error!("Failed to fetch resource {}: {}", url, e);
                Err(format!("Failed to fetch resource: {}", e))
            }
        }
    }
    
    /// Load and parse HTML content
    pub async fn load_html(&self, url: Url) -> Result<String, String> {
        match self.resource_manager.fetch_html(url.as_str()).await {
            Ok(response) => {
                log::info!("Successfully fetched HTML: {} (status: {}, {} bytes)", 
                          url, response.status(), response.body().len());
                
                // Convert bytes to string
                response.body_text()
                    .map_err(|e| format!("Failed to convert HTML to string: {}", e))
            }
            Err(e) => {
                log::error!("Failed to fetch HTML {}: {}", url, e);
                Err(format!("Failed to fetch HTML: {}", e))
            }
        }
    }
    
    /// Load CSS content
    pub async fn load_css(&self, url: Url) -> Result<String, String> {
        match self.resource_manager.fetch(url.as_str(), Some(ResourceType::Css)).await {
            Ok(response) => {
                log::info!("Successfully fetched CSS: {} (status: {}, {} bytes)", 
                          url, response.status(), response.body().len());
                
                // Convert bytes to string and validate CSS
                let css_content = response.body_text()
                    .map_err(|e| format!("Failed to convert CSS to string: {}", e))?;
                
                // TODO: Parse and sanitize CSS using citadel-parser
                Ok(css_content)
            }
            Err(e) => {
                log::error!("Failed to fetch CSS {}: {}", url, e);
                Err(format!("Failed to fetch CSS: {}", e))
            }
        }
    }
    
    /// Load JavaScript content
    pub async fn load_javascript(&self, url: Url) -> Result<String, String> {
        match self.resource_manager.fetch(url.as_str(), Some(ResourceType::Script)).await {
            Ok(response) => {
                log::info!("Successfully fetched JavaScript: {} (status: {}, {} bytes)", 
                          url, response.status(), response.body().len());
                
                // Convert bytes to string
                let js_content = response.body_text()
                    .map_err(|e| format!("Failed to convert JavaScript to string: {}", e))?;
                
                // TODO: Parse and sanitize JavaScript
                Ok(js_content)
            }
            Err(e) => {
                log::error!("Failed to fetch JavaScript {}: {}", url, e);
                Err(format!("Failed to fetch JavaScript: {}", e))
            }
        }
    }
    
    /// Load image data
    pub async fn load_image(&self, url: Url) -> Result<Vec<u8>, String> {
        match self.resource_manager.fetch(url.as_str(), Some(ResourceType::Image)).await {
            Ok(response) => {
                log::info!("Successfully fetched image: {} (status: {}, {} bytes)", 
                          url, response.status(), response.body().len());
                Ok(response.body().to_vec())
            }
            Err(e) => {
                log::error!("Failed to fetch image {}: {}", url, e);
                Err(format!("Failed to fetch image: {}", e))
            }
        }
    }

    /// Get the current page URL
    pub fn get_current_url(&self) -> Option<String> {
        self.current_url.lock().unwrap().as_ref().map(|url| url.to_string())
    }

    /// Get the current page title
    pub fn get_page_title(&self) -> Option<String> {
        self.page_title.lock().unwrap().clone()
    }

    /// Update page information
    pub fn update_page_info(&self, url: Option<Url>, title: Option<String>) {
        if let Some(new_url) = url {
            *self.current_url.lock().unwrap() = Some(new_url);
        }
        if let Some(new_title) = title {
            *self.page_title.lock().unwrap() = Some(new_title);
        }
    }

    /// Fetch a webpage and return the HTML content
    pub async fn fetch_webpage(&mut self, url: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let url_obj = Url::parse(url)?;

        // Update current URL
        *self.current_url.lock().unwrap() = Some(url_obj.clone());

        // Load the HTML content
        let content = self.load_html(url_obj).await?;
        Ok(content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_resource_loader_creation() {
        let security_context = Arc::new(SecurityContext::new(10)); // Use the default constructor
        let loader = ResourceLoader::new(security_context).await;
        
        // Test that loader was created successfully
        assert!(loader.is_ok());
        let loader = loader.unwrap();
        
        // Get stats from resource manager
        let stats = loader.resource_manager.get_stats().await;
        assert_eq!(stats.total_requests, 0); // Should start with 0 requests
    }
}
