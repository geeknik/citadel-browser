use std::sync::Arc;
use url::Url;
use citadel_networking::{ResourceManager, resource::ResourceType};
use citadel_security::SecurityContext;

/// Resource loader for fetching web resources (HTML, CSS, JS, images, etc.)
pub struct ResourceLoader {
    /// Resource manager for caching and policy enforcement
    resource_manager: Arc<ResourceManager>,
    /// Security context for validation
    security_context: Arc<SecurityContext>,
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
