use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use url::Url;

use crate::error::NetworkError;
use crate::resource::{Resource, ResourceType};
use crate::request::{Method, Request};
use crate::response::Response;
use crate::NetworkConfig;
use crate::PrivacyLevel;

/// Resource loading policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourcePolicy {
    /// Allow loading all resources
    AllowAll,
    /// Block scripts
    BlockScripts,
    /// Block third-party resources
    BlockThirdParty,
    /// Block tracking resources (aggressive)
    BlockTracking,
    /// Custom policy
    Custom,
}

/// Cache control policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    /// Use standard caching rules
    Normal,
    /// Prefer cached resources
    PreferCache,
    /// Always validate with server
    AlwaysValidate,
    /// Never cache (private browsing)
    NeverCache,
}

/// Origin classification for privacy protections
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginType {
    /// First-party origin (same domain)
    FirstParty,
    /// Third-party origin
    ThirdParty,
    /// Known tracker
    Tracker,
    /// Analytics service
    Analytics,
    /// Social media service
    SocialMedia,
    /// CDN or API service
    Service,
}

/// Resource cache entry
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Cached response
    response: Response,
    /// When this entry expires
    expires: Instant,
    /// Entity tag for conditional requests
    etag: Option<String>,
    /// Last modified timestamp
    last_modified: Option<String>,
}

/// Configuration for the ResourceManager
#[derive(Debug, Clone)]
pub struct ResourceManagerConfig {
    /// Network configuration
    pub network_config: NetworkConfig,
    /// Resource loading policy
    pub resource_policy: ResourcePolicy,
    /// Cache policy
    pub cache_policy: CachePolicy,
    /// Maximum cache size in MB
    pub max_cache_size_mb: usize,
    /// Default cache TTL
    pub default_cache_ttl: Duration,
}

impl Default for ResourceManagerConfig {
    fn default() -> Self {
        Self {
            network_config: NetworkConfig::default(),
            resource_policy: ResourcePolicy::BlockTracking,
            cache_policy: CachePolicy::Normal,
            max_cache_size_mb: 50, // 50MB default cache size
            default_cache_ttl: Duration::from_secs(3600), // 1 hour default TTL
        }
    }
}

/// Comprehensive resource management with privacy protections
pub struct ResourceManager {
    /// Resource fetcher
    resource: Arc<Resource>,
    
    /// Resource cache
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    
    /// Current configuration
    pub config: ResourceManagerConfig,
    
    /// Known tracker domains
    tracker_domains: Arc<RwLock<HashMap<String, OriginType>>>,
    
    /// Resource load stats for the current session
    load_stats: Arc<Mutex<ResourceStats>>,
    
    /// Main frame URL (top-level document)
    main_frame_url: Arc<RwLock<Option<Url>>>,
}

/// Statistics about resource loading
#[derive(Debug, Default, Clone)]
pub struct ResourceStats {
    /// Total requests attempted
    pub total_requests: usize,
    
    /// Successful requests
    pub successful_requests: usize,
    
    /// Failed requests
    pub failed_requests: usize,
    
    /// Cached responses
    pub cache_hits: usize,
    
    /// Blocked resources by type
    pub blocked: HashMap<String, usize>,
    
    /// Bytes transferred
    pub bytes_transferred: usize,
}

impl ResourceManager {
    /// Create a new ResourceManager with default configuration
    pub async fn new() -> Result<Self, NetworkError> {
        Self::with_config(ResourceManagerConfig::default()).await
    }
    
    /// Create a new ResourceManager with custom configuration
    pub async fn with_config(config: ResourceManagerConfig) -> Result<Self, NetworkError> {
        // Create the resource fetcher
        let resource = Arc::new(
            Resource::new(config.network_config.clone()).await?
        );
        
        // Initialize tracker domains with common trackers
        let mut tracker_domains = HashMap::new();
        
        // Add known analytics trackers
        for domain in [
            "google-analytics.com", "analytics.google.com", "stats.g.doubleclick.net",
            "pixel.facebook.com", "analytics.facebook.com", "analytics.twitter.com",
            "matomo.org", "statcounter.com", "quantserve.com", "hotjar.com",
        ] {
            tracker_domains.insert(domain.to_string(), OriginType::Analytics);
        }
        
        // Add known social media trackers
        for domain in [
            "connect.facebook.net", "platform.twitter.com", "platform.linkedin.com",
            "platform.instagram.com", "widgets.pinterest.com", "api.tiktok.com",
        ] {
            tracker_domains.insert(domain.to_string(), OriginType::SocialMedia);
        }
        
        Ok(Self {
            resource,
            cache: Arc::new(RwLock::new(HashMap::new())),
            config,
            tracker_domains: Arc::new(RwLock::new(tracker_domains)),
            load_stats: Arc::new(Mutex::new(ResourceStats::default())),
            main_frame_url: Arc::new(RwLock::new(None)),
        })
    }
    
    /// Set the main frame URL (top-level document)
    pub fn set_main_frame_url(&self, url: Url) {
        if let Ok(mut main_frame) = self.main_frame_url.write() {
            *main_frame = Some(url);
        }
    }
    
    /// Check if a resource should be blocked based on policy
    fn should_block_resource(&self, url: &Url, resource_type: ResourceType) -> Option<String> {
        // Get main frame URL for comparison
        let main_frame = if let Ok(main_frame) = self.main_frame_url.read() {
            main_frame.clone()
        } else {
            None
        };
        
        // Determine origin type
        let origin_type = self.classify_origin(url, main_frame.as_ref());
        
        // Apply resource policy
        match self.config.resource_policy {
            ResourcePolicy::AllowAll => None,
            
            ResourcePolicy::BlockScripts => {
                if resource_type == ResourceType::Script {
                    Some("Scripts are blocked by policy".to_string())
                } else {
                    None
                }
            },
            
            ResourcePolicy::BlockThirdParty => {
                if origin_type == OriginType::ThirdParty || 
                   origin_type == OriginType::Tracker || 
                   origin_type == OriginType::Analytics ||
                   origin_type == OriginType::SocialMedia {
                    Some(format!("Third-party resource blocked: {:?}", origin_type))
                } else {
                    None
                }
            },
            
            ResourcePolicy::BlockTracking => {
                if origin_type == OriginType::Tracker || 
                   origin_type == OriginType::Analytics ||
                   origin_type == OriginType::SocialMedia {
                    Some(format!("Tracking resource blocked: {:?}", origin_type))
                } else {
                    None
                }
            },
            
            ResourcePolicy::Custom => {
                // Custom policies would be implemented here
                None
            },
        }
    }
    
    /// Classify the origin of a URL relative to the main frame
    fn classify_origin(&self, url: &Url, main_frame: Option<&Url>) -> OriginType {
        // Check if it's a known tracker
        if let Ok(trackers) = self.tracker_domains.read() {
            if let Some(host) = url.host_str() {
                // Check for exact match
                if let Some(origin_type) = trackers.get(host) {
                    return *origin_type;
                }
                
                // Check for subdomain match
                for (tracker, origin_type) in trackers.iter() {
                    if host.ends_with(tracker) {
                        return *origin_type;
                    }
                }
            }
        }
        
        // If we have a main frame, check if it's first or third party
        if let Some(main) = main_frame {
            if let (Some(main_host), Some(url_host)) = (main.host_str(), url.host_str()) {
                // Extract domain from host (e.g., example.com from www.example.com)
                let main_domain = Self::extract_domain(main_host);
                let url_domain = Self::extract_domain(url_host);
                
                if main_domain == url_domain {
                    return OriginType::FirstParty;
                } else {
                    // Check if it's a CDN or API service
                    if url_host.contains("cdn.") || 
                       url_host.contains("api.") || 
                       url_host.contains("assets.") {
                        return OriginType::Service;
                    }
                    
                    return OriginType::ThirdParty;
                }
            }
        }
        
        // Default to third-party if we can't determine
        OriginType::ThirdParty
    }
    
    /// Extract the base domain from a host
    fn extract_domain(host: &str) -> String {
        let parts: Vec<&str> = host.split('.').collect();
        
        // For hosts with enough parts, take the last two (e.g., example.com from www.example.com)
        if parts.len() >= 2 {
            let domain = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
            
            // Handle special cases like co.uk
            if parts.len() >= 3 && (
                (parts[parts.len() - 1] == "uk" && parts[parts.len() - 2] == "co") ||
                (parts[parts.len() - 1] == "au" && parts[parts.len() - 2] == "com") || 
                // Add other special TLDs as needed
                false
            ) {
                return format!("{}.{}.{}", parts[parts.len() - 3], parts[parts.len() - 2], parts[parts.len() - 1]);
            }
            
            return domain;
        }
        
        // If we can't determine, return the original
        host.to_string()
    }
    
    /// Check if a resource is in the cache
    fn check_cache(&self, url: &Url) -> Option<Response> {
        // Apply cache policy
        if self.config.cache_policy == CachePolicy::NeverCache {
            return None;
        }
        
        if let Ok(cache) = self.cache.read() {
            let key = url.as_str();
            
            if let Some(entry) = cache.get(key) {
                // Check if expired
                if entry.expires > Instant::now() || self.config.cache_policy == CachePolicy::PreferCache {
                    // Update stats
                    if let Ok(mut stats) = self.load_stats.try_lock() {
                        stats.cache_hits += 1;
                    }
                    
                    return Some(entry.response.clone());
                }
            }
        }
        
        None
    }
    
    /// Update the cache with a new response
    fn update_cache(&self, url: &Url, response: Response) {
        // Don't cache if policy is NeverCache
        if self.config.cache_policy == CachePolicy::NeverCache {
            return;
        }
        
        // Get cache control headers
        let cache_control = response.header("cache-control")
            .map(|s| s.to_lowercase());
        
        // Check for no-store directive
        if let Some(cc) = &cache_control {
            if cc.contains("no-store") {
                return;
            }
        }
        
        // Calculate TTL
        let ttl = if let Some(cc) = &cache_control {
            if cc.contains("no-cache") && self.config.cache_policy != CachePolicy::PreferCache {
                // Honor no-cache unless we're set to prefer cache
                return;
            }
            
            // Try to parse max-age
            if let Some(max_age_pos) = cc.find("max-age=") {
                let max_age_str = &cc[max_age_pos + 8..];
                if let Some(end_pos) = max_age_str.find(|c: char| !c.is_ascii_digit()) {
                    if let Ok(seconds) = max_age_str[..end_pos].parse::<u64>() {
                        Duration::from_secs(seconds)
                    } else {
                        self.config.default_cache_ttl
                    }
                } else if let Ok(seconds) = max_age_str.parse::<u64>() {
                    Duration::from_secs(seconds)
                } else {
                    self.config.default_cache_ttl
                }
            } else {
                self.config.default_cache_ttl
            }
        } else {
            self.config.default_cache_ttl
        };
        
        // Extract ETag
        let etag = response.header("etag").cloned();
        
        // Extract Last-Modified
        let last_modified = response.header("last-modified").cloned();
        
        // Create cache entry
        let entry = CacheEntry {
            response: response.clone(),
            expires: Instant::now() + ttl,
            etag,
            last_modified,
        };
        
        // Update cache
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(url.as_str().to_string(), entry);
            
            // Implement cache size management (simple version)
            // A real implementation would track memory usage and evict oldest entries
            if cache.len() > self.config.max_cache_size_mb * 20 { // rough estimate
                // Remove oldest 25% of entries
                let keys_to_remove: Vec<String> = cache.keys()
                    .take(cache.len() / 4)
                    .cloned()
                    .collect();
                
                for key in keys_to_remove {
                    cache.remove(&key);
                }
            }
        }
    }
    
    /// Fetch a resource with privacy protections
    pub async fn fetch(&self, url: &str, resource_type: Option<ResourceType>) -> Result<Response, NetworkError> {
        let url = Url::parse(url).map_err(NetworkError::UrlError)?;
        
        // Update stats
        if let Ok(mut stats) = self.load_stats.try_lock() {
            stats.total_requests += 1;
        }
        
        // Determine resource type if not specified
        let resource_type = resource_type.unwrap_or(ResourceType::Other);
        
        // Check policy before loading
        if let Some(block_reason) = self.should_block_resource(&url, resource_type) {
            // Update blocked stats
            if let Ok(mut stats) = self.load_stats.try_lock() {
                let counter = stats.blocked.entry(block_reason.clone()).or_insert(0);
                *counter += 1;
                stats.failed_requests += 1;
            }
            
            return Err(NetworkError::PrivacyViolationError(block_reason));
        }
        
        // Check cache first
        if let Some(cached) = self.check_cache(&url) {
            return Ok(cached);
        }
        
        // If not in cache, create a request based on resource type
        let request = match resource_type {
            ResourceType::Html => {
                Request::new(Method::GET, url.as_str())?
                    .with_header("Accept", "text/html,application/xhtml+xml")
            },
            ResourceType::Css => {
                Request::new(Method::GET, url.as_str())?
                    .with_header("Accept", "text/css")
            },
            ResourceType::Script => {
                Request::new(Method::GET, url.as_str())?
                    .with_header("Accept", "application/javascript,text/javascript")
            },
            ResourceType::Image => {
                Request::new(Method::GET, url.as_str())?
                    .with_header("Accept", "image/*")
            },
            ResourceType::Font => {
                Request::new(Method::GET, url.as_str())?
                    .with_header("Accept", "font/*,application/font-*")
            },
            ResourceType::Json => {
                Request::new(Method::GET, url.as_str())?
                    .with_header("Accept", "application/json")
            },
            ResourceType::Xml => {
                Request::new(Method::GET, url.as_str())?
                    .with_header("Accept", "application/xml,text/xml")
            },
            ResourceType::Text => {
                Request::new(Method::GET, url.as_str())?
                    .with_header("Accept", "text/plain")
            },
            _ => Request::new(Method::GET, url.as_str())?,
        };
        
        // Set privacy level based on origin type
        let origin_type = self.classify_origin(&url, None);
        let privacy_level = match origin_type {
            OriginType::FirstParty => self.config.network_config.privacy_level,
            OriginType::ThirdParty => {
                // Use stricter privacy for third-party resources
                match self.config.network_config.privacy_level {
                    PrivacyLevel::Maximum => PrivacyLevel::Maximum,
                    PrivacyLevel::High => PrivacyLevel::Maximum,
                    PrivacyLevel::Balanced => PrivacyLevel::High,
                    PrivacyLevel::Custom => PrivacyLevel::High,
                }
            },
            _ => PrivacyLevel::Maximum, // Maximum privacy for trackers, etc.
        };
        
        // Add cache validation headers if needed
        let request_with_validation = if self.config.cache_policy == CachePolicy::AlwaysValidate {
            if let Ok(cache) = self.cache.read() {
                if let Some(entry) = cache.get(url.as_str()) {
                    let mut req = request;
                    
                    // Add ETag if available
                    if let Some(etag) = &entry.etag {
                        req = req.with_header("If-None-Match", etag);
                    }
                    
                    // Add Last-Modified if available
                    if let Some(last_modified) = &entry.last_modified {
                        req = req.with_header("If-Modified-Since", last_modified);
                    }
                    
                    req
                } else {
                    request
                }
            } else {
                request
            }
        } else {
            request
        };
        
        // Prepare the request with the appropriate privacy level
        let final_request = request_with_validation
            .with_privacy_level(privacy_level)
            .prepare();
        
        // Fetch the resource
        let result = self.resource.fetch(final_request).await;
        
        match result {
            Ok(response) => {
                // Update stats
                if let Ok(mut stats) = self.load_stats.try_lock() {
                    stats.successful_requests += 1;
                    stats.bytes_transferred += response.body().len();
                }
                
                // Update cache
                self.update_cache(&url, response.clone());
                
                Ok(response)
            },
            Err(e) => {
                // Update stats
                if let Ok(mut stats) = self.load_stats.try_lock() {
                    stats.failed_requests += 1;
                }
                
                Err(e)
            },
        }
    }
    
    /// Helper method to fetch an HTML document (main frame)
    pub async fn fetch_html(&self, url: &str) -> Result<Response, NetworkError> {
        // Parse URL for later use
        let parsed_url = Url::parse(url).map_err(NetworkError::UrlError)?;
        
        // Set as main frame URL
        self.set_main_frame_url(parsed_url.clone());
        
        // Fetch as HTML resource type
        self.fetch(url, Some(ResourceType::Html)).await
    }
    
    /// Clear the resource cache
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }
    
    /// Get current resource stats
    pub async fn get_stats(&self) -> ResourceStats {
        let stats = self.load_stats.lock().await;
        // Create a clone of the stats to return
        ResourceStats {
            total_requests: stats.total_requests,
            successful_requests: stats.successful_requests,
            failed_requests: stats.failed_requests,
            cache_hits: stats.cache_hits,
            blocked: stats.blocked.clone(),
            bytes_transferred: stats.bytes_transferred,
        }
    }
    
    /// Add a domain to the tracker list
    pub fn add_tracker(&self, domain: &str, origin_type: OriginType) {
        if let Ok(mut trackers) = self.tracker_domains.write() {
            trackers.insert(domain.to_string(), origin_type);
        }
    }
    
    /// Check if a domain is in the tracker list
    pub fn is_tracker(&self, domain: &str) -> bool {
        if let Ok(trackers) = self.tracker_domains.read() {
            if trackers.contains_key(domain) {
                return true;
            }
            
            // Check for subdomain match
            for tracker in trackers.keys() {
                if domain.ends_with(tracker) {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Update the resource manager configuration
    pub async fn update_config(&self, config: ResourceManagerConfig) -> Result<(), NetworkError> {
        // We can't modify self.resource directly since it's behind an Arc
        // Instead, in a real implementation with mutable config, we would create a new Resource
        // and update the Arc.
        
        // For this implementation, we'll just log that the config would be updated
        if self.config.network_config != config.network_config {
            log::info!("Network configuration would be updated");
        }
        
        if self.config.resource_policy != config.resource_policy {
            log::info!("Resource policy would be updated to {:?}", config.resource_policy);
        }
        
        if self.config.cache_policy != config.cache_policy {
            log::info!("Cache policy would be updated to {:?}", config.cache_policy);
        }
        
        // In a real implementation, we would update self.config here
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_resource_manager_creation() {
        let manager = ResourceManager::new().await;
        assert!(manager.is_ok());
    }
    
    #[tokio::test]
    async fn test_domain_extraction() {
        assert_eq!(ResourceManager::extract_domain("www.example.com"), "example.com");
        assert_eq!(ResourceManager::extract_domain("api.service.co.uk"), "service.co.uk");
        assert_eq!(ResourceManager::extract_domain("cdn.assets.example.com"), "example.com");
    }
} 