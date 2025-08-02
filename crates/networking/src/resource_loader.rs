use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::future::join_all;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use url::Url;

use crate::cache::{ResourceCache, CacheConfig};
use crate::error::NetworkError;
use crate::resource::{Resource, ResourceType};
use crate::resource_discovery::{ResourceDiscovery, ResourceRef, ResourceContext};
use crate::response::Response;
use crate::NetworkConfig;

/// Progress information for resource loading
#[derive(Debug, Clone)]
pub struct LoadProgress {
    /// Total number of resources to load
    pub total: usize,
    /// Number of resources loaded successfully
    pub loaded: usize,
    /// Number of resources that failed to load
    pub failed: usize,
    /// Number of resources served from cache
    pub cached: usize,
    /// Total bytes loaded
    pub bytes_loaded: usize,
    /// Loading start time
    pub started_at: Instant,
    /// Current loading phase
    pub phase: LoadPhase,
    /// Details of individual resource loads
    pub resource_details: HashMap<String, ResourceLoadResult>,
}

impl LoadProgress {
    /// Create a new progress tracker
    pub fn new(total: usize) -> Self {
        Self {
            total,
            loaded: 0,
            failed: 0,
            cached: 0,
            bytes_loaded: 0,
            started_at: Instant::now(),
            phase: LoadPhase::Discovering,
            resource_details: HashMap::new(),
        }
    }
    
    /// Get the completion percentage (0.0 to 1.0)
    pub fn completion_percentage(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            (self.loaded + self.failed + self.cached) as f64 / self.total as f64
        }
    }
    
    /// Get the elapsed time since loading started
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }
    
    /// Check if loading is complete
    pub fn is_complete(&self) -> bool {
        (self.loaded + self.failed + self.cached) >= self.total
    }
    
    /// Get the success rate (0.0 to 1.0)
    pub fn success_rate(&self) -> f64 {
        let completed = self.loaded + self.failed + self.cached;
        if completed == 0 {
            0.0
        } else {
            (self.loaded + self.cached) as f64 / completed as f64
        }
    }
}

/// Loading phases
#[derive(Debug, Clone, PartialEq)]
pub enum LoadPhase {
    /// Discovering resources from HTML/CSS
    Discovering,
    /// Loading critical resources (CSS, fonts)
    Critical,
    /// Loading non-critical resources (images, scripts)
    NonCritical,
    /// Completed
    Complete,
}

/// Result of loading a single resource
#[derive(Debug, Clone)]
pub struct ResourceLoadResult {
    /// The URL that was loaded
    pub url: Url,
    /// Resource type
    pub resource_type: ResourceType,
    /// Whether the load was successful
    pub success: bool,
    /// Error message if load failed
    pub error: Option<String>,
    /// Whether the resource was served from cache
    pub from_cache: bool,
    /// Size of the loaded resource in bytes
    pub size_bytes: usize,
    /// Time it took to load the resource
    pub load_time: Duration,
    /// HTTP status code (if applicable)
    pub status_code: Option<u16>,
}

/// Options for resource loading
#[derive(Debug, Clone)]
pub struct LoadOptions {
    /// Maximum number of concurrent requests
    pub max_concurrent: usize,
    /// Timeout for individual resource loads
    pub request_timeout: Duration,
    /// Total timeout for the entire loading process
    pub total_timeout: Duration,
    /// Whether to load non-critical resources
    pub load_non_critical: bool,
    /// Whether to use cache
    pub use_cache: bool,
    /// Whether to validate cached resources
    pub validate_cache: bool,
    /// Maximum retries for failed requests
    pub max_retries: usize,
    /// Resource types to load
    pub allowed_types: Option<Vec<ResourceType>>,
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self {
            max_concurrent: 6,  // Browser-like concurrency limit
            request_timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(120),
            load_non_critical: true,
            use_cache: true,
            validate_cache: true,
            max_retries: 2,
            allowed_types: None,
        }
    }
}

/// Result of a complete resource loading operation
#[derive(Debug)]
pub struct LoadResult {
    /// Final progress information
    pub progress: LoadProgress,
    /// Successfully loaded responses
    pub responses: HashMap<Url, Response>,
    /// Errors that occurred during loading
    pub errors: HashMap<Url, NetworkError>,
    /// Total time taken
    pub total_time: Duration,
}

/// Progress callback type
type ProgressCallback = Arc<dyn Fn(&LoadProgress) + Send + Sync>;

/// Concurrent resource loader with privacy protections
pub struct ResourceLoader {
    /// Resource fetcher
    resource: Resource,
    /// Resource discovery engine
    discovery: ResourceDiscovery,
    /// Resource cache
    cache: Arc<ResourceCache>,
    /// Loading options
    options: LoadOptions,
    /// Progress callback
    progress_callback: Option<ProgressCallback>,
}

impl ResourceLoader {
    /// Create a new resource loader
    pub async fn new(config: NetworkConfig) -> Result<Self, NetworkError> {
        let resource = Resource::new(config).await?;
        let discovery = ResourceDiscovery::new()?;
        let cache = Arc::new(ResourceCache::default());
        
        Ok(Self {
            resource,
            discovery,
            cache,
            options: LoadOptions::default(),
            progress_callback: None,
        })
    }
    
    /// Create a resource loader with custom cache configuration
    pub async fn with_cache_config(
        config: NetworkConfig,
        cache_config: CacheConfig,
    ) -> Result<Self, NetworkError> {
        let resource = Resource::new(config).await?;
        let discovery = ResourceDiscovery::new()?;
        let cache = Arc::new(ResourceCache::new(cache_config));
        
        Ok(Self {
            resource,
            discovery,
            cache,
            options: LoadOptions::default(),
            progress_callback: None,
        })
    }
    
    /// Set loading options
    pub fn with_options(mut self, options: LoadOptions) -> Self {
        self.options = options;
        self
    }
    
    /// Set a progress callback
    pub fn with_progress_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&LoadProgress) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Arc::new(callback));
        self
    }
    
    /// Load resources from HTML content
    pub async fn load_from_html(
        &self,
        html: &str,
        base_url: Url,
    ) -> Result<LoadResult, NetworkError> {
        let context = ResourceContext::new(base_url.clone())
            .include_non_critical(self.options.load_non_critical)
            .allowed_types(self.options.allowed_types.clone().unwrap_or_default());
        
        // Discover resources
        let mut progress = LoadProgress::new(0);
        progress.phase = LoadPhase::Discovering;
        self.notify_progress(&progress);
        
        let resources = self.discovery.discover_all(html, &context)?;
        progress.total = resources.len();
        
        // Load discovered resources
        self.load_resources(resources, progress).await
    }
    
    /// Load resources from a list of resource references
    pub async fn load_resources(
        &self,
        resources: Vec<ResourceRef>,
        mut progress: LoadProgress,
    ) -> Result<LoadResult, NetworkError> {
        let start_time = Instant::now();
        progress.total = resources.len();
        
        if resources.is_empty() {
            progress.phase = LoadPhase::Complete;
            self.notify_progress(&progress);
            return Ok(LoadResult {
                progress,
                responses: HashMap::new(),
                errors: HashMap::new(),
                total_time: start_time.elapsed(),
            });
        }
        
        // Separate critical and non-critical resources
        let (critical_resources, non_critical_resources): (Vec<_>, Vec<_>) = 
            resources.into_iter().partition(|r| r.is_critical);
        
        let mut responses = HashMap::new();
        let mut errors = HashMap::new();
        
        // Load critical resources first
        if !critical_resources.is_empty() {
            progress.phase = LoadPhase::Critical;
            self.notify_progress(&progress);
            
            let (critical_responses, critical_errors, updated_progress) = 
                self.load_resource_batch(critical_resources, progress).await?;
            
            responses.extend(critical_responses);
            errors.extend(critical_errors);
            progress = updated_progress;
        }
        
        // Load non-critical resources
        if !non_critical_resources.is_empty() && self.options.load_non_critical {
            progress.phase = LoadPhase::NonCritical;
            self.notify_progress(&progress);
            
            let (non_critical_responses, non_critical_errors, updated_progress) = 
                self.load_resource_batch(non_critical_resources, progress).await?;
            
            responses.extend(non_critical_responses);
            errors.extend(non_critical_errors);
            progress = updated_progress;
        }
        
        progress.phase = LoadPhase::Complete;
        self.notify_progress(&progress);
        
        Ok(LoadResult {
            progress,
            responses,
            errors,
            total_time: start_time.elapsed(),
        })
    }
    
    /// Load a batch of resources concurrently
    async fn load_resource_batch(
        &self,
        resources: Vec<ResourceRef>,
        progress: LoadProgress,
    ) -> Result<(HashMap<Url, Response>, HashMap<Url, NetworkError>, LoadProgress), NetworkError> {
        if resources.is_empty() {
            return Ok((HashMap::new(), HashMap::new(), progress));
        }
        
        // Create semaphore for concurrency control
        let semaphore = Arc::new(Semaphore::new(self.options.max_concurrent));
        
        // Create progress tracking
        let progress_arc = Arc::new(Mutex::new(progress.clone()));
        
        // Create tasks for each resource
        let tasks: Vec<_> = resources.into_iter().map(|resource_ref| {
            let semaphore = Arc::clone(&semaphore);
            let progress_arc = Arc::clone(&progress_arc);
            let cache = Arc::clone(&self.cache);
            let resource = &self.resource;
            let options = self.options.clone();
            let callback = self.progress_callback.clone();
            
            async move {
                // Acquire semaphore permit
                let _permit = semaphore.acquire().await.unwrap();
                
                // Load the resource
                let result = Self::load_single_resource(
                    resource,
                    &resource_ref,
                    cache,
                    &options,
                ).await;
                
                // Update progress
                {
                    let mut prog = progress_arc.lock().unwrap();
                    match &result {
                        Ok(response) => {
                            if response.from_cache() {
                                prog.cached += 1;
                            } else {
                                prog.loaded += 1;
                            }
                            prog.bytes_loaded += response.body().len();
                        }
                        Err(_) => {
                            prog.failed += 1;
                        }
                    }
                    
                    // Add resource details
                    let load_result = match &result {
                        Ok(response) => ResourceLoadResult {
                            url: resource_ref.url.clone(),
                            resource_type: resource_ref.resource_type,
                            success: true,
                            error: None,
                            from_cache: response.from_cache(),
                            size_bytes: response.body().len(),
                            load_time: Duration::from_millis(0), // Would be tracked in real implementation
                            status_code: Some(response.status()),
                        },
                        Err(e) => ResourceLoadResult {
                            url: resource_ref.url.clone(),
                            resource_type: resource_ref.resource_type,
                            success: false,
                            error: Some(e.to_string()),
                            from_cache: false,
                            size_bytes: 0,
                            load_time: Duration::from_millis(0),
                            status_code: None,
                        },
                    };
                    
                    prog.resource_details.insert(
                        resource_ref.url.to_string(),
                        load_result,
                    );
                    
                    // Notify progress callback
                    if let Some(ref cb) = callback {
                        cb(&prog);
                    }
                }
                
                (resource_ref.url, result)
            }
        }).collect();
        
        // Apply total timeout to the entire batch
        let batch_future = join_all(tasks);
        let results = timeout(self.options.total_timeout, batch_future)
            .await
            .map_err(|_| NetworkError::TimeoutError(self.options.total_timeout))?;
        
        // Separate successful and failed results
        let mut responses = HashMap::new();
        let mut errors = HashMap::new();
        
        for (url, result) in results {
            match result {
                Ok(response) => {
                    responses.insert(url, response);
                }
                Err(error) => {
                    errors.insert(url, error);
                }
            }
        }
        
        // Get final progress
        let final_progress = {
            let prog = progress_arc.lock().unwrap();
            prog.clone()
        };
        
        Ok((responses, errors, final_progress))
    }
    
    /// Load a single resource with caching and retries
    async fn load_single_resource(
        resource: &Resource,
        resource_ref: &ResourceRef,
        cache: Arc<ResourceCache>,
        options: &LoadOptions,
    ) -> Result<Response, NetworkError> {
        let url = &resource_ref.url;
        
        // Check cache first if enabled
        if options.use_cache {
            if let Some(cached_response) = cache.get(url) {
                log::debug!("Cache hit for {}", url);
                return Ok(cached_response);
            }
            
            // Check if we can validate a stale entry
            if options.validate_cache {
                if let Some(stale_entry) = cache.get_for_validation(url) {
                    log::debug!("Validating stale cache entry for {}", url);
                    
                    // Create conditional request
                    let mut request = crate::request::Request::new(
                        crate::request::Method::GET,
                        url.as_str(),
                    )?;
                    
                    // Add validation headers
                    if let Some(etag) = &stale_entry.etag {
                        request = request.with_header("If-None-Match", etag);
                    }
                    if let Some(last_modified) = &stale_entry.last_modified {
                        request = request.with_header("If-Modified-Since", last_modified);
                    }
                    
                    let prepared_request = request.prepare();
                    
                    // Make conditional request
                    match timeout(options.request_timeout, resource.fetch(prepared_request)).await {
                        Ok(Ok(response)) => {
                            if response.status() == 304 {
                                // Not modified, use cached version
                                log::debug!("304 Not Modified for {}, using cache", url);
                                return Ok(stale_entry.response);
                            } else {
                                // Modified, cache and return new response
                                log::debug!("Resource modified, caching new version: {}", url);
                                let _ = cache.update_after_validation(url, response.clone());
                                return Ok(response);
                            }
                        }
                        Ok(Err(e)) => {
                            log::debug!("Validation request failed for {}: {}", url, e);
                            // Fall through to regular loading
                        }
                        Err(_) => {
                            log::debug!("Validation request timed out for {}", url);
                            // Fall through to regular loading
                        }
                    }
                }
            }
        }
        
        // Load from network with retries
        let mut last_error = NetworkError::UnknownError("No attempts made".to_string());
        
        for attempt in 0..=options.max_retries {
            log::debug!("Loading {} (attempt {})", url, attempt + 1);
            
            // Create request based on resource type
            let request = match resource_ref.resource_type {
                ResourceType::Css => {
                    crate::request::Request::new(crate::request::Method::GET, url.as_str())?
                        .with_header("Accept", "text/css")
                        .with_timeout(options.request_timeout)
                        .prepare()
                }
                ResourceType::Script => {
                    crate::request::Request::new(crate::request::Method::GET, url.as_str())?
                        .with_header("Accept", "application/javascript,text/javascript")
                        .with_timeout(options.request_timeout)
                        .prepare()
                }
                ResourceType::Image => {
                    crate::request::Request::new(crate::request::Method::GET, url.as_str())?
                        .with_header("Accept", "image/*")
                        .with_timeout(options.request_timeout)
                        .prepare()
                }
                ResourceType::Font => {
                    crate::request::Request::new(crate::request::Method::GET, url.as_str())?
                        .with_header("Accept", "font/*,application/font-*")
                        .with_timeout(options.request_timeout)
                        .prepare()
                }
                _ => {
                    crate::request::Request::new(crate::request::Method::GET, url.as_str())?
                        .with_timeout(options.request_timeout)
                        .prepare()
                }
            };
            
            // Make the request with timeout
            match timeout(options.request_timeout, resource.fetch(request)).await {
                Ok(Ok(response)) => {
                    log::debug!("Successfully loaded {} ({} bytes)", url, response.body().len());
                    
                    // Cache the response if caching is enabled
                    if options.use_cache {
                        if let Err(cache_error) = cache.put(url, response.clone()) {
                            log::debug!("Failed to cache {}: {}", url, cache_error);
                        }
                    }
                    
                    return Ok(response);
                }
                Ok(Err(e)) => {
                    last_error = e;
                    log::debug!("Failed to load {} (attempt {}): {}", url, attempt + 1, last_error);
                    
                    // Don't retry on certain errors
                    if !last_error.is_retryable() {
                        break;
                    }
                }
                Err(_) => {
                    last_error = NetworkError::TimeoutError(options.request_timeout);
                    log::debug!("Timeout loading {} (attempt {})", url, attempt + 1);
                }
            }
            
            // Wait before retry (exponential backoff)
            if attempt < options.max_retries {
                let delay = Duration::from_millis(100 * (1 << attempt));
                tokio::time::sleep(delay).await;
            }
        }
        
        log::debug!("Failed to load {} after {} attempts", url, options.max_retries + 1);
        Err(last_error)
    }
    
    /// Notify progress callback if set
    fn notify_progress(&self, progress: &LoadProgress) {
        if let Some(ref callback) = self.progress_callback {
            callback(progress);
        }
    }
    
    /// Get cache statistics
    pub fn cache_stats(&self) -> crate::cache::CacheStats {
        self.cache.stats()
    }
    
    /// Clear the resource cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NetworkConfig;
    
    #[tokio::test]
    async fn test_resource_loader_creation() {
        let config = NetworkConfig::default();
        let loader = ResourceLoader::new(config).await;
        assert!(loader.is_ok());
    }
    
    #[test]
    fn test_load_progress() {
        let mut progress = LoadProgress::new(10);
        assert_eq!(progress.completion_percentage(), 0.0);
        assert!(!progress.is_complete());
        
        progress.loaded = 5;
        assert_eq!(progress.completion_percentage(), 0.5);
        
        progress.loaded = 7;
        progress.failed = 2;
        progress.cached = 1;
        assert_eq!(progress.completion_percentage(), 1.0);
        assert!(progress.is_complete());
    }
    
    #[test]
    fn test_load_options_default() {
        let options = LoadOptions::default();
        assert_eq!(options.max_concurrent, 6);
        assert_eq!(options.request_timeout, Duration::from_secs(30));
        assert!(options.load_non_critical);
        assert!(options.use_cache);
    }
    
    #[tokio::test]
    async fn test_empty_resource_loading() {
        let config = NetworkConfig::default();
        let loader = ResourceLoader::new(config).await.unwrap();
        
        let progress = LoadProgress::new(0);
        let result = loader.load_resources(vec![], progress).await.unwrap();
        
        assert_eq!(result.responses.len(), 0);
        assert_eq!(result.errors.len(), 0);
        assert!(result.progress.is_complete());
    }
}