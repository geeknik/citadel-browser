use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::future::join_all;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::{timeout, sleep};
use url::Url;

use crate::cache::ResourceCache;
use crate::error::NetworkError;
use crate::resource::{Resource, ResourceType};
use crate::resource_discovery::{ResourceDiscovery, ResourceRef, ResourceContext};
use crate::resource_loader::{LoadProgress, LoadResult, LoadOptions};
use crate::response::Response;
use crate::NetworkConfig;

/// Advanced resource priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// Critical resources that block rendering
    Critical = 0,
    /// High priority resources needed for initial view
    High = 1,
    /// Medium priority resources for user experience
    Medium = 2,
    /// Low priority resources for enhancements
    Low = 3,
    /// Preload resources for future use
    Preload = 4,
}

/// Resource loading strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadingStrategy {
    /// Load resources as discovered
    Sequential,
    /// Load resources in parallel with priority ordering
    Parallel,
    /// Load critical resources first, then others
    CriticalFirst,
    /// Adaptive loading based on network conditions
    Adaptive,
}

/// Network condition assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkCondition {
    /// Fast network (>10Mbps)
    Fast,
    /// Medium network (1-10Mbps)
    Medium,
    /// Slow network (<1Mbps)
    Slow,
    /// Unknown network condition
    Unknown,
}

/// Bandwidth tracking for adaptive loading
#[derive(Debug, Clone)]
pub struct BandwidthTracker {
    /// Recent download speeds (bytes per second)
    recent_speeds: VecDeque<u64>,
    /// Maximum samples to keep
    max_samples: usize,
    /// Current estimated bandwidth
    estimated_bandwidth: u64,
    /// Last update time
    last_update: Instant,
}

impl BandwidthTracker {
    pub fn new() -> Self {
        Self {
            recent_speeds: VecDeque::new(),
            max_samples: 10,
            estimated_bandwidth: 0,
            last_update: Instant::now(),
        }
    }

    /// Record a download speed sample
    pub fn record_speed(&mut self, bytes: usize, duration: Duration) {
        if duration.as_millis() > 0 {
            let speed = (bytes as u64 * 1000) / duration.as_millis() as u64;
            
            self.recent_speeds.push_back(speed);
            if self.recent_speeds.len() > self.max_samples {
                self.recent_speeds.pop_front();
            }
            
            // Calculate moving average
            let sum: u64 = self.recent_speeds.iter().sum();
            self.estimated_bandwidth = sum / self.recent_speeds.len() as u64;
            self.last_update = Instant::now();
        }
    }

    /// Get current network condition assessment
    pub fn network_condition(&self) -> NetworkCondition {
        match self.estimated_bandwidth {
            speed if speed > 1_250_000 => NetworkCondition::Fast,    // >10Mbps
            speed if speed > 125_000 => NetworkCondition::Medium,    // 1-10Mbps
            speed if speed > 0 => NetworkCondition::Slow,            // <1Mbps
            _ => NetworkCondition::Unknown,
        }
    }

    /// Get estimated bandwidth in bytes per second
    pub fn estimated_bandwidth(&self) -> u64 {
        self.estimated_bandwidth
    }
}

/// Enhanced progress tracking with bandwidth monitoring
#[derive(Debug, Clone)]
pub struct AdvancedProgress {
    /// Basic progress information
    pub basic: LoadProgress,
    /// Current bandwidth estimate
    pub bandwidth: u64,
    /// Network condition
    pub network_condition: NetworkCondition,
    /// Resources by priority level
    pub priority_breakdown: HashMap<Priority, usize>,
    /// ETA for completion
    pub estimated_completion: Option<Duration>,
    /// Critical path blocking resources
    pub critical_blocking: usize,
}

impl AdvancedProgress {
    pub fn new(total: usize) -> Self {
        Self {
            basic: LoadProgress::new(total),
            bandwidth: 0,
            network_condition: NetworkCondition::Unknown,
            priority_breakdown: HashMap::new(),
            estimated_completion: None,
            critical_blocking: 0,
        }
    }

    /// Update bandwidth estimation
    pub fn update_bandwidth(&mut self, tracker: &BandwidthTracker) {
        self.bandwidth = tracker.estimated_bandwidth();
        self.network_condition = tracker.network_condition();
        
        // Calculate ETA based on remaining bytes and bandwidth
        if self.bandwidth > 0 {
            let remaining_resources = self.basic.total - (self.basic.loaded + self.basic.failed + self.basic.cached);
            if remaining_resources > 0 {
                // Rough estimate: assume 50KB average per resource
                let estimated_bytes = remaining_resources * 50_000;
                let eta_seconds = estimated_bytes as u64 / self.bandwidth;
                self.estimated_completion = Some(Duration::from_secs(eta_seconds));
            }
        }
    }
}

impl Default for BandwidthTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Advanced resource loader with intelligent prioritization and adaptive loading
pub struct AdvancedResourceLoader {
    /// Base resource loader components
    resource: Resource,
    discovery: ResourceDiscovery,
    cache: Arc<ResourceCache>,
    
    /// Advanced loading configuration
    strategy: LoadingStrategy,
    max_concurrent_per_priority: HashMap<Priority, usize>,
    
    /// Bandwidth tracking
    bandwidth_tracker: Arc<Mutex<BandwidthTracker>>,
    
    /// Resource priority queue
    priority_queue: Arc<Mutex<HashMap<Priority, Vec<ResourceRef>>>>,
    
    /// Progress tracking
    progress_tx: Option<mpsc::UnboundedSender<AdvancedProgress>>,
    
    /// Preload queue for future resources  
    preload_queue: Arc<Mutex<VecDeque<ResourceRef>>>,
}

impl AdvancedResourceLoader {
    /// Create a new advanced resource loader
    pub async fn new(config: NetworkConfig, strategy: LoadingStrategy) -> Result<Self, NetworkError> {
        let resource = Resource::new(config).await?;
        let discovery = ResourceDiscovery::new()?;
        let cache = Arc::new(ResourceCache::default());
        
        // Configure concurrency per priority level
        let mut max_concurrent_per_priority = HashMap::new();
        max_concurrent_per_priority.insert(Priority::Critical, 8);  // Max critical
        max_concurrent_per_priority.insert(Priority::High, 6);
        max_concurrent_per_priority.insert(Priority::Medium, 4);
        max_concurrent_per_priority.insert(Priority::Low, 2);
        max_concurrent_per_priority.insert(Priority::Preload, 1);
        
        Ok(Self {
            resource,
            discovery,
            cache,
            strategy,
            max_concurrent_per_priority,
            bandwidth_tracker: Arc::new(Mutex::new(BandwidthTracker::new())),
            priority_queue: Arc::new(Mutex::new(HashMap::new())),
            progress_tx: None,
            preload_queue: Arc::new(Mutex::new(VecDeque::new())),
        })
    }

    /// Set progress tracking channel
    pub fn with_progress_channel(mut self, tx: mpsc::UnboundedSender<AdvancedProgress>) -> Self {
        self.progress_tx = Some(tx);
        self
    }

    /// Load resources with advanced prioritization and adaptive loading
    pub async fn load_with_strategy(
        &self,
        html: &str,
        base_url: Url,
        options: LoadOptions,
    ) -> Result<LoadResult, NetworkError> {
        let context = ResourceContext::new(base_url.clone());
        
        // Discover all resources
        let discovered = self.discovery.discover_all(html, &context)?;
        
        // Prioritize resources based on type and context
        let prioritized = self.prioritize_resources(discovered, &base_url);
        
        // Execute loading strategy
        match self.strategy {
            LoadingStrategy::Sequential => self.load_sequential(prioritized, options).await,
            LoadingStrategy::Parallel => self.load_parallel(prioritized, options).await,
            LoadingStrategy::CriticalFirst => self.load_critical_first(prioritized, options).await,
            LoadingStrategy::Adaptive => self.load_adaptive(prioritized, options).await,
        }
    }

    /// Prioritize resources based on type, location, and user interaction patterns
    fn prioritize_resources(&self, resources: Vec<ResourceRef>, base_url: &Url) -> HashMap<Priority, Vec<ResourceRef>> {
        let mut prioritized: HashMap<Priority, Vec<ResourceRef>> = HashMap::new();
        
        for resource in resources {
            let priority = self.calculate_priority(&resource, base_url);
            prioritized.entry(priority).or_default().push(resource);
        }
        
        // Sort within each priority level
        for resources in prioritized.values_mut() {
            resources.sort_by(|a, b| {
                // Sort by critical flag first, then by URL length (shorter = likely more important)
                b.is_critical.cmp(&a.is_critical)
                    .then_with(|| a.url.as_str().len().cmp(&b.url.as_str().len()))
            });
        }
        
        // Update the priority queue with discovered resources
        self.update_priority_queue(prioritized.clone());
        
        prioritized
    }
    
    /// Update the internal priority queue with new resources
    fn update_priority_queue(&self, prioritized: HashMap<Priority, Vec<ResourceRef>>) {
        if let Ok(mut queue) = self.priority_queue.lock() {
            for (priority, resources) in prioritized {
                queue.entry(priority).or_default().extend(resources);
            }
        }
    }
    
    /// Get the next batch of resources to load from priority queue
    fn get_next_priority_batch(&self, priority: Priority) -> Vec<ResourceRef> {
        if let Ok(mut queue) = self.priority_queue.lock() {
            if let Some(resources) = queue.get_mut(&priority) {
                let batch_size = *self
                    .max_concurrent_per_priority
                    .get(&priority)
                    .unwrap_or(&2);
                resources.drain(..resources.len().min(batch_size)).collect()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    }
    
    /// Clear completed resources from priority queue
    fn clear_priority_queue(&self) {
        if let Ok(mut queue) = self.priority_queue.lock() {
            queue.clear();
        }
    }

    /// Calculate resource priority based on multiple factors
    fn calculate_priority(&self, resource: &ResourceRef, base_url: &Url) -> Priority {
        // Start with basic type-based priority
        let base_priority = match resource.resource_type {
            ResourceType::Html => Priority::Critical,
            ResourceType::Css => Priority::Critical,
            ResourceType::Font => Priority::High,
            ResourceType::Script => Priority::Medium,
            ResourceType::Image => Priority::Low,
            _ => Priority::Low,
        };

        // Adjust based on resource location and context
        let adjusted_priority = if self.is_above_fold_resource(resource) {
            // Above-the-fold resources get higher priority
            match base_priority {
                Priority::Low => Priority::Medium,
                Priority::Medium => Priority::High,
                p => p,
            }
        } else if self.is_third_party_resource(resource, base_url) {
            // Third-party resources get lower priority
            match base_priority {
                Priority::Critical => Priority::High,
                Priority::High => Priority::Medium,
                Priority::Medium => Priority::Low,
                p => p,
            }
        } else {
            base_priority
        };

        // Further adjust based on metadata hints
        if let Some(preload) = resource.metadata.get("rel") {
            if preload == "preload" {
                return Priority::High;
            } else if preload == "prefetch" {
                return Priority::Preload;
            }
        }

        adjusted_priority
    }

    /// Check if resource is likely above the fold
    fn is_above_fold_resource(&self, resource: &ResourceRef) -> bool {
        // Simple heuristics - in a real implementation this would be more sophisticated
        let url_str = resource.url.as_str();
        
        // CSS files are typically above the fold
        if resource.resource_type == ResourceType::Css {
            return true;
        }
        
        // Images with certain patterns are likely above fold
        if resource.resource_type == ResourceType::Image {
            return url_str.contains("logo") || 
                   url_str.contains("hero") || 
                   url_str.contains("banner") ||
                   url_str.contains("header");
        }
        
        false
    }

    /// Check if resource is from a third-party domain
    fn is_third_party_resource(&self, resource: &ResourceRef, base_url: &Url) -> bool {
        if let (Some(base_host), Some(resource_host)) = (base_url.host_str(), resource.url.host_str()) {
            let base_domain = self.extract_domain(base_host);
            let resource_domain = self.extract_domain(resource_host);
            base_domain != resource_domain
        } else {
            true // Assume third-party if we can't determine
        }
    }

    /// Extract base domain from host
    fn extract_domain(&self, host: &str) -> String {
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() >= 2 {
            format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
        } else {
            host.to_string()
        }
    }

    /// Load resources sequentially
    async fn load_sequential(
        &self,
        prioritized: HashMap<Priority, Vec<ResourceRef>>,
        options: LoadOptions,
    ) -> Result<LoadResult, NetworkError> {
        let start_time = Instant::now();
        let mut all_responses = HashMap::new();
        let mut all_errors = HashMap::new();
        let mut progress = AdvancedProgress::new(
            prioritized.values().map(|v| v.len()).sum()
        );

        // Load in priority order
        for priority in [Priority::Critical, Priority::High, Priority::Medium, Priority::Low, Priority::Preload] {
            if let Some(resources) = prioritized.get(&priority) {
                for resource in resources {
                    match self.load_single_resource_tracked(resource, &options).await {
                        Ok(response) => {
                            all_responses.insert(resource.url.clone(), response);
                            progress.basic.loaded += 1;
                        }
                        Err(error) => {
                            all_errors.insert(resource.url.clone(), error);
                            progress.basic.failed += 1;
                        }
                    }
                    
                    // Update progress
                    self.send_progress_update(&progress);
                }
            }
        }

        Ok(LoadResult {
            progress: progress.basic,
            responses: all_responses,
            errors: all_errors,
            total_time: start_time.elapsed(),
        })
    }

    /// Load resources in parallel with priority ordering
    async fn load_parallel(
        &self,
        prioritized: HashMap<Priority, Vec<ResourceRef>>,
        options: LoadOptions,
    ) -> Result<LoadResult, NetworkError> {
        let start_time = Instant::now();
        let mut all_responses = HashMap::new();
        let mut all_errors = HashMap::new();
        let mut progress = AdvancedProgress::new(
            prioritized.values().map(|v| v.len()).sum()
        );

        // Load each priority level in parallel, but wait for higher priorities first
        for priority in [Priority::Critical, Priority::High, Priority::Medium, Priority::Low, Priority::Preload] {
            if let Some(resources) = prioritized.get(&priority) {
                let max_concurrent = self.max_concurrent_per_priority.get(&priority).unwrap_or(&4);
                let semaphore = Arc::new(Semaphore::new(*max_concurrent));
                
                let tasks: Vec<_> = resources.iter().map(|resource| {
                    let semaphore = Arc::clone(&semaphore);
                    let options = options.clone();
                    let resource = resource.clone();
                    
                    async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        let url = resource.url.clone();
                        let result = self.load_single_resource_tracked(&resource, &options).await;
                        (url, result)
                    }
                }).collect();

                let results = join_all(tasks).await;
                
                for (url, result) in results {
                    match result {
                        Ok(response) => {
                            all_responses.insert(url, response);
                            progress.basic.loaded += 1;
                        }
                        Err(error) => {
                            all_errors.insert(url, error);
                            progress.basic.failed += 1;
                        }
                    }
                }
                
                // Update progress after each priority level
                self.send_progress_update(&progress);
            }
        }

        Ok(LoadResult {
            progress: progress.basic,
            responses: all_responses,
            errors: all_errors,
            total_time: start_time.elapsed(),
        })
    }

    /// Load critical resources first, then others
    async fn load_critical_first(
        &self,
        prioritized: HashMap<Priority, Vec<ResourceRef>>,
        options: LoadOptions,
    ) -> Result<LoadResult, NetworkError> {
        let start_time = Instant::now();
        let mut all_responses = HashMap::new();
        let mut all_errors = HashMap::new();
        let mut progress = AdvancedProgress::new(
            prioritized.values().map(|v| v.len()).sum()
        );

        // First, load all critical resources
        let mut critical_resources = self.get_next_priority_batch(Priority::Critical);
        if critical_resources.is_empty() {
            critical_resources = prioritized
                .get(&Priority::Critical)
                .cloned()
                .unwrap_or_default();
        }
        
        for resource in &critical_resources {
            match self.load_single_resource_tracked(resource, &options).await {
                Ok(response) => {
                    all_responses.insert(resource.url.clone(), response);
                    progress.basic.loaded += 1;
                }
                Err(error) => {
                    all_errors.insert(resource.url.clone(), error);
                    progress.basic.failed += 1;
                }
            }
        }
        
        // Update progress after critical resources
        progress.critical_blocking = 0;
        self.send_progress_update(&progress);

        // Then load other resources in parallel
        let remaining_priorities = [Priority::High, Priority::Medium, Priority::Low, Priority::Preload];
        let mut remaining_tasks = Vec::new();
        
        for priority in remaining_priorities {
            let mut resources = self.get_next_priority_batch(priority);
            if resources.is_empty() {
                if let Some(fallback) = prioritized.get(&priority) {
                    resources = fallback.clone();
                }
            }

            if resources.is_empty() {
                continue;
            }

            let max_concurrent = self.max_concurrent_per_priority.get(&priority).unwrap_or(&4);
            let semaphore = Arc::new(Semaphore::new(*max_concurrent));
            
            for resource in resources {
                let semaphore = Arc::clone(&semaphore);
                let options = options.clone();
                let resource = resource.clone();
                
                remaining_tasks.push(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let url = resource.url.clone();
                    let result = self.load_single_resource_tracked(&resource, &options).await;
                    (url, result)
                });
            }
        }

        let remaining_results = join_all(remaining_tasks).await;
        
        for (url, result) in remaining_results {
            match result {
                Ok(response) => {
                    all_responses.insert(url, response);
                    progress.basic.loaded += 1;
                }
                Err(error) => {
                    all_errors.insert(url, error);
                    progress.basic.failed += 1;
                }
            }
        }

        // Clear queue now that all prioritized work is complete
        self.clear_priority_queue();

        Ok(LoadResult {
            progress: progress.basic,
            responses: all_responses,
            errors: all_errors,
            total_time: start_time.elapsed(),
        })
    }

    /// Adaptive loading based on network conditions
    async fn load_adaptive(
        &self,
        prioritized: HashMap<Priority, Vec<ResourceRef>>,
        options: LoadOptions,
    ) -> Result<LoadResult, NetworkError> {
        // Get current network condition
        let network_condition = {
            let tracker = self.bandwidth_tracker.lock().unwrap();
            tracker.network_condition()
        };

        // Adapt strategy based on network condition
        match network_condition {
            NetworkCondition::Fast => {
                // Use full parallel loading
                self.load_parallel(prioritized, options).await
            }
            NetworkCondition::Medium => {
                // Use critical-first with reduced concurrency
                let mut adapted_options = options;
                adapted_options.max_concurrent = 4;
                self.load_critical_first(prioritized, adapted_options).await
            }
            NetworkCondition::Slow => {
                // Use sequential loading for critical resources only
                let mut critical_only = HashMap::new();
                if let Some(critical) = prioritized.get(&Priority::Critical) {
                    critical_only.insert(Priority::Critical, critical.clone());
                }
                if let Some(high) = prioritized.get(&Priority::High) {
                    critical_only.insert(Priority::High, high.clone());
                }
                
                let mut adapted_options = options;
                adapted_options.max_concurrent = 2;
                adapted_options.load_non_critical = false;
                
                self.load_sequential(critical_only, adapted_options).await
            }
            NetworkCondition::Unknown => {
                // Use conservative parallel loading
                let mut adapted_options = options;
                adapted_options.max_concurrent = 3;
                self.load_critical_first(prioritized, adapted_options).await
            }
        }
    }

    /// Load a single resource with bandwidth tracking
    async fn load_single_resource_tracked(
        &self,
        resource: &ResourceRef,
        options: &LoadOptions,
    ) -> Result<Response, NetworkError> {
        let start_time = Instant::now();
        
        // Check cache first
        if let Some(cached) = self.cache.get(&resource.url) {
            return Ok(cached);
        }

        // Create request with appropriate headers
        let request = crate::request::Request::new(
            crate::request::Method::GET, 
            resource.url.as_str()
        )?
        .with_timeout(options.request_timeout)
        .prepare();

        // Make the request
        let result = timeout(
            options.request_timeout,
            self.resource.fetch(request)
        ).await;

        match result {
            Ok(Ok(response)) => {
                let elapsed = start_time.elapsed();
                let bytes = response.body().len();
                
                // Update bandwidth tracking
                {
                    let mut tracker = self.bandwidth_tracker.lock().unwrap();
                    tracker.record_speed(bytes, elapsed);
                }
                
                // Cache the response
                let _ = self.cache.put(&resource.url, response.clone());
                
                Ok(response)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(NetworkError::TimeoutError(options.request_timeout)),
        }
    }

    /// Send progress update if channel is available
    fn send_progress_update(&self, progress: &AdvancedProgress) {
        if let Some(tx) = &self.progress_tx {
            let _ = tx.send(progress.clone());
        }
    }

    /// Add resources to preload queue
    pub fn queue_preload(&self, resources: Vec<ResourceRef>) {
        if let Ok(mut queue) = self.preload_queue.lock() {
            for resource in resources {
                queue.push_back(resource);
            }
        }
    }

    /// Process preload queue in background
    pub async fn process_preload_queue(&self, options: LoadOptions) {
        let mut processed = 0;
        const MAX_PRELOAD_BATCH: usize = 10;
        
        while processed < MAX_PRELOAD_BATCH {
            let resource = {
                let mut queue = self.preload_queue.lock().unwrap();
                queue.pop_front()
            };
            
            if let Some(resource) = resource {
                // Load with low priority and longer timeout
                let mut preload_options = options.clone();
                preload_options.request_timeout = Duration::from_secs(60);
                preload_options.max_retries = 1;
                
                let _ = self.load_single_resource_tracked(&resource, &preload_options).await;
                processed += 1;
                
                // Small delay between preloads to avoid overwhelming the network
                sleep(Duration::from_millis(100)).await;
            } else {
                break;
            }
        }
    }

    /// Get current bandwidth estimate
    pub fn current_bandwidth(&self) -> u64 {
        self.bandwidth_tracker.lock().unwrap().estimated_bandwidth()
    }

    /// Get current network condition
    pub fn network_condition(&self) -> NetworkCondition {
        self.bandwidth_tracker.lock().unwrap().network_condition()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_bandwidth_tracker() {
        let mut tracker = BandwidthTracker::new();
        
        // Record some speeds
        tracker.record_speed(1000, Duration::from_millis(100)); // 10KB/s
        tracker.record_speed(2000, Duration::from_millis(100)); // 20KB/s
        
        assert!(tracker.estimated_bandwidth() > 0);
        assert_eq!(tracker.network_condition(), NetworkCondition::Slow);
    }

    #[test]
    fn test_priority_calculation() {
        // This would test the priority calculation logic
        // Implementation would depend on having mock data
    }

    #[tokio::test]
    async fn test_advanced_loader_creation() {
        let config = NetworkConfig::default();
        let loader = AdvancedResourceLoader::new(config, LoadingStrategy::Adaptive).await;
        assert!(loader.is_ok());
    }
}
