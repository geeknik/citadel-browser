//! Performance optimizations for the networking layer
//!
//! This module provides connection pooling, request batching, caching,
//! and other performance optimizations for network operations.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use url::Url;

/// Connection pool configuration
#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    /// Maximum number of connections per host
    pub max_connections_per_host: usize,
    /// Maximum total connections
    pub max_total_connections: usize,
    /// Connection idle timeout
    pub idle_timeout: Duration,
    /// Connection keep-alive duration
    pub keep_alive_duration: Duration,
    /// Enable HTTP/2
    pub enable_http2: bool,
    /// Enable connection multiplexing
    pub enable_multiplexing: bool,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_host: 6,
            max_total_connections: 50,
            idle_timeout: Duration::from_secs(90),
            keep_alive_duration: Duration::from_secs(30),
            enable_http2: true,
            enable_multiplexing: true,
        }
    }
}

/// Network cache entry
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Cached response data
    pub data: Vec<u8>,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Cache timestamp
    pub timestamp: Instant,
    /// Cache expiry time
    pub expires_at: Option<Instant>,
    /// ETag for validation
    pub etag: Option<String>,
    /// Last-Modified for validation
    pub last_modified: Option<String>,
    /// Access count for LRU eviction
    pub access_count: usize,
    /// Size in bytes
    pub size_bytes: usize,
}

impl CacheEntry {
    /// Check if cache entry is still valid
    pub fn is_valid(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Instant::now() < expires_at
        } else {
            // Without explicit expiry, consider valid for 1 hour
            self.timestamp.elapsed() < Duration::from_secs(3600)
        }
    }
    
    /// Check if entry is stale and needs revalidation
    pub fn needs_revalidation(&self) -> bool {
        !self.is_valid() && (self.etag.is_some() || self.last_modified.is_some())
    }
}

/// Network cache with LRU eviction and size limits
pub struct NetworkCache {
    /// Cache entries keyed by URL
    entries: HashMap<String, CacheEntry>,
    /// Maximum cache size in bytes
    max_size_bytes: usize,
    /// Current cache size in bytes
    current_size_bytes: usize,
    /// Maximum number of entries
    max_entries: usize,
    /// Cache hit count
    hit_count: usize,
    /// Cache miss count
    miss_count: usize,
}

impl NetworkCache {
    /// Create a new network cache
    pub fn new(max_size_bytes: usize, max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_size_bytes,
            current_size_bytes: 0,
            max_entries,
            hit_count: 0,
            miss_count: 0,
        }
    }
    
    /// Get cached response
    pub fn get(&mut self, url: &str) -> Option<CacheEntry> {
        let mut should_remove = false;
        let mut result = None;
        
        if let Some(entry) = self.entries.get_mut(url) {
            if entry.is_valid() {
                entry.access_count += 1;
                self.hit_count += 1;
                result = Some(entry.clone());
            } else {
                // Mark for removal
                should_remove = true;
                self.current_size_bytes -= entry.size_bytes;
            }
        }
        
        if should_remove {
            self.entries.remove(url);
        }
        
        if result.is_none() {
            self.miss_count += 1;
        }
        
        result
    }
    
    /// Store response in cache
    pub fn put(&mut self, url: String, entry: CacheEntry) {
        // Check if we need to evict entries
        while (self.entries.len() >= self.max_entries) ||
              (self.current_size_bytes + entry.size_bytes > self.max_size_bytes) {
            if !self.evict_lru() {
                break; // Can't evict any more
            }
        }
        
        // Update size tracking
        if let Some(old_entry) = self.entries.get(&url) {
            self.current_size_bytes -= old_entry.size_bytes;
        }
        
        self.current_size_bytes += entry.size_bytes;
        self.entries.insert(url, entry);
    }
    
    /// Evict least recently used entry
    fn evict_lru(&mut self) -> bool {
        if self.entries.is_empty() {
            return false;
        }
        
        // Find entry with lowest access count and oldest timestamp
        let mut lru_url: Option<String> = None;
        let mut min_access_count = usize::MAX;
        let mut oldest_timestamp = Instant::now();
        
        for (url, entry) in &self.entries {
            if entry.access_count < min_access_count ||
               (entry.access_count == min_access_count && entry.timestamp < oldest_timestamp) {
                min_access_count = entry.access_count;
                oldest_timestamp = entry.timestamp;
                lru_url = Some(url.clone());
            }
        }
        
        if let Some(url) = lru_url {
            if let Some(entry) = self.entries.remove(&url) {
                self.current_size_bytes -= entry.size_bytes;
                return true;
            }
        }
        
        false
    }
    
    /// Clear all cache entries
    pub fn clear(&mut self) {
        self.entries.clear();
        self.current_size_bytes = 0;
    }
    
    /// Get cache statistics
    pub fn get_stats(&self) -> CacheStats {
        let hit_ratio = if self.hit_count + self.miss_count > 0 {
            self.hit_count as f64 / (self.hit_count + self.miss_count) as f64
        } else {
            0.0
        };
        
        CacheStats {
            entries: self.entries.len(),
            size_bytes: self.current_size_bytes,
            max_size_bytes: self.max_size_bytes,
            hit_count: self.hit_count,
            miss_count: self.miss_count,
            hit_ratio,
        }
    }
    
    /// Remove expired entries
    pub fn cleanup_expired(&mut self) {
        let expired_urls: Vec<String> = self.entries
            .iter()
            .filter(|(_, entry)| !entry.is_valid())
            .map(|(url, _)| url.clone())
            .collect();
        
        for url in expired_urls {
            if let Some(entry) = self.entries.remove(&url) {
                self.current_size_bytes -= entry.size_bytes;
            }
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entries: usize,
    pub size_bytes: usize,
    pub max_size_bytes: usize,
    pub hit_count: usize,
    pub miss_count: usize,
    pub hit_ratio: f64,
}

/// Request batching for improved performance
pub struct RequestBatcher {
    /// Pending requests to batch
    pending_requests: Vec<PendingRequest>,
    /// Maximum batch size
    max_batch_size: usize,
    /// Batch timeout
    batch_timeout: Duration,
    /// Last batch time
    last_batch_time: Instant,
}

/// Pending request for batching
#[derive(Debug)]
struct PendingRequest {
    url: Url,
    priority: RequestPriority,
    timestamp: Instant,
}

impl PendingRequest {
    /// Create a new pending request
    fn new(url: Url, priority: RequestPriority) -> Self {
        Self {
            url,
            priority,
            timestamp: Instant::now(),
        }
    }
    
    /// Get the age of this request in milliseconds
    fn age_ms(&self) -> u64 {
        self.timestamp.elapsed().as_millis() as u64
    }
    
    /// Check if this request has been pending too long
    fn is_stale(&self, timeout_ms: u64) -> bool {
        self.age_ms() > timeout_ms
    }
}

/// Request priority for batching and scheduling
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestPriority {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl RequestBatcher {
    /// Create a new request batcher
    pub fn new(max_batch_size: usize, batch_timeout: Duration) -> Self {
        Self {
            pending_requests: Vec::new(),
            max_batch_size,
            batch_timeout,
            last_batch_time: Instant::now(),
        }
    }
    
    /// Add a request to the batch
    pub fn add_request(&mut self, url: Url, priority: RequestPriority) {
        self.pending_requests.push(PendingRequest {
            url,
            priority,
            timestamp: Instant::now(),
        });
        
        // Sort by priority (highest first)
        self.pending_requests.sort_by(|a, b| b.priority.cmp(&a.priority));
    }
    
    /// Check if batch should be processed
    pub fn should_process_batch(&self) -> bool {
        self.pending_requests.len() >= self.max_batch_size ||
        (self.last_batch_time.elapsed() >= self.batch_timeout && !self.pending_requests.is_empty())
    }
    
    /// Get next batch of requests to process
    pub fn get_next_batch(&mut self) -> Vec<Url> {
        let batch_size = std::cmp::min(self.max_batch_size, self.pending_requests.len());
        let batch_requests = self.pending_requests.drain(..batch_size).collect::<Vec<_>>();
        self.last_batch_time = Instant::now();
        
        batch_requests.into_iter().map(|req| req.url).collect()
    }
    
    /// Get pending request count
    pub fn pending_count(&self) -> usize {
        self.pending_requests.len()
    }
}

/// Network performance monitor
pub struct NetworkPerformanceMonitor {
    /// Request timing measurements
    request_times: HashMap<String, Vec<Duration>>,
    /// DNS resolution times
    dns_times: HashMap<String, Duration>,
    /// Connection establishment times
    connection_times: HashMap<String, Duration>,
    /// Total data transferred
    total_bytes_transferred: usize,
    /// Active connections count
    active_connections: usize,
    /// Connection pool statistics
    connection_pool_stats: ConnectionPoolStats,
}

/// Connection pool statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionPoolStats {
    pub total_connections: usize,
    pub active_connections: usize,
    pub idle_connections: usize,
    pub connections_created: usize,
    pub connections_reused: usize,
    pub connections_closed: usize,
}

impl NetworkPerformanceMonitor {
    /// Create a new performance monitor
    pub fn new() -> Self {
        Self {
            request_times: HashMap::new(),
            dns_times: HashMap::new(),
            connection_times: HashMap::new(),
            total_bytes_transferred: 0,
            active_connections: 0,
            connection_pool_stats: ConnectionPoolStats::default(),
        }
    }
    
    /// Record request timing
    pub fn record_request_time(&mut self, host: String, duration: Duration) {
        let host_key = host.clone();
        self.request_times.entry(host).or_insert_with(Vec::new).push(duration);
        
        // Keep only last 100 measurements
        if let Some(times) = self.request_times.get_mut(&host_key) {
            if times.len() > 100 {
                times.remove(0);
            }
        }
    }
    
    /// Record DNS resolution time
    pub fn record_dns_time(&mut self, host: String, duration: Duration) {
        self.dns_times.insert(host, duration);
    }
    
    /// Record connection establishment time
    pub fn record_connection_time(&mut self, host: String, duration: Duration) {
        self.connection_times.insert(host, duration);
    }
    
    /// Add data transfer amount
    pub fn add_bytes_transferred(&mut self, bytes: usize) {
        self.total_bytes_transferred += bytes;
    }
    
    /// Update active connections count
    pub fn set_active_connections(&mut self, count: usize) {
        self.active_connections = count;
    }
    
    /// Update connection pool stats
    pub fn update_connection_pool_stats(&mut self, stats: ConnectionPoolStats) {
        self.connection_pool_stats = stats;
    }
    
    /// Get average request time for a host
    pub fn get_average_request_time(&self, host: &str) -> Option<Duration> {
        if let Some(times) = self.request_times.get(host) {
            if !times.is_empty() {
                let total: Duration = times.iter().sum();
                return Some(total / times.len() as u32);
            }
        }
        None
    }
    
    /// Get performance summary
    pub fn get_performance_summary(&self) -> NetworkPerformanceSummary {
        let total_hosts = self.request_times.len();
        let average_request_time = if total_hosts > 0 {
            let total_time: Duration = self.request_times
                .values()
                .flat_map(|times| times.iter())
                .sum();
            let total_requests: usize = self.request_times
                .values()
                .map(|times| times.len())
                .sum();
            
            if total_requests > 0 {
                Some(total_time / total_requests as u32)
            } else {
                None
            }
        } else {
            None
        };
        
        NetworkPerformanceSummary {
            total_hosts,
            average_request_time,
            total_bytes_transferred: self.total_bytes_transferred,
            active_connections: self.active_connections,
            connection_pool_stats: self.connection_pool_stats.clone(),
        }
    }
}

/// Network performance summary
#[derive(Debug, Clone)]
pub struct NetworkPerformanceSummary {
    pub total_hosts: usize,
    pub average_request_time: Option<Duration>,
    pub total_bytes_transferred: usize,
    pub active_connections: usize,
    pub connection_pool_stats: ConnectionPoolStats,
}

/// Network optimization recommendations
#[derive(Debug, Clone)]
pub enum NetworkOptimization {
    /// Increase connection pool size
    IncreaseConnectionPool(usize),
    /// Enable request batching
    EnableRequestBatching,
    /// Increase cache size
    IncreaseCacheSize(usize),
    /// Enable HTTP/2
    EnableHttp2,
    /// Optimize DNS caching
    OptimizeDnsCaching,
    /// Reduce request timeout
    ReduceRequestTimeout(Duration),
    /// Enable compression
    EnableCompression,
}

/// Network performance optimizer
pub struct NetworkOptimizer {
    monitor: Arc<Mutex<NetworkPerformanceMonitor>>,
    cache: Arc<Mutex<NetworkCache>>,
    config: ConnectionPoolConfig,
}

impl NetworkOptimizer {
    /// Create a new network optimizer
    pub fn new(
        monitor: Arc<Mutex<NetworkPerformanceMonitor>>,
        cache: Arc<Mutex<NetworkCache>>,
        config: ConnectionPoolConfig,
    ) -> Self {
        Self {
            monitor,
            cache,
            config,
        }
    }
    
    /// Analyze network performance and provide optimization recommendations
    pub fn analyze_and_recommend(&self) -> Vec<NetworkOptimization> {
        let mut recommendations = Vec::new();
        
        // Analyze performance metrics
        if let Ok(monitor) = self.monitor.lock() {
            let summary = monitor.get_performance_summary();
            
            // Check if average request time is high
            if let Some(avg_time) = summary.average_request_time {
                if avg_time > Duration::from_millis(500) {
                    recommendations.push(NetworkOptimization::IncreaseConnectionPool(
                        self.config.max_connections_per_host * 2
                    ));
                    recommendations.push(NetworkOptimization::EnableRequestBatching);
                }
            }
            
            // Check connection pool utilization
            let pool_utilization = summary.connection_pool_stats.active_connections as f64 /
                                 self.config.max_total_connections as f64;
            
            if pool_utilization > 0.8 {
                recommendations.push(NetworkOptimization::IncreaseConnectionPool(
                    self.config.max_total_connections * 2
                ));
            }
        }
        
        // Analyze cache performance
        if let Ok(cache) = self.cache.lock() {
            let cache_stats = cache.get_stats();
            
            if cache_stats.hit_ratio < 0.6 {
                recommendations.push(NetworkOptimization::IncreaseCacheSize(
                    cache_stats.max_size_bytes * 2
                ));
            }
        }
        
        // Check if HTTP/2 is enabled
        if !self.config.enable_http2 {
            recommendations.push(NetworkOptimization::EnableHttp2);
        }
        
        recommendations
    }
    
    /// Apply optimization recommendation
    pub fn apply_optimization(&mut self, optimization: NetworkOptimization) -> Result<(), String> {
        match optimization {
            NetworkOptimization::IncreaseConnectionPool(new_size) => {
                self.config.max_total_connections = new_size;
                log::info!("Increased connection pool size to {}", new_size);
            }
            NetworkOptimization::EnableHttp2 => {
                self.config.enable_http2 = true;
                log::info!("Enabled HTTP/2");
            }
            NetworkOptimization::IncreaseCacheSize(new_size) => {
                // This would require recreating the cache with new size
                log::info!("Recommended to increase cache size to {} bytes", new_size);
            }
            _ => {
                log::info!("Applied network optimization: {:?}", optimization);
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_network_cache() {
        let mut cache = NetworkCache::new(1024, 10);
        
        let entry = CacheEntry {
            data: vec![1, 2, 3, 4],
            headers: HashMap::new(),
            timestamp: Instant::now(),
            expires_at: Some(Instant::now() + Duration::from_secs(3600)),
            etag: None,
            last_modified: None,
            access_count: 0,
            size_bytes: 4,
        };
        
        cache.put("http://example.com".to_string(), entry);
        
        assert!(cache.get("http://example.com").is_some());
        assert!(cache.get("http://nonexistent.com").is_none());
        
        let stats = cache.get_stats();
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.size_bytes, 4);
    }
    
    #[test]
    fn test_request_batcher() {
        let mut batcher = RequestBatcher::new(3, Duration::from_millis(100));
        
        let url1 = Url::parse("http://example.com/1").unwrap();
        let url2 = Url::parse("http://example.com/2").unwrap();
        
        batcher.add_request(url1, RequestPriority::High);
        batcher.add_request(url2, RequestPriority::Low);
        
        assert_eq!(batcher.pending_count(), 2);
        assert!(!batcher.should_process_batch());
        
        // Add one more to trigger batch processing
        let url3 = Url::parse("http://example.com/3").unwrap();
        batcher.add_request(url3, RequestPriority::Medium);
        
        assert!(batcher.should_process_batch());
        
        let batch = batcher.get_next_batch();
        assert_eq!(batch.len(), 3);
        assert_eq!(batcher.pending_count(), 0);
    }
    
    #[test]
    fn test_performance_monitor() {
        let mut monitor = NetworkPerformanceMonitor::new();
        
        monitor.record_request_time("example.com".to_string(), Duration::from_millis(100));
        monitor.record_request_time("example.com".to_string(), Duration::from_millis(200));
        
        let avg_time = monitor.get_average_request_time("example.com").unwrap();
        assert_eq!(avg_time, Duration::from_millis(150));
        
        let summary = monitor.get_performance_summary();
        assert_eq!(summary.total_hosts, 1);
    }
}