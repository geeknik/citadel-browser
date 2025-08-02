use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use url::Url;

use crate::error::NetworkError;
use crate::response::Response;

/// Configuration for the resource cache
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum cache size in bytes
    pub max_size_bytes: usize,
    /// Maximum number of entries
    pub max_entries: usize,
    /// Default TTL for cached entries
    pub default_ttl: Duration,
    /// Maximum TTL allowed (security limit)
    pub max_ttl: Duration,
    /// Whether to respect Cache-Control headers
    pub respect_cache_control: bool,
    /// Whether to enable cache validation (ETag/Last-Modified)
    pub enable_validation: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 50 * 1024 * 1024,  // 50MB
            max_entries: 1000,
            default_ttl: Duration::from_secs(3600),      // 1 hour
            max_ttl: Duration::from_secs(24 * 3600),     // 24 hours max for privacy
            respect_cache_control: true,
            enable_validation: true,
        }
    }
}

/// Cache entry with metadata for privacy-preserving caching
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Cached response
    pub response: Response,
    /// When this entry was created
    pub created_at: Instant,
    /// When this entry expires
    pub expires_at: Instant,
    /// Size of the entry in bytes
    pub size_bytes: usize,
    /// ETag for validation
    pub etag: Option<String>,
    /// Last-Modified header for validation
    pub last_modified: Option<String>,
    /// Access count for LRU eviction
    pub access_count: u64,
    /// Last access time for LRU eviction
    pub last_accessed: Instant,
    /// Whether this entry can be served stale
    pub allow_stale: bool,
}

impl CacheEntry {
    /// Create a new cache entry from a response
    pub fn new(response: Response, ttl: Duration) -> Self {
        let now = Instant::now();
        let size_bytes = response.body().len() + 
                        response.headers().iter()
                            .map(|(k, v)| k.len() + v.len())
                            .sum::<usize>() +
                        response.url().as_str().len();
        
        let etag = response.header("etag").cloned();
        let last_modified = response.header("last-modified").cloned();
        
        Self {
            response,
            created_at: now,
            expires_at: now + ttl,
            size_bytes,
            etag,
            last_modified,
            access_count: 1,
            last_accessed: now,
            allow_stale: false,
        }
    }
    
    /// Check if this entry is expired
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
    
    /// Check if this entry is fresh (not expired)
    pub fn is_fresh(&self) -> bool {
        !self.is_expired()
    }
    
    /// Check if this entry can be validated (has ETag or Last-Modified)
    pub fn can_validate(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }
    
    /// Mark this entry as accessed (for LRU tracking)
    pub fn mark_accessed(&mut self) {
        self.access_count += 1;
        self.last_accessed = Instant::now();
    }
    
    /// Get the age of this entry
    pub fn age(&self) -> Duration {
        Instant::now().duration_since(self.created_at)
    }
}

/// Privacy-preserving resource cache with LRU eviction
#[derive(Debug)]
pub struct ResourceCache {
    /// Cache entries indexed by URL
    entries: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Cache configuration
    config: CacheConfig,
    /// Current cache size in bytes
    current_size: Arc<RwLock<usize>>,
}

impl ResourceCache {
    /// Create a new resource cache with the given configuration
    pub fn new(config: CacheConfig) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            config,
            current_size: Arc::new(RwLock::new(0)),
        }
    }
    
    /// Create a new resource cache with default configuration
    pub fn default() -> Self {
        Self::new(CacheConfig::default())
    }
    
    /// Get a cached response if available and fresh
    pub fn get(&self, url: &Url) -> Option<Response> {
        let key = self.cache_key(url);
        
        if let Ok(mut entries) = self.entries.write() {
            if let Some(entry) = entries.get_mut(&key) {
                // Check if entry is fresh
                if entry.is_fresh() {
                    entry.mark_accessed();
                    return Some(entry.response.clone());
                } else if entry.allow_stale {
                    // Serve stale content if allowed (useful for offline scenarios)
                    entry.mark_accessed();
                    let mut stale_response = entry.response.clone();
                    stale_response.set_from_cache(true);
                    return Some(stale_response);
                } else {
                    // Remove expired entry
                    if let Ok(mut size) = self.current_size.write() {
                        *size = size.saturating_sub(entry.size_bytes);
                    }
                    entries.remove(&key);
                }
            }
        }
        
        None
    }
    
    /// Get a cached entry for validation (even if expired)
    pub fn get_for_validation(&self, url: &Url) -> Option<CacheEntry> {
        let key = self.cache_key(url);
        
        if let Ok(entries) = self.entries.read() {
            entries.get(&key).cloned()
        } else {
            None
        }
    }
    
    /// Store a response in the cache
    pub fn put(&self, url: &Url, response: Response) -> Result<(), NetworkError> {
        let key = self.cache_key(url);
        
        // Calculate TTL based on response headers and configuration
        let ttl = self.calculate_ttl(&response);
        
        // Don't cache if TTL is zero or negative
        if ttl.is_zero() {
            return Ok(());
        }
        
        let entry = CacheEntry::new(response, ttl);
        
        // Check cache size limits before adding
        if entry.size_bytes > self.config.max_size_bytes {
            // Entry is too large to cache
            return Err(NetworkError::ResourceError(
                format!("Response too large to cache: {} bytes", entry.size_bytes)
            ));
        }
        
        if let Ok(mut entries) = self.entries.write() {
            // Remove existing entry if present
            if let Some(old_entry) = entries.remove(&key) {
                if let Ok(mut size) = self.current_size.write() {
                    *size = size.saturating_sub(old_entry.size_bytes);
                }
            }
            
            // Ensure we have space for the new entry
            self.ensure_space_for(entry.size_bytes)?;
            
            // Add the new entry
            if let Ok(mut size) = self.current_size.write() {
                *size += entry.size_bytes;
            }
            entries.insert(key, entry);
        }
        
        Ok(())
    }
    
    /// Update an existing cache entry after validation
    pub fn update_after_validation(&self, url: &Url, response: Response) -> Result<(), NetworkError> {
        let key = self.cache_key(url);
        
        if let Ok(mut entries) = self.entries.write() {
            if let Some(entry) = entries.remove(&key) {
                // Update size tracking
                if let Ok(mut size) = self.current_size.write() {
                    *size = size.saturating_sub(entry.size_bytes);
                }
                
                // Create new entry with updated response
                let ttl = self.calculate_ttl(&response);
                let new_entry = CacheEntry::new(response, ttl);
                
                // Preserve access statistics
                let mut updated_entry = new_entry;
                updated_entry.access_count = entry.access_count + 1;
                updated_entry.last_accessed = Instant::now();
                
                // Update size tracking
                if let Ok(mut size) = self.current_size.write() {
                    *size += updated_entry.size_bytes;
                }
                
                entries.insert(key, updated_entry);
            }
        }
        
        Ok(())
    }
    
    /// Clear the entire cache
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.clear();
        }
        if let Ok(mut size) = self.current_size.write() {
            *size = 0;
        }
    }
    
    /// Remove expired entries from the cache
    pub fn cleanup_expired(&self) {
        if let Ok(mut entries) = self.entries.write() {
            let now = Instant::now();
            let mut removed_size = 0;
            
            entries.retain(|_, entry| {
                if now > entry.expires_at {
                    removed_size += entry.size_bytes;
                    false
                } else {
                    true
                }
            });
            
            if removed_size > 0 {
                if let Ok(mut size) = self.current_size.write() {
                    *size = size.saturating_sub(removed_size);
                }
            }
        }
    }
    
    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        if let (Ok(entries), Ok(size)) = (self.entries.read(), self.current_size.read()) {
            let entry_count = entries.len();
            let total_size = *size;
            let expired_count = entries.values()
                .filter(|entry| entry.is_expired())
                .count();
            
            CacheStats {
                entry_count,
                total_size_bytes: total_size,
                expired_entries: expired_count,
                max_size_bytes: self.config.max_size_bytes,
                max_entries: self.config.max_entries,
            }
        } else {
            CacheStats::default()
        }
    }
    
    /// Generate a cache key for a URL
    fn cache_key(&self, url: &Url) -> String {
        // Use the full URL as the cache key
        // In a more sophisticated implementation, we might normalize URLs
        url.as_str().to_string()
    }
    
    /// Calculate TTL for a response based on headers and configuration
    fn calculate_ttl(&self, response: &Response) -> Duration {
        if !self.config.respect_cache_control {
            return self.config.default_ttl;
        }
        
        // Check Cache-Control header
        if let Some(cache_control) = response.header("cache-control") {
            let cc = cache_control.to_lowercase();
            
            // Don't cache if no-store is present
            if cc.contains("no-store") {
                return Duration::ZERO;
            }
            
            // Don't cache if no-cache is present (unless we're doing validation)
            if cc.contains("no-cache") && !self.config.enable_validation {
                return Duration::ZERO;
            }
            
            // Look for max-age directive
            if let Some(max_age_start) = cc.find("max-age=") {
                let max_age_str = &cc[max_age_start + 8..];
                if let Some(end) = max_age_str.find(|c: char| !c.is_ascii_digit()) {
                    let seconds_str = &max_age_str[..end];
                    if let Ok(seconds) = seconds_str.parse::<u64>() {
                        let ttl = Duration::from_secs(seconds);
                        return std::cmp::min(ttl, self.config.max_ttl);
                    }
                } else if let Ok(seconds) = max_age_str.parse::<u64>() {
                    let ttl = Duration::from_secs(seconds);
                    return std::cmp::min(ttl, self.config.max_ttl);
                }
            }
        }
        
        // Check Expires header
        if let Some(_expires) = response.header("expires") {
            // In a real implementation, we would parse the HTTP date
            // For now, use default TTL
        }
        
        // Use default TTL, capped by max TTL
        std::cmp::min(self.config.default_ttl, self.config.max_ttl)
    }
    
    /// Ensure there's space for a new entry of the given size
    fn ensure_space_for(&self, size_bytes: usize) -> Result<(), NetworkError> {
        if let (Ok(mut entries), Ok(mut current_size)) = 
            (self.entries.write(), self.current_size.write()) {
            
            // Check if we need to make space
            while (*current_size + size_bytes > self.config.max_size_bytes) ||
                  (entries.len() >= self.config.max_entries) {
                
                if entries.is_empty() {
                    break;
                }
                
                // Find LRU entry to evict
                let lru_key = entries.iter()
                    .min_by_key(|(_, entry)| (entry.last_accessed, entry.access_count))
                    .map(|(key, _)| key.clone());
                
                if let Some(key) = lru_key {
                    if let Some(removed) = entries.remove(&key) {
                        *current_size = current_size.saturating_sub(removed.size_bytes);
                        log::debug!("Evicted cache entry: {} ({} bytes)", key, removed.size_bytes);
                    }
                } else {
                    break;
                }
            }
        }
        
        Ok(())
    }
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of entries in the cache
    pub entry_count: usize,
    /// Total size of cached data in bytes
    pub total_size_bytes: usize,
    /// Number of expired entries
    pub expired_entries: usize,
    /// Maximum allowed cache size in bytes
    pub max_size_bytes: usize,
    /// Maximum allowed number of entries
    pub max_entries: usize,
}

impl CacheStats {
    /// Get cache utilization as a percentage
    pub fn size_utilization(&self) -> f64 {
        if self.max_size_bytes == 0 {
            0.0
        } else {
            (self.total_size_bytes as f64 / self.max_size_bytes as f64) * 100.0
        }
    }
    
    /// Get entry utilization as a percentage
    pub fn entry_utilization(&self) -> f64 {
        if self.max_entries == 0 {
            0.0
        } else {
            (self.entry_count as f64 / self.max_entries as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::Method;
    use std::collections::HashMap;
    use bytes::Bytes;
    
    fn create_test_response(url: &str, body: &str) -> Response {
        let headers = HashMap::new();
        Response::new(
            200,
            headers,
            Bytes::from(body.to_string()),
            Url::parse(url).unwrap(),
            Method::GET,
        )
    }
    
    #[test]
    fn test_cache_entry_creation() {
        let response = create_test_response("https://example.com/test", "test content");
        let ttl = Duration::from_secs(3600);
        let entry = CacheEntry::new(response, ttl);
        
        assert!(entry.is_fresh());
        assert!(!entry.is_expired());
        assert_eq!(entry.access_count, 1);
    }
    
    #[test]
    fn test_cache_put_and_get() {
        let cache = ResourceCache::default();
        let url = Url::parse("https://example.com/test").unwrap();
        let response = create_test_response("https://example.com/test", "test content");
        
        // Put response in cache
        cache.put(&url, response.clone()).unwrap();
        
        // Get response from cache
        let cached = cache.get(&url).unwrap();
        assert_eq!(cached.body_text().unwrap(), "test content");
    }
    
    #[test]
    fn test_cache_expiration() {
        let mut config = CacheConfig::default();
        config.default_ttl = Duration::from_millis(10); // Very short TTL
        
        let cache = ResourceCache::new(config);
        let url = Url::parse("https://example.com/test").unwrap();
        let response = create_test_response("https://example.com/test", "test content");
        
        // Put response in cache
        cache.put(&url, response).unwrap();
        
        // Should be available immediately
        assert!(cache.get(&url).is_some());
        
        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));
        
        // Should be expired now
        assert!(cache.get(&url).is_none());
    }
    
    #[test]
    fn test_cache_size_limit() {
        let mut config = CacheConfig::default();
        config.max_size_bytes = 100; // Very small cache
        
        let cache = ResourceCache::new(config);
        
        // Add a large response that exceeds cache size
        let url = Url::parse("https://example.com/large").unwrap();
        let large_content = "x".repeat(200); // 200 bytes
        let response = create_test_response("https://example.com/large", &large_content);
        
        // Should fail to cache due to size
        let result = cache.put(&url, response);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_lru_eviction() {
        let mut config = CacheConfig::default();
        config.max_entries = 2; // Only allow 2 entries
        
        let cache = ResourceCache::new(config);
        
        // Add first entry
        let url1 = Url::parse("https://example.com/1").unwrap();
        let response1 = create_test_response("https://example.com/1", "content1");
        cache.put(&url1, response1).unwrap();
        
        // Add second entry
        let url2 = Url::parse("https://example.com/2").unwrap();
        let response2 = create_test_response("https://example.com/2", "content2");
        cache.put(&url2, response2).unwrap();
        
        // Access first entry to make it more recently used
        cache.get(&url1);
        
        // Add third entry (should evict second entry as it's LRU)
        let url3 = Url::parse("https://example.com/3").unwrap();
        let response3 = create_test_response("https://example.com/3", "content3");
        cache.put(&url3, response3).unwrap();
        
        // First and third should be present, second should be evicted
        assert!(cache.get(&url1).is_some());
        assert!(cache.get(&url2).is_none());
        assert!(cache.get(&url3).is_some());
    }
    
    #[test]
    fn test_cache_stats() {
        let cache = ResourceCache::default();
        let stats = cache.stats();
        
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.total_size_bytes, 0);
        
        // Add an entry
        let url = Url::parse("https://example.com/test").unwrap();
        let response = create_test_response("https://example.com/test", "test");
        cache.put(&url, response).unwrap();
        
        let stats = cache.stats();
        assert_eq!(stats.entry_count, 1);
        assert!(stats.total_size_bytes > 0);
    }
    
    #[test]
    fn test_cache_clear() {
        let cache = ResourceCache::default();
        
        // Add some entries
        for i in 0..5 {
            let url = Url::parse(&format!("https://example.com/{}", i)).unwrap();
            let response = create_test_response(&format!("https://example.com/{}", i), "test");
            cache.put(&url, response).unwrap();
        }
        
        assert_eq!(cache.stats().entry_count, 5);
        
        // Clear cache
        cache.clear();
        
        let stats = cache.stats();
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.total_size_bytes, 0);
    }
}