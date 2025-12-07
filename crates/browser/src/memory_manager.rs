//! Advanced memory management for Citadel Browser
//!
//! This module provides sophisticated memory management including tab isolation,
//! cache optimization, memory leak prevention, and resource pooling.

use std::sync::{Arc, Mutex, RwLock};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use std::thread;
use tokio::sync::Semaphore;
use serde::{Serialize, Deserialize};
use log::{debug, info, warn, error};

/// Memory pool for reusing allocations
pub struct MemoryPool<T> {
    pool: VecDeque<T>,
    max_size: usize,
    factory: fn() -> T,
    reset_fn: fn(&mut T),
}

impl<T> MemoryPool<T> {
    pub fn new(max_size: usize, factory: fn() -> T, reset_fn: fn(&mut T)) -> Self {
        Self {
            pool: VecDeque::with_capacity(max_size),
            max_size,
            factory,
            reset_fn,
        }
    }

    pub fn acquire(&mut self) -> T {
        if let Some(item) = self.pool.pop_front() {
            debug!("Reusing item from memory pool");
            item
        } else {
            debug!("Creating new item for memory pool");
            (self.factory)()
        }
    }

    pub fn release(&mut self, mut item: T) {
        if self.pool.len() < self.max_size {
            (self.reset_fn)(&mut item);
            self.pool.push_back(item);
        }
    }

    pub fn clear(&mut self) {
        self.pool.clear();
    }

    pub fn size(&self) -> usize {
        self.pool.len()
    }
}

/// Tab memory tracker for isolation and cleanup
#[derive(Debug, Clone)]
pub struct TabMemoryTracker {
    pub tab_id: uuid::Uuid,
    pub dom_memory: usize,
    pub layout_memory: usize,
    pub render_cache: usize,
    pub image_cache: usize,
    pub js_heap: usize,
    pub last_activity: Instant,
    pub is_background: bool,
}

impl TabMemoryTracker {
    pub fn new(tab_id: uuid::Uuid) -> Self {
        Self {
            tab_id,
            dom_memory: 0,
            layout_memory: 0,
            render_cache: 0,
            image_cache: 0,
            js_heap: 0,
            last_activity: Instant::now(),
            is_background: false,
        }
    }

    pub fn total_memory(&self) -> usize {
        self.dom_memory + self.layout_memory + self.render_cache +
        self.image_cache + self.js_heap
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn set_background(&mut self, background: bool) {
        self.is_background = background;
    }
}

/// Advanced memory manager for Citadel Browser
pub struct MemoryManager {
    /// Track memory usage per tab
    tab_memory: Arc<RwLock<HashMap<uuid::Uuid, TabMemoryTracker>>>,

    /// Memory pools for different object types
    layout_pool: Arc<Mutex<MemoryPool<Vec<taffy::style::Style>>>>,

    /// Cache management
    image_cache: Arc<RwLock<HashMap<String, CachedImage>>>,
    font_cache: Arc<RwLock<HashMap<String, CachedFont>>>,

    /// Memory limits and thresholds
    config: MemoryConfig,

    /// Cleanup scheduler
    cleanup_semaphore: Arc<Semaphore>,

    /// Statistics
    stats: Arc<Mutex<MemoryStats>>,

    /// Last cleanup time
    last_cleanup: Arc<Mutex<Instant>>,
}

/// Configuration for memory management
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    /// Maximum memory per tab in bytes
    pub max_tab_memory: usize,
    /// Maximum total browser memory in bytes
    pub max_total_memory: usize,
    /// Background tab memory limit
    pub background_tab_limit: usize,
    /// Cache size limits
    pub image_cache_limit: usize,
    pub font_cache_limit: usize,
    /// Cleanup intervals
    pub gentle_cleanup_interval: Duration,
    pub moderate_cleanup_interval: Duration,
    /// Memory pressure thresholds
    pub pressure_threshold_low: f64,  // 70% of max
    pub pressure_threshold_high: f64, // 85% of max
    pub pressure_threshold_critical: f64, // 95% of max
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            max_tab_memory: 256 * 1024 * 1024,  // 256MB per tab
            max_total_memory: 1024 * 1024 * 1024, // 1GB total
            background_tab_limit: 64 * 1024 * 1024, // 64MB for background tabs
            image_cache_limit: 100 * 1024 * 1024, // 100MB
            font_cache_limit: 20 * 1024 * 1024,   // 20MB
            gentle_cleanup_interval: Duration::from_secs(60),
            moderate_cleanup_interval: Duration::from_secs(30),
            pressure_threshold_low: 0.7,
            pressure_threshold_high: 0.85,
            pressure_threshold_critical: 0.95,
        }
    }
}

/// Cached image with metadata
#[derive(Debug, Clone)]
struct CachedImage {
    data: Vec<u8>,
    width: u32,
    height: u32,
    size_bytes: usize,
    last_accessed: Instant,
    access_count: u64,
}

/// Cached font with metadata
#[derive(Debug, Clone)]
struct CachedFont {
    data: Vec<u8>,
    size_bytes: usize,
    last_accessed: Instant,
    access_count: u64,
}

/// Memory usage statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    pub total_allocated: usize,
    pub total_freed: usize,
    pub peak_usage: usize,
    pub cleanup_count: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub tab_count: usize,
    pub background_tabs: usize,
}

/// Memory cleanup strategies
#[derive(Debug, Clone, PartialEq)]
pub enum CleanupStrategy {
    /// Gentle cleanup - only expired entries
    Gentle,
    /// Moderate cleanup - LRU eviction of 25%
    Moderate,
    /// Aggressive cleanup - LRU eviction of 50%
    Aggressive,
    /// Emergency cleanup - clear all non-essential caches
    Emergency,
}

impl MemoryManager {
    /// Create a new memory manager with default configuration
    pub fn new() -> Self {
        Self::with_config(MemoryConfig::default())
    }

    /// Create a new memory manager with custom configuration
    pub fn with_config(config: MemoryConfig) -> Self {
        let layout_pool = Arc::new(Mutex::new(MemoryPool::new(
            1000,
            || Vec::new(),
            |vec| vec.clear()
        )));

        Self {
            tab_memory: Arc::new(RwLock::new(HashMap::new())),
            layout_pool,
            image_cache: Arc::new(RwLock::new(HashMap::new())),
            font_cache: Arc::new(RwLock::new(HashMap::new())),
            config,
            cleanup_semaphore: Arc::new(Semaphore::new(1)), // Only one cleanup at a time
            stats: Arc::new(Mutex::new(MemoryStats::default())),
            last_cleanup: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Register a new tab for memory tracking
    pub fn register_tab(&self, tab_id: uuid::Uuid) {
        let mut tab_memory = self.tab_memory.write().unwrap();
        let tracker = TabMemoryTracker::new(tab_id);
        tab_memory.insert(tab_id, tracker);

        if let Ok(mut stats) = self.stats.lock() {
            stats.tab_count = tab_memory.len();
        }

        debug!("Registered tab {} for memory tracking", tab_id);
    }

    /// Unregister a tab and clean up its memory
    pub fn unregister_tab(&self, tab_id: uuid::Uuid) {
        let mut tab_memory = self.tab_memory.write().unwrap();
        if let Some(tracker) = tab_memory.remove(&tab_id) {
            info!("Cleaning up tab {} - used {}MB",
                  tab_id, tracker.total_memory() / 1024 / 1024);

            if let Ok(mut stats) = self.stats.lock() {
                stats.total_freed += tracker.total_memory();
                stats.tab_count = tab_memory.len();
                if tracker.is_background {
                    stats.background_tabs = stats.background_tabs.saturating_sub(1);
                }
            }
        }
    }

    /// Update memory usage for a specific component of a tab
    pub fn update_tab_memory(&self, tab_id: uuid::Uuid, component: &str, size: usize) {
        if let Ok(mut tab_memory) = self.tab_memory.write() {
            if let Some(tracker) = tab_memory.get_mut(&tab_id) {
                match component {
                    "dom" => tracker.dom_memory = size,
                    "layout" => tracker.layout_memory = size,
                    "render_cache" => tracker.render_cache = size,
                    "image_cache" => tracker.image_cache = size,
                    "js_heap" => tracker.js_heap = size,
                    _ => warn!("Unknown memory component: {}", component),
                }
                tracker.update_activity();

                // Check if tab exceeds limits
                let total = tracker.total_memory();
                if total > self.config.max_tab_memory {
                    warn!("Tab {} exceeded memory limit: {}MB",
                          tab_id, total / 1024 / 1024);
                    self.handle_tab_memory_pressure(tab_id, tracker);
                }
            }
        }
    }

    /// Set tab as background/foreground
    pub fn set_tab_background(&self, tab_id: uuid::Uuid, background: bool) {
        if let Ok(mut tab_memory) = self.tab_memory.write() {
            if let Some(tracker) = tab_memory.get_mut(&tab_id) {
                tracker.set_background(background);

                if let Ok(mut stats) = self.stats.lock() {
                    if background {
                        stats.background_tabs += 1;
                        // Reduce memory usage for background tabs
                        self.reduce_background_tab_memory(tracker);
                    } else {
                        stats.background_tabs = stats.background_tabs.saturating_sub(1);
                    }
                }
            }
        }
    }

    /// Acquire a layout vector from the pool
    pub fn acquire_layout_vector(&self) -> Vec<taffy::style::Style> {
        if let Ok(mut pool) = self.layout_pool.lock() {
            pool.acquire()
        } else {
            Vec::new()
        }
    }

    /// Release a layout vector back to the pool
    pub fn release_layout_vector(&self, mut vec: Vec<taffy::style::Style>) {
        if let Ok(mut pool) = self.layout_pool.lock() {
            pool.release(vec);
        }
    }

    /// Cache an image with LRU eviction
    pub fn cache_image(&self, key: String, data: Vec<u8>, width: u32, height: u32) {
        let size = data.len();

        // Check if image is too large to cache
        if size > 10 * 1024 * 1024 { // 10MB limit per image
            debug!("Image too large to cache: {}MB", size / 1024 / 1024);
            return;
        }

        let cached_image = CachedImage {
            data,
            width,
            height,
            size_bytes: size,
            last_accessed: Instant::now(),
            access_count: 1,
        };

        if let Ok(mut cache) = self.image_cache.write() {
            // Ensure cache size limit
            while cache.len() > 1000 ||
                  cache.values().map(|img| img.size_bytes).sum::<usize>() > self.config.image_cache_limit {
                if let Some(lru_key) = cache.iter()
                    .min_by_key(|(_, img)| (img.last_accessed, img.access_count))
                    .map(|(k, _)| k.clone()) {
                    cache.remove(&lru_key);
                    debug!("Evicted image from cache: {}", lru_key);
                } else {
                    break;
                }
            }

            cache.insert(key, cached_image);

            if let Ok(mut stats) = self.stats.lock() {
                stats.total_allocated += size;
            }
        }
    }

    /// Get a cached image
    pub fn get_cached_image(&self, key: &str) -> Option<Vec<u8>> {
        if let Ok(mut cache) = self.image_cache.write() {
            if let Some(image) = cache.get_mut(key) {
                image.last_accessed = Instant::now();
                image.access_count += 1;

                if let Ok(mut stats) = self.stats.lock() {
                    stats.cache_hits += 1;
                }

                return Some(image.data.clone());
            }
        }

        if let Ok(mut stats) = self.stats.lock() {
            stats.cache_misses += 1;
        }

        None
    }

    /// Trigger memory cleanup based on current usage
    pub async fn trigger_cleanup(&self, strategy: CleanupStrategy) {
        // Use semaphore to prevent concurrent cleanups
        let _permit = self.cleanup_semaphore.acquire().await;

        let start_time = Instant::now();
        info!("Starting memory cleanup with strategy: {:?}", strategy);

        match strategy {
            CleanupStrategy::Gentle => self.gentle_cleanup().await,
            CleanupStrategy::Moderate => self.moderate_cleanup().await,
            CleanupStrategy::Aggressive => self.aggressive_cleanup().await,
            CleanupStrategy::Emergency => self.emergency_cleanup().await,
        }

        let duration = start_time.elapsed();
        info!("Memory cleanup completed in {:?}", duration);

        if let Ok(mut stats) = self.stats.lock() {
            stats.cleanup_count += 1;
        }

        if let Ok(mut last_cleanup) = self.last_cleanup.lock() {
            *last_cleanup = Instant::now();
        }
    }

    /// Check memory pressure and trigger appropriate cleanup
    pub async fn check_memory_pressure(&self) {
        let current_usage = self.get_total_memory_usage();
        let usage_ratio = current_usage as f64 / self.config.max_total_memory as f64;

        if let Ok(last_cleanup) = self.last_cleanup.lock() {
            let time_since_cleanup = last_cleanup.elapsed();

            let strategy = if usage_ratio > self.config.pressure_threshold_critical {
                CleanupStrategy::Emergency
            } else if usage_ratio > self.config.pressure_threshold_high {
                CleanupStrategy::Aggressive
            } else if usage_ratio > self.config.pressure_threshold_low &&
                      time_since_cleanup > self.config.moderate_cleanup_interval {
                CleanupStrategy::Moderate
            } else if time_since_cleanup > self.config.gentle_cleanup_interval {
                CleanupStrategy::Gentle
            } else {
                return; // No cleanup needed
            };

            self.trigger_cleanup(strategy).await;
        }
    }

    /// Get current memory usage statistics
    pub fn get_memory_stats(&self) -> MemoryStats {
        self.stats.lock().unwrap().clone()
    }

    /// Get total memory usage across all tabs
    pub fn get_total_memory_usage(&self) -> usize {
        let tab_memory = self.tab_memory.read().unwrap();
        tab_memory.values().map(|tracker| tracker.total_memory()).sum()
    }

    /// Gentle cleanup - remove expired entries only
    async fn gentle_cleanup(&self) {
        // Clean up expired cache entries
        self.cleanup_expired_cache_entries().await;
    }

    /// Moderate cleanup - LRU eviction of 25%
    async fn moderate_cleanup(&self) {
        self.gentle_cleanup().await;
        self.evict_cache_entries(0.25).await;
        self.compress_background_tabs().await;
    }

    /// Aggressive cleanup - LRU eviction of 50%
    async fn aggressive_cleanup(&self) {
        self.gentle_cleanup().await;
        self.evict_cache_entries(0.5).await;
        self.compress_background_tabs().await;
        self.clear_memory_pools();
    }

    /// Emergency cleanup - clear all non-essential caches
    async fn emergency_cleanup(&self) {
        self.clear_all_caches().await;
        self.compress_background_tabs().await;
        self.clear_memory_pools();
        self.unregister_inactive_tabs().await;
    }

    /// Clean up expired cache entries
    async fn cleanup_expired_cache_entries(&self) {
        let now = Instant::now();

        // Clean image cache
        if let Ok(mut cache) = self.image_cache.write() {
            cache.retain(|_, img| now.duration_since(img.last_accessed) < Duration::from_secs(3600));
        }

        // Clean font cache
        if let Ok(mut cache) = self.font_cache.write() {
            cache.retain(|_, font| now.duration_since(font.last_accessed) < Duration::from_secs(7200));
        }
    }

    /// Evict a percentage of cache entries based on LRU
    async fn evict_cache_entries(&self, percentage: f64) {
        // Evict from image cache
        if let Ok(mut cache) = self.image_cache.write() {
            let entries_to_remove = (cache.len() as f64 * percentage).ceil() as usize;
            let mut entries: Vec<_> = cache.iter().collect();
            entries.sort_by_key(|(_, img)| (img.last_accessed, img.access_count));

            let keys_to_remove: Vec<String> = entries.iter().take(entries_to_remove).map(|(k, _)| (*k).clone()).collect();
            for key in keys_to_remove {
                cache.remove(&key);
            }
        }

        // Similar for font cache
        if let Ok(mut cache) = self.font_cache.write() {
            let entries_to_remove = (cache.len() as f64 * percentage).ceil() as usize;
            let mut entries: Vec<_> = cache.iter().collect();
            entries.sort_by_key(|(_, font)| (font.last_accessed, font.access_count));

            let keys_to_remove: Vec<String> = entries.iter().take(entries_to_remove).map(|(k, _)| (*k).clone()).collect();
            for key in keys_to_remove {
                cache.remove(&key);
            }
        }
    }

    /// Compress memory usage for background tabs
    async fn compress_background_tabs(&self) {
        if let Ok(mut tab_memory) = self.tab_memory.write() {
            for tracker in tab_memory.values_mut() {
                if tracker.is_background && tracker.total_memory() > self.config.background_tab_limit {
                    // Reduce cached content for background tabs
                    tracker.image_cache = tracker.image_cache / 2;
                    tracker.render_cache = tracker.render_cache / 2;

                    info!("Compressed background tab {} to {}MB",
                          tracker.tab_id, tracker.total_memory() / 1024 / 1024);
                }
            }
        }
    }

    /// Clear all memory pools
    fn clear_memory_pools(&self) {
        if let Ok(mut pool) = self.layout_pool.lock() {
            pool.clear();
        }
    }

    /// Clear all caches
    async fn clear_all_caches(&self) {
        if let Ok(mut cache) = self.image_cache.write() {
            let size = cache.len();
            cache.clear();
            info!("Cleared image cache: {} entries", size);
        }

        if let Ok(mut cache) = self.font_cache.write() {
            let size = cache.len();
            cache.clear();
            info!("Cleared font cache: {} entries", size);
        }
    }

    /// Unregister tabs that have been inactive too long
    async fn unregister_inactive_tabs(&self) {
        let now = Instant::now();
        let mut tabs_to_remove = Vec::new();

        if let Ok(tab_memory) = self.tab_memory.read() {
            for (tab_id, tracker) in tab_memory.iter() {
                if now.duration_since(tracker.last_activity) > Duration::from_secs(3600) {
                    tabs_to_remove.push(*tab_id);
                }
            }
        }

        for tab_id in tabs_to_remove {
            self.unregister_tab(tab_id);
        }
    }

    /// Handle memory pressure for a specific tab
    fn handle_tab_memory_pressure(&self, tab_id: uuid::Uuid, tracker: &mut TabMemoryTracker) {
        // Start by clearing caches
        tracker.image_cache = 0;
        tracker.render_cache = 0;

        // If still over limit, force garbage collection
        if tracker.total_memory() > self.config.max_tab_memory {
            warn!("Forcing cleanup for tab {} due to memory pressure", tab_id);
            // In a real implementation, this would trigger JS GC and DOM cleanup
        }
    }

    /// Reduce memory usage for background tabs
    fn reduce_background_tab_memory(&self, tracker: &mut TabMemoryTracker) {
        if tracker.total_memory() > self.config.background_tab_limit {
            let reduction_factor = self.config.background_tab_limit as f64 / tracker.total_memory() as f64;

            tracker.image_cache = (tracker.image_cache as f64 * reduction_factor) as usize;
            tracker.render_cache = (tracker.render_cache as f64 * reduction_factor) as usize;
            tracker.layout_memory = (tracker.layout_memory as f64 * reduction_factor * 0.8) as usize;

            info!("Reduced background tab memory to {}MB",
                  tracker.total_memory() / 1024 / 1024);
        }
    }

    /// Start the background memory management task
    pub fn start_background_task(&self) {
        let manager = self.clone();
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30));

                loop {
                    interval.tick().await;
                    manager.check_memory_pressure().await;
                }
            });
        });
    }
}

impl Clone for MemoryManager {
    fn clone(&self) -> Self {
        Self {
            tab_memory: Arc::clone(&self.tab_memory),
            layout_pool: Arc::clone(&self.layout_pool),
            image_cache: Arc::clone(&self.image_cache),
            font_cache: Arc::clone(&self.font_cache),
            config: self.config.clone(),
            cleanup_semaphore: Arc::clone(&self.cleanup_semaphore),
            stats: Arc::clone(&self.stats),
            last_cleanup: Arc::clone(&self.last_cleanup),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_pool() {
        let mut pool = MemoryPool::new(
            5,
            || Vec::new(),
            |vec| vec.clear()
        );

        // Acquire and release items
        let mut vec1 = pool.acquire();
        vec1.push(1);
        vec1.push(2);

        pool.release(vec1);

        // Next acquire should reuse the item
        let vec2 = pool.acquire();
        assert!(vec2.is_empty()); // Should be reset
    }

    #[test]
    fn test_tab_memory_tracker() {
        let mut tracker = TabMemoryTracker::new(uuid::Uuid::new_v4());

        tracker.dom_memory = 1024;
        tracker.layout_memory = 2048;

        assert_eq!(tracker.total_memory(), 3072);
        assert!(!tracker.is_background);

        tracker.set_background(true);
        assert!(tracker.is_background);
    }

    #[test]
    fn test_memory_config_defaults() {
        let config = MemoryConfig::default();

        assert_eq!(config.max_tab_memory, 256 * 1024 * 1024);
        assert_eq!(config.max_total_memory, 1024 * 1024 * 1024);
        assert_eq!(config.background_tab_limit, 64 * 1024 * 1024);
    }

    #[tokio::test]
    async fn test_memory_manager_basic() {
        let manager = MemoryManager::new();
        let tab_id = uuid::Uuid::new_v4();

        // Register a tab
        manager.register_tab(tab_id);

        // Update memory usage
        manager.update_tab_memory(tab_id, "dom", 1024);
        manager.update_tab_memory(tab_id, "layout", 2048);

        // Check total usage
        let total = manager.get_total_memory_usage();
        assert_eq!(total, 3072);

        // Unregister tab
        manager.unregister_tab(tab_id);

        // Usage should be 0 now
        let total = manager.get_total_memory_usage();
        assert_eq!(total, 0);
    }

    #[tokio::test]
    async fn test_image_caching() {
        let manager = MemoryManager::new();
        let key = "test_image".to_string();
        let data = vec![1, 2, 3, 4, 5];

        // Cache image
        manager.cache_image(key.clone(), data.clone(), 100, 100);

        // Retrieve image
        let cached_data = manager.get_cached_image(&key);
        assert_eq!(cached_data, Some(data));

        // Non-existent key should return None
        let none_data = manager.get_cached_image("non_existent");
        assert_eq!(none_data, None);
    }

    #[tokio::test]
    async fn test_cleanup_strategies() {
        let manager = MemoryManager::new();

        // Test different cleanup strategies
        manager.trigger_cleanup(CleanupStrategy::Gentle).await;
        manager.trigger_cleanup(CleanupStrategy::Moderate).await;
        manager.trigger_cleanup(CleanupStrategy::Aggressive).await;
        manager.trigger_cleanup(CleanupStrategy::Emergency).await;

        // Check stats
        let stats = manager.get_memory_stats();
        assert_eq!(stats.cleanup_count, 4);
    }
}