//! Memory Protection and Resource Management for Citadel Browser
//!
//! This module implements comprehensive memory exhaustion protection, resource limits,
//! and attack prevention mechanisms to ensure system stability and security.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use std::fmt;
use thiserror::Error;
use log::{info, warn, error, debug};

use crate::context::SecurityViolation;

/// Memory protection error types
#[derive(Debug, Error)]
pub enum MemoryProtectionError {
    #[error("Memory limit exceeded: {limit} bytes, attempted: {attempted} bytes")]
    MemoryLimitExceeded { limit: usize, attempted: usize },
    
    #[error("Resource pool exhausted: {resource_type}, limit: {limit}")]
    ResourcePoolExhausted { resource_type: String, limit: usize },
    
    #[error("Emergency cleanup failed: {reason}")]
    EmergencyCleanupFailed { reason: String },
    
    #[error("Memory allocation failed: {size} bytes")]
    AllocationFailed { size: usize },
    
    #[error("Resource tracking error: {error}")]
    ResourceTrackingError { error: String },
    
    #[error("Configuration error: {error}")]
    ConfigurationError { error: String },
}

/// Memory protection result type
pub type MemoryProtectionResult<T> = Result<T, MemoryProtectionError>;

/// Resource type identifiers for tracking and limiting
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResourceType {
    /// DOM nodes and elements
    DomNodes,
    /// CSS rules and selectors
    CssRules,
    /// JavaScript objects and contexts
    JsObjects,
    /// Network connections and requests
    NetworkConnections,
    /// Image data and caches
    ImageData,
    /// Font data and caches
    FontData,
    /// Audio/video media
    MediaData,
    /// WebGL contexts and buffers
    WebGlContexts,
    /// Canvas contexts and buffers
    CanvasData,
    /// Generic memory allocations
    GenericMemory,
    /// Tab-specific memory
    TabMemory,
    /// Parser memory (temporary allocations)
    ParserMemory,
}

impl fmt::Display for ResourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceType::DomNodes => write!(f, "DOM Nodes"),
            ResourceType::CssRules => write!(f, "CSS Rules"),
            ResourceType::JsObjects => write!(f, "JavaScript Objects"),
            ResourceType::NetworkConnections => write!(f, "Network Connections"),
            ResourceType::ImageData => write!(f, "Image Data"),
            ResourceType::FontData => write!(f, "Font Data"),
            ResourceType::MediaData => write!(f, "Media Data"),
            ResourceType::WebGlContexts => write!(f, "WebGL Contexts"),
            ResourceType::CanvasData => write!(f, "Canvas Data"),
            ResourceType::GenericMemory => write!(f, "Generic Memory"),
            ResourceType::TabMemory => write!(f, "Tab Memory"),
            ResourceType::ParserMemory => write!(f, "Parser Memory"),
        }
    }
}

/// Memory allocation tracking information
#[derive(Debug, Clone)]
pub struct AllocationInfo {
    /// Size of the allocation in bytes
    pub size: usize,
    /// When the allocation was made
    pub timestamp: Instant,
    /// Source location (if available)
    pub source: Option<String>,
    /// Whether this is a critical allocation
    pub critical: bool,
    /// Priority for cleanup (lower = higher priority to keep)
    pub priority: u8,
}

/// Resource pool configuration and limits
#[derive(Debug, Clone)]
pub struct ResourcePoolConfig {
    /// Maximum number of items in this pool
    pub max_count: usize,
    /// Maximum total memory for this resource type (bytes)
    pub max_memory: usize,
    /// Soft limit for triggering early cleanup (bytes)
    pub soft_limit: usize,
    /// Whether this resource type supports emergency cleanup
    pub emergency_cleanup_enabled: bool,
    /// Timeout for individual resource operations
    pub operation_timeout: Duration,
}

impl Default for ResourcePoolConfig {
    fn default() -> Self {
        Self {
            max_count: 10000,
            max_memory: 64 * 1024 * 1024, // 64MB
            soft_limit: 48 * 1024 * 1024, // 48MB
            emergency_cleanup_enabled: true,
            operation_timeout: Duration::from_secs(30),
        }
    }
}

/// Memory protection configuration
#[derive(Debug, Clone)]
pub struct MemoryProtectionConfig {
    /// Total memory limit for the browser instance (bytes)
    pub total_memory_limit: usize,
    /// Per-tab memory limit (bytes)
    pub per_tab_memory_limit: usize,
    /// Emergency cleanup threshold (percentage of total limit)
    pub emergency_threshold: f32,
    /// Aggressive cleanup threshold (percentage of total limit)
    pub aggressive_threshold: f32,
    /// Resource pool configurations
    pub resource_pools: HashMap<ResourceType, ResourcePoolConfig>,
    /// Enable detailed memory tracking
    pub detailed_tracking: bool,
    /// Memory check interval
    pub check_interval: Duration,
    /// Maximum allocation size for single request
    pub max_single_allocation: usize,
    /// Enable protection against memory exhaustion attacks
    pub attack_protection: bool,
}

impl Default for MemoryProtectionConfig {
    fn default() -> Self {
        let mut resource_pools = HashMap::new();
        
        // DOM nodes - critical for page structure
        resource_pools.insert(ResourceType::DomNodes, ResourcePoolConfig {
            max_count: 50000,
            max_memory: 100 * 1024 * 1024, // 100MB
            soft_limit: 80 * 1024 * 1024,  // 80MB
            emergency_cleanup_enabled: false, // Don't cleanup DOM nodes in emergency
            operation_timeout: Duration::from_secs(5),
        });
        
        // CSS rules - moderate priority
        resource_pools.insert(ResourceType::CssRules, ResourcePoolConfig {
            max_count: 100000,
            max_memory: 50 * 1024 * 1024, // 50MB
            soft_limit: 40 * 1024 * 1024, // 40MB
            emergency_cleanup_enabled: true,
            operation_timeout: Duration::from_secs(10),
        });
        
        // JavaScript objects - high cleanup priority
        resource_pools.insert(ResourceType::JsObjects, ResourcePoolConfig {
            max_count: 1000000,
            max_memory: 200 * 1024 * 1024, // 200MB
            soft_limit: 150 * 1024 * 1024, // 150MB
            emergency_cleanup_enabled: true,
            operation_timeout: Duration::from_secs(15),
        });
        
        // Network connections - strict limits
        resource_pools.insert(ResourceType::NetworkConnections, ResourcePoolConfig {
            max_count: 100, // HTTP/2 multiplexing reduces need for many connections
            max_memory: 10 * 1024 * 1024, // 10MB
            soft_limit: 8 * 1024 * 1024,  // 8MB
            emergency_cleanup_enabled: true,
            operation_timeout: Duration::from_secs(30),
        });
        
        // Image data - large but cleanable
        resource_pools.insert(ResourceType::ImageData, ResourcePoolConfig {
            max_count: 1000,
            max_memory: 500 * 1024 * 1024, // 500MB
            soft_limit: 400 * 1024 * 1024, // 400MB
            emergency_cleanup_enabled: true,
            operation_timeout: Duration::from_secs(20),
        });
        
        // Font data - moderate size, cache-friendly
        resource_pools.insert(ResourceType::FontData, ResourcePoolConfig {
            max_count: 200,
            max_memory: 50 * 1024 * 1024, // 50MB
            soft_limit: 40 * 1024 * 1024, // 40MB
            emergency_cleanup_enabled: true,
            operation_timeout: Duration::from_secs(10),
        });
        
        // Media data - very large, aggressive cleanup
        resource_pools.insert(ResourceType::MediaData, ResourcePoolConfig {
            max_count: 50,
            max_memory: 1024 * 1024 * 1024, // 1GB
            soft_limit: 800 * 1024 * 1024,  // 800MB
            emergency_cleanup_enabled: true,
            operation_timeout: Duration::from_secs(60),
        });
        
        // WebGL contexts - limited by GPU memory
        resource_pools.insert(ResourceType::WebGlContexts, ResourcePoolConfig {
            max_count: 20,
            max_memory: 200 * 1024 * 1024, // 200MB
            soft_limit: 150 * 1024 * 1024, // 150MB
            emergency_cleanup_enabled: true,
            operation_timeout: Duration::from_secs(5),
        });
        
        // Canvas data - moderate size
        resource_pools.insert(ResourceType::CanvasData, ResourcePoolConfig {
            max_count: 100,
            max_memory: 100 * 1024 * 1024, // 100MB
            soft_limit: 80 * 1024 * 1024,  // 80MB
            emergency_cleanup_enabled: true,
            operation_timeout: Duration::from_secs(10),
        });
        
        // Generic memory - fallback category
        resource_pools.insert(ResourceType::GenericMemory, ResourcePoolConfig {
            max_count: usize::MAX,
            max_memory: 100 * 1024 * 1024, // 100MB
            soft_limit: 80 * 1024 * 1024,  // 80MB
            emergency_cleanup_enabled: true,
            operation_timeout: Duration::from_secs(5),
        });
        
        // Tab memory - per-tab tracking
        resource_pools.insert(ResourceType::TabMemory, ResourcePoolConfig {
            max_count: 1,
            max_memory: 512 * 1024 * 1024, // 512MB per tab
            soft_limit: 400 * 1024 * 1024, // 400MB per tab
            emergency_cleanup_enabled: true,
            operation_timeout: Duration::from_secs(30),
        });
        
        // Parser memory - temporary allocations
        resource_pools.insert(ResourceType::ParserMemory, ResourcePoolConfig {
            max_count: 10000,
            max_memory: 64 * 1024 * 1024, // 64MB
            soft_limit: 48 * 1024 * 1024, // 48MB
            emergency_cleanup_enabled: true,
            operation_timeout: Duration::from_secs(10),
        });
        
        Self {
            total_memory_limit: 2 * 1024 * 1024 * 1024, // 2GB total
            per_tab_memory_limit: 512 * 1024 * 1024,    // 512MB per tab
            emergency_threshold: 0.90,   // 90% for emergency cleanup
            aggressive_threshold: 0.75,  // 75% for aggressive cleanup
            resource_pools,
            detailed_tracking: true,
            check_interval: Duration::from_secs(10),
            max_single_allocation: 100 * 1024 * 1024, // 100MB max single allocation
            attack_protection: true,
        }
    }
}

/// Resource pool for tracking specific resource types
pub struct ResourcePool {
    /// Configuration for this pool
    config: ResourcePoolConfig,
    /// Current allocations
    allocations: HashMap<usize, AllocationInfo>,
    /// Current total memory usage
    current_memory: usize,
    /// Current allocation count
    current_count: usize,
    /// Next allocation ID
    next_id: usize,
    /// Cleanup callback
    cleanup_callback: Option<Box<dyn Fn(Vec<usize>) + Send + Sync>>,
    /// Last cleanup time
    last_cleanup: Instant,
}

impl std::fmt::Debug for ResourcePool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourcePool")
            .field("config", &self.config)
            .field("allocations", &self.allocations)
            .field("current_memory", &self.current_memory)
            .field("current_count", &self.current_count)
            .field("next_id", &self.next_id)
            .field("cleanup_callback", &self.cleanup_callback.is_some())
            .field("last_cleanup", &self.last_cleanup)
            .finish()
    }
}

impl ResourcePool {
    /// Create a new resource pool
    pub fn new(config: ResourcePoolConfig) -> Self {
        Self {
            config,
            allocations: HashMap::new(),
            current_memory: 0,
            current_count: 0,
            next_id: 1,
            cleanup_callback: None,
            last_cleanup: Instant::now(),
        }
    }
    
    /// Register a cleanup callback for this pool
    pub fn set_cleanup_callback<F>(&mut self, callback: F)
    where
        F: Fn(Vec<usize>) + Send + Sync + 'static,
    {
        self.cleanup_callback = Some(Box::new(callback));
    }
    
    /// Allocate resources in this pool
    pub fn allocate(&mut self, size: usize, critical: bool, source: Option<String>) -> MemoryProtectionResult<usize> {
        // Check count limit
        if self.current_count >= self.config.max_count {
            return Err(MemoryProtectionError::ResourcePoolExhausted {
                resource_type: "count".to_string(),
                limit: self.config.max_count,
            });
        }
        
        // Check memory limit
        if self.current_memory + size > self.config.max_memory {
            return Err(MemoryProtectionError::MemoryLimitExceeded {
                limit: self.config.max_memory,
                attempted: self.current_memory + size,
            });
        }
        
        let allocation_id = self.next_id;
        self.next_id += 1;
        
        let allocation = AllocationInfo {
            size,
            timestamp: Instant::now(),
            source,
            critical,
            priority: if critical { 0 } else { 5 },
        };
        
        self.allocations.insert(allocation_id, allocation);
        self.current_memory += size;
        self.current_count += 1;
        
        debug!("Allocated {} bytes (ID: {}), pool memory: {} / {}", 
               size, allocation_id, self.current_memory, self.config.max_memory);
        
        Ok(allocation_id)
    }
    
    /// Deallocate resources from this pool
    pub fn deallocate(&mut self, allocation_id: usize) -> MemoryProtectionResult<()> {
        if let Some(allocation) = self.allocations.remove(&allocation_id) {
            self.current_memory = self.current_memory.saturating_sub(allocation.size);
            self.current_count = self.current_count.saturating_sub(1);
            
            debug!("Deallocated {} bytes (ID: {}), pool memory: {} / {}", 
                   allocation.size, allocation_id, self.current_memory, self.config.max_memory);
            
            Ok(())
        } else {
            Err(MemoryProtectionError::ResourceTrackingError {
                error: format!("Allocation ID {} not found", allocation_id),
            })
        }
    }
    
    /// Check if allocation would exceed soft limit
    pub fn would_exceed_soft_limit(&self, size: usize) -> bool {
        self.current_memory + size > self.config.soft_limit
    }
    
    /// Get current memory usage
    pub fn current_memory(&self) -> usize {
        self.current_memory
    }
    
    /// Get current allocation count
    pub fn current_count(&self) -> usize {
        self.current_count
    }
    
    /// Get memory utilization ratio (0.0 to 1.0)
    pub fn memory_utilization(&self) -> f32 {
        self.current_memory as f32 / self.config.max_memory as f32
    }
    
    /// Trigger cleanup of non-critical allocations
    pub fn cleanup_non_critical(&mut self, target_reduction: usize) -> usize {
        let mut cleaned_size = 0;
        let mut to_cleanup = Vec::new();
        
        // Sort allocations by priority (higher priority = more likely to be cleaned)
        let mut sortable_allocs: Vec<_> = self.allocations.iter().collect();
        sortable_allocs.sort_by(|(_, a), (_, b)| {
            b.priority.cmp(&a.priority)
                .then(b.timestamp.cmp(&a.timestamp)) // Older allocations cleaned first
        });
        
        for (&id, allocation) in sortable_allocs {
            if !allocation.critical && cleaned_size < target_reduction {
                to_cleanup.push(id);
                cleaned_size += allocation.size;
            }
        }
        
        // Execute cleanup callback if available
        if let Some(ref callback) = self.cleanup_callback {
            if !to_cleanup.is_empty() {
                callback(to_cleanup.clone());
            }
        }
        
        // Remove cleaned allocations
        for id in &to_cleanup {
            if let Some(allocation) = self.allocations.remove(id) {
                self.current_memory = self.current_memory.saturating_sub(allocation.size);
                self.current_count = self.current_count.saturating_sub(1);
            }
        }
        
        self.last_cleanup = Instant::now();
        cleaned_size
    }
    
    /// Emergency cleanup - remove all non-critical allocations
    pub fn emergency_cleanup(&mut self) -> usize {
        if !self.config.emergency_cleanup_enabled {
            return 0;
        }
        
        let target_reduction = (self.current_memory as f32 * 0.5) as usize; // Clean 50%
        self.cleanup_non_critical(target_reduction)
    }
    
    /// Get pool statistics
    pub fn get_stats(&self) -> ResourcePoolStats {
        ResourcePoolStats {
            current_memory: self.current_memory,
            max_memory: self.config.max_memory,
            current_count: self.current_count,
            max_count: self.config.max_count,
            utilization: self.memory_utilization(),
            total_allocations: self.allocations.len(),
            critical_allocations: self.allocations.values().filter(|a| a.critical).count(),
            last_cleanup: self.last_cleanup,
        }
    }
}

/// Statistics for a resource pool
#[derive(Debug, Clone)]
pub struct ResourcePoolStats {
    pub current_memory: usize,
    pub max_memory: usize,
    pub current_count: usize,
    pub max_count: usize,
    pub utilization: f32,
    pub total_allocations: usize,
    pub critical_allocations: usize,
    pub last_cleanup: Instant,
}

/// Attack detection for memory exhaustion attempts
#[derive(Debug)]
pub struct AttackDetector {
    /// Recent allocation patterns
    recent_allocations: VecDeque<(Instant, usize)>,
    /// Suspicious pattern thresholds
    rapid_allocation_threshold: usize,
    /// Time window for pattern detection
    time_window: Duration,
    /// Large allocation threshold
    large_allocation_threshold: usize,
}

use std::collections::VecDeque;

impl AttackDetector {
    /// Create a new attack detector
    pub fn new() -> Self {
        Self {
            recent_allocations: VecDeque::new(),
            rapid_allocation_threshold: 1000, // 1000 allocations per minute
            time_window: Duration::from_secs(60),
            large_allocation_threshold: 50 * 1024 * 1024, // 50MB
        }
    }
    
    /// Record an allocation for attack detection
    pub fn record_allocation(&mut self, size: usize) -> Option<AttackPattern> {
        let now = Instant::now();
        
        // Clean old allocations outside time window
        while let Some(&(timestamp, _)) = self.recent_allocations.front() {
            if now.duration_since(timestamp) > self.time_window {
                self.recent_allocations.pop_front();
            } else {
                break;
            }
        }
        
        // Add current allocation
        self.recent_allocations.push_back((now, size));
        
        // Check for attack patterns
        self.detect_patterns(size)
    }
    
    /// Detect suspicious allocation patterns
    fn detect_patterns(&self, current_size: usize) -> Option<AttackPattern> {
        // Check for rapid allocation pattern
        if self.recent_allocations.len() > self.rapid_allocation_threshold {
            return Some(AttackPattern::RapidAllocation {
                rate: self.recent_allocations.len(),
                time_window: self.time_window,
            });
        }
        
        // Check for large allocation
        if current_size > self.large_allocation_threshold {
            return Some(AttackPattern::LargeAllocation {
                size: current_size,
                threshold: self.large_allocation_threshold,
            });
        }
        
        // Check for memory bomb pattern (many medium allocations)
        let total_in_window: usize = self.recent_allocations.iter().map(|(_, size)| size).sum();
        if total_in_window > 200 * 1024 * 1024 { // 200MB in time window
            return Some(AttackPattern::MemoryBomb {
                total_size: total_in_window,
                allocation_count: self.recent_allocations.len(),
            });
        }
        
        None
    }
}

/// Detected attack patterns
#[derive(Debug, Clone)]
pub enum AttackPattern {
    RapidAllocation { rate: usize, time_window: Duration },
    LargeAllocation { size: usize, threshold: usize },
    MemoryBomb { total_size: usize, allocation_count: usize },
}

/// Main memory protection system
pub struct MemoryProtectionSystem {
    /// Configuration
    config: MemoryProtectionConfig,
    /// Resource pools by type
    pools: RwLock<HashMap<ResourceType, Mutex<ResourcePool>>>,
    /// Total memory tracking
    total_memory: Arc<Mutex<usize>>,
    /// Attack detector
    attack_detector: Mutex<AttackDetector>,
    /// Last system check
    last_check: Mutex<Instant>,
    /// Emergency mode flag
    emergency_mode: Arc<Mutex<bool>>,
    /// Violation callback
    violation_callback: Option<Box<dyn Fn(SecurityViolation) + Send + Sync>>,
}

impl MemoryProtectionSystem {
    /// Create a new memory protection system
    pub fn new(config: MemoryProtectionConfig) -> Self {
        let mut pools = HashMap::new();
        
        // Initialize resource pools
        for (resource_type, pool_config) in &config.resource_pools {
            pools.insert(
                resource_type.clone(),
                Mutex::new(ResourcePool::new(pool_config.clone()))
            );
        }
        
        Self {
            config,
            pools: RwLock::new(pools),
            total_memory: Arc::new(Mutex::new(0)),
            attack_detector: Mutex::new(AttackDetector::new()),
            last_check: Mutex::new(Instant::now()),
            emergency_mode: Arc::new(Mutex::new(false)),
            violation_callback: None,
        }
    }
    
    /// Set violation callback for security reporting
    pub fn set_violation_callback<F>(&mut self, callback: F)
    where
        F: Fn(SecurityViolation) + Send + Sync + 'static,
    {
        self.violation_callback = Some(Box::new(callback));
    }
    
    /// Allocate memory for a specific resource type
    pub fn allocate(
        &self, 
        resource_type: ResourceType, 
        size: usize, 
        critical: bool,
        source: Option<String>
    ) -> MemoryProtectionResult<usize> {
        // Check for single allocation size limit
        if size > self.config.max_single_allocation {
            self.record_violation(SecurityViolation::MemoryExhaustion {
                resource_type: resource_type.to_string(),
                limit_exceeded: self.config.max_single_allocation,
                attempted_size: size,
            });
            
            return Err(MemoryProtectionError::MemoryLimitExceeded {
                limit: self.config.max_single_allocation,
                attempted: size,
            });
        }
        
        // Check total memory limit
        {
            let total_memory = self.total_memory.lock().unwrap();
            if *total_memory + size > self.config.total_memory_limit {
                self.record_violation(SecurityViolation::MemoryExhaustion {
                    resource_type: "total".to_string(),
                    limit_exceeded: self.config.total_memory_limit,
                    attempted_size: *total_memory + size,
                });
                
                return Err(MemoryProtectionError::MemoryLimitExceeded {
                    limit: self.config.total_memory_limit,
                    attempted: *total_memory + size,
                });
            }
        }
        
        // Attack detection
        if self.config.attack_protection {
            if let Ok(mut detector) = self.attack_detector.lock() {
                if let Some(pattern) = detector.record_allocation(size) {
                    warn!("Potential memory exhaustion attack detected: {:?}", pattern);
                    
                    self.record_violation(SecurityViolation::SuspiciousActivity {
                        activity_type: "memory_attack".to_string(),
                        details: format!("Attack pattern: {:?}", pattern),
                        source_url: source.clone().unwrap_or_else(|| "unknown".to_string()),
                    });
                    
                    // Enter emergency mode if attack detected
                    *self.emergency_mode.lock().unwrap() = true;
                }
            }
        }
        
        // Allocate in specific pool
        let pools = self.pools.read().unwrap();
        if let Some(pool_mutex) = pools.get(&resource_type) {
            let mut pool = pool_mutex.lock().unwrap();
            
            // Check if we need preemptive cleanup
            if pool.would_exceed_soft_limit(size) {
                info!("Soft limit approached for {}, triggering cleanup", resource_type);
                pool.cleanup_non_critical(size);
            }
            
            match pool.allocate(size, critical, source) {
                Ok(allocation_id) => {
                    // Update total memory
                    *self.total_memory.lock().unwrap() += size;
                    
                    debug!("Successfully allocated {} bytes for {} (ID: {})", 
                           size, resource_type, allocation_id);
                    
                    Ok(allocation_id)
                }
                Err(e) => {
                    error!("Failed to allocate {} bytes for {}: {}", 
                           size, resource_type, e);
                    
                    // Try emergency cleanup and retry once
                    if pool.config.emergency_cleanup_enabled {
                        warn!("Attempting emergency cleanup for {}", resource_type);
                        let cleaned = pool.emergency_cleanup();
                        
                        if cleaned > 0 {
                            info!("Emergency cleanup freed {} bytes", cleaned);
                            // Retry allocation
                            match pool.allocate(size, critical, None) {
                                Ok(allocation_id) => {
                                    *self.total_memory.lock().unwrap() += size;
                                    return Ok(allocation_id);
                                }
                                Err(retry_error) => {
                                    error!("Allocation failed even after emergency cleanup: {}", retry_error);
                                }
                            }
                        }
                    }
                    
                    Err(e)
                }
            }
        } else {
            Err(MemoryProtectionError::ConfigurationError {
                error: format!("No pool configured for resource type: {}", resource_type),
            })
        }
    }
    
    /// Deallocate memory for a specific resource type
    pub fn deallocate(&self, resource_type: ResourceType, allocation_id: usize) -> MemoryProtectionResult<()> {
        let pools = self.pools.read().unwrap();
        if let Some(pool_mutex) = pools.get(&resource_type) {
            let mut pool = pool_mutex.lock().unwrap();
            
            // Get allocation size before deallocation
            let size = pool.allocations.get(&allocation_id)
                .map(|a| a.size)
                .unwrap_or(0);
            
            match pool.deallocate(allocation_id) {
                Ok(()) => {
                    // Update total memory
                    let mut total_memory = self.total_memory.lock().unwrap();
                    *total_memory = total_memory.saturating_sub(size);
                    
                    debug!("Successfully deallocated {} bytes for {} (ID: {})", 
                           size, resource_type, allocation_id);
                    
                    Ok(())
                }
                Err(e) => {
                    error!("Failed to deallocate for {}: {}", resource_type, e);
                    Err(e)
                }
            }
        } else {
            Err(MemoryProtectionError::ConfigurationError {
                error: format!("No pool configured for resource type: {}", resource_type),
            })
        }
    }
    
    /// Force cleanup across all pools
    pub fn force_cleanup(&self, aggressive: bool) -> usize {
        let mut total_cleaned = 0;
        let pools = self.pools.read().unwrap();
        
        for (resource_type, pool_mutex) in pools.iter() {
            if let Ok(mut pool) = pool_mutex.lock() {
                let cleaned = if aggressive {
                    pool.emergency_cleanup()
                } else {
                    // Clean 25% of current usage
                    let target = (pool.current_memory() as f32 * 0.25) as usize;
                    pool.cleanup_non_critical(target)
                };
                
                if cleaned > 0 {
                    info!("Cleaned {} bytes from {} pool", cleaned, resource_type);
                    total_cleaned += cleaned;
                    
                    // Update total memory
                    let mut total_memory = self.total_memory.lock().unwrap();
                    *total_memory = total_memory.saturating_sub(cleaned);
                }
            }
        }
        
        info!("Force cleanup completed, freed {} bytes total", total_cleaned);
        total_cleaned
    }
    
    /// Periodic system check and maintenance
    pub fn periodic_check(&self) {
        let mut last_check = self.last_check.lock().unwrap();
        let now = Instant::now();
        
        if now.duration_since(*last_check) < self.config.check_interval {
            return;
        }
        
        *last_check = now;
        
        let total_memory = *self.total_memory.lock().unwrap();
        let utilization = total_memory as f32 / self.config.total_memory_limit as f32;
        
        debug!("Memory utilization: {:.1}% ({} / {} bytes)", 
               utilization * 100.0, total_memory, self.config.total_memory_limit);
        
        // Check if we need cleanup
        if utilization > self.config.emergency_threshold {
            error!("Emergency memory threshold exceeded: {:.1}%", utilization * 100.0);
            *self.emergency_mode.lock().unwrap() = true;
            self.force_cleanup(true);
        } else if utilization > self.config.aggressive_threshold {
            warn!("Aggressive cleanup threshold exceeded: {:.1}%", utilization * 100.0);
            self.force_cleanup(false);
        }
        
        // Exit emergency mode if memory usage is back to normal
        if utilization < (self.config.aggressive_threshold - 0.1) {
            let mut emergency = self.emergency_mode.lock().unwrap();
            if *emergency {
                info!("Exiting emergency memory mode");
                *emergency = false;
            }
        }
    }
    
    /// Check if system is in emergency mode
    pub fn is_emergency_mode(&self) -> bool {
        *self.emergency_mode.lock().unwrap()
    }
    
    /// Get current total memory usage
    pub fn total_memory_usage(&self) -> usize {
        *self.total_memory.lock().unwrap()
    }
    
    /// Get memory utilization ratio
    pub fn memory_utilization(&self) -> f32 {
        let total = *self.total_memory.lock().unwrap();
        total as f32 / self.config.total_memory_limit as f32
    }
    
    /// Get statistics for all resource pools
    pub fn get_statistics(&self) -> HashMap<ResourceType, ResourcePoolStats> {
        let mut stats = HashMap::new();
        let pools = self.pools.read().unwrap();
        
        for (resource_type, pool_mutex) in pools.iter() {
            if let Ok(pool) = pool_mutex.lock() {
                stats.insert(resource_type.clone(), pool.get_stats());
            }
        }
        
        stats
    }
    
    /// Record a security violation
    fn record_violation(&self, violation: SecurityViolation) {
        if let Some(ref callback) = self.violation_callback {
            callback(violation);
        }
    }
    
    /// Update configuration
    pub fn update_config(&mut self, config: MemoryProtectionConfig) {
        self.config = config;
        
        // Reinitialize pools with new configuration
        let mut pools = self.pools.write().unwrap();
        pools.clear();
        
        for (resource_type, pool_config) in &self.config.resource_pools {
            pools.insert(
                resource_type.clone(),
                Mutex::new(ResourcePool::new(pool_config.clone()))
            );
        }
    }
}

/// Memory protection system builder for easy configuration
pub struct MemoryProtectionBuilder {
    config: MemoryProtectionConfig,
}

impl MemoryProtectionBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self {
            config: MemoryProtectionConfig::default(),
        }
    }
    
    /// Set total memory limit
    pub fn total_memory_limit(mut self, limit: usize) -> Self {
        self.config.total_memory_limit = limit;
        self
    }
    
    /// Set per-tab memory limit
    pub fn per_tab_memory_limit(mut self, limit: usize) -> Self {
        self.config.per_tab_memory_limit = limit;
        self
    }
    
    /// Set thresholds for cleanup
    pub fn thresholds(mut self, aggressive: f32, emergency: f32) -> Self {
        self.config.aggressive_threshold = aggressive.clamp(0.0, 1.0);
        self.config.emergency_threshold = emergency.clamp(0.0, 1.0);
        self
    }
    
    /// Configure a specific resource pool
    pub fn resource_pool(mut self, resource_type: ResourceType, config: ResourcePoolConfig) -> Self {
        self.config.resource_pools.insert(resource_type, config);
        self
    }
    
    /// Enable or disable attack protection
    pub fn attack_protection(mut self, enabled: bool) -> Self {
        self.config.attack_protection = enabled;
        self
    }
    
    /// Build the memory protection system
    pub fn build(self) -> MemoryProtectionSystem {
        MemoryProtectionSystem::new(self.config)
    }
}

impl Default for MemoryProtectionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[test]
    fn test_resource_pool_allocation() {
        let config = ResourcePoolConfig::default();
        let mut pool = ResourcePool::new(config);
        
        let id = pool.allocate(1024, false, None).unwrap();
        assert_eq!(pool.current_memory(), 1024);
        assert_eq!(pool.current_count(), 1);
        
        pool.deallocate(id).unwrap();
        assert_eq!(pool.current_memory(), 0);
        assert_eq!(pool.current_count(), 0);
    }
    
    #[test]
    fn test_memory_limit_enforcement() {
        let config = ResourcePoolConfig {
            max_memory: 1024,
            ..Default::default()
        };
        let mut pool = ResourcePool::new(config);
        
        // Should succeed
        let _id1 = pool.allocate(512, false, None).unwrap();
        
        // Should fail - exceeds limit
        let result = pool.allocate(600, false, None);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_cleanup_behavior() {
        let config = ResourcePoolConfig {
            max_memory: 2048,
            soft_limit: 1024,
            ..Default::default()
        };
        let mut pool = ResourcePool::new(config);
        
        // Add several allocations
        let _id1 = pool.allocate(300, true, None).unwrap();  // Critical
        let _id2 = pool.allocate(300, false, None).unwrap(); // Non-critical
        let _id3 = pool.allocate(300, false, None).unwrap(); // Non-critical
        
        assert_eq!(pool.current_memory(), 900);
        
        // Trigger cleanup
        let cleaned = pool.cleanup_non_critical(400);
        assert!(cleaned >= 400); // Should clean at least 400 bytes
    }
    
    #[test]
    fn test_attack_detection() {
        let mut detector = AttackDetector::new();
        
        // Simulate rapid allocations
        for _ in 0..1500 {
            if let Some(pattern) = detector.record_allocation(1024) {
                match pattern {
                    AttackPattern::RapidAllocation { .. } => {
                        // Expected
                        break;
                    }
                    _ => panic!("Unexpected attack pattern"),
                }
            }
        }
    }
    
    #[test]
    fn test_memory_protection_system() {
        let system = MemoryProtectionBuilder::new()
            .total_memory_limit(10 * 1024 * 1024) // 10MB
            .attack_protection(true)
            .build();
        
        // Normal allocation should work
        let id = system.allocate(
            ResourceType::DomNodes, 
            1024, 
            false, 
            Some("test".to_string())
        ).unwrap();
        
        assert_eq!(system.total_memory_usage(), 1024);
        
        // Deallocation should work
        system.deallocate(ResourceType::DomNodes, id).unwrap();
        assert_eq!(system.total_memory_usage(), 0);
    }
    
    #[test]
    fn test_emergency_mode() {
        let system = MemoryProtectionBuilder::new()
            .total_memory_limit(1024) // Very small limit
            .thresholds(0.5, 0.8)
            .build();
        
        // Fill memory to exceed emergency threshold (> 80% = > 819 bytes)
        let _id = system.allocate(ResourceType::GenericMemory, 850, false, None).unwrap();
        
        // Force periodic check by setting last check time to past
        {
            let mut last_check = system.last_check.lock().unwrap();
            *last_check = Instant::now() - Duration::from_secs(60);
        }
        
        // This should trigger emergency mode
        system.periodic_check();
        assert!(system.is_emergency_mode());
    }
}