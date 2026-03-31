//! Memory Protection Integration for Citadel Browser
//!
//! This module integrates the memory protection system with the browser engine,
//! providing comprehensive memory management and attack prevention.

use std::sync::Arc;
use std::time::Duration;
use log::{info, warn, error, debug};
use tokio::task;

use citadel_security::{
    MemoryProtectionSystem, MemoryProtectionBuilder, MemoryProtectionConfig,
    ResourceType, SecurityContext,
};
use crate::performance::{PerformanceMonitor, CleanupPriority};

/// Browser memory manager that coordinates between security and performance systems
pub struct BrowserMemoryManager {
    /// Core memory protection system
    protection_system: Arc<MemoryProtectionSystem>,
    /// Performance monitoring system
    performance_monitor: Arc<PerformanceMonitor>,
    /// Security context for violation reporting
    security_context: Arc<SecurityContext>,
    /// Background task handle
    background_task: Option<task::JoinHandle<()>>,
}

impl BrowserMemoryManager {
    /// Create a new browser memory manager
    pub fn new(
        security_context: Arc<SecurityContext>,
        performance_monitor: Arc<PerformanceMonitor>,
    ) -> Self {
        // Create memory protection system with browser-optimized configuration
        let protection_config = Self::create_browser_config();
        let mut protection_system = MemoryProtectionBuilder::new()
            .total_memory_limit(protection_config.total_memory_limit)
            .per_tab_memory_limit(protection_config.per_tab_memory_limit)
            .thresholds(protection_config.aggressive_threshold, protection_config.emergency_threshold)
            .attack_protection(true)
            .build();
        
        // Set up violation reporting callback
        let security_context_clone = Arc::clone(&security_context);
        protection_system.set_violation_callback(move |violation| {
            security_context_clone.record_violation(violation);
        });
        
        let protection_system = Arc::new(protection_system);
        
        // Start background monitoring task
        let background_task = Self::start_background_monitoring(
            Arc::clone(&protection_system),
            Arc::clone(&performance_monitor),
        );
        
        Self {
            protection_system,
            performance_monitor,
            security_context,
            background_task: Some(background_task),
        }
    }
    
    /// Create browser-optimized memory protection configuration
    fn create_browser_config() -> MemoryProtectionConfig {
        use citadel_security::{ResourcePoolConfig};
        use std::collections::HashMap;
        
        let mut config = MemoryProtectionConfig::default();
        
        // Adjust for browser-specific needs
        config.total_memory_limit = 4 * 1024 * 1024 * 1024; // 4GB total for browser
        config.per_tab_memory_limit = 1024 * 1024 * 1024;   // 1GB per tab
        config.emergency_threshold = 0.85;  // 85% for emergency
        config.aggressive_threshold = 0.70; // 70% for aggressive cleanup
        config.check_interval = Duration::from_secs(5); // Check every 5 seconds
        
        // Configure resource pools for browser components
        let mut resource_pools = HashMap::new();
        
        // DOM nodes - critical for rendering
        resource_pools.insert(ResourceType::DomNodes, ResourcePoolConfig {
            max_count: 100000,
            max_memory: 200 * 1024 * 1024, // 200MB
            soft_limit: 160 * 1024 * 1024,  // 160MB
            emergency_cleanup_enabled: false, // Never cleanup DOM in emergency
            operation_timeout: Duration::from_secs(10),
        });
        
        // JavaScript objects - high cleanup priority
        resource_pools.insert(ResourceType::JsObjects, ResourcePoolConfig {
            max_count: 2000000,
            max_memory: 512 * 1024 * 1024, // 512MB
            soft_limit: 400 * 1024 * 1024, // 400MB
            emergency_cleanup_enabled: true,
            operation_timeout: Duration::from_secs(30),
        });
        
        // Image cache - large but cleanable
        resource_pools.insert(ResourceType::ImageData, ResourcePoolConfig {
            max_count: 2000,
            max_memory: 1024 * 1024 * 1024, // 1GB
            soft_limit: 800 * 1024 * 1024,  // 800MB
            emergency_cleanup_enabled: true,
            operation_timeout: Duration::from_secs(15),
        });
        
        // Network connections - strict control
        resource_pools.insert(ResourceType::NetworkConnections, ResourcePoolConfig {
            max_count: 200, // Increased for better performance
            max_memory: 50 * 1024 * 1024, // 50MB
            soft_limit: 40 * 1024 * 1024, // 40MB
            emergency_cleanup_enabled: true,
            operation_timeout: Duration::from_secs(60),
        });
        
        // CSS rules - moderate limits
        resource_pools.insert(ResourceType::CssRules, ResourcePoolConfig {
            max_count: 500000,
            max_memory: 100 * 1024 * 1024, // 100MB
            soft_limit: 80 * 1024 * 1024,  // 80MB
            emergency_cleanup_enabled: true,
            operation_timeout: Duration::from_secs(15),
        });
        
        config.resource_pools = resource_pools;
        config
    }
    
    /// Start background monitoring task
    fn start_background_monitoring(
        protection_system: Arc<MemoryProtectionSystem>,
        performance_monitor: Arc<PerformanceMonitor>,
    ) -> task::JoinHandle<()> {
        task::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            
            loop {
                interval.tick().await;
                
                // Perform periodic checks
                protection_system.periodic_check();
                
                // Update performance metrics
                let memory_usage = protection_system.total_memory_usage();
                let utilization = protection_system.memory_utilization();
                
                performance_monitor.update_memory_usage("total", memory_usage);
                
                // Log memory status periodically
                if memory_usage > 0 {
                    debug!("Memory status: {:.1}MB ({:.1}% utilization)", 
                           memory_usage as f64 / 1024.0 / 1024.0,
                           utilization * 100.0);
                }
                
                // Check for emergency conditions
                if protection_system.is_emergency_mode() {
                    warn!("Browser in emergency memory mode - aggressive cleanup active");
                    performance_monitor.add_measurement("memory_pressure", 1);
                }
            }
        })
    }
    
    /// Allocate memory for DOM operations
    pub fn allocate_dom_memory(&self, size: usize, critical: bool) -> Result<usize, String> {
        match self.protection_system.allocate(
            ResourceType::DomNodes,
            size,
            critical,
            Some("dom_operation".to_string())
        ) {
            Ok(id) => {
                self.performance_monitor.update_memory_usage("dom", 
                    self.get_resource_memory_usage(ResourceType::DomNodes));
                Ok(id)
            }
            Err(e) => {
                error!("DOM memory allocation failed: {}", e);
                Err(format!("DOM allocation failed: {}", e))
            }
        }
    }
    
    /// Allocate memory for JavaScript engine
    pub fn allocate_js_memory(&self, size: usize, critical: bool) -> Result<usize, String> {
        match self.protection_system.allocate(
            ResourceType::JsObjects,
            size,
            critical,
            Some("js_engine".to_string())
        ) {
            Ok(id) => {
                self.performance_monitor.update_memory_usage("js", 
                    self.get_resource_memory_usage(ResourceType::JsObjects));
                Ok(id)
            }
            Err(e) => {
                error!("JavaScript memory allocation failed: {}", e);
                Err(format!("JS allocation failed: {}", e))
            }
        }
    }
    
    /// Allocate memory for network operations
    pub fn allocate_network_memory(&self, size: usize) -> Result<usize, String> {
        match self.protection_system.allocate(
            ResourceType::NetworkConnections,
            size,
            false, // Network allocations are not critical
            Some("network_operation".to_string())
        ) {
            Ok(id) => {
                self.performance_monitor.update_memory_usage("network_cache", 
                    self.get_resource_memory_usage(ResourceType::NetworkConnections));
                Ok(id)
            }
            Err(e) => {
                error!("Network memory allocation failed: {}", e);
                Err(format!("Network allocation failed: {}", e))
            }
        }
    }
    
    /// Allocate memory for image cache
    pub fn allocate_image_memory(&self, size: usize) -> Result<usize, String> {
        match self.protection_system.allocate(
            ResourceType::ImageData,
            size,
            false, // Images are not critical
            Some("image_cache".to_string())
        ) {
            Ok(id) => {
                self.performance_monitor.update_memory_usage("image_cache", 
                    self.get_resource_memory_usage(ResourceType::ImageData));
                Ok(id)
            }
            Err(e) => {
                error!("Image memory allocation failed: {}", e);
                Err(format!("Image allocation failed: {}", e))
            }
        }
    }
    
    /// Deallocate memory for a specific resource type
    pub fn deallocate_memory(&self, resource_type: ResourceType, allocation_id: usize) -> Result<(), String> {
        match self.protection_system.deallocate(resource_type.clone(), allocation_id) {
            Ok(()) => {
                // Update performance monitor
                let component = match resource_type {
                    ResourceType::DomNodes => "dom",
                    ResourceType::JsObjects => "js",
                    ResourceType::NetworkConnections => "network_cache",
                    ResourceType::ImageData => "image_cache",
                    ResourceType::FontData => "font_cache",
                    _ => "generic",
                };
                
                self.performance_monitor.update_memory_usage(component, 
                    self.get_resource_memory_usage(resource_type));
                
                Ok(())
            }
            Err(e) => {
                error!("Memory deallocation failed: {}", e);
                Err(format!("Deallocation failed: {}", e))
            }
        }
    }
    
    /// Force memory cleanup across all resource types
    pub fn force_cleanup(&self, aggressive: bool) -> usize {
        info!("Forcing browser memory cleanup (aggressive: {})", aggressive);
        
        let cleaned = self.protection_system.force_cleanup(aggressive);
        
        // Update all performance metrics after cleanup
        self.update_all_performance_metrics();
        
        // Record cleanup in performance metrics
        let cleanup_priority = if aggressive { CleanupPriority::Critical } else { CleanupPriority::Medium };
        self.performance_monitor.force_cleanup(cleanup_priority);
        
        info!("Memory cleanup completed, freed {} bytes", cleaned);
        cleaned
    }
    
    /// Check if browser is in emergency memory mode
    pub fn is_emergency_mode(&self) -> bool {
        self.protection_system.is_emergency_mode()
    }
    
    /// Get current total memory usage
    pub fn total_memory_usage(&self) -> usize {
        self.protection_system.total_memory_usage()
    }
    
    /// Get memory utilization ratio (0.0 to 1.0)
    pub fn memory_utilization(&self) -> f32 {
        self.protection_system.memory_utilization()
    }
    
    /// Get memory usage for a specific resource type
    pub fn get_resource_memory_usage(&self, resource_type: ResourceType) -> usize {
        let stats = self.protection_system.get_statistics();
        stats.get(&resource_type)
            .map(|stat| stat.current_memory)
            .unwrap_or(0)
    }
    
    /// Update all performance metrics with current memory usage
    fn update_all_performance_metrics(&self) {
        let stats = self.protection_system.get_statistics();
        
        for (resource_type, stat) in stats {
            let component = match resource_type {
                ResourceType::DomNodes => "dom",
                ResourceType::JsObjects => "js",
                ResourceType::NetworkConnections => "network_cache",
                ResourceType::ImageData => "image_cache",
                ResourceType::FontData => "font_cache",
                ResourceType::CssRules => "layout",
                _ => continue,
            };
            
            self.performance_monitor.update_memory_usage(component, stat.current_memory);
        }
    }
    
    /// Get detailed memory statistics
    pub fn get_memory_statistics(&self) -> BrowserMemoryStatistics {
        let stats = self.protection_system.get_statistics();
        let total_usage = self.total_memory_usage();
        let utilization = self.memory_utilization();
        
        BrowserMemoryStatistics {
            total_usage,
            utilization,
            emergency_mode: self.is_emergency_mode(),
            dom_memory: stats.get(&ResourceType::DomNodes).map(|s| s.current_memory).unwrap_or(0),
            js_memory: stats.get(&ResourceType::JsObjects).map(|s| s.current_memory).unwrap_or(0),
            network_memory: stats.get(&ResourceType::NetworkConnections).map(|s| s.current_memory).unwrap_or(0),
            image_memory: stats.get(&ResourceType::ImageData).map(|s| s.current_memory).unwrap_or(0),
            css_memory: stats.get(&ResourceType::CssRules).map(|s| s.current_memory).unwrap_or(0),
            resource_stats: stats,
        }
    }
    
    /// Handle tab creation - allocate tab-specific memory pool
    pub fn allocate_tab_memory(&self, tab_id: u32) -> Result<usize, String> {
        match self.protection_system.allocate(
            ResourceType::TabMemory,
            1024, // Initial allocation for tab overhead
            true, // Tab allocations are critical
            Some(format!("tab_{}", tab_id))
        ) {
            Ok(id) => {
                info!("Allocated memory pool for tab {}", tab_id);
                Ok(id)
            }
            Err(e) => {
                error!("Failed to allocate tab memory for tab {}: {}", tab_id, e);
                Err(format!("Tab allocation failed: {}", e))
            }
        }
    }
    
    /// Handle tab closure - cleanup tab-specific memory
    pub fn deallocate_tab_memory(&self, allocation_id: usize) -> Result<(), String> {
        self.deallocate_memory(ResourceType::TabMemory, allocation_id)
    }
    
    /// Check if we can safely create a new tab
    pub fn can_create_tab(&self) -> bool {
        let current_utilization = self.memory_utilization();
        let tab_limit_ratio = 0.8; // Don't create new tabs if we're above 80% memory usage
        
        if current_utilization > tab_limit_ratio {
            warn!("Rejecting new tab creation due to high memory usage: {:.1}%", 
                  current_utilization * 100.0);
            false
        } else {
            true
        }
    }
    
    /// Emergency memory cleanup specifically for browser stability
    pub fn emergency_browser_cleanup(&self) -> usize {
        error!("Executing emergency browser memory cleanup");
        
        // First try standard aggressive cleanup
        let cleaned = self.force_cleanup(true);
        
        // If still in emergency mode, try more drastic measures
        if self.is_emergency_mode() {
            warn!("Standard cleanup insufficient, triggering drastic measures");
            
            // Force garbage collection in JavaScript engine
            // (This would integrate with the actual JS engine)
            self.performance_monitor.add_measurement("emergency_cleanup", 1);
            
            // Clear non-essential caches
            // (This would integrate with actual cache systems)
        }
        
        cleaned
    }
}

impl Drop for BrowserMemoryManager {
    fn drop(&mut self) {
        if let Some(handle) = self.background_task.take() {
            handle.abort();
        }
    }
}

/// Browser memory statistics
#[derive(Debug, Clone)]
pub struct BrowserMemoryStatistics {
    pub total_usage: usize,
    pub utilization: f32,
    pub emergency_mode: bool,
    pub dom_memory: usize,
    pub js_memory: usize,
    pub network_memory: usize,
    pub image_memory: usize,
    pub css_memory: usize,
    pub resource_stats: std::collections::HashMap<ResourceType, citadel_security::ResourcePoolStats>,
}

impl BrowserMemoryStatistics {
    /// Format memory statistics for display
    pub fn format_for_display(&self) -> String {
        format!(
            "Memory Usage: {:.1}MB ({:.1}%) - DOM: {:.1}MB, JS: {:.1}MB, Images: {:.1}MB, Network: {:.1}MB, CSS: {:.1}MB{}",
            self.total_usage as f64 / 1024.0 / 1024.0,
            self.utilization * 100.0,
            self.dom_memory as f64 / 1024.0 / 1024.0,
            self.js_memory as f64 / 1024.0 / 1024.0,
            self.image_memory as f64 / 1024.0 / 1024.0,
            self.network_memory as f64 / 1024.0 / 1024.0,
            self.css_memory as f64 / 1024.0 / 1024.0,
            if self.emergency_mode { " [EMERGENCY]" } else { "" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_security::SecurityContext;
    use crate::performance::{PerformanceMonitor, MemoryConfig};
    
    #[tokio::test]
    async fn test_browser_memory_manager_creation() {
        let security_context = Arc::new(SecurityContext::new_default());
        let performance_monitor = Arc::new(PerformanceMonitor::new(MemoryConfig::default()));
        
        let memory_manager = BrowserMemoryManager::new(security_context, performance_monitor);
        
        assert!(!memory_manager.is_emergency_mode());
        assert_eq!(memory_manager.total_memory_usage(), 0);
    }
    
    #[tokio::test]
    async fn test_dom_memory_allocation() {
        let security_context = Arc::new(SecurityContext::new_default());
        let performance_monitor = Arc::new(PerformanceMonitor::new(MemoryConfig::default()));
        let memory_manager = BrowserMemoryManager::new(security_context, performance_monitor);
        
        let allocation_id = memory_manager.allocate_dom_memory(1024, false).unwrap();
        assert!(memory_manager.total_memory_usage() >= 1024);
        
        memory_manager.deallocate_memory(ResourceType::DomNodes, allocation_id).unwrap();
    }
    
    #[tokio::test]
    async fn test_tab_memory_management() {
        let security_context = Arc::new(SecurityContext::new_default());
        let performance_monitor = Arc::new(PerformanceMonitor::new(MemoryConfig::default()));
        let memory_manager = BrowserMemoryManager::new(security_context, performance_monitor);
        
        assert!(memory_manager.can_create_tab());
        
        let tab_id = memory_manager.allocate_tab_memory(1).unwrap();
        memory_manager.deallocate_tab_memory(tab_id).unwrap();
    }
    
    #[tokio::test]
    async fn test_memory_statistics() {
        let security_context = Arc::new(SecurityContext::new_default());
        let performance_monitor = Arc::new(PerformanceMonitor::new(MemoryConfig::default()));
        let memory_manager = BrowserMemoryManager::new(security_context, performance_monitor);
        
        let _dom_id = memory_manager.allocate_dom_memory(1024, false).unwrap();
        let _js_id = memory_manager.allocate_js_memory(2048, false).unwrap();
        
        let stats = memory_manager.get_memory_statistics();
        assert!(stats.total_usage >= 3072);
        assert!(stats.dom_memory >= 1024);
        assert!(stats.js_memory >= 2048);
        
        let display = stats.format_for_display();
        assert!(display.contains("Memory Usage:"));
    }
}