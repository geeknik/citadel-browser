//! Performance and memory optimization for Citadel Browser
//!
//! This module provides comprehensive performance monitoring, memory management,
//! and optimization features for the browser engine.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use log;

/// Memory usage tracking for different browser components
#[derive(Debug, Clone, Default)]
pub struct MemoryUsage {
    /// DOM memory usage in bytes
    pub dom_memory: usize,
    /// Layout engine memory in bytes
    pub layout_memory: usize,
    /// Renderer memory in bytes
    pub renderer_memory: usize,
    /// JavaScript engine memory in bytes
    pub js_memory: usize,
    /// Network cache memory in bytes
    pub network_cache_memory: usize,
    /// Image cache memory in bytes
    pub image_cache_memory: usize,
    /// Font cache memory in bytes
    pub font_cache_memory: usize,
    /// Total browser memory in bytes
    pub total_memory: usize,
}

impl MemoryUsage {
    /// Calculate total memory from components
    pub fn calculate_total(&mut self) {
        self.total_memory = self.dom_memory + 
                           self.layout_memory + 
                           self.renderer_memory + 
                           self.js_memory + 
                           self.network_cache_memory + 
                           self.image_cache_memory + 
                           self.font_cache_memory;
    }
    
    /// Get memory usage as a formatted string
    pub fn format_memory(&self) -> String {
        format!(
            "Total: {:.1}MB (DOM: {:.1}MB, Layout: {:.1}MB, Renderer: {:.1}MB, JS: {:.1}MB, Caches: {:.1}MB)",
            self.total_memory as f64 / 1024.0 / 1024.0,
            self.dom_memory as f64 / 1024.0 / 1024.0,
            self.layout_memory as f64 / 1024.0 / 1024.0,
            self.renderer_memory as f64 / 1024.0 / 1024.0,
            self.js_memory as f64 / 1024.0 / 1024.0,
            (self.network_cache_memory + self.image_cache_memory + self.font_cache_memory) as f64 / 1024.0 / 1024.0
        )
    }
}

/// Performance metrics for browser operations
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    /// Page load times in milliseconds
    pub page_load_times: VecDeque<u64>,
    /// Layout computation times in milliseconds
    pub layout_times: VecDeque<u64>,
    /// Render times in milliseconds
    pub render_times: VecDeque<u64>,
    /// JavaScript execution times in milliseconds
    pub js_execution_times: VecDeque<u64>,
    /// Network request times in milliseconds
    pub network_times: VecDeque<u64>,
    /// Frame rates for smooth scrolling
    pub frame_rates: VecDeque<f64>,
    /// Cache hit ratios
    pub cache_hit_ratios: HashMap<String, f64>,
    /// Memory pressure events
    pub memory_pressure_events: usize,
    /// Last measurement timestamp
    pub last_measurement: Instant,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            page_load_times: VecDeque::new(),
            layout_times: VecDeque::new(),
            render_times: VecDeque::new(),
            js_execution_times: VecDeque::new(),
            network_times: VecDeque::new(),
            frame_rates: VecDeque::new(),
            cache_hit_ratios: HashMap::new(),
            memory_pressure_events: 0,
            last_measurement: Instant::now(),
        }
    }
}

impl PerformanceMetrics {
    /// Maximum number of measurements to keep
    const MAX_MEASUREMENTS: usize = 100;
    
    /// Add a page load time measurement
    pub fn add_page_load_time(&mut self, time_ms: u64) {
        if self.page_load_times.len() >= Self::MAX_MEASUREMENTS {
            self.page_load_times.pop_front();
        }
        self.page_load_times.push_back(time_ms);
        self.last_measurement = Instant::now();
    }
    
    /// Add a layout computation time
    pub fn add_layout_time(&mut self, time_ms: u64) {
        if self.layout_times.len() >= Self::MAX_MEASUREMENTS {
            self.layout_times.pop_front();
        }
        self.layout_times.push_back(time_ms);
        self.last_measurement = Instant::now();
    }
    
    /// Add a render time measurement
    pub fn add_render_time(&mut self, time_ms: u64) {
        if self.render_times.len() >= Self::MAX_MEASUREMENTS {
            self.render_times.pop_front();
        }
        self.render_times.push_back(time_ms);
        self.last_measurement = Instant::now();
    }
    
    /// Add a JavaScript execution time
    pub fn add_js_execution_time(&mut self, time_ms: u64) {
        if self.js_execution_times.len() >= Self::MAX_MEASUREMENTS {
            self.js_execution_times.pop_front();
        }
        self.js_execution_times.push_back(time_ms);
        self.last_measurement = Instant::now();
    }
    
    /// Add a network request time
    pub fn add_network_time(&mut self, time_ms: u64) {
        if self.network_times.len() >= Self::MAX_MEASUREMENTS {
            self.network_times.pop_front();
        }
        self.network_times.push_back(time_ms);
        self.last_measurement = Instant::now();
    }
    
    /// Add a frame rate measurement
    pub fn add_frame_rate(&mut self, fps: f64) {
        if self.frame_rates.len() >= Self::MAX_MEASUREMENTS {
            self.frame_rates.pop_front();
        }
        self.frame_rates.push_back(fps);
        self.last_measurement = Instant::now();
    }
    
    /// Set cache hit ratio for a component
    pub fn set_cache_hit_ratio(&mut self, component: String, ratio: f64) {
        self.cache_hit_ratios.insert(component, ratio);
        self.last_measurement = Instant::now();
    }
    
    /// Record memory pressure event
    pub fn record_memory_pressure(&mut self) {
        self.memory_pressure_events += 1;
        self.last_measurement = Instant::now();
    }
    
    /// Helper to add measurement with size limit
    fn add_measurement(&mut self, queue: &mut VecDeque<u64>, value: u64) {
        if queue.len() >= Self::MAX_MEASUREMENTS {
            queue.pop_front();
        }
        queue.push_back(value);
        self.last_measurement = Instant::now();
    }
    
    /// Calculate average page load time
    pub fn average_page_load_time(&self) -> Option<f64> {
        if self.page_load_times.is_empty() {
            None
        } else {
            let sum: u64 = self.page_load_times.iter().sum();
            Some(sum as f64 / self.page_load_times.len() as f64)
        }
    }
    
    /// Calculate average layout time
    pub fn average_layout_time(&self) -> Option<f64> {
        if self.layout_times.is_empty() {
            None
        } else {
            let sum: u64 = self.layout_times.iter().sum();
            Some(sum as f64 / self.layout_times.len() as f64)
        }
    }
    
    /// Calculate average render time
    pub fn average_render_time(&self) -> Option<f64> {
        if self.render_times.is_empty() {
            None
        } else {
            let sum: u64 = self.render_times.iter().sum();
            Some(sum as f64 / self.render_times.len() as f64)
        }
    }
    
    /// Calculate average frame rate
    pub fn average_frame_rate(&self) -> Option<f64> {
        if self.frame_rates.is_empty() {
            None
        } else {
            let sum: f64 = self.frame_rates.iter().sum();
            Some(sum / self.frame_rates.len() as f64)
        }
    }
    
    /// Get performance summary
    pub fn get_summary(&self) -> PerformanceSummary {
        PerformanceSummary {
            average_page_load_ms: self.average_page_load_time().unwrap_or(0.0),
            average_layout_ms: self.average_layout_time().unwrap_or(0.0),
            average_render_ms: self.average_render_time().unwrap_or(0.0),
            average_fps: self.average_frame_rate().unwrap_or(0.0),
            total_measurements: self.page_load_times.len() + 
                               self.layout_times.len() + 
                               self.render_times.len(),
            memory_pressure_events: self.memory_pressure_events,
            cache_hit_ratios: self.cache_hit_ratios.clone(),
        }
    }
}

/// Performance summary for reporting
#[derive(Debug, Clone)]
pub struct PerformanceSummary {
    pub average_page_load_ms: f64,
    pub average_layout_ms: f64,
    pub average_render_ms: f64,
    pub average_fps: f64,
    pub total_measurements: usize,
    pub memory_pressure_events: usize,
    pub cache_hit_ratios: HashMap<String, f64>,
}

/// Memory pressure levels
#[derive(Debug, Clone, PartialEq)]
pub enum MemoryPressure {
    Low,
    Medium,
    High,
    Critical,
}

/// Resource cleanup priorities
#[derive(Debug, Clone, PartialEq, Ord, PartialOrd, Eq)]
pub enum CleanupPriority {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Memory management configuration
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    /// Maximum total memory usage in bytes
    pub max_total_memory: usize,
    /// Memory threshold for triggering cleanup
    pub cleanup_threshold: usize,
    /// Critical memory threshold
    pub critical_threshold: usize,
    /// Cache size limits for different components
    pub cache_limits: HashMap<String, usize>,
    /// Enable aggressive cleanup
    pub aggressive_cleanup: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        let mut cache_limits = HashMap::new();
        cache_limits.insert("layout".to_string(), 50 * 1024 * 1024); // 50MB
        cache_limits.insert("images".to_string(), 100 * 1024 * 1024); // 100MB
        cache_limits.insert("fonts".to_string(), 20 * 1024 * 1024); // 20MB
        cache_limits.insert("network".to_string(), 30 * 1024 * 1024); // 30MB
        
        Self {
            max_total_memory: 512 * 1024 * 1024, // 512MB per tab
            cleanup_threshold: 400 * 1024 * 1024, // 400MB
            critical_threshold: 480 * 1024 * 1024, // 480MB
            cache_limits,
            aggressive_cleanup: false,
        }
    }
}

/// Performance and memory monitor
pub struct PerformanceMonitor {
    /// Current memory usage
    memory_usage: Arc<Mutex<MemoryUsage>>,
    /// Performance metrics
    metrics: Arc<Mutex<PerformanceMetrics>>,
    /// Memory configuration
    config: MemoryConfig,
    /// Cleanup callbacks for different components
    cleanup_callbacks: HashMap<String, Box<dyn Fn(CleanupPriority) + Send + Sync>>,
    /// Memory measurement timer
    last_memory_check: Instant,
    /// Performance measurement enabled
    monitoring_enabled: bool,
}

impl PerformanceMonitor {
    /// Create a new performance monitor
    pub fn new(config: MemoryConfig) -> Self {
        Self {
            memory_usage: Arc::new(Mutex::new(MemoryUsage::default())),
            metrics: Arc::new(Mutex::new(PerformanceMetrics::default())),
            config,
            cleanup_callbacks: HashMap::new(),
            last_memory_check: Instant::now(),
            monitoring_enabled: true,
        }
    }
    
    /// Enable or disable performance monitoring
    pub fn set_monitoring_enabled(&mut self, enabled: bool) {
        self.monitoring_enabled = enabled;
    }
    
    /// Register a cleanup callback for a component
    pub fn register_cleanup_callback<F>(&mut self, component: String, callback: F)
    where
        F: Fn(CleanupPriority) + Send + Sync + 'static,
    {
        self.cleanup_callbacks.insert(component, Box::new(callback));
    }
    
    /// Update memory usage for a component
    pub fn update_memory_usage(&self, component: &str, bytes: usize) {
        if !self.monitoring_enabled {
            return;
        }
        
        if let Ok(mut usage) = self.memory_usage.lock() {
            match component {
                "dom" => usage.dom_memory = bytes,
                "layout" => usage.layout_memory = bytes,
                "renderer" => usage.renderer_memory = bytes,
                "js" => usage.js_memory = bytes,
                "network_cache" => usage.network_cache_memory = bytes,
                "image_cache" => usage.image_cache_memory = bytes,
                "font_cache" => usage.font_cache_memory = bytes,
                _ => log::warn!("Unknown memory component: {}", component),
            }
            
            usage.calculate_total();
            
            // Check for memory pressure
            let pressure = self.assess_memory_pressure(&usage);
            if pressure != MemoryPressure::Low {
                self.handle_memory_pressure(pressure);
            }
        }
    }
    
    /// Add performance measurement
    pub fn add_measurement(&self, measurement_type: &str, value: u64) {
        if !self.monitoring_enabled {
            return;
        }
        
        if let Ok(mut metrics) = self.metrics.lock() {
            match measurement_type {
                "page_load" => metrics.add_page_load_time(value),
                "layout" => metrics.add_layout_time(value),
                "render" => metrics.add_render_time(value),
                "js_execution" => metrics.add_js_execution_time(value),
                "network" => metrics.add_network_time(value),
                _ => log::warn!("Unknown measurement type: {}", measurement_type),
            }
        }
    }
    
    /// Add frame rate measurement
    pub fn add_frame_rate(&self, fps: f64) {
        if !self.monitoring_enabled {
            return;
        }
        
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.add_frame_rate(fps);
        }
    }
    
    /// Set cache hit ratio
    pub fn set_cache_hit_ratio(&self, component: &str, ratio: f64) {
        if !self.monitoring_enabled {
            return;
        }
        
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.set_cache_hit_ratio(component.to_string(), ratio);
        }
    }
    
    /// Get current memory usage
    pub fn get_memory_usage(&self) -> MemoryUsage {
        self.memory_usage.lock().unwrap().clone()
    }
    
    /// Get performance summary
    pub fn get_performance_summary(&self) -> PerformanceSummary {
        self.metrics.lock().unwrap().get_summary()
    }
    
    /// Force memory cleanup
    pub fn force_cleanup(&self, priority: CleanupPriority) {
        log::info!("Forcing memory cleanup with priority: {:?}", priority);
        
        for (component, callback) in &self.cleanup_callbacks {
            log::debug!("Cleaning up component: {}", component);
            callback(priority.clone());
        }
        
        // Record memory pressure event
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_memory_pressure();
        }
    }
    
    /// Assess current memory pressure level
    fn assess_memory_pressure(&self, usage: &MemoryUsage) -> MemoryPressure {
        if usage.total_memory >= self.config.critical_threshold {
            MemoryPressure::Critical
        } else if usage.total_memory >= self.config.cleanup_threshold {
            MemoryPressure::High
        } else if usage.total_memory >= (self.config.cleanup_threshold * 3 / 4) {
            MemoryPressure::Medium
        } else {
            MemoryPressure::Low
        }
    }
    
    /// Handle memory pressure by triggering appropriate cleanup
    fn handle_memory_pressure(&self, pressure: MemoryPressure) {
        let cleanup_priority = match pressure {
            MemoryPressure::Low => return, // No cleanup needed
            MemoryPressure::Medium => CleanupPriority::Low,
            MemoryPressure::High => CleanupPriority::Medium,
            MemoryPressure::Critical => CleanupPriority::Critical,
        };
        
        log::info!("Memory pressure detected: {:?}, triggering cleanup", pressure);
        self.force_cleanup(cleanup_priority);
    }
    
    /// Check if memory usage is within limits
    pub fn is_memory_within_limits(&self) -> bool {
        if let Ok(usage) = self.memory_usage.lock() {
            usage.total_memory <= self.config.max_total_memory
        } else {
            true // Assume OK if we can't check
        }
    }
    
    /// Get memory pressure level
    pub fn get_memory_pressure(&self) -> MemoryPressure {
        if let Ok(usage) = self.memory_usage.lock() {
            self.assess_memory_pressure(&usage)
        } else {
            MemoryPressure::Low
        }
    }
    
    /// Periodic memory check (should be called regularly)
    pub fn check_memory_periodically(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_memory_check) >= Duration::from_secs(30) {
            self.last_memory_check = now;
            
            let pressure = self.get_memory_pressure();
            if pressure != MemoryPressure::Low {
                self.handle_memory_pressure(pressure);
            }
        }
    }
    
    /// Reset all performance metrics
    pub fn reset_metrics(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            *metrics = PerformanceMetrics::default();
        }
    }
    
    /// Update memory configuration
    pub fn update_config(&mut self, config: MemoryConfig) {
        self.config = config;
    }
}

/// Performance optimization recommendations
#[derive(Debug, Clone)]
pub enum OptimizationRecommendation {
    /// Increase cache size for component
    IncreaseCacheSize(String, usize),
    /// Decrease cache size for component
    DecreaseCacheSize(String, usize),
    /// Enable viewport culling
    EnableViewportCulling,
    /// Increase cleanup frequency
    IncreaseCleanupFrequency,
    /// Reduce image quality
    ReduceImageQuality,
    /// Optimize layout computation
    OptimizeLayoutComputation,
    /// Reduce JavaScript complexity
    ReduceJavaScriptComplexity,
}

/// Performance optimizer that provides recommendations
pub struct PerformanceOptimizer {
    monitor: Arc<PerformanceMonitor>,
    optimization_threshold: f64,
}

impl PerformanceOptimizer {
    /// Create a new performance optimizer
    pub fn new(monitor: Arc<PerformanceMonitor>) -> Self {
        Self {
            monitor,
            optimization_threshold: 0.7, // 70% threshold for optimization recommendations
        }
    }
    
    /// Analyze performance and provide recommendations
    pub fn analyze_and_recommend(&self) -> Vec<OptimizationRecommendation> {
        let mut recommendations = Vec::new();
        
        let memory_usage = self.monitor.get_memory_usage();
        let performance_summary = self.monitor.get_performance_summary();
        
        // Memory-based recommendations
        let memory_utilization = memory_usage.total_memory as f64 / 
                                self.monitor.config.max_total_memory as f64;
        
        if memory_utilization > self.optimization_threshold {
            recommendations.push(OptimizationRecommendation::IncreaseCleanupFrequency);
            
            // Recommend reducing cache sizes
            if memory_usage.image_cache_memory > 50 * 1024 * 1024 {
                recommendations.push(OptimizationRecommendation::DecreaseCacheSize(
                    "images".to_string(), 
                    memory_usage.image_cache_memory / 2
                ));
            }
        }
        
        // Performance-based recommendations
        if performance_summary.average_layout_ms > 50.0 {
            recommendations.push(OptimizationRecommendation::OptimizeLayoutComputation);
            recommendations.push(OptimizationRecommendation::EnableViewportCulling);
        }
        
        if performance_summary.average_fps < 30.0 {
            recommendations.push(OptimizationRecommendation::ReduceImageQuality);
        }
        
        // Cache efficiency recommendations
        for (component, hit_ratio) in &performance_summary.cache_hit_ratios {
            if *hit_ratio < 0.5 {
                recommendations.push(OptimizationRecommendation::IncreaseCacheSize(
                    component.clone(),
                    self.monitor.config.cache_limits.get(component).unwrap_or(&0) * 2
                ));
            }
        }
        
        recommendations
    }
    
    /// Set optimization threshold
    pub fn set_optimization_threshold(&mut self, threshold: f64) {
        self.optimization_threshold = threshold.clamp(0.0, 1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_memory_usage_calculation() {
        let mut usage = MemoryUsage::default();
        usage.dom_memory = 1024;
        usage.layout_memory = 2048;
        usage.renderer_memory = 4096;
        usage.calculate_total();
        
        assert_eq!(usage.total_memory, 7168);
    }
    
    #[test]
    fn test_performance_metrics() {
        let mut metrics = PerformanceMetrics::default();
        
        metrics.add_page_load_time(1000);
        metrics.add_page_load_time(1500);
        metrics.add_page_load_time(800);
        
        let avg = metrics.average_page_load_time().unwrap();
        assert!((avg - 1100.0).abs() < 0.1);
    }
    
    #[test]
    fn test_memory_pressure_assessment() {
        let config = MemoryConfig::default();
        let monitor = PerformanceMonitor::new(config);
        
        let mut usage = MemoryUsage::default();
        usage.total_memory = 100 * 1024 * 1024; // 100MB
        
        let pressure = monitor.assess_memory_pressure(&usage);
        assert_eq!(pressure, MemoryPressure::Low);
        
        usage.total_memory = 450 * 1024 * 1024; // 450MB
        let pressure = monitor.assess_memory_pressure(&usage);
        assert_eq!(pressure, MemoryPressure::High);
    }
    
    #[test]
    fn test_performance_optimizer() {
        let config = MemoryConfig::default();
        let monitor = Arc::new(PerformanceMonitor::new(config));
        let optimizer = PerformanceOptimizer::new(monitor.clone());
        
        // Simulate high memory usage
        monitor.update_memory_usage("dom", 200 * 1024 * 1024);
        monitor.update_memory_usage("layout", 150 * 1024 * 1024);
        monitor.update_memory_usage("renderer", 200 * 1024 * 1024);
        
        let recommendations = optimizer.analyze_and_recommend();
        assert!(!recommendations.is_empty());
    }
}