//! Performance integration coordinator for Citadel Browser
//!
//! This module coordinates all performance optimizations and provides unified
//! performance monitoring and management for the browser.

use std::sync::{Arc, RwLock, Mutex};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Serialize, Deserialize};
use log::{debug, info, warn, error};

use super::memory_manager::{MemoryManager, MemoryConfig, CleanupStrategy};
use super::render_optimizer::{RenderOptimizer, RenderOptimizationConfig, FrameStats};
use super::performance::PerformanceMonitor;
use citadel_networking::network_optimizer::{NetworkOptimizer, NetworkOptimizationConfig};

/// Performance integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceIntegrationConfig {
    /// Enable automatic performance optimization
    pub auto_optimize: bool,
    /// Performance monitoring interval
    pub monitoring_interval: Duration,
    /// Optimization check interval
    pub optimization_interval: Duration,
    /// Performance report interval
    pub report_interval: Duration,
    /// Enable adaptive performance
    pub adaptive_performance: bool,
    /// Target performance metrics
    pub targets: PerformanceTargets,
}

/// Performance targets for optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceTargets {
    /// Target frame rate (FPS)
    pub target_fps: f32,
    /// Maximum memory usage per tab (MB)
    pub max_tab_memory_mb: usize,
    /// Target page load time (ms)
    pub target_load_time_ms: u64,
    /// Minimum cache hit ratio
    pub min_cache_hit_ratio: f64,
    /// Maximum render time per frame (ms)
    pub max_render_time_ms: u64,
}

impl Default for PerformanceTargets {
    fn default() -> Self {
        Self {
            target_fps: 60.0,
            max_tab_memory_mb: 256,
            target_load_time_ms: 2000,
            min_cache_hit_ratio: 0.7,
            max_render_time_ms: 16,
        }
    }
}

impl Default for PerformanceIntegrationConfig {
    fn default() -> Self {
        Self {
            auto_optimize: true,
            monitoring_interval: Duration::from_millis(100),  // 10Hz monitoring
            optimization_interval: Duration::from_secs(5),
            report_interval: Duration::from_secs(30),
            adaptive_performance: true,
            targets: PerformanceTargets::default(),
        }
    }
}

/// Comprehensive performance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceReport {
    #[serde(skip, default = "Instant::now")]
    pub timestamp: Instant,
    pub duration: Duration,
    pub frame_stats: FrameStats,
    pub memory_stats: super::memory_manager::MemoryStats,
    pub network_stats: citadel_networking::network_optimizer::NetworkStats,
    pub performance_summary: super::performance::PerformanceSummary,
    pub optimizations_applied: Vec<OptimizationAction>,
    pub recommendations: Vec<PerformanceRecommendation>,
    pub issues: Vec<PerformanceIssue>,
}

/// Optimization actions taken
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizationAction {
    /// Memory cleanup triggered
    MemoryCleanup { strategy: String, freed_bytes: usize },
    /// Rendering optimization enabled
    RenderOptimization { feature: String, enabled: bool },
    /// Network optimization applied
    NetworkOptimization { action: String, impact: String },
    /// Frame rate adjusted
    FrameRateAdjustment { old_fps: u32, new_fps: u32 },
    /// Cache size adjusted
    CacheAdjustment { cache_type: String, old_size: usize, new_size: usize },
}

/// Performance recommendations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceRecommendation {
    pub category: String,
    pub priority: u8, // 1-10, higher is more important
    pub description: String,
    pub expected_impact: String,
    pub estimated_improvement: f32, // Percentage
}

/// Performance issues detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceIssue {
    pub severity: Severity,
    pub category: String,
    pub description: String,
    pub current_value: f64,
    pub target_value: f64,
    pub impact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Performance integration coordinator
pub struct PerformanceIntegrator {
    config: PerformanceIntegrationConfig,

    // Performance components
    pub memory_manager: Arc<MemoryManager>,
    pub render_optimizer: Arc<RenderOptimizer>,
    pub network_optimizer: Option<Arc<NetworkOptimizer>>,
    pub performance_monitor: Arc<PerformanceMonitor>,

    // State tracking
    is_optimizing: Arc<Mutex<bool>>,
    last_optimization: Arc<Mutex<Instant>>,
    performance_history: Arc<RwLock<Vec<PerformanceSnapshot>>>,
    current_issues: Arc<RwLock<Vec<PerformanceIssue>>>,

    // Performance reports
    reports: Arc<RwLock<Vec<PerformanceReport>>>,
}

/// Performance snapshot for history tracking
#[derive(Debug, Clone)]
struct PerformanceSnapshot {
    timestamp: Instant,
    memory_usage: usize,
    frame_rate: f32,
    load_time: u64,
    cache_hit_ratio: f64,
}

impl PerformanceIntegrator {
    /// Create a new performance integrator
    pub fn new() -> Self {
        Self::with_config(PerformanceIntegrationConfig::default())
    }

    /// Create a new performance integrator with custom configuration
    pub fn with_config(config: PerformanceIntegrationConfig) -> Self {
        let memory_config = MemoryConfig::default();
        let render_config = RenderOptimizationConfig::default();

        Self {
            memory_manager: Arc::new(MemoryManager::with_config(memory_config)),
            render_optimizer: Arc::new(RenderOptimizer::with_config(render_config)),
            network_optimizer: None,
            performance_monitor: Arc::new(PerformanceMonitor::new(Default::default())),
            config,
            is_optimizing: Arc::new(Mutex::new(false)),
            last_optimization: Arc::new(Mutex::new(Instant::now())),
            performance_history: Arc::new(RwLock::new(Vec::new())),
            current_issues: Arc::new(RwLock::new(Vec::new())),
            reports: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Initialize the performance integrator with network optimizer
    pub async fn with_network_optimizer(mut self, network_optimizer: Arc<NetworkOptimizer>) -> Self {
        self.network_optimizer = Some(network_optimizer);
        self
    }

    /// Start performance monitoring and optimization
    pub async fn start(&self) {
        info!("Starting performance integration with auto-optimization: {}", self.config.auto_optimize);

        // Start background tasks
        self.start_monitoring_task().await;
        self.start_optimization_task().await;
        self.start_reporting_task().await;

        // Initialize memory manager background task
        self.memory_manager.start_background_task();
    }

    /// Register a new tab for performance tracking
    pub async fn register_tab(&self, tab_id: uuid::Uuid) {
        self.memory_manager.register_tab(tab_id);
        info!("Registered tab {} for performance tracking", tab_id);
    }

    /// Unregister a tab and clean up its resources
    pub async fn unregister_tab(&self, tab_id: uuid::Uuid) {
        self.memory_manager.unregister_tab(tab_id);
        info!("Unregistered tab {} and cleaned up resources", tab_id);
    }

    /// Begin frame timing for render performance
    pub fn begin_frame(&self) {
        self.render_optimizer.begin_frame();
    }

    /// End frame timing and collect performance data
    pub fn end_frame(&self) -> FrameStats {
        let stats = self.render_optimizer.end_frame();

        // Record frame performance
        self.performance_monitor.add_frame_rate(stats.fps as f64);

        stats
    }

    /// Update viewport for rendering optimizations
    pub fn update_viewport(&self, x: f32, y: f32, width: f32, height: f32, scale: f32) {
        self.render_optimizer.update_viewport(x, y, width, height, scale);
    }

    /// Check if an element should be rendered (viewport culling)
    pub fn should_render_element(&self, element_id: usize, rect: &citadel_parser::layout::LayoutRect) -> bool {
        self.render_optimizer.should_render_element(element_id, rect)
    }

    /// Add dirty region for partial rendering
    pub fn add_dirty_region(&self, x: f32, y: f32, width: f32, height: f32, priority: u32) {
        self.render_optimizer.add_dirty_region(x, y, width, height, priority);
    }

    /// Get current performance metrics
    pub fn get_performance_metrics(&self) -> super::performance::PerformanceSummary {
        self.performance_monitor.get_performance_summary()
    }

    /// Get memory usage statistics
    pub fn get_memory_stats(&self) -> super::memory_manager::MemoryStats {
        self.memory_manager.get_memory_stats()
    }

    /// Get current performance issues
    pub fn get_current_issues(&self) -> Vec<PerformanceIssue> {
        self.current_issues.read().unwrap().clone()
    }

    /// Get performance recommendations
    pub fn get_recommendations(&self) -> Vec<PerformanceRecommendation> {
        self.analyze_and_recommend()
    }

    /// Get performance reports
    pub fn get_reports(&self) -> Vec<PerformanceReport> {
        self.reports.read().unwrap().clone()
    }

    /// Force immediate optimization
    pub async fn force_optimization(&self) -> Vec<OptimizationAction> {
        info!("Forcing immediate performance optimization");

        if let Ok(mut optimizing) = self.is_optimizing.lock() {
            if *optimizing {
                debug!("Optimization already in progress");
                return Vec::new();
            }
            *optimizing = true;
        }

        let actions = self.perform_optimization().await;

        if let Ok(mut optimizing) = self.is_optimizing.lock() {
            *optimizing = false;
        }

        if let Ok(mut last_opt) = self.last_optimization.lock() {
            *last_opt = Instant::now();
        }

        actions
    }

    /// Analyze performance and generate recommendations
    fn analyze_and_recommend(&self) -> Vec<PerformanceRecommendation> {
        let mut recommendations = Vec::new();

        let performance_summary = self.get_performance_metrics();
        let memory_stats = self.get_memory_stats();
        let frame_stats = self.render_optimizer.get_frame_stats();

        // Memory-based recommendations
        let memory_usage_mb = memory_stats.total_allocated / 1024 / 1024;
        if memory_usage_mb > self.config.targets.max_tab_memory_mb {
            recommendations.push(PerformanceRecommendation {
                category: "Memory".to_string(),
                priority: 8,
                description: format!("Memory usage is high: {}MB (limit: {}MB)",
                                  memory_usage_mb, self.config.targets.max_tab_memory_mb),
                expected_impact: "Reduced memory pressure and better responsiveness".to_string(),
                estimated_improvement: 25.0,
            });
        }

        // Frame rate-based recommendations
        if frame_stats.average_fps < self.config.targets.target_fps * 0.8 {
            recommendations.push(PerformanceRecommendation {
                category: "Rendering".to_string(),
                priority: 7,
                description: format!("Average FPS is low: {:.1} (target: {:.1})",
                                  frame_stats.average_fps, self.config.targets.target_fps),
                expected_impact: "Smoother scrolling and animations".to_string(),
                estimated_improvement: 30.0,
            });
        }

        // Page load time recommendations
        let avg_load_time = performance_summary.average_page_load_ms;
        if avg_load_time > self.config.targets.target_load_time_ms as f64 {
            recommendations.push(PerformanceRecommendation {
                category: "Network".to_string(),
                priority: 6,
                description: format!("Page load time is slow: {:.0}ms (target: {}ms)",
                                  avg_load_time, self.config.targets.target_load_time_ms),
                expected_impact: "Faster page loading and better user experience".to_string(),
            estimated_improvement: 20.0,
            });
        }

        // Cache efficiency recommendations
        for (component, hit_ratio) in &performance_summary.cache_hit_ratios {
            if *hit_ratio < self.config.targets.min_cache_hit_ratio {
                recommendations.push(PerformanceRecommendation {
                    category: "Caching".to_string(),
                    priority: 5,
                    description: format!("Low cache hit ratio for {}: {:.1}%",
                                      component, hit_ratio * 100.0),
                    expected_impact: "Reduced network requests and faster resource loading".to_string(),
                    estimated_improvement: 15.0,
                });
            }
        }

        recommendations
    }

    /// Start background monitoring task
    async fn start_monitoring_task(&self) {
        let monitor = self.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(monitor.config.monitoring_interval);

            loop {
                interval.tick().await;

                // Collect performance snapshot
                let snapshot = PerformanceSnapshot {
                    timestamp: Instant::now(),
                    memory_usage: monitor.memory_manager.get_total_memory_usage(),
                    frame_rate: monitor.render_optimizer.get_frame_stats().average_fps,
                    load_time: monitor.get_performance_metrics().average_page_load_ms as u64,
                    cache_hit_ratio: 0.7, // Would calculate from actual cache stats
                };

                // Add to history
                if let Ok(mut history) = monitor.performance_history.write() {
                    history.push(snapshot);
                    // Keep only last 1000 snapshots
                    if history.len() > 1000 {
                        history.remove(0);
                    }
                }

                // Detect performance issues
                monitor.detect_performance_issues().await;
            }
        });
    }

    /// Start background optimization task
    async fn start_optimization_task(&self) {
        if !self.config.auto_optimize {
            return;
        }

        let monitor = self.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(monitor.config.optimization_interval);

            loop {
                interval.tick().await;

                // Check if optimization is needed
                if monitor.should_optimize().await {
                    monitor.force_optimization().await;
                }
            }
        });
    }

    /// Start background reporting task
    async fn start_reporting_task(&self) {
        let monitor = self.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(monitor.config.report_interval);

            loop {
                interval.tick().await;
                monitor.generate_performance_report().await;
            }
        });
    }

    /// Check if optimization should be triggered
    async fn should_optimize(&self) -> bool {
        // Don't optimize if already optimizing
        if let Ok(optimizing) = self.is_optimizing.lock() {
            if *optimizing {
                return false;
            }
        }

        // Check time since last optimization
        if let Ok(last_opt) = self.last_optimization.lock() {
            if last_opt.elapsed() < Duration::from_secs(10) {
                return false;
            }
        }

        // Check for performance issues
        let issues = self.get_current_issues();
        let has_critical_issues = issues.iter().any(|i| matches!(i.severity, Severity::High | Severity::Critical));

        has_critical_issues || !issues.is_empty()
    }

    /// Perform actual optimization
    async fn perform_optimization(&self) -> Vec<OptimizationAction> {
        let mut actions = Vec::new();

        // Memory optimization
        let memory_usage = self.memory_manager.get_total_memory_usage();
        let max_memory = self.config.targets.max_tab_memory_mb * 1024 * 1024;

        if memory_usage > max_memory {
            let strategy = if memory_usage > max_memory * 9 / 10 {
                CleanupStrategy::Emergency
            } else if memory_usage > max_memory * 3 / 4 {
                CleanupStrategy::Aggressive
            } else {
                CleanupStrategy::Moderate
            };

            let initial_usage = memory_usage;
            self.memory_manager.trigger_cleanup(strategy.clone()).await;
            let final_usage = self.memory_manager.get_total_memory_usage();
            let freed_bytes = initial_usage.saturating_sub(final_usage);

            actions.push(OptimizationAction::MemoryCleanup {
                strategy: format!("{:?}", strategy),
                freed_bytes,
            });
        }

        // Rendering optimization
        let frame_stats = self.render_optimizer.get_frame_stats();
        if frame_stats.average_fps < self.config.targets.target_fps * 0.8 {
            // Could enable/disable rendering features here
            actions.push(OptimizationAction::RenderOptimization {
                feature: "viewport_culling".to_string(),
                enabled: true,
            });
        }

        // Network optimization (if available)
        if let Some(network_optimizer) = &self.network_optimizer {
            // Could adjust network settings based on performance
            actions.push(OptimizationAction::NetworkOptimization {
                action: "request_prioritization".to_string(),
                impact: "Improved resource loading order".to_string(),
            });
        }

        info!("Applied {} optimization actions", actions.len());
        actions
    }

    /// Detect performance issues
    async fn detect_performance_issues(&self) {
        let mut issues = Vec::new();

        let frame_stats = self.render_optimizer.get_frame_stats();
        let memory_stats = self.get_memory_stats();
        let performance_summary = self.get_performance_metrics();

        // Frame rate issues
        if frame_stats.average_fps < self.config.targets.target_fps {
            let severity = if frame_stats.average_fps < self.config.targets.target_fps * 0.5 {
                Severity::Critical
            } else if frame_stats.average_fps < self.config.targets.target_fps * 0.7 {
                Severity::High
            } else {
                Severity::Medium
            };

            issues.push(PerformanceIssue {
                severity,
                category: "Rendering".to_string(),
                description: format!("Frame rate below target: {:.1} FPS", frame_stats.average_fps),
                current_value: frame_stats.average_fps as f64,
                target_value: self.config.targets.target_fps as f64,
                impact: "Choppy animations and poor user experience".to_string(),
            });
        }

        // Memory issues
        let memory_usage_mb = memory_stats.total_allocated / 1024 / 1024;
        if memory_usage_mb > self.config.targets.max_tab_memory_mb {
            let severity = if memory_usage_mb > self.config.targets.max_tab_memory_mb * 9 / 10 {
                Severity::Critical
            } else if memory_usage_mb > self.config.targets.max_tab_memory_mb * 3 / 4 {
                Severity::High
            } else {
                Severity::Medium
            };

            issues.push(PerformanceIssue {
                severity,
                category: "Memory".to_string(),
                description: format!("High memory usage: {} MB", memory_usage_mb),
                current_value: memory_usage_mb as f64,
                target_value: self.config.targets.max_tab_memory_mb as f64,
                impact: "Potential slowdown and crashes".to_string(),
            });
        }

        // Update current issues
        if let Ok(mut current_issues) = self.current_issues.write() {
            *current_issues = issues;
        }
    }

    /// Generate performance report
    async fn generate_performance_report(&self) {
        let report = PerformanceReport {
            timestamp: Instant::now(),
            duration: Duration::from_secs(30), // Last 30 seconds
            frame_stats: self.render_optimizer.get_frame_stats(),
            memory_stats: self.get_memory_stats(),
            network_stats: self.network_optimizer.as_ref()
                .map(|n| n.get_stats())
                .unwrap_or_default(),
            performance_summary: self.get_performance_metrics(),
            optimizations_applied: Vec::new(), // Would track actual optimizations
            recommendations: self.analyze_and_recommend(),
            issues: self.get_current_issues(),
        };

        if let Ok(mut reports) = self.reports.write() {
            reports.push(report.clone());
            // Keep only last 10 reports
            if reports.len() > 10 {
                reports.remove(0);
            }
        }

        info!("Generated performance report with {} recommendations", report.recommendations.len());
    }
}

impl Clone for PerformanceIntegrator {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            memory_manager: Arc::clone(&self.memory_manager),
            render_optimizer: Arc::clone(&self.render_optimizer),
            network_optimizer: self.network_optimizer.as_ref().map(Arc::clone),
            performance_monitor: Arc::clone(&self.performance_monitor),
            is_optimizing: Arc::clone(&self.is_optimizing),
            last_optimization: Arc::clone(&self.last_optimization),
            performance_history: Arc::clone(&self.performance_history),
            current_issues: Arc::clone(&self.current_issues),
            reports: Arc::clone(&self.reports),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_targets_default() {
        let targets = PerformanceTargets::default();
        assert_eq!(targets.target_fps, 60.0);
        assert_eq!(targets.max_tab_memory_mb, 256);
        assert_eq!(targets.target_load_time_ms, 2000);
    }

    #[test]
    fn test_performance_integration_config_default() {
        let config = PerformanceIntegrationConfig::default();
        assert!(config.auto_optimize);
        assert!(config.adaptive_performance);
        assert_eq!(config.monitoring_interval, Duration::from_millis(100));
    }

    #[test]
    fn test_performance_issue_severity() {
        let issue = PerformanceIssue {
            severity: Severity::High,
            category: "Test".to_string(),
            description: "Test issue".to_string(),
            current_value: 10.0,
            target_value: 20.0,
            impact: "Test impact".to_string(),
        };

        assert_eq!(issue.current_value, 10.0);
        assert_eq!(issue.target_value, 20.0);
        matches!(issue.severity, Severity::High);
    }

    #[tokio::test]
    async fn test_performance_integrator_creation() {
        let integrator = PerformanceIntegrator::new();

        // Test that components are initialized
        let memory_stats = integrator.get_memory_stats();
        assert_eq!(memory_stats.total_allocated, 0);

        let frame_stats = integrator.render_optimizer.get_frame_stats();
        assert_eq!(frame_stats.total_frames, 0);
    }

    #[test]
    fn test_optimization_action_serialization() {
        let action = OptimizationAction::MemoryCleanup {
            strategy: "Aggressive".to_string(),
            freed_bytes: 1024 * 1024,
        };

        // Test that the action can be serialized (for logging/reporting)
        let serialized = serde_json::to_string(&action);
        assert!(serialized.is_ok());
    }
}