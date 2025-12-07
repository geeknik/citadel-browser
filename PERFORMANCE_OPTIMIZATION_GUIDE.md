# Citadel Browser Performance Optimization Guide

This guide provides practical information on how to use and customize the performance optimization system in Citadel Browser.

## Quick Start

### Basic Usage

```rust
use citadel_browser::{
    PerformanceIntegrator, PerformanceTargets,
    MemoryConfig, RenderOptimizationConfig
};

// Create performance integrator with default settings
let integrator = PerformanceIntegrator::new();

// Start performance monitoring
integrator.start().await;

// Register a tab for performance tracking
let tab_id = uuid::Uuid::new_v4();
integrator.register_tab(tab_id).await;

// Begin frame timing
integrator.begin_frame();

// ... your rendering code ...

// End frame timing and get stats
let frame_stats = integrator.end_frame();
println!("FPS: {:.1}", frame_stats.fps);
```

### Custom Configuration

```rust
use citadel_browser::performance_integrator::{
    PerformanceIntegrationConfig, PerformanceTargets
};

// Custom performance targets
let targets = PerformanceTargets {
    target_fps: 120.0,              // High refresh rate display
    max_tab_memory_mb: 512,         // More memory per tab
    target_load_time_ms: 1500,      // Faster page loads
    min_cache_hit_ratio: 0.85,      // Better caching
    max_render_time_ms: 8,          // 120 FPS target
};

let config = PerformanceIntegrationConfig {
    auto_optimize: true,
    adaptive_performance: true,
    targets,
    ..Default::default()
};

let integrator = PerformanceIntegrator::with_config(config);
```

## Performance Components

### 1. Memory Manager

The Memory Manager handles tab isolation, memory pooling, and cleanup.

```rust
use citadel_browser::{MemoryManager, MemoryConfig, CleanupStrategy};

// Configure memory management
let config = MemoryConfig {
    max_tab_memory: 256 * 1024 * 1024,  // 256MB per tab
    max_total_memory: 1024 * 1024 * 1024, // 1GB total
    background_tab_limit: 64 * 1024 * 1024, // 64MB for background tabs
    ..Default::default()
};

let memory_manager = MemoryManager::with_config(config);

// Register a tab
let tab_id = uuid::Uuid::new_v4();
memory_manager.register_tab(tab_id);

// Update memory usage for components
memory_manager.update_tab_memory(tab_id, "dom", 1024 * 1024);
memory_manager.update_tab_memory(tab_id, "layout", 512 * 1024);

// Set tab as background (reduces memory usage)
memory_manager.set_tab_background(tab_id, true);

// Trigger cleanup
memory_manager.trigger_cleanup(CleanupStrategy::Moderate).await;

// Unregister tab and clean up
memory_manager.unregister_tab(tab_id);
```

#### Memory Pool Usage

```rust
use citadel_browser::memory_manager::MemoryPool;

// Create memory pool for layout vectors
let mut layout_pool = MemoryPool::new(
    1000,  // Pool size
    || Vec::new(),
    |vec| vec.clear()  // Reset function
);

// Acquire from pool
let mut vec = layout_pool.acquire();
vec.push(1);
vec.push(2);

// Return to pool
layout_pool.release(vec);
```

### 2. Render Optimizer

The Render Optimizer handles viewport culling, dirty regions, and frame timing.

```rust
use citadel_browser::{RenderOptimizer, RenderOptimizationConfig};

// Configure rendering
let config = RenderOptimizationConfig {
    viewport_culling: ViewportCullingConfig {
        enabled: true,
        margin: 200.0,  // 200px margin around viewport
        ..Default::default()
    },
    frame_rate: FrameRateConfig {
        target_fps: 120,
        adaptive: true,
        ..Default::default()
    },
    ..Default::default()
};

let render_optimizer = RenderOptimizer::with_config(config);

// Update viewport for culling
render_optimizer.update_viewport(0.0, 0.0, 1920.0, 1080.0, 1.0);

// Check if element should be rendered
let rect = citadel_parser::layout::LayoutRect {
    x: 100.0, y: 100.0, width: 50.0, height: 50.0
};

if render_optimizer.should_render_element(0, &rect) {
    // Render the element
}

// Add dirty region for partial updates
render_optimizer.add_dirty_region(100.0, 100.0, 50.0, 50.0, 1);

// Get and clear dirty regions
let regions = render_optimizer.get_dirty_regions();
render_optimizer.clear_dirty_regions();

// Start smooth scroll animation
render_optimizer.start_smooth_scroll(
    "scroll_area".to_string(),
    0.0,   // start_y
    500.0  // target_y
);

// Update animations in render loop
let scroll_positions = render_optimizer.update_scroll_animations();
```

#### Frame Timing Integration

```rust
// In your render loop:
render_optimizer.begin_frame();

// ... render your frame ...

let stats = render_optimizer.end_frame();

// Check if should skip frame for performance
if render_optimizer.should_skip_frame() {
    // Skip expensive rendering this frame
}
```

### 3. Performance Dashboard

The Performance Dashboard provides real-time monitoring and insights.

```rust
use citadel_browser::{PerformanceDashboard, DashboardMessage, DashboardTab};

// Create dashboard
let dashboard = PerformanceDashboard::new(integrator);

// Get current view
let view = dashboard.view();

// Handle UI messages
dashboard.update(DashboardMessage::SelectTab(DashboardTab::Memory));
dashboard.update(DashboardMessage::RefreshData);

// Run benchmark
dashboard.update(DashboardMessage::RunBenchmark);

// Get real-time metrics
let metrics = dashboard.get_current_metrics();
println!("Current FPS: {:.1}", metrics.fps);
println!("Memory Usage: {:.1} MB", metrics.memory_usage_mb);

// Get active alerts
let alerts = dashboard.get_active_alerts();
for alert in alerts {
    if !alert.acknowledged {
        println!("Alert: {} - {}", alert.title, alert.description);
    }
}
```

### 4. Benchmarking

The Benchmark Suite provides comprehensive performance testing.

```rust
use citadel_browser::PerformanceBenchmark;

let benchmark = PerformanceBenchmark::new();

// Run individual test
let result = benchmark.run_benchmark("memory_management").await;
if let Some(result) = result {
    println!("Memory benchmark: {:.2} ops/sec", result.operations_per_second);
}

// Run full benchmark suite
let report = benchmark.run_full_benchmark().await;

println!("Overall Score: {:.1}/100", report.summary.overall_score);
println!("Memory Efficiency: {:.1}/100", report.summary.memory_efficiency_score);
println!("Render Performance: {:.1}/100", report.summary.render_performance_score);

// View recommendations
for recommendation in &report.recommendations {
    println!("{} (Priority: {}): {}",
             recommendation.category,
             recommendation.priority,
             recommendation.description);
}
```

## Performance Monitoring

### Real-time Metrics

```rust
// Get current performance metrics
let metrics = integrator.get_performance_metrics();

println!("Page Load Time: {:.0} ms", metrics.average_page_load_ms);
println!("Layout Time: {:.0} ms", metrics.average_layout_ms);
println!("Render Time: {:.0} ms", metrics.average_render_time_ms);

// Cache efficiency
for (component, hit_ratio) in &metrics.cache_hit_ratios {
    println!("{} Cache Hit Ratio: {:.1}%", component, hit_ratio * 100.0);
}
```

### Memory Statistics

```rust
// Get memory usage statistics
let stats = integrator.get_memory_stats();

println!("Total Allocated: {:.1} MB", stats.total_allocated as f64 / 1024.0 / 1024.0);
println!("Total Freed: {:.1} MB", stats.total_freed as f64 / 1024.0 / 1024.0);
println!("Peak Usage: {:.1} MB", stats.peak_usage as f64 / 1024.0 / 1024.0);
println!("Active Tabs: {}", stats.tab_count);
println!("Background Tabs: {}", stats.background_tabs);
println!("Cache Hits: {}", stats.cache_hits);
println!("Cache Misses: {}", stats.cache_misses);
```

### Performance Issues

```rust
// Get current performance issues
let issues = integrator.get_current_issues();

for issue in &issues {
    match issue.severity {
        Severity::Critical => println!("🔴 CRITICAL: {}", issue.description),
        Severity::High => println!("🟠 HIGH: {}", issue.description),
        Severity::Medium => println!("🟡 MEDIUM: {}", issue.description),
        Severity::Low => println!("🔵 LOW: {}", issue.description),
    }
}
```

## Advanced Usage

### Custom Optimization Strategies

```rust
use citadel_browser::performance_integrator::OptimizationAction;

// Force optimization manually
let actions = integrator.force_optimization().await;

for action in &actions {
    match action {
        OptimizationAction::MemoryCleanup { strategy, freed_bytes } => {
            println!("Memory cleanup ({}) freed {} MB", strategy, freed_bytes / 1024 / 1024);
        },
        OptimizationAction::RenderOptimization { feature, enabled } => {
            println!("{} optimization {}", feature, if *enabled { "enabled" } else { "disabled" });
        },
        // ... other action types
    }
}
```

### Adaptive Performance

```rust
use citadel_browser::performance_integrator::PerformanceIntegrationConfig;

let config = PerformanceIntegrationConfig {
    adaptive_performance: true,
    auto_optimize: true,
    monitoring_interval: Duration::from_millis(100),  // 10Hz
    optimization_interval: Duration::from_secs(5),
    ..Default::default()
};

// The system will automatically:
// 1. Monitor performance metrics
// 2. Detect performance issues
// 3. Apply optimizations automatically
// 4. Adjust settings based on device capabilities
```

### Custom Memory Configuration

```rust
// For high-performance desktop
let desktop_config = MemoryConfig {
    max_tab_memory: 512 * 1024 * 1024,  // 512MB per tab
    max_total_memory: 2048 * 1024 * 1024, // 2GB total
    image_cache_limit: 200 * 1024 * 1024, // 200MB image cache
    font_cache_limit: 50 * 1024 * 1024,   // 50MB font cache
    ..Default::default()
};

// For low-end mobile
let mobile_config = MemoryConfig {
    max_tab_memory: 128 * 1024 * 1024,   // 128MB per tab
    max_total_memory: 512 * 1024 * 1024,  // 512MB total
    background_tab_limit: 32 * 1024 * 1024, // 32MB for background tabs
    image_cache_limit: 50 * 1024 * 1024,  // 50MB image cache
    font_cache_limit: 10 * 1024 * 1024,   // 10MB font cache
    ..Default::default()
};
```

## Integration with Existing Code

### Browser Engine Integration

```rust
// In your browser engine constructor
pub struct CitadelEngine {
    performance_integrator: Arc<PerformanceIntegrator>,
    // ... other fields
}

impl CitadelEngine {
    pub async fn new() -> Self {
        let performance_integrator = Arc::new(PerformanceIntegrator::new());
        performance_integrator.start().await;

        Self {
            performance_integrator,
            // ... other initialization
        }
    }

    pub async fn load_page(&mut self, url: &str) -> Result<(), LoadError> {
        let tab_id = uuid::Uuid::new_v4();
        self.performance_integrator.register_tab(tab_id).await;

        let start_time = Instant::now();

        // ... load the page ...

        let load_time = start_time.elapsed().as_millis() as u64;
        self.performance_integrator
            .performance_monitor
            .add_measurement("page_load", load_time);

        self.performance_integrator.unregister_tab(tab_id).await;
        Ok(())
    }
}
```

### Renderer Integration

```rust
// In your renderer's render method
impl CitadelRenderer {
    pub fn render(&mut self, viewport: &Viewport) -> RenderResult {
        // Update viewport for culling
        self.performance_integrator
            .update_viewport(viewport.x, viewport.y, viewport.width, viewport.height, viewport.scale);

        // Begin frame timing
        self.performance_integrator.begin_frame();

        let start_time = Instant::now();

        // Clear dirty regions from previous frame
        self.performance_integrator.clear_dirty_regions();

        // Render only visible elements
        let mut elements_rendered = 0;
        for (id, element) in &self.elements {
            if self.performance_integrator.should_render_element(*id, &element.rect) {
                self.render_element(element);
                elements_rendered += 1;
            }
        }

        let render_time = start_time.elapsed().as_millis() as u64;

        // End frame timing
        let frame_stats = self.performance_integrator.end_frame();

        RenderResult::success(
            elements_rendered,
            render_time,
            viewport.width,
            viewport.height
        )
    }
}
```

## Best Practices

### 1. Performance Targets

Set realistic performance targets based on device capabilities:

```rust
// High-end desktop
PerformanceTargets {
    target_fps: 120.0,
    target_load_time_ms: 1000,
    min_cache_hit_ratio: 0.9,
    max_render_time_ms: 8,
    ..Default::default()
}

// Mid-range device
PerformanceTargets {
    target_fps: 60.0,
    target_load_time_ms: 2000,
    min_cache_hit_ratio: 0.8,
    max_render_time_ms: 16,
    ..Default::default()
}

// Low-end device
PerformanceTargets {
    target_fps: 30.0,
    target_load_time_ms: 3000,
    min_cache_hit_ratio: 0.7,
    max_render_time_ms: 33,
    ..Default::default()
}
```

### 2. Memory Management

- Always unregister tabs when they're closed
- Set background tabs to background mode to reduce memory
- Use memory pools for frequently allocated objects
- Monitor memory usage and trigger cleanup before hitting limits

### 3. Rendering Optimization

- Enable viewport culling for complex pages
- Use dirty regions for partial updates
- Target 60 FPS but handle lower-end devices gracefully
- Monitor frame time and adjust quality dynamically

### 4. Network Optimization

- Prioritize critical resources
- Use connection pooling for HTTP/2
- Implement predictive preloading
- Monitor cache hit ratios and adjust cache sizes

## Troubleshooting

### Common Performance Issues

1. **High Memory Usage**
   ```rust
   // Check memory statistics
   let stats = integrator.get_memory_stats();
   if stats.total_allocated > stats.peak_usage * 9 / 10 {
       integrator.force_optimization().await;
   }
   ```

2. **Low Frame Rate**
   ```rust
   // Check frame statistics
   let frame_stats = integrator.render_optimizer.get_frame_stats();
   if frame_stats.average_fps < 30.0 {
       // Enable more aggressive optimizations
       integrator.force_optimization().await;
   }
   ```

3. **Slow Page Loading**
   ```rust
   // Check cache hit ratios
   let metrics = integrator.get_performance_metrics();
   for (component, hit_ratio) in &metrics.cache_hit_ratios {
       if *hit_ratio < 0.5 {
           println!("Low cache hit ratio for {}: {:.1}%", component, hit_ratio * 100.0);
       }
   }
   ```

### Performance Debugging

```rust
// Enable detailed logging
env_logger::init_from_env(env_logger::Env::new().default_filter_or("citadel_browser=debug"));

// Run benchmark to identify bottlenecks
let report = benchmark.run_full_benchmark().await;
for result in &report.results {
    if result.average_time > Duration::from_millis(100) {
        println!("Slow operation: {} - {:?}", result.test_name, result.average_time);
    }
}
```

## Conclusion

The Citadel Browser performance optimization system provides comprehensive tools for:

- **Memory Management**: Intelligent allocation, pooling, and cleanup
- **Rendering Optimization**: Viewport culling, dirty regions, and frame timing
- **Network Performance**: Request prioritization and caching
- **Real-time Monitoring**: Performance metrics and adaptive optimization
- **Benchmarking**: Comprehensive performance testing

By following this guide and integrating these components into your browser implementation, you can achieve significant performance improvements while maintaining Citadel Browser's security and privacy features.

For more detailed information about specific components, refer to the individual module documentation and the `PERFORMANCE_OPTIMIZATION_SUMMARY.md` file.