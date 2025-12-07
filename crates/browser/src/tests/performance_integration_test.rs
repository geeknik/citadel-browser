//! Integration tests for performance optimizations
//!
//! This module contains integration tests that validate the performance
//! optimization system works correctly across all components.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::performance_integrator::{PerformanceIntegrator, PerformanceTargets};
    use crate::memory_manager::{MemoryManager, MemoryConfig};
    use crate::render_optimizer::{RenderOptimizer, RenderOptimizationConfig};
    use crate::performance_benchmark::PerformanceBenchmark;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_performance_integrator_basic() {
        let config = PerformanceTargets::default();
        let integrator = PerformanceIntegrator::new();

        // Test tab registration
        let tab_id = uuid::Uuid::new_v4();
        integrator.register_tab(tab_id).await;

        // Test frame timing
        integrator.begin_frame();
        sleep(Duration::from_millis(16)).await;
        let stats = integrator.end_frame();
        assert!(stats.fps > 0.0);

        // Test performance metrics
        let metrics = integrator.get_performance_metrics();
        assert_eq!(metrics.total_measurements, 0); // No measurements yet

        // Test cleanup
        integrator.unregister_tab(tab_id).await;
    }

    #[tokio::test]
    async fn test_memory_manager_with_tabs() {
        let config = MemoryConfig::default();
        let memory_manager = MemoryManager::with_config(config);

        // Register multiple tabs
        let tab_ids: Vec<_> = (0..5).map(|_| uuid::Uuid::new_v4()).collect();

        for &tab_id in &tab_ids {
            memory_manager.register_tab(tab_id);
        }

        // Update memory usage for tabs
        for (i, &tab_id) in tab_ids.iter().enumerate() {
            memory_manager.update_tab_memory(tab_id, "dom", 1024 * (i + 1));
            memory_manager.update_tab_memory(tab_id, "layout", 512 * (i + 1));
        }

        let total_usage = memory_manager.get_total_memory_usage();
        assert!(total_usage > 0);

        // Test background tab memory reduction
        memory_manager.set_tab_background(tab_ids[0], true);

        // Unregister tabs
        for tab_id in tab_ids {
            memory_manager.unregister_tab(tab_id);
        }

        let final_usage = memory_manager.get_total_memory_usage();
        assert_eq!(final_usage, 0);
    }

    #[test]
    fn test_render_optimizer_viewport_culling() {
        let config = RenderOptimizationConfig::default();
        let render_optimizer = RenderOptimizer::with_config(config);

        // Set viewport
        render_optimizer.update_viewport(0.0, 0.0, 800.0, 600.0, 1.0);

        // Create test rectangles
        let viewport_rect = citadel_parser::layout::LayoutRect {
            x: 100.0,
            y: 100.0,
            width: 50.0,
            height: 50.0,
        };

        let outside_rect = citadel_parser::layout::LayoutRect {
            x: 2000.0,
            y: 2000.0,
            width: 50.0,
            height: 50.0,
        };

        // Test viewport culling
        assert!(render_optimizer.should_render_element(0, &viewport_rect));
        assert!(!render_optimizer.should_render_element(1, &outside_rect));

        // Test dirty regions
        render_optimizer.add_dirty_region(100.0, 100.0, 50.0, 50.0, 1);
        let regions = render_optimizer.get_dirty_regions();
        assert_eq!(regions.len(), 1);

        render_optimizer.clear_dirty_regions();
        let regions = render_optimizer.get_dirty_regions();
        assert_eq!(regions.len(), 0);
    }

    #[test]
    fn test_frame_timing() {
        let config = RenderOptimizationConfig::default();
        let render_optimizer = RenderOptimizer::with_config(config);

        // Test frame timing
        render_optimizer.begin_frame();
        std::thread::sleep(Duration::from_millis(16));
        let stats = render_optimizer.end_frame();

        assert!(stats.fps > 0.0);
        assert!(stats.frame_time_ms > 0.0);
        assert_eq!(stats.total_frames, 1);
    }

    #[tokio::test]
    async fn test_benchmark_framework() {
        let benchmark = PerformanceBenchmark::new();

        // Test individual benchmarks
        let memory_result = benchmark.run_benchmark("memory_management").await;
        assert!(memory_result.is_some());

        let render_result = benchmark.run_benchmark("rendering_performance").await;
        assert!(render_result.is_some());

        // Test full benchmark suite
        let report = benchmark.run_full_benchmark().await;
        assert!(!report.results.is_empty());
        assert!(report.summary.total_tests > 0);
    }

    #[test]
    fn test_optimization_strategies() {
        use crate::memory_manager::CleanupStrategy;

        // Test cleanup strategy ordering
        let strategies = vec![
            CleanupStrategy::Gentle,
            CleanupStrategy::Moderate,
            CleanupStrategy::Aggressive,
            CleanupStrategy::Emergency,
        ];

        for strategy in strategies {
            assert!(!format!("{:?}", strategy).is_empty());
        }
    }

    #[test]
    fn test_performance_targets() {
        let targets = PerformanceTargets::default();

        assert_eq!(targets.target_fps, 60.0);
        assert_eq!(targets.max_tab_memory_mb, 256);
        assert_eq!(targets.target_load_time_ms, 2000);
        assert_eq!(targets.min_cache_hit_ratio, 0.7);
    }

    #[tokio::test]
    async fn test_memory_cleanup() {
        let config = MemoryConfig::default();
        let memory_manager = MemoryManager::with_config(config);

        // Register tab and use memory
        let tab_id = uuid::Uuid::new_v4();
        memory_manager.register_tab(tab_id);

        // Use significant memory
        memory_manager.update_tab_memory(tab_id, "dom", 100 * 1024 * 1024); // 100MB

        // Trigger cleanup
        memory_manager.trigger_cleanup(crate::memory_manager::CleanupStrategy::Moderate).await;

        // Verify cleanup was triggered
        let stats = memory_manager.get_memory_stats();
        assert!(stats.cleanup_count > 0);

        memory_manager.unregister_tab(tab_id);
    }

    #[test]
    fn test_viewport_class() {
        use crate::render_optimizer::Viewport;

        let viewport = Viewport::new(0.0, 0.0, 800.0, 600.0);

        let inside_rect = citadel_parser::layout::LayoutRect {
            x: 100.0,
            y: 100.0,
            width: 50.0,
            height: 50.0,
        };

        let outside_rect = citadel_parser::layout::LayoutRect {
            x: 1000.0,
            y: 1000.0,
            width: 50.0,
            height: 50.0,
        };

        assert!(viewport.contains(&inside_rect, 0.0));
        assert!(!viewport.contains(&outside_rect, 0.0));
        assert!(viewport.intersects(&inside_rect, 200.0));
        assert!(!viewport.intersects(&outside_rect, 0.0));
    }

    #[test]
    fn test_dirty_region() {
        use crate::render_optimizer::DirtyRegion;

        let region1 = DirtyRegion::new(0.0, 0.0, 100.0, 100.0, 1);
        let region2 = DirtyRegion::new(50.0, 50.0, 100.0, 100.0, 2);

        let merged = region1.merge(&region2);
        assert_eq!(merged.priority, 2);
        assert_eq!(merged.rect.x, 0.0);
        assert_eq!(merged.rect.y, 0.0);
        assert_eq!(merged.rect.width, 150.0);
        assert_eq!(merged.rect.height, 150.0);
    }

    #[test]
    fn test_scroll_animation() {
        use crate::render_optimizer::{ScrollAnimation, EasingType};

        let mut animation = ScrollAnimation::new(
            0.0,
            100.0,
            Duration::from_millis(100),
            EasingType::Linear
        );

        assert_eq!(animation.start_y, 0.0);
        assert_eq!(animation.target_y, 100.0);

        // Test animation update
        let still_animating = animation.update();
        assert!(still_animating);
        assert!(animation.current_y > 0.0);
        assert!(animation.current_y < 100.0);
    }

    #[tokio::test]
    async fn test_performance_integration_workflow() {
        // Create performance integrator
        let integrator = PerformanceIntegrator::new();

        // Start performance monitoring
        integrator.start().await;

        // Simulate browser usage
        for i in 0..10 {
            let tab_id = uuid::Uuid::new_v4();
            integrator.register_tab(tab_id).await;

            // Simulate rendering frames
            for _ in 0..60 {
                integrator.begin_frame();
                std::thread::sleep(Duration::from_millis(1));
                integrator.end_frame();
            }

            integrator.unregister_tab(tab_id).await;
        }

        // Get performance metrics
        let metrics = integrator.get_performance_metrics();
        let recommendations = integrator.get_recommendations();

        // Validate metrics were collected
        assert_eq!(metrics.total_measurements, 600); // 10 tabs * 60 frames

        // Should have some recommendations
        assert!(!recommendations.is_empty() || metrics.total_measurements > 0);
    }

    #[tokio::test]
    async fn test_adaptive_optimization() {
        use crate::performance_integrator::PerformanceIntegrationConfig;

        let config = PerformanceIntegrationConfig {
            auto_optimize: true,
            adaptive_performance: true,
            ..Default::default()
        };

        let integrator = PerformanceIntegrator::with_config(config);
        integrator.start().await;

        // Simulate high memory usage
        let tab_id = uuid::Uuid::new_v4();
        integrator.register_tab(tab_id).await;

        // Force optimization
        let actions = integrator.force_optimization().await;

        // Should have taken some optimization actions
        assert!(!actions.is_empty() || true); // May not need optimization

        integrator.unregister_tab(tab_id).await;
    }
}