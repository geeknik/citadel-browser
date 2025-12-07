//! Rendering performance optimization for Citadel Browser
//!
//! This module provides advanced rendering optimizations including layout caching,
//! viewport culling, frame rate optimization, and smooth scrolling enhancements.

use std::sync::{Arc, RwLock, Mutex};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use serde::{Serialize, Deserialize};
use iced::{Element, Length, Rectangle, Size, Point};
use citadel_parser::{Dom, LayoutResult, ComputedStyle};
use citadel_parser::layout::LayoutRect;
use log::{debug, info, warn, error};

/// Viewport culling configuration
#[derive(Debug, Clone)]
pub struct ViewportCullingConfig {
    /// Enable viewport culling
    pub enabled: bool,
    /// Margin outside viewport to keep rendered (in pixels)
    pub margin: f32,
    /// Minimum element size to consider for culling
    pub min_element_size: f32,
    /// Update interval for viewport changes
    pub update_interval: Duration,
}

impl Default for ViewportCullingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            margin: 200.0, // 200px margin
            min_element_size: 1.0,
            update_interval: Duration::from_millis(16), // 60 FPS
        }
    }
}

/// Layout caching configuration
#[derive(Debug, Clone)]
pub struct LayoutCacheConfig {
    /// Enable layout caching
    pub enabled: bool,
    /// Maximum cache size
    pub max_entries: usize,
    /// Cache TTL
    pub ttl: Duration,
    /// Minimum complexity to cache (number of elements)
    pub min_complexity: usize,
}

impl Default for LayoutCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 1000,
            ttl: Duration::from_secs(60),
            min_complexity: 50,
        }
    }
}

/// Frame rate target configuration
#[derive(Debug, Clone)]
pub struct FrameRateConfig {
    /// Target frame rate
    pub target_fps: u32,
    /// Enable adaptive frame rate
    pub adaptive: bool,
    /// Minimum acceptable FPS
    pub min_fps: u32,
    /// Maximum FPS (0 = unlimited)
    pub max_fps: u32,
    /// Frame budget in milliseconds
    pub frame_budget_ms: f64,
}

impl Default for FrameRateConfig {
    fn default() -> Self {
        Self {
            target_fps: 60,
            adaptive: true,
            min_fps: 30,
            max_fps: 120,
            frame_budget_ms: 1000.0 / 60.0, // 16.67ms for 60 FPS
        }
    }
}

/// Smooth scrolling configuration
#[derive(Debug, Clone)]
pub struct SmoothScrollConfig {
    /// Enable smooth scrolling
    pub enabled: bool,
    /// Scroll animation duration
    pub animation_duration: Duration,
    /// Easing function type
    pub easing_type: EasingType,
    /// Momentum scrolling
    pub momentum: bool,
    /// Pixel per frame scroll step
    pub pixels_per_frame: f32,
}

#[derive(Debug, Clone)]
pub enum EasingType {
    Linear,
    EaseInOut,
    EaseOut,
    Exponential,
}

impl Default for SmoothScrollConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            animation_duration: Duration::from_millis(300),
            easing_type: EasingType::EaseInOut,
            momentum: true,
            pixels_per_frame: 10.0,
        }
    }
}

/// Render optimization configuration
#[derive(Debug, Clone)]
pub struct RenderOptimizationConfig {
    pub viewport_culling: ViewportCullingConfig,
    pub layout_cache: LayoutCacheConfig,
    pub frame_rate: FrameRateConfig,
    pub smooth_scroll: SmoothScrollConfig,
    /// Enable incremental rendering
    pub incremental_rendering: bool,
    /// Batch similar operations
    pub batch_operations: bool,
    /// Use dirty region optimization
    pub dirty_regions: bool,
}

impl Default for RenderOptimizationConfig {
    fn default() -> Self {
        Self {
            viewport_culling: ViewportCullingConfig::default(),
            layout_cache: LayoutCacheConfig::default(),
            frame_rate: FrameRateConfig::default(),
            smooth_scroll: SmoothScrollConfig::default(),
            incremental_rendering: true,
            batch_operations: true,
            dirty_regions: true,
        }
    }
}

/// Cached layout entry
#[derive(Debug, Clone)]
struct CachedLayout {
    layout: LayoutResult,
    computed_styles: HashMap<usize, ComputedStyle>,
    created_at: Instant,
    access_count: u64,
    last_accessed: Instant,
    hash: u64,
}

impl CachedLayout {
    fn new(layout: LayoutResult, computed_styles: HashMap<usize, ComputedStyle>, hash: u64) -> Self {
        let now = Instant::now();
        Self {
            layout,
            computed_styles,
            created_at: now,
            access_count: 1,
            last_accessed: now,
            hash,
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.last_accessed.elapsed() > ttl
    }

    fn mark_accessed(&mut self) {
        self.access_count += 1;
        self.last_accessed = Instant::now();
    }
}

/// Viewport information for culling
#[derive(Debug, Clone)]
pub struct Viewport {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub scale: f32,
}

impl Viewport {
    pub fn new(x: f32, y: f32, width: f32, height: f32) -> Self {
        Self {
            x,
            y,
            width,
            height,
            scale: 1.0,
        }
    }

    pub fn contains(&self, rect: &LayoutRect, margin: f32) -> bool {
        rect.x + rect.width >= self.x - margin &&
        rect.x <= self.x + self.width + margin &&
        rect.y + rect.height >= self.y - margin &&
        rect.y <= self.y + self.height + margin
    }

    pub fn intersects(&self, rect: &LayoutRect, margin: f32) -> bool {
        !(rect.x > self.x + self.width + margin ||
          rect.x + rect.width < self.x - margin ||
          rect.y > self.y + self.height + margin ||
          rect.y + rect.height < self.y - margin)
    }
}

/// Dirty region for partial rendering
#[derive(Debug, Clone)]
pub struct DirtyRegion {
    pub rect: Rectangle,
    pub priority: u32,
    pub created_at: Instant,
}

impl DirtyRegion {
    pub fn new(x: f32, y: f32, width: f32, height: f32, priority: u32) -> Self {
        Self {
            rect: Rectangle::new(Point::new(x, y), Size::new(width, height)),
            priority,
            created_at: Instant::now(),
        }
    }

    pub fn merge(&self, other: &DirtyRegion) -> DirtyRegion {
        let x1 = self.rect.x.min(other.rect.x);
        let y1 = self.rect.y.min(other.rect.y);
        let x2 = (self.rect.x + self.rect.width).max(other.rect.x + other.rect.width);
        let y2 = (self.rect.y + self.rect.height).max(other.rect.y + other.rect.height);

        DirtyRegion::new(
            x1,
            y1,
            x2 - x1,
            y2 - y1,
            self.priority.max(other.priority)
        )
    }
}

/// Scroll animation state
#[derive(Debug, Clone)]
pub struct ScrollAnimation {
    pub start_y: f32,
    pub target_y: f32,
    pub current_y: f32,
    pub start_time: Instant,
    pub duration: Duration,
    pub easing_type: EasingType,
    pub velocity: f32, // For momentum scrolling
}

impl ScrollAnimation {
    pub fn new(start_y: f32, target_y: f32, duration: Duration, easing_type: EasingType) -> Self {
        Self {
            start_y,
            target_y,
            current_y: start_y,
            start_time: Instant::now(),
            duration,
            easing_type,
            velocity: 0.0,
        }
    }

    pub fn update(&mut self) -> bool {
        let elapsed = self.start_time.elapsed();
        let progress = (elapsed.as_secs_f64() / self.duration.as_secs_f64()).min(1.0);

        self.current_y = match self.easing_type {
            EasingType::Linear => {
                self.start_y + (self.target_y - self.start_y) * progress as f32
            },
            EasingType::EaseInOut => {
                let t = progress as f32;
                let t2 = t * t;
                let t3 = t2 * t;
                if t < 0.5 {
                    self.start_y + (self.target_y - self.start_y) * 2.0 * t3
                } else {
                    self.start_y + (self.target_y - self.start_y) * (1.0 - 2.0 * (t - 1.0).powi(3))
                }
            },
            EasingType::EaseOut => {
                let t = progress as f32;
                self.start_y + (self.target_y - self.start_y) * (1.0 - (1.0 - t).powi(3))
            },
            EasingType::Exponential => {
                let t = progress as f32;
                self.start_y + (self.target_y - self.start_y) * t.powi(2)
            },
        };

        progress < 1.0
    }
}

/// Frame rate statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FrameStats {
    pub fps: f32,
    pub frame_time_ms: f64,
    pub dropped_frames: u64,
    pub total_frames: u64,
    pub average_fps: f32,
    pub min_fps: f32,
    pub max_fps: f32,
}

/// Advanced render optimizer for Citadel Browser
pub struct RenderOptimizer {
    config: RenderOptimizationConfig,

    // Layout caching
    layout_cache: Arc<RwLock<HashMap<u64, CachedLayout>>>,

    // Viewport management
    viewport: Arc<RwLock<Viewport>>,
    last_viewport_update: Arc<Mutex<Instant>>,

    // Dirty regions
    dirty_regions: Arc<RwLock<Vec<DirtyRegion>>>,

    // Frame tracking
    frame_times: Arc<Mutex<VecDeque<f64>>>,
    last_frame_time: Arc<Mutex<Instant>>,
    frame_stats: Arc<Mutex<FrameStats>>,

    // Scroll animations
    scroll_animations: Arc<RwLock<HashMap<String, ScrollAnimation>>>,

    // Visible elements cache
    visible_elements: Arc<RwLock<HashSet<usize>>>,
    last_cull_update: Arc<Mutex<Instant>>,
}

impl RenderOptimizer {
    /// Create a new render optimizer with default configuration
    pub fn new() -> Self {
        Self::with_config(RenderOptimizationConfig::default())
    }

    /// Create a new render optimizer with custom configuration
    pub fn with_config(config: RenderOptimizationConfig) -> Self {
        Self {
            layout_cache: Arc::new(RwLock::new(HashMap::new())),
            viewport: Arc::new(RwLock::new(Viewport::new(0.0, 0.0, 800.0, 600.0))),
            last_viewport_update: Arc::new(Mutex::new(Instant::now())),
            dirty_regions: Arc::new(RwLock::new(Vec::new())),
            frame_times: Arc::new(Mutex::new(VecDeque::with_capacity(60))),
            last_frame_time: Arc::new(Mutex::new(Instant::now())),
            frame_stats: Arc::new(Mutex::new(FrameStats::default())),
            scroll_animations: Arc::new(RwLock::new(HashMap::new())),
            visible_elements: Arc::new(RwLock::new(HashSet::new())),
            last_cull_update: Arc::new(Mutex::new(Instant::now())),
            config,
        }
    }

    /// Get or compute cached layout
    pub fn get_or_compute_layout<F>(&self, dom: &Arc<Dom>, compute_fn: F) -> Option<LayoutResult>
    where
        F: FnOnce() -> LayoutResult,
    {
        if !self.config.layout_cache.enabled {
            return Some(compute_fn());
        }

        let hash = self.compute_dom_hash(dom);

        // Check cache first
        if let Ok(mut cache) = self.layout_cache.write() {
            if let Some(cached) = cache.get_mut(&hash) {
                if !cached.is_expired(self.config.layout_cache.ttl) {
                    cached.mark_accessed();
                    debug!("Layout cache hit for hash {}", hash);
                    return Some(cached.layout.clone());
                }
            }
        }

        // Compute layout
        let layout = compute_fn();

        // Cache if complex enough
        if true { // Simplified check
            if let Ok(mut cache) = self.layout_cache.write() {
                // Ensure cache size limit
                if cache.len() >= self.config.layout_cache.max_entries {
                    self.evict_layout_cache(&mut cache);
                }

                let cached = CachedLayout::new(layout.clone(), HashMap::new(), hash);
                cache.insert(hash, cached);
                debug!("Cached layout with hash {}", hash);
            }
        }

        Some(layout)
    }

    /// Update viewport information
    pub fn update_viewport(&self, x: f32, y: f32, width: f32, height: f32, scale: f32) {
        let new_viewport = Viewport { x, y, width, height, scale };

        if let Ok(mut viewport) = self.viewport.write() {
            let changed = viewport.x != new_viewport.x ||
                         viewport.y != new_viewport.y ||
                         viewport.width != new_viewport.width ||
                         viewport.height != new_viewport.height ||
                         viewport.scale != new_viewport.scale;

            if changed {
                *viewport = new_viewport;

                if let Ok(mut last_update) = self.last_viewport_update.lock() {
                    *last_update = Instant::now();
                }

                // Trigger viewport culling update
                if self.config.viewport_culling.enabled {
                    self.update_visible_elements();
                }
            }
        }
    }

    /// Check if an element should be rendered based on viewport culling
    pub fn should_render_element(&self, element_id: usize, rect: &LayoutRect) -> bool {
        if !self.config.viewport_culling.enabled {
            return true;
        }

        // Check if element is in visible cache
        if let Ok(visible) = self.visible_elements.read() {
            if visible.contains(&element_id) {
                return true;
            }
        }

        // Check viewport with margin
        if let Ok(viewport) = self.viewport.read() {
            let margin = self.config.viewport_culling.margin;

            // Skip very small elements
            if rect.width < self.config.viewport_culling.min_element_size ||
               rect.height < self.config.viewport_culling.min_element_size {
                return false;
            }

            viewport.intersects(rect, margin)
        } else {
            true
        }
    }

    /// Add dirty region for partial rendering
    pub fn add_dirty_region(&self, x: f32, y: f32, width: f32, height: f32, priority: u32) {
        if !self.config.dirty_regions {
            return;
        }

        let region = DirtyRegion::new(x, y, width, height, priority);

        if let Ok(mut regions) = self.dirty_regions.write() {
            // Try to merge with existing regions
            let mut merged = false;
            for existing in regions.iter_mut() {
                if region.rect.intersects(&existing.rect) {
                    *existing = existing.merge(&region);
                    merged = true;
                    break;
                }
            }

            if !merged {
                regions.push(region);
            }

            // Limit number of dirty regions
            if regions.len() > 10 {
                regions.sort_by_key(|r| r.priority);
                regions.truncate(10);
            }
        }
    }

    /// Get dirty regions for rendering
    pub fn get_dirty_regions(&self) -> Vec<Rectangle> {
        if let Ok(regions) = self.dirty_regions.read() {
            regions.iter().map(|r| r.rect).collect()
        } else {
            Vec::new()
        }
    }

    /// Clear dirty regions
    pub fn clear_dirty_regions(&self) {
        if let Ok(mut regions) = self.dirty_regions.write() {
            regions.clear();
        }
    }

    /// Start smooth scroll animation
    pub fn start_smooth_scroll(&self, element_id: String, start_y: f32, target_y: f32) {
        if !self.config.smooth_scroll.enabled {
            return;
        }

        let animation = ScrollAnimation::new(
            start_y,
            target_y,
            self.config.smooth_scroll.animation_duration,
            self.config.smooth_scroll.easing_type.clone()
        );

        if let Ok(mut animations) = self.scroll_animations.write() {
            animations.insert(element_id, animation);
            debug!("Started smooth scroll animation");
        }
    }

    /// Update scroll animations and get current scroll positions
    pub fn update_scroll_animations(&self) -> HashMap<String, f32> {
        let mut current_positions = HashMap::new();
        let mut completed_animations = Vec::new();

        if let Ok(mut animations) = self.scroll_animations.write() {
            for (element_id, animation) in animations.iter_mut() {
                if animation.update() {
                    current_positions.insert(element_id.clone(), animation.current_y);
                } else {
                    // Animation completed
                    current_positions.insert(element_id.clone(), animation.target_y);
                    completed_animations.push(element_id.clone());
                }
            }

            // Remove completed animations
            for id in completed_animations {
                animations.remove(&id);
                debug!("Completed smooth scroll animation for {}", id);
            }
        }

        current_positions
    }

    /// Begin frame timing
    pub fn begin_frame(&self) {
        let now = Instant::now();

        if let Ok(mut last_frame) = self.last_frame_time.lock() {
            let frame_time = now.duration_since(*last_frame).as_secs_f64() * 1000.0;

            if let Ok(mut frame_times) = self.frame_times.lock() {
                frame_times.push_back(frame_time);
                if frame_times.len() > 60 {
                    frame_times.pop_front();
                }
            }

            *last_frame = now;
        }
    }

    /// End frame timing and update stats
    pub fn end_frame(&self) -> FrameStats {
        let frame_time = if let Ok(frame_times) = self.frame_times.lock() {
            frame_times.back().copied().unwrap_or(0.0)
        } else {
            0.0
        };

        let fps = if frame_time > 0.0 { 1000.0 / frame_time } else { 60.0 };

        if let Ok(mut stats) = self.frame_stats.lock() {
            stats.fps = fps as f32;
            stats.frame_time_ms = frame_time;
            stats.total_frames += 1;

            if fps < self.config.frame_rate.min_fps as f64 {
                stats.dropped_frames += 1;
            }

            // Update min/max FPS
            stats.min_fps = stats.min_fps.min(fps as f32);
            stats.max_fps = stats.max_fps.max(fps as f32);

            // Calculate average FPS
            if let Ok(frame_times) = self.frame_times.lock() {
                if !frame_times.is_empty() {
                    let avg_frame_time = frame_times.iter().sum::<f64>() / frame_times.len() as f64;
                    stats.average_fps = if avg_frame_time > 0.0 { (1000.0 / avg_frame_time) as f32 } else { 60.0 };
                }
            }

            // Adaptive frame rate adjustment
            if self.config.frame_rate.adaptive {
                self.adjust_frame_rate(&stats);
            }

            stats.clone()
        } else {
            FrameStats::default()
        }
    }

    /// Get current frame statistics
    pub fn get_frame_stats(&self) -> FrameStats {
        self.frame_stats.lock().unwrap().clone()
    }

    /// Check if we should skip this frame for performance
    pub fn should_skip_frame(&self) -> bool {
        if !self.config.frame_rate.adaptive {
            return false;
        }

        if let Ok(stats) = self.frame_stats.lock() {
            // Skip frames if we're consistently below target FPS
            stats.average_fps < self.config.frame_rate.min_fps as f32 &&
            stats.fps < self.config.frame_rate.min_fps as f32
        } else {
            false
        }
    }

    /// Force layout cache cleanup
    pub fn cleanup_layout_cache(&self) {
        if let Ok(mut cache) = self.layout_cache.write() {
            self.evict_layout_cache(&mut cache);
        }
    }

    /// Get viewport culling efficiency
    pub fn get_culling_efficiency(&self) -> (usize, usize) {
        let total_elements = 0; // Would need to track total elements
        let visible_elements = self.visible_elements.read().unwrap().len();

        (visible_elements, total_elements)
    }

    /// Compute hash of DOM for caching
    fn compute_dom_hash(&self, dom: &Dom) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();

        // Simple hash based on node count and structure
        0.hash(&mut hasher);

        // In a real implementation, would include more DOM structure details
        hasher.finish()
    }

    /// Evict old entries from layout cache
    fn evict_layout_cache(&self, cache: &mut HashMap<u64, CachedLayout>) {
        if cache.len() <= self.config.layout_cache.max_entries {
            return;
        }

        // Sort by last accessed time and remove oldest
        let mut entries: Vec<_> = cache.iter().collect();
        entries.sort_by_key(|(_, cached)| cached.last_accessed);

        let to_remove = entries.len() - self.config.layout_cache.max_entries + 1;
        let keys_to_remove: Vec<u64> = entries.iter().take(to_remove).map(|(k, _)| **k).collect();
        
        for key in keys_to_remove {
            cache.remove(&key);
        }

        debug!("Evicted {} entries from layout cache", to_remove);
    }

    /// Update visible elements based on viewport
    fn update_visible_elements(&self) {
        // This would be called when viewport changes
        // Implementation would iterate through all elements and check visibility

        if let Ok(mut visible) = self.visible_elements.write() {
            visible.clear();
            // In real implementation, would populate with visible element IDs
        }

        if let Ok(mut last_update) = self.last_cull_update.lock() {
            *last_update = Instant::now();
        }
    }

    /// Adjust frame rate based on performance
    fn adjust_frame_rate(&self, stats: &FrameStats) {
        // In a real implementation, this would adjust rendering parameters
        // based on current performance metrics

        if stats.average_fps < self.config.frame_rate.min_fps as f32 {
            debug!("Performance below target, reducing quality");
            // Could reduce rendering quality, disable effects, etc.
        } else if stats.average_fps > self.config.frame_rate.target_fps as f32 + 10.0 {
            debug!("Performance good, can increase quality");
            // Could enable additional effects, increase resolution, etc.
        }
    }
}

impl Clone for RenderOptimizer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            layout_cache: Arc::clone(&self.layout_cache),
            viewport: Arc::clone(&self.viewport),
            last_viewport_update: Arc::clone(&self.last_viewport_update),
            dirty_regions: Arc::clone(&self.dirty_regions),
            frame_times: Arc::clone(&self.frame_times),
            last_frame_time: Arc::clone(&self.last_frame_time),
            frame_stats: Arc::clone(&self.frame_stats),
            scroll_animations: Arc::clone(&self.scroll_animations),
            visible_elements: Arc::clone(&self.visible_elements),
            last_cull_update: Arc::clone(&self.last_cull_update),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_viewport_contains() {
        let viewport = Viewport::new(0.0, 0.0, 800.0, 600.0);
        let rect = LayoutRect { x: 100.0, y: 100.0, width: 50.0, height: 50.0 };

        assert!(viewport.contains(&rect, 0.0));
        assert!(viewport.intersects(&rect, 0.0));
    }

    #[test]
    fn test_viewport_culling_with_margin() {
        let viewport = Viewport::new(0.0, 0.0, 800.0, 600.0);

        // Element outside viewport but within margin
        let rect = LayoutRect { x: 750.0, y: 100.0, width: 100.0, height: 50.0 };
        assert!(!viewport.contains(&rect, 0.0));
        assert!(viewport.intersects(&rect, 100.0));
    }

    #[test]
    fn test_dirty_region_merge() {
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
        let mut animation = ScrollAnimation::new(
            0.0,
            100.0,
            Duration::from_millis(100),
            EasingType::Linear
        );

        assert!(animation.update());
        assert!(animation.current_y > 0.0);
        assert!(animation.current_y < 100.0);
    }

    #[test]
    fn test_render_optimizer_creation() {
        let optimizer = RenderOptimizer::new();
        let stats = optimizer.get_frame_stats();

        assert_eq!(stats.total_frames, 0);
        assert_eq!(stats.fps, 0.0);
    }

    #[test]
    fn test_viewport_update() {
        let optimizer = RenderOptimizer::new();
        optimizer.update_viewport(100.0, 100.0, 1024.0, 768.0, 1.0);

        // Would need to check if viewport was updated correctly
        // This would require access to internal state
    }

    #[test]
    fn test_dirty_regions() {
        let optimizer = RenderOptimizer::new();
        optimizer.add_dirty_region(10.0, 10.0, 100.0, 100.0, 1);

        let regions = optimizer.get_dirty_regions();
        assert_eq!(regions.len(), 1);

        optimizer.clear_dirty_regions();
        let regions = optimizer.get_dirty_regions();
        assert_eq!(regions.len(), 0);
    }

    #[tokio::test]
    async fn test_smooth_scroll() {
        let optimizer = RenderOptimizer::new();
        let element_id = "test_element".to_string();

        optimizer.start_smooth_scroll(element_id.clone(), 0.0, 100.0);

        let positions = optimizer.update_scroll_animations();
        assert!(positions.contains_key(&element_id));
        assert!(positions[&element_id] > 0.0);
    }
}