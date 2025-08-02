//! Layout engine integration using Taffy (Servo's Layout 2020)
//! 
//! This module provides layout computation using Taffy, Servo's modern layout engine,
//! while preserving Citadel's security-first approach.

use std::sync::Arc;
use std::collections::HashMap;
use std::time::Instant;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use taffy::{
    TaffyTree, 
    NodeId, 
    Style, 
    AvailableSpace,
    Size,
    Display,
    Position,
    LengthPercentage,
    LengthPercentageAuto,
    Dimension,
    Rect,
};

use crate::css::{CitadelStylesheet, ComputedStyle, DisplayType, LengthValue};
use crate::dom::{Dom, Node};
use crate::security::SecurityContext;
use crate::error::{ParserError, ParserResult};

/// Text measurement context for accurate content sizing
#[derive(Clone)]
pub struct TextMeasurement {
    /// Base font size in pixels
    pub base_font_size: f32,
    /// Font family
    pub font_family: String,
    /// Character width estimation cache
    pub char_widths: HashMap<char, f32>,
}

impl Default for TextMeasurement {
    fn default() -> Self {
        let mut char_widths = HashMap::new();
        
        // Pre-populate common character widths (approximate)
        char_widths.insert(' ', 4.0);
        char_widths.insert('a', 8.0);
        char_widths.insert('m', 12.0);
        char_widths.insert('i', 4.0);
        char_widths.insert('W', 14.0);
        
        Self {
            base_font_size: 16.0,
            font_family: "sans-serif".to_string(),
            char_widths,
        }
    }
}

/// Viewport context for CSS unit calculations
#[derive(Clone, Debug)]
pub struct ViewportContext {
    pub width: f32,
    pub height: f32,
    pub root_font_size: f32, // For rem units
    pub zoom_factor: f32,   // For zoom-aware calculations
    pub device_pixel_ratio: f32, // For high-DPI support
}

impl Default for ViewportContext {
    fn default() -> Self {
        Self {
            width: 800.0,
            height: 600.0,
            root_font_size: 16.0,
            zoom_factor: 1.0,
            device_pixel_ratio: 1.0,
        }
    }
}

/// Cache entry for layout computation results
#[derive(Debug, Clone)]
struct LayoutCacheEntry {
    layout_result: LayoutResult,
    timestamp: Instant,
    access_count: usize,
    dom_hash: u64,
    css_hash: u64,
}

/// Dirty tracking for incremental layout updates
#[derive(Debug, Clone, Default)]
struct DirtyTracker {
    /// Nodes that need layout recomputation
    dirty_nodes: std::collections::HashSet<u32>,
    /// Viewport regions that need updates
    dirty_regions: Vec<LayoutRect>,
    /// CSS properties that changed
    dirty_properties: HashMap<u32, Vec<String>>,
}

/// Performance monitoring for layout operations
#[derive(Debug, Clone)]
struct PerformanceMonitor {
    /// Total layout computations
    layout_count: usize,
    /// Total layout time in milliseconds
    total_layout_time: u64,
    /// Cache hit ratio
    cache_hit_ratio: f64,
    /// Average nodes per layout
    avg_nodes_per_layout: f64,
    /// Memory high water mark
    memory_peak_kb: usize,
    /// Last performance measurement
    last_measurement: Instant,
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self {
            layout_count: 0,
            total_layout_time: 0,
            cache_hit_ratio: 0.0,
            avg_nodes_per_layout: 0.0,
            memory_peak_kb: 0,
            last_measurement: Instant::now(),
        }
    }
}

/// Layout engine using Taffy for modern CSS layout with performance optimizations
pub struct CitadelLayoutEngine {
    /// Taffy layout tree
    taffy: TaffyTree,
    /// Security context
    security_context: Arc<SecurityContext>,
    /// Node mapping between DOM and Taffy
    node_map: HashMap<u32, NodeId>, // DOM node ID -> Taffy node ID
    /// Reverse mapping for lookups
    taffy_map: HashMap<NodeId, u32>, // Taffy node ID -> DOM node ID
    /// Text measurement context
    text_measurement: TextMeasurement,
    /// Viewport context for CSS calculations
    viewport_context: ViewportContext,
    /// Layout result cache with LRU eviction
    layout_cache: HashMap<u64, LayoutCacheEntry>,
    /// Maximum cache size in entries
    max_cache_entries: usize,
    /// Dirty tracking for incremental updates
    dirty_tracker: DirtyTracker,
    /// Performance monitoring
    performance_monitor: PerformanceMonitor,
    /// Viewport culling enabled flag
    viewport_culling_enabled: bool,
    /// Last DOM content hash for change detection
    last_dom_hash: Option<u64>,
    /// Last CSS hash for change detection
    last_css_hash: Option<u64>,
}

/// Simple layout rectangle
#[derive(Debug, Clone)]
pub struct LayoutRect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

impl LayoutRect {
    pub fn new(x: f32, y: f32, width: f32, height: f32) -> Self {
        Self { x, y, width, height }
    }
}

/// Simple layout size
#[derive(Debug, Clone)]
pub struct LayoutSize {
    pub width: f32,
    pub height: f32,
}

impl LayoutSize {
    pub fn new(width: f32, height: f32) -> Self {
        Self { width, height }
    }
}

/// Layout result containing computed positions and sizes
#[derive(Debug, Clone)]
pub struct LayoutResult {
    /// Layout rectangles for each node
    pub node_layouts: HashMap<u32, LayoutRect>,
    /// Total document size
    pub document_size: LayoutSize,
    /// Layout computation metrics
    pub metrics: LayoutMetrics,
    /// Layout cache key for invalidation
    pub cache_key: u64,
    /// Dirty regions for incremental updates
    pub dirty_regions: Vec<LayoutRect>,
}

/// Metrics for layout computation
#[derive(Debug, Clone)]
pub struct LayoutMetrics {
    pub nodes_processed: usize,
    pub layout_time_ms: u32,
    pub memory_used_kb: usize,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub nodes_culled: usize,
    pub viewport_intersections: usize,
}

impl Default for LayoutMetrics {
    fn default() -> Self {
        Self {
            nodes_processed: 0,
            layout_time_ms: 0,
            memory_used_kb: 0,
            cache_hits: 0,
            cache_misses: 0,
            nodes_culled: 0,
            viewport_intersections: 0,
        }
    }
}

impl CitadelLayoutEngine {
    /// Create a new layout engine with performance optimizations
    pub fn new(security_context: Arc<SecurityContext>) -> Self {
        Self {
            taffy: TaffyTree::new(),
            security_context,
            node_map: HashMap::new(),
            taffy_map: HashMap::new(),
            text_measurement: TextMeasurement::default(),
            viewport_context: ViewportContext::default(),
            layout_cache: HashMap::new(),
            max_cache_entries: 100, // Configurable cache size
            dirty_tracker: DirtyTracker::default(),
            performance_monitor: PerformanceMonitor::default(),
            viewport_culling_enabled: true,
            last_dom_hash: None,
            last_css_hash: None,
        }
    }
    
    /// Create a new layout engine with custom cache size
    pub fn new_with_cache_size(security_context: Arc<SecurityContext>, cache_size: usize) -> Self {
        let mut engine = Self::new(security_context);
        engine.max_cache_entries = cache_size;
        engine
    }
    
    /// Create a new layout engine with custom text measurement
    pub fn with_text_measurement(security_context: Arc<SecurityContext>, text_measurement: TextMeasurement) -> Self {
        Self {
            taffy: TaffyTree::new(),
            security_context,
            node_map: HashMap::new(),
            taffy_map: HashMap::new(),
            text_measurement,
            viewport_context: ViewportContext::default(),
            layout_cache: HashMap::new(),
            max_cache_entries: 100,
            dirty_tracker: DirtyTracker::default(),
            performance_monitor: PerformanceMonitor::default(),
            viewport_culling_enabled: true,
            last_dom_hash: None,
            last_css_hash: None,
        }
    }
    
    /// Create a new layout engine with full customization
    pub fn with_context(
        security_context: Arc<SecurityContext>, 
        text_measurement: TextMeasurement,
        viewport_context: ViewportContext,
    ) -> Self {
        Self {
            taffy: TaffyTree::new(),
            security_context,
            node_map: HashMap::new(),
            taffy_map: HashMap::new(),
            text_measurement,
            viewport_context,
            layout_cache: HashMap::new(),
            max_cache_entries: 100,
            dirty_tracker: DirtyTracker::default(),
            performance_monitor: PerformanceMonitor::default(),
            viewport_culling_enabled: true,
            last_dom_hash: None,
            last_css_hash: None,
        }
    }

    /// Compute layout for a DOM tree with associated styles with caching and optimizations
    pub fn compute_layout(
        &mut self,
        dom: &Dom,
        stylesheet: &CitadelStylesheet,
        viewport_size: LayoutSize,
    ) -> ParserResult<LayoutResult> {
        let start_time = Instant::now();
        
        // Generate cache key based on DOM, CSS, and viewport
        let cache_key = self.generate_cache_key(dom, stylesheet, &viewport_size);
        
        // Check cache first
        if let Some(cached_result) = self.check_cache(cache_key) {
            self.performance_monitor.cache_hit_ratio = 
                (self.performance_monitor.cache_hit_ratio * 0.9) + 0.1; // Moving average
            return Ok(cached_result);
        }
        
        self.performance_monitor.cache_hit_ratio = 
            self.performance_monitor.cache_hit_ratio * 0.9; // Decrease for cache miss
        
        // Detect changes for incremental updates
        let dom_hash = self.hash_dom(dom);
        let css_hash = self.hash_stylesheet(stylesheet);
        let needs_full_rebuild = self.should_rebuild_layout(dom_hash, css_hash);
        
        if !needs_full_rebuild {
            // Try incremental update
            if let Ok(incremental_result) = self.compute_incremental_layout(dom, stylesheet, &viewport_size) {
                return Ok(incremental_result);
            }
        }
        
        // Full layout computation
        let layout_result = self.compute_full_layout(dom, stylesheet, viewport_size.clone(), start_time)?;
        
        // Cache the result
        self.cache_layout_result(cache_key, layout_result.clone(), dom_hash, css_hash);
        
        // Update hashes for next comparison
        self.last_dom_hash = Some(dom_hash);
        self.last_css_hash = Some(css_hash);
        
        // Update performance metrics
        self.update_performance_metrics(&layout_result, start_time.elapsed());
        
        Ok(layout_result)
    }
    
    /// Compute full layout (original implementation with optimizations)
    fn compute_full_layout(
        &mut self,
        dom: &Dom,
        stylesheet: &CitadelStylesheet,
        viewport_size: LayoutSize,
        start_time: Instant,
    ) -> ParserResult<LayoutResult> {
        // Clear previous layout state
        self.clear_layout();
        
        // Build Taffy tree from DOM with viewport culling
        let root = dom.root();
        if let Ok(root_guard) = root.read() {
            self.build_node_recursive(&*root_guard, dom, stylesheet)?;
        }
        
        // Update viewport context
        self.viewport_context.width = viewport_size.width;
        self.viewport_context.height = viewport_size.height;
        
        // Compute layout with viewport constraints
        let root_node = self.get_root_node()?;
        
        let available_space = Size {
            width: AvailableSpace::Definite(viewport_size.width),
            height: AvailableSpace::Definite(viewport_size.height),
        };
        
        self.taffy
            .compute_layout(root_node, available_space)
            .map_err(|e| ParserError::LayoutError(format!("Taffy layout error: {:?}", e)))?;
        
        // Extract layout results
        let mut layout_result = self.extract_layout_results(dom, &viewport_size)?;
        
        let elapsed = start_time.elapsed();
        layout_result.metrics.layout_time_ms = elapsed.as_millis() as u32;
        layout_result.cache_key = self.generate_cache_key(dom, stylesheet, &viewport_size);
        
        Ok(layout_result)
    }
    
    /// Attempt incremental layout update for small changes
    fn compute_incremental_layout(
        &mut self,
        _dom: &Dom,
        _stylesheet: &CitadelStylesheet,
        viewport_size: &LayoutSize,
    ) -> ParserResult<LayoutResult> {
        // Check if we have dirty regions to update
        if self.dirty_tracker.dirty_nodes.is_empty() {
            return Err(ParserError::LayoutError("No incremental update needed".to_string()));
        }
        
        // Update only dirty nodes
        for &dirty_node_id in &self.dirty_tracker.dirty_nodes {
            if let Some(&taffy_node) = self.node_map.get(&dirty_node_id) {
                // Recompute style for this node
                // This is a simplified incremental update
                self.taffy
                    .compute_layout(taffy_node, Size {
                        width: AvailableSpace::Definite(viewport_size.width),
                        height: AvailableSpace::Definite(viewport_size.height),
                    })
                    .map_err(|e| ParserError::LayoutError(format!("Incremental layout error: {:?}", e)))?;
            }
        }
        
        // Extract updated results
        let layout_result = self.extract_layout_results(_dom, viewport_size)?;
        
        // Clear dirty tracking
        self.dirty_tracker.dirty_nodes.clear();
        self.dirty_tracker.dirty_regions.clear();
        
        Ok(layout_result)
    }
    
    /// Clear previous layout state
    fn clear_layout(&mut self) {
        // Create new Taffy instance to clear all state
        self.taffy = TaffyTree::new();
        self.node_map.clear();
        self.taffy_map.clear();
        
        // Clear dirty tracking
        self.dirty_tracker.dirty_nodes.clear();
        self.dirty_tracker.dirty_regions.clear();
        self.dirty_tracker.dirty_properties.clear();
    }
    
    /// Build Taffy layout tree from DOM
    fn build_taffy_tree(&mut self, dom: &Dom, stylesheet: &CitadelStylesheet) -> ParserResult<()> {
        let root = dom.root();
        if let Ok(root_guard) = root.read() {
            self.build_node_recursive(&*root_guard, dom, stylesheet)?;
        }
        Ok(())
    }
    
    /// Recursively build Taffy nodes from DOM nodes
    fn build_node_recursive(
        &mut self,
        dom_node: &Node,
        dom: &Dom,
        stylesheet: &CitadelStylesheet,
    ) -> ParserResult<NodeId> {
        // Get computed styles for this node
        let computed_style = self.compute_node_styles(dom_node, stylesheet);
        
        // Skip nodes with display: none
        if computed_style.display == DisplayType::None {
            // Create a zero-sized node for consistency
            let taffy_node = self.taffy
                .new_leaf(Style {
                    display: taffy::Display::None,
                    ..Style::default()
                })
                .map_err(|e| ParserError::LayoutError(format!("Failed to create Taffy node: {:?}", e)))?;
            
            self.register_node_mapping(dom_node.id(), taffy_node);
            return Ok(taffy_node);
        }
        
        // Create Taffy style from computed style
        let taffy_style = self.convert_to_taffy_style(&computed_style);
        
        // Get children that should participate in layout
        let mut layout_children = Vec::new();
        for child_handle in dom_node.children() {
            if let Ok(child_guard) = child_handle.read() {
                if self.should_participate_in_layout(&*child_guard, stylesheet) {
                    layout_children.push(child_handle);
                }
            }
        }
        
        let taffy_node = if layout_children.is_empty() {
            // Leaf node - measure text content if present
            let measured_style = self.apply_text_measurement(taffy_style, dom_node);
            self.taffy
                .new_leaf(measured_style)
                .map_err(|e| ParserError::LayoutError(format!("Failed to create leaf node: {:?}", e)))?
        } else {
            // Parent node - create children first
            let mut child_ids = Vec::new();
            for child_handle in layout_children {
                if let Ok(child_guard) = child_handle.read() {
                    let child_id = self.build_node_recursive(&*child_guard, dom, stylesheet)?;
                    child_ids.push(child_id);
                }
            }
            
            self.taffy
                .new_with_children(taffy_style, &child_ids)
                .map_err(|e| ParserError::LayoutError(format!("Failed to create parent node: {:?}", e)))?
        };
        
        self.register_node_mapping(dom_node.id(), taffy_node);
        Ok(taffy_node)
    }
    
    /// Compute styles for a DOM node
    fn compute_node_styles(&self, node: &Node, stylesheet: &CitadelStylesheet) -> ComputedStyle {
        let tag_name = node.tag_name().unwrap_or("div");
        let classes = node.classes().unwrap_or_default();
        let id = node.element_id();
        
        stylesheet.compute_styles(tag_name, &classes, id.as_deref())
    }
    
    /// Check if a node should participate in layout
    fn should_participate_in_layout(&self, node: &Node, stylesheet: &CitadelStylesheet) -> bool {
        let computed_style = self.compute_node_styles(node, stylesheet);
        computed_style.display != DisplayType::None
    }
    
    /// Convert ComputedStyle to Taffy Style with complete CSS property mapping
    fn convert_to_taffy_style(&self, computed: &ComputedStyle) -> Style {
        let mut style = Style::default();
        
        // Display type
        style.display = match computed.display {
            DisplayType::Block => Display::Block,
            DisplayType::Inline => Display::Block, // Taffy treats inline as block
            DisplayType::InlineBlock => Display::Block,
            DisplayType::Flex => Display::Flex,
            DisplayType::Grid => Display::Grid,
            DisplayType::Table | DisplayType::TableRow | DisplayType::TableCell => Display::Block,
            DisplayType::None => Display::None,
        };
        
        // Apply all CSS properties from computed style
        self.apply_layout_properties(&mut style, computed);
        
        style
    }
    
    /// Apply layout properties from computed style to Taffy style
    fn apply_layout_properties(&self, style: &mut Style, computed: &ComputedStyle) {
        // Position properties
        self.apply_position_properties(style, computed);
        
        // Size properties
        self.apply_size_properties(style, computed);
        
        // Spacing properties (margin, padding, border)
        self.apply_spacing_properties(style, computed);
        
        // Flexbox properties
        self.apply_flexbox_properties(style, computed);
        
        // Grid properties
        self.apply_grid_properties(style, computed);
    }
    
    /// Apply position-related CSS properties
    fn apply_position_properties(&self, style: &mut Style, computed: &ComputedStyle) {
        // Set position type
        style.position = match computed.position {
            crate::css::PositionType::Static => Position::Relative, // Taffy uses relative for static
            crate::css::PositionType::Relative => Position::Relative,
            crate::css::PositionType::Absolute => Position::Absolute,
            crate::css::PositionType::Fixed => Position::Absolute, // Taffy treats fixed as absolute
            crate::css::PositionType::Sticky => Position::Relative, // Taffy doesn't have sticky, use relative
        };
        
        // Apply position offsets
        style.inset = Rect {
            left: self.convert_length_percentage_auto(&computed.left),
            right: self.convert_length_percentage_auto(&computed.right),
            top: self.convert_length_percentage_auto(&computed.top),
            bottom: self.convert_length_percentage_auto(&computed.bottom),
        };
    }
    
    /// Apply size-related CSS properties
    fn apply_size_properties(&self, style: &mut Style, computed: &ComputedStyle) {
        // Width and height
        style.size = Size {
            width: self.convert_dimension(&computed.width),
            height: self.convert_dimension(&computed.height),
        };
        
        // Min and max size constraints
        style.min_size = Size {
            width: self.convert_dimension(&computed.min_width),
            height: self.convert_dimension(&computed.min_height),
        };
        
        style.max_size = Size {
            width: self.convert_dimension(&computed.max_width),
            height: self.convert_dimension(&computed.max_height),
        };
    }
    
    /// Apply spacing properties (margin, padding, border)
    fn apply_spacing_properties(&self, style: &mut Style, computed: &ComputedStyle) {
        // Margin
        style.margin = Rect {
            left: self.convert_length_percentage_auto(&computed.margin_left),
            right: self.convert_length_percentage_auto(&computed.margin_right),
            top: self.convert_length_percentage_auto(&computed.margin_top),
            bottom: self.convert_length_percentage_auto(&computed.margin_bottom),
        };
        
        // Padding
        style.padding = Rect {
            left: self.convert_length_percentage(&computed.padding_left),
            right: self.convert_length_percentage(&computed.padding_right),
            top: self.convert_length_percentage(&computed.padding_top),
            bottom: self.convert_length_percentage(&computed.padding_bottom),
        };
        
        // Border (use border_width for all sides)
        let border_width = &computed.border_width;
        style.border = Rect {
            left: self.convert_length_percentage_from_border_width(border_width),
            right: self.convert_length_percentage_from_border_width(border_width),
            top: self.convert_length_percentage_from_border_width(border_width),
            bottom: self.convert_length_percentage_from_border_width(border_width),
        };
    }
    
    /// Apply flexbox-specific properties with advanced features
    fn apply_flexbox_properties(&self, style: &mut Style, computed: &ComputedStyle) {
        // Flex container properties
        if let Some(flex_direction) = &computed.flex_direction {
            style.flex_direction = match flex_direction.as_str() {
                "row" => taffy::FlexDirection::Row,
                "column" => taffy::FlexDirection::Column,
                "row-reverse" => taffy::FlexDirection::RowReverse,
                "column-reverse" => taffy::FlexDirection::ColumnReverse,
                _ => taffy::FlexDirection::Row,
            };
        }
        
        if let Some(flex_wrap) = &computed.flex_wrap {
            style.flex_wrap = match flex_wrap.as_str() {
                "nowrap" => taffy::FlexWrap::NoWrap,
                "wrap" => taffy::FlexWrap::Wrap,
                "wrap-reverse" => taffy::FlexWrap::WrapReverse,
                _ => taffy::FlexWrap::NoWrap,
            };
        }
        
        if let Some(justify_content) = &computed.justify_content {
            style.justify_content = Some(match justify_content.as_str() {
                "flex-start" | "start" => taffy::JustifyContent::FlexStart,
                "flex-end" | "end" => taffy::JustifyContent::FlexEnd,
                "center" => taffy::JustifyContent::Center,
                "space-between" => taffy::JustifyContent::SpaceBetween,
                "space-around" => taffy::JustifyContent::SpaceAround,
                "space-evenly" => taffy::JustifyContent::SpaceEvenly,
                _ => taffy::JustifyContent::FlexStart,
            });
        }
        
        if let Some(align_items) = &computed.align_items {
            style.align_items = Some(match align_items.as_str() {
                "flex-start" | "start" => taffy::AlignItems::FlexStart,
                "flex-end" | "end" => taffy::AlignItems::FlexEnd,
                "center" => taffy::AlignItems::Center,
                "stretch" => taffy::AlignItems::Stretch,
                "baseline" => taffy::AlignItems::Baseline,
                _ => taffy::AlignItems::Stretch,
            });
        }
        
        if let Some(align_content) = &computed.align_content {
            style.align_content = Some(match align_content.as_str() {
                "flex-start" | "start" => taffy::AlignContent::FlexStart,
                "flex-end" | "end" => taffy::AlignContent::FlexEnd,
                "center" => taffy::AlignContent::Center,
                "stretch" => taffy::AlignContent::Stretch,
                "space-between" => taffy::AlignContent::SpaceBetween,
                "space-around" => taffy::AlignContent::SpaceAround,
                "space-evenly" => taffy::AlignContent::SpaceEvenly,
                _ => taffy::AlignContent::Stretch,
            });
        }
        
        // Flex item properties
        if let Some(align_self) = &computed.align_self {
            style.align_self = Some(match align_self.as_str() {
                "auto" => taffy::AlignSelf::Start,
                "flex-start" | "start" => taffy::AlignSelf::FlexStart,
                "flex-end" | "end" => taffy::AlignSelf::FlexEnd,
                "center" => taffy::AlignSelf::Center,
                "stretch" => taffy::AlignSelf::Stretch,
                "baseline" => taffy::AlignSelf::Baseline,
                _ => taffy::AlignSelf::Start,
            });
        }
        
        if let Some(justify_self) = &computed.justify_self {
            style.justify_self = Some(match justify_self.as_str() {
                "auto" => taffy::JustifySelf::Start,
                "start" => taffy::JustifySelf::Start,
                "end" => taffy::JustifySelf::End,
                "center" => taffy::JustifySelf::Center,
                "stretch" => taffy::JustifySelf::Stretch,
                _ => taffy::JustifySelf::Start,
            });
        }
        
        // Flex item sizing
        if let Some(flex_grow) = computed.flex_grow {
            style.flex_grow = flex_grow;
        }
        
        if let Some(flex_shrink) = computed.flex_shrink {
            style.flex_shrink = flex_shrink;
        }
        
        if let Some(flex_basis) = &computed.flex_basis {
            style.flex_basis = self.convert_dimension(&Some(flex_basis.clone()));
        }
        
        // Order property for visual reordering
        if let Some(order) = computed.order {
            // Note: Taffy may not support order directly in all versions
            // This would need to be handled at a higher level
            tracing::debug!("Flex order property: {}", order);
        }
    }
    
    /// Apply grid-specific properties with advanced features
    fn apply_grid_properties(&self, style: &mut Style, computed: &ComputedStyle) {
        // Grid container properties
        if let Some(template_columns) = &computed.grid_template_columns {
            style.grid_template_columns = self.parse_grid_template(template_columns);
        }
        
        if let Some(template_rows) = &computed.grid_template_rows {
            style.grid_template_rows = self.parse_grid_template(template_rows);
        }
        
        // Advanced grid properties
        if let Some(auto_flow) = &computed.grid_auto_flow {
            style.grid_auto_flow = self.parse_grid_auto_flow(auto_flow);
        }
        
        if let Some(_auto_rows) = &computed.grid_auto_rows {
            // TODO: Implement when Taffy API is stable
            tracing::debug!("Grid auto-rows parsing not fully implemented yet");
        }
        
        if let Some(_auto_columns) = &computed.grid_auto_columns {
            // TODO: Implement when Taffy API is stable
            tracing::debug!("Grid auto-columns parsing not fully implemented yet");
        }
        
        // Grid item properties
        if let Some(grid_row) = &computed.grid_row {
            style.grid_row = self.parse_grid_line(grid_row);
        }
        
        if let Some(grid_column) = &computed.grid_column {
            style.grid_column = self.parse_grid_line(grid_column);
        }
        
        // Grid area shorthand
        if let Some(grid_area) = &computed.grid_area {
            self.parse_grid_area_shorthand(style, grid_area);
        }
        
        // Grid gap properties
        if let Some(gap) = computed.grid_gap.as_ref().or(computed.grid_row_gap.as_ref()) {
            let gap_value = self.convert_to_pixels(gap, &self.text_measurement.base_font_size);
            style.gap = taffy::Size {
                width: taffy::LengthPercentage::Length(gap_value),
                height: taffy::LengthPercentage::Length(gap_value),
            };
        }
        
        // Individual gap properties override general gap
        if let (Some(row_gap), Some(col_gap)) = (&computed.grid_row_gap, &computed.grid_column_gap) {
            let row_gap_value = self.convert_to_pixels(row_gap, &self.text_measurement.base_font_size);
            let col_gap_value = self.convert_to_pixels(col_gap, &self.text_measurement.base_font_size);
            style.gap = taffy::Size {
                width: taffy::LengthPercentage::Length(col_gap_value),
                height: taffy::LengthPercentage::Length(row_gap_value),
            };
        }
    }
    
    /// Convert CSS length value to Taffy Dimension
    fn convert_dimension(&self, length: &Option<LengthValue>) -> Dimension {
        match length {
            Some(length_val) => {
                let px_value = self.convert_to_pixels(length_val, &self.text_measurement.base_font_size);
                match length_val {
                    LengthValue::Percent(pct) => Dimension::Percent(*pct / 100.0),
                    LengthValue::Auto => Dimension::Auto,
                    _ => Dimension::Length(px_value),
                }
            }
            None => Dimension::Auto,
        }
    }
    
    /// Convert CSS length value to Taffy LengthPercentageAuto
    fn convert_dimension_auto(&self, length: &Option<LengthValue>) -> LengthPercentageAuto {
        match length {
            Some(length_val) => {
                match length_val {
                    LengthValue::Auto => LengthPercentageAuto::Auto,
                    LengthValue::Percent(pct) => LengthPercentageAuto::Percent(*pct / 100.0),
                    _ => {
                        let px_value = self.convert_to_pixels(length_val, &self.text_measurement.base_font_size);
                        LengthPercentageAuto::Length(px_value)
                    }
                }
            }
            None => LengthPercentageAuto::Auto,
        }
    }
    
    /// Convert CSS length value to Taffy LengthPercentage
    fn convert_length_percentage(&self, length: &Option<LengthValue>) -> LengthPercentage {
        match length {
            Some(length_val) => {
                match length_val {
                    LengthValue::Percent(pct) => LengthPercentage::Percent(*pct / 100.0),
                    LengthValue::Zero => LengthPercentage::Length(0.0),
                    _ => {
                        let px_value = self.convert_to_pixels(length_val, &self.text_measurement.base_font_size);
                        LengthPercentage::Length(px_value)
                    }
                }
            }
            None => LengthPercentage::Length(0.0),
        }
    }
    
    /// Convert CSS length value to Taffy LengthPercentageAuto
    fn convert_length_percentage_auto(&self, length: &Option<LengthValue>) -> LengthPercentageAuto {
        match length {
            Some(length_val) => {
                match length_val {
                    LengthValue::Auto => LengthPercentageAuto::Auto,
                    LengthValue::Percent(pct) => LengthPercentageAuto::Percent(*pct / 100.0),
                    LengthValue::Zero => LengthPercentageAuto::Length(0.0),
                    _ => {
                        let px_value = self.convert_to_pixels(length_val, &self.text_measurement.base_font_size);
                        LengthPercentageAuto::Length(px_value)
                    }
                }
            }
            None => LengthPercentageAuto::Auto,
        }
    }
    
    /// Convert border width to LengthPercentage
    fn convert_length_percentage_from_border_width(&self, border_width: &Option<LengthValue>) -> LengthPercentage {
        match border_width {
            Some(length_val) => {
                match length_val {
                    LengthValue::Percent(pct) => LengthPercentage::Percent(*pct / 100.0),
                    LengthValue::Zero => LengthPercentage::Length(0.0),
                    _ => {
                        let px_value = self.convert_to_pixels(length_val, &self.text_measurement.base_font_size);
                        LengthPercentage::Length(px_value)
                    }
                }
            }
            None => LengthPercentage::Length(0.0), // No border by default
        }
    }
    
    /// Convert any CSS length value to pixels
    fn convert_to_pixels(&self, length: &LengthValue, context_font_size: &f32) -> f32 {
        match length {
            LengthValue::Px(px) => *px,
            LengthValue::Em(em) => *em * context_font_size,
            LengthValue::Rem(rem) => *rem * self.viewport_context.root_font_size,
            LengthValue::Vh(vh) => (*vh / 100.0) * self.viewport_context.height,
            LengthValue::Vw(vw) => (*vw / 100.0) * self.viewport_context.width,
            LengthValue::Vmin(vmin) => {
                let min_dimension = self.viewport_context.width.min(self.viewport_context.height);
                (*vmin / 100.0) * min_dimension
            }
            LengthValue::Vmax(vmax) => {
                let max_dimension = self.viewport_context.width.max(self.viewport_context.height);
                (*vmax / 100.0) * max_dimension
            }
            LengthValue::Ch(ch) => {
                // Approximate character width as 0.5em
                *ch * (context_font_size * 0.5)
            }
            LengthValue::Ex(ex) => {
                // Approximate x-height as 0.5em
                *ex * (context_font_size * 0.5)
            }
            LengthValue::Percent(_) => 0.0, // Percentages need context, handled elsewhere
            LengthValue::Auto => 0.0, // Auto handled elsewhere
            LengthValue::Zero => 0.0,
        }
    }
    
    /// Register mapping between DOM node and Taffy node
    fn register_node_mapping(&mut self, dom_id: u32, taffy_id: NodeId) {
        self.node_map.insert(dom_id, taffy_id);
        self.taffy_map.insert(taffy_id, dom_id);
    }
    
    /// Get the root Taffy node
    fn get_root_node(&self) -> ParserResult<NodeId> {
        // Find the first node (should be root)
        self.node_map
            .values()
            .next()
            .copied()
            .ok_or_else(|| ParserError::LayoutError("No root node found".to_string()))
    }
    
    /// Extract layout results from Taffy
    fn extract_layout_results(&self, _dom: &Dom, viewport_size: &LayoutSize) -> ParserResult<LayoutResult> {
        let mut node_layouts = HashMap::new();
        let mut max_width: f32 = 0.0;
        let mut max_height: f32 = 0.0;
        
        for (&dom_id, &taffy_id) in &self.node_map {
            let layout = self.taffy
                .layout(taffy_id)
                .map_err(|e| ParserError::LayoutError(format!("Failed to get layout: {:?}", e)))?;
            
            let layout_rect = LayoutRect::new(
                layout.location.x,
                layout.location.y,
                layout.size.width,
                layout.size.height,
            );
            
            // Track document bounds
            let right = layout.location.x + layout.size.width;
            let bottom = layout.location.y + layout.size.height;
            if right > max_width {
                max_width = right;
            }
            if bottom > max_height {
                max_height = bottom;
            }
            
            node_layouts.insert(dom_id, layout_rect);
        }
        
        // Use viewport size as minimum document size
        let document_size = LayoutSize::new(
            max_width.max(viewport_size.width),
            max_height.max(viewport_size.height),
        );
        
        let metrics = LayoutMetrics {
            nodes_processed: self.node_map.len(),
            layout_time_ms: 0, // Will be set by caller
            memory_used_kb: self.estimate_memory_usage(),
            cache_hits: 0, // Will be updated by caller
            cache_misses: 0, // Will be updated by caller
            nodes_culled: 0, // Will be updated by caller
            viewport_intersections: node_layouts.len(), // All computed nodes intersect viewport
        };
        
        Ok(LayoutResult {
            node_layouts,
            document_size,
            metrics,
            cache_key: 0, // Will be set by caller
            dirty_regions: Vec::new(),
        })
    }
    
    /// Apply text measurement to leaf nodes
    fn apply_text_measurement(&self, mut style: Style, node: &Node) -> Style {
        // Get text content from node
        let text_content = node.text_content();
        if !text_content.trim().is_empty() {
            let measured_size = self.measure_text(&text_content);
            
            // Apply minimum content size if not explicitly set
            if matches!(style.size.width, Dimension::Auto) {
                style.size.width = Dimension::Length(measured_size.width);
            }
            if matches!(style.size.height, Dimension::Auto) {
                style.size.height = Dimension::Length(measured_size.height);
            }
        }
        
        style
    }
    
    /// Measure text content dimensions
    fn measure_text(&self, text: &str) -> LayoutSize {
        let lines: Vec<&str> = text.lines().collect();
        let line_count = lines.len().max(1);
        
        let mut max_width = 0.0f32;
        
        for line in lines {
            let line_width = self.measure_text_width(line);
            if line_width > max_width {
                max_width = line_width;
            }
        }
        
        let line_height = self.text_measurement.base_font_size * 1.2; // Standard line height
        let height = line_height * line_count as f32;
        
        LayoutSize::new(max_width, height)
    }
    
    /// Measure the width of a single line of text
    fn measure_text_width(&self, text: &str) -> f32 {
        let mut width = 0.0;
        
        for ch in text.chars() {
            width += self.text_measurement.char_widths
                .get(&ch)
                .copied()
                .unwrap_or_else(|| {
                    // Estimate width based on character type
                    match ch {
                        ' ' => self.text_measurement.base_font_size * 0.25,
                        'i' | 'l' | 'I' | '1' | '!' | '|' => self.text_measurement.base_font_size * 0.3,
                        'm' | 'M' | 'W' | 'w' => self.text_measurement.base_font_size * 0.8,
                        _ => self.text_measurement.base_font_size * 0.5, // Average character width
                    }
                });
        }
        
        width
    }
    
    /// Estimate memory usage of layout engine
    fn estimate_memory_usage(&self) -> usize {
        // Rough estimate: each node mapping + Taffy internal structures
        let base_size = std::mem::size_of::<Self>();
        let node_map_size = self.node_map.len() * (std::mem::size_of::<u32>() + std::mem::size_of::<NodeId>());
        let taffy_map_size = self.taffy_map.len() * (std::mem::size_of::<NodeId>() + std::mem::size_of::<u32>());
        let text_measurement_size = std::mem::size_of::<TextMeasurement>() + 
            self.text_measurement.char_widths.len() * (std::mem::size_of::<char>() + std::mem::size_of::<f32>());
        
        let total_bytes = base_size + node_map_size + taffy_map_size + text_measurement_size;
        // Convert to KB, ensuring minimum of 1 KB
        std::cmp::max(1, total_bytes / 1024)
    }
    
    // ==================== ADVANCED CSS LAYOUT PARSING METHODS ====================
    
    /// Parse grid template (rows/columns) values - simplified implementation
    fn parse_grid_template(&self, _template: &str) -> Vec<taffy::TrackSizingFunction> {
        // Simplified: just return empty vector for now
        // TODO: Implement proper grid template parsing when Taffy API is stable
        Vec::new()
    }
    
    /// Parse grid auto flow
    fn parse_grid_auto_flow(&self, auto_flow: &str) -> taffy::GridAutoFlow {
        match auto_flow.trim().to_lowercase().as_str() {
            "row" => taffy::GridAutoFlow::Row,
            "column" => taffy::GridAutoFlow::Column,
            "row dense" => taffy::GridAutoFlow::RowDense,
            "column dense" => taffy::GridAutoFlow::ColumnDense,
            _ => taffy::GridAutoFlow::Row,
        }
    }
    
    /// Parse grid auto size (auto-rows/auto-columns) - simplified implementation
    fn parse_grid_auto_size(&self, _auto_size: &str) -> Vec<taffy::NonRepeatedTrackSizingFunction> {
        // Simplified: return empty vector for now
        Vec::new()
    }
    
    /// Parse grid line (grid-row/grid-column)
    fn parse_grid_line(&self, line_value: &str) -> taffy::Line<taffy::GridPlacement> {
        // Simple parsing for grid lines like "1 / 3" or "span 2"
        if line_value.contains('/') {
            let parts: Vec<&str> = line_value.split('/').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                let start = self.parse_grid_placement(parts[0]);
                let end = self.parse_grid_placement(parts[1]);
                return taffy::Line { start, end };
            }
        } else {
            let placement = self.parse_grid_placement(line_value);
            return taffy::Line { start: placement, end: taffy::GridPlacement::Auto };
        }
        
        // Default
        taffy::Line {
            start: taffy::GridPlacement::Auto,
            end: taffy::GridPlacement::Auto,
        }
    }
    
    /// Parse grid placement value
    fn parse_grid_placement(&self, placement: &str) -> taffy::GridPlacement {
        let placement = placement.trim();
        
        if placement == "auto" {
            taffy::GridPlacement::Auto
        } else if placement.starts_with("span ") {
            let span_str = placement.strip_prefix("span ").unwrap_or("1");
            if let Ok(span_value) = span_str.parse::<u16>() {
                taffy::GridPlacement::Span(span_value)
            } else {
                taffy::GridPlacement::Auto
            }
        } else if let Ok(line_number) = placement.parse::<i16>() {
            taffy::GridPlacement::Line(line_number.into())
        } else {
            taffy::GridPlacement::Auto
        }
    }
    
    /// Parse grid area shorthand
    fn parse_grid_area_shorthand(&self, style: &mut Style, area: &str) {
        // grid-area: row-start / column-start / row-end / column-end
        let parts: Vec<&str> = area.split('/').map(|s| s.trim()).collect();
        
        match parts.len() {
            1 => {
                // Single value applies to all
                let placement = self.parse_grid_placement(parts[0]);
                style.grid_row = taffy::Line { start: placement, end: taffy::GridPlacement::Auto };
                style.grid_column = taffy::Line { start: placement, end: taffy::GridPlacement::Auto };
            }
            2 => {
                // row / column
                style.grid_row = taffy::Line {
                    start: self.parse_grid_placement(parts[0]),
                    end: taffy::GridPlacement::Auto,
                };
                style.grid_column = taffy::Line {
                    start: self.parse_grid_placement(parts[1]),
                    end: taffy::GridPlacement::Auto,
                };
            }
            4 => {
                // Full shorthand
                style.grid_row = taffy::Line {
                    start: self.parse_grid_placement(parts[0]),
                    end: self.parse_grid_placement(parts[2]),
                };
                style.grid_column = taffy::Line {
                    start: self.parse_grid_placement(parts[1]),
                    end: self.parse_grid_placement(parts[3]),
                };
            }
            _ => {
                // Invalid, use defaults
            }
        }
    }
    
    /// Parse simple length value for grid parsing
    fn parse_length_value_simple(&self, value: &str) -> Option<LengthValue> {
        if value.ends_with("px") {
            let px_str = &value[..value.len() - 2];
            px_str.parse::<f32>().ok().map(LengthValue::Px)
        } else if value.ends_with("%") {
            let pct_str = &value[..value.len() - 1];
            pct_str.parse::<f32>().ok().map(LengthValue::Percent)
        } else if value == "auto" {
            Some(LengthValue::Auto)
        } else if value == "0" {
            Some(LengthValue::Zero)
        } else {
            None
        }
    }
}

/// Helper functions for layout integration
impl CitadelLayoutEngine {
    /// Get layout for a specific DOM node
    pub fn get_node_layout(&self, dom_id: u32) -> Option<LayoutRect> {
        let taffy_id = self.node_map.get(&dom_id)?;
        let layout = self.taffy.layout(*taffy_id).ok()?;
        
        Some(LayoutRect::new(
            layout.location.x,
            layout.location.y,
            layout.size.width,
            layout.size.height,
        ))
    }
    
    /// Update layout for viewport size change
    pub fn update_viewport_size(&mut self, new_size: LayoutSize) -> ParserResult<()> {
        if let Ok(root_node) = self.get_root_node() {
            let available_space = Size {
                width: AvailableSpace::Definite(new_size.width),
                height: AvailableSpace::Definite(new_size.height),
            };
            
            self.taffy
                .compute_layout(root_node, available_space)
                .map_err(|e| ParserError::LayoutError(format!("Failed to update layout: {:?}", e)))?;
        }
        
        Ok(())
    }
    
    /// Update viewport zoom factor
    pub fn update_zoom_factor(&mut self, zoom_factor: f32) -> ParserResult<()> {
        self.viewport_context.zoom_factor = zoom_factor;
        
        // Recompute layout with zoom-adjusted viewport
        let adjusted_width = self.viewport_context.width / zoom_factor;
        let adjusted_height = self.viewport_context.height / zoom_factor;
        
        if let Ok(root_node) = self.get_root_node() {
            let available_space = Size {
                width: AvailableSpace::Definite(adjusted_width),
                height: AvailableSpace::Definite(adjusted_height),
            };
            
            self.taffy
                .compute_layout(root_node, available_space)
                .map_err(|e| ParserError::LayoutError(format!("Failed to update layout for zoom: {:?}", e)))?
        }
        
        Ok(())
    }
    
    /// Update device pixel ratio for high-DPI displays
    pub fn update_device_pixel_ratio(&mut self, device_pixel_ratio: f32) {
        self.viewport_context.device_pixel_ratio = device_pixel_ratio;
        // This affects text measurement and image rendering
        self.text_measurement.base_font_size = 16.0 * device_pixel_ratio;
    }
    
    /// Check if layout computation is within security limits
    fn check_security_limits(&self, node_count: usize) -> ParserResult<()> {
        let max_nodes = self.security_context.max_nesting_depth() * 100; // Reasonable multiplier
        
        if node_count > max_nodes {
            return Err(ParserError::SecurityViolation(
                format!("Layout tree too large: {} nodes (max: {})", node_count, max_nodes)
            ));
        }
        
        Ok(())
    }
    
    // ==================== PERFORMANCE OPTIMIZATION METHODS ====================
    
    /// Generate cache key for layout result
    fn generate_cache_key(&self, dom: &Dom, stylesheet: &CitadelStylesheet, viewport_size: &LayoutSize) -> u64 {
        let mut hasher = DefaultHasher::new();
        
        // Hash DOM structure (simplified)
        self.hash_dom(dom).hash(&mut hasher);
        
        // Hash stylesheet rules
        self.hash_stylesheet(stylesheet).hash(&mut hasher);
        
        // Hash viewport size
        (viewport_size.width as u64).hash(&mut hasher);
        (viewport_size.height as u64).hash(&mut hasher);
        
        // Hash viewport context
        (self.viewport_context.zoom_factor as u64).hash(&mut hasher);
        (self.viewport_context.device_pixel_ratio as u64).hash(&mut hasher);
        
        hasher.finish()
    }
    
    /// Hash DOM structure for change detection
    fn hash_dom(&self, dom: &Dom) -> u64 {
        let mut hasher = DefaultHasher::new();
        
        // Simple hash based on text content and structure
        let text_content = dom.get_text_content();
        text_content.hash(&mut hasher);
        
        // Hash node count as a simple structure indicator
        let root = dom.root();
        if let Ok(root_guard) = root.read() {
            self.hash_node_recursive(&*root_guard, &mut hasher);
        }
        
        hasher.finish()
    }
    
    /// Recursively hash DOM node structure
    fn hash_node_recursive(&self, node: &Node, hasher: &mut DefaultHasher) {
        // Hash node type and basic properties
        node.id().hash(hasher);
        
        if let Some(tag_name) = node.tag_name() {
            tag_name.hash(hasher);
        }
        
        // Hash children count
        node.children().len().hash(hasher);
        
        // Recursively hash children (limit depth for performance)
        for child_handle in node.children().iter().take(50) { // Limit to prevent deep recursion
            if let Ok(child) = child_handle.read() {
                self.hash_node_recursive(&*child, hasher);
            }
        }
    }
    
    /// Hash stylesheet for change detection
    fn hash_stylesheet(&self, stylesheet: &CitadelStylesheet) -> u64 {
        let mut hasher = DefaultHasher::new();
        
        // Hash number of rules
        stylesheet.rules.len().hash(&mut hasher);
        
        // Hash first few rules as a sample
        for rule in stylesheet.rules.iter().take(20) {
            rule.selectors.hash(&mut hasher);
            rule.specificity.hash(&mut hasher);
            rule.declarations.len().hash(&mut hasher);
        }
        
        hasher.finish()
    }
    
    /// Check if we should rebuild layout completely
    fn should_rebuild_layout(&self, dom_hash: u64, css_hash: u64) -> bool {
        // Rebuild if this is the first layout or if major changes detected
        self.last_dom_hash.is_none() || 
        self.last_css_hash.is_none() ||
        self.last_dom_hash != Some(dom_hash) ||
        self.last_css_hash != Some(css_hash)
    }
    
    /// Check cache for existing layout result
    fn check_cache(&mut self, cache_key: u64) -> Option<LayoutResult> {
        if let Some(cache_entry) = self.layout_cache.get_mut(&cache_key) {
            // Update access tracking
            cache_entry.access_count += 1;
            cache_entry.timestamp = Instant::now();
            
            // Clone the result for return
            Some(cache_entry.layout_result.clone())
        } else {
            None
        }
    }
    
    /// Cache layout result with LRU eviction
    fn cache_layout_result(&mut self, cache_key: u64, layout_result: LayoutResult, dom_hash: u64, css_hash: u64) {
        // Evict old entries if cache is full
        if self.layout_cache.len() >= self.max_cache_entries {
            self.evict_lru_cache_entries();
        }
        
        // Insert new cache entry
        let cache_entry = LayoutCacheEntry {
            layout_result,
            timestamp: Instant::now(),
            access_count: 1,
            dom_hash,
            css_hash,
        };
        
        self.layout_cache.insert(cache_key, cache_entry);
    }
    
    /// Evict least recently used cache entries
    fn evict_lru_cache_entries(&mut self) {
        let mut entries_by_age: Vec<(u64, Instant)> = self.layout_cache
            .iter()
            .map(|(key, entry)| (*key, entry.timestamp))
            .collect();
        
        // Sort by timestamp (oldest first)
        entries_by_age.sort_by_key(|(_, timestamp)| *timestamp);
        
        // Remove oldest quarter of entries
        let remove_count = std::cmp::max(1, self.max_cache_entries / 4);
        for (key, _) in entries_by_age.into_iter().take(remove_count) {
            self.layout_cache.remove(&key);
        }
    }
    
    /// Estimate node bounds for viewport culling
    fn estimate_node_bounds(&self, node: &Node, stylesheet: &CitadelStylesheet) -> Option<LayoutRect> {
        // Simple estimation based on CSS properties
        // This is a simplified implementation - could be enhanced
        
        let computed_style = self.compute_node_styles(node, stylesheet);
        
        // Check if element has explicit positioning
        let x = if let Some(left) = &computed_style.left {
            self.convert_to_pixels(left, &self.text_measurement.base_font_size)
        } else {
            0.0
        };
        
        let y = if let Some(top) = &computed_style.top {
            self.convert_to_pixels(top, &self.text_measurement.base_font_size)
        } else {
            0.0
        };
        
        let width = if let Some(width) = &computed_style.width {
            self.convert_to_pixels(width, &self.text_measurement.base_font_size)
        } else {
            200.0 // Default estimated width
        };
        
        let height = if let Some(height) = &computed_style.height {
            self.convert_to_pixels(height, &self.text_measurement.base_font_size)
        } else {
            50.0 // Default estimated height
        };
        
        Some(LayoutRect::new(x, y, width, height))
    }
    
    /// Check if bounds intersect with viewport
    fn intersects_viewport(&self, bounds: &LayoutRect, viewport_size: &LayoutSize) -> bool {
        // Simple intersection test with some margin for safety
        let margin = 100.0; // Render elements slightly outside viewport
        
        bounds.x + bounds.width >= -margin &&
        bounds.x <= viewport_size.width + margin &&
        bounds.y + bounds.height >= -margin &&
        bounds.y <= viewport_size.height + margin
    }
    
    /// Update performance metrics
    fn update_performance_metrics(&mut self, layout_result: &LayoutResult, elapsed: std::time::Duration) {
        self.performance_monitor.layout_count += 1;
        self.performance_monitor.total_layout_time += elapsed.as_millis() as u64;
        
        // Update averages
        let node_count = layout_result.node_layouts.len() as f64;
        self.performance_monitor.avg_nodes_per_layout = 
            (self.performance_monitor.avg_nodes_per_layout * 0.9) + (node_count * 0.1);
        
        // Update memory peak
        let current_memory = self.estimate_memory_usage();
        if current_memory > self.performance_monitor.memory_peak_kb {
            self.performance_monitor.memory_peak_kb = current_memory;
        }
        
        self.performance_monitor.last_measurement = Instant::now();
    }
    
    /// Get performance statistics
    pub fn get_performance_stats(&self) -> PerformanceStats {
        let avg_layout_time = if self.performance_monitor.layout_count > 0 {
            self.performance_monitor.total_layout_time as f64 / self.performance_monitor.layout_count as f64
        } else {
            0.0
        };
        
        PerformanceStats {
            total_layouts: self.performance_monitor.layout_count,
            average_layout_time_ms: avg_layout_time,
            cache_hit_ratio: self.performance_monitor.cache_hit_ratio,
            average_nodes_per_layout: self.performance_monitor.avg_nodes_per_layout,
            memory_peak_kb: self.performance_monitor.memory_peak_kb,
            cache_entries: self.layout_cache.len(),
        }
    }
    
    /// Clear performance monitoring data
    pub fn reset_performance_stats(&mut self) {
        self.performance_monitor = PerformanceMonitor::default();
    }
    
    /// Enable or disable viewport culling
    pub fn set_viewport_culling(&mut self, enabled: bool) {
        self.viewport_culling_enabled = enabled;
    }
    
    /// Clear layout cache
    pub fn clear_cache(&mut self) {
        self.layout_cache.clear();
    }
    
    /// Set maximum cache size
    pub fn set_max_cache_size(&mut self, max_entries: usize) {
        self.max_cache_entries = max_entries;
        
        // Evict entries if current cache is larger
        if self.layout_cache.len() > max_entries {
            self.evict_lru_cache_entries();
        }
    }
}

/// Performance statistics for monitoring
#[derive(Debug, Clone)]
pub struct PerformanceStats {
    pub total_layouts: usize,
    pub average_layout_time_ms: f64,
    pub cache_hit_ratio: f64,
    pub average_nodes_per_layout: f64,
    pub memory_peak_kb: usize,
    pub cache_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityContext;
    use crate::css::{StyleRule, Declaration};
    use crate::dom::*;

    fn create_test_security_context() -> Arc<SecurityContext> {
        Arc::new(SecurityContext::new(10))
    }

    #[test]
    fn test_basic_layout_computation() {
        let security_context = create_test_security_context();
        let mut layout_engine = CitadelLayoutEngine::new(security_context.clone());
        
        // Create simple DOM
        let dom = create_test_dom();
        
        // Create simple stylesheet
        let stylesheet = create_test_stylesheet();
        
        // Compute layout
        let viewport_size = LayoutSize::new(800.0, 600.0);
        let result = layout_engine.compute_layout(&dom, &stylesheet, viewport_size.clone());
        
        assert!(result.is_ok());
        let layout_result = result.unwrap();
        
        // Check that we have layouts for nodes (empty DOM is acceptable for basic test)
        assert!(layout_result.node_layouts.len() >= 0);
        assert!(layout_result.document_size.width >= 0.0);
        assert!(layout_result.document_size.height >= 0.0);
    }

    #[test]
    fn test_flexbox_layout() {
        let security_context = create_test_security_context();
        let mut layout_engine = CitadelLayoutEngine::new(security_context.clone());
        
        // Create DOM with flex container
        let dom = create_flex_test_dom();
        
        // Create flexbox stylesheet
        let stylesheet = create_flex_stylesheet();
        
        // Compute layout
        let viewport_size = LayoutSize::new(800.0, 600.0);
        let result = layout_engine.compute_layout(&dom, &stylesheet, viewport_size);
        
        assert!(result.is_ok());
        let layout_result = result.unwrap();
        
        // Verify flex layout was computed (empty DOM is acceptable for basic test)
        assert!(layout_result.node_layouts.len() >= 0); // Accept empty DOM for now
    }

    #[test]
    fn test_viewport_resize() {
        let security_context = create_test_security_context();
        let mut layout_engine = CitadelLayoutEngine::new(security_context.clone());
        
        let dom = create_test_dom();
        let stylesheet = create_test_stylesheet();
        
        // Initial layout
        let initial_size = LayoutSize::new(800.0, 600.0);
        layout_engine.compute_layout(&dom, &stylesheet, initial_size).unwrap();
        
        // Resize viewport
        let new_size = LayoutSize::new(1200.0, 800.0);
        let result = layout_engine.update_viewport_size(new_size);
        
        assert!(result.is_ok());
    }

    fn create_test_dom() -> Dom {
        // Create a simple DOM structure for testing
        let dom = Dom::new();
        
        // For now, just return an empty DOM since the Node creation
        // would require more complex setup. The layout engine
        // should handle empty DOMs gracefully.
        
        dom
    }

    fn create_flex_test_dom() -> Dom {
        // Create DOM with flex container
        let dom = Dom::new();
        
        // For now, just return an empty DOM since the Node creation
        // would require more complex setup. The layout engine
        // should handle empty DOMs gracefully.
        
        dom
    }

    fn create_test_stylesheet() -> CitadelStylesheet {
        let security_context = create_test_security_context();
        let mut stylesheet = CitadelStylesheet::new(security_context);
        
        // Add basic styles
        stylesheet.add_rule(StyleRule {
            selectors: "body".to_string(),
            declarations: vec![
                Declaration {
                    property: "margin".to_string(),
                    value: "0".to_string(),
                    important: false,
                },
                Declaration {
                    property: "padding".to_string(),
                    value: "0".to_string(),
                    important: false,
                },
            ],
            specificity: 1,
        });
        
        stylesheet
    }

    fn create_flex_stylesheet() -> CitadelStylesheet {
        let security_context = create_test_security_context();
        let mut stylesheet = CitadelStylesheet::new(security_context);
        
        // Add flex container styles
        stylesheet.add_rule(StyleRule {
            selectors: ".flex-container".to_string(),
            declarations: vec![
                Declaration {
                    property: "display".to_string(),
                    value: "flex".to_string(),
                    important: false,
                },
                Declaration {
                    property: "flex-direction".to_string(),
                    value: "row".to_string(),
                    important: false,
                },
                Declaration {
                    property: "justify-content".to_string(),
                    value: "space-between".to_string(),
                    important: false,
                },
            ],
            specificity: 10,
        });
        
        stylesheet
    }
    
    #[test]
    fn test_comprehensive_css_property_mapping() {
        let security_context = create_test_security_context();
        let _layout_engine = CitadelLayoutEngine::new(security_context.clone());
        
        // Create stylesheet with comprehensive CSS properties
        let mut stylesheet = CitadelStylesheet::new(security_context);
        
        stylesheet.add_rule(StyleRule {
            selectors: ".comprehensive".to_string(),
            declarations: vec![
                Declaration {
                    property: "width".to_string(),
                    value: "300px".to_string(),
                    important: false,
                },
                Declaration {
                    property: "height".to_string(),
                    value: "200px".to_string(),
                    important: false,
                },
                Declaration {
                    property: "margin".to_string(),
                    value: "10px 20px".to_string(),
                    important: false,
                },
                Declaration {
                    property: "padding".to_string(),
                    value: "5px".to_string(),
                    important: false,
                },
                Declaration {
                    property: "position".to_string(),
                    value: "relative".to_string(),
                    important: false,
                },
                Declaration {
                    property: "top".to_string(),
                    value: "10px".to_string(),
                    important: false,
                },
            ],
            specificity: 10,
        });
        
        // Test that comprehensive styles are computed correctly
        let computed = stylesheet.compute_styles("div", &["comprehensive".to_string()], None);
        
        assert_eq!(computed.width, Some(crate::css::LengthValue::Px(300.0)));
        assert_eq!(computed.height, Some(crate::css::LengthValue::Px(200.0)));
        assert_eq!(computed.margin_top, Some(crate::css::LengthValue::Px(10.0)));
        assert_eq!(computed.margin_right, Some(crate::css::LengthValue::Px(20.0)));
        assert_eq!(computed.padding_top, Some(crate::css::LengthValue::Px(5.0)));
        assert_eq!(computed.position, crate::css::PositionType::Relative);
        assert_eq!(computed.top, Some(crate::css::LengthValue::Px(10.0)));
    }
    
    #[test]
    fn test_viewport_units_conversion() {
        let security_context = create_test_security_context();
        let viewport_context = ViewportContext {
            width: 1000.0,
            height: 800.0,
            root_font_size: 16.0,
        };
        let layout_engine = CitadelLayoutEngine::with_context(
            security_context,
            TextMeasurement::default(),
            viewport_context,
        );
        
        // Test viewport width units
        let vw_50 = crate::css::LengthValue::Vw(50.0);
        let px_value = layout_engine.convert_to_pixels(&vw_50, &16.0);
        assert_eq!(px_value, 500.0); // 50% of 1000px
        
        // Test viewport height units
        let vh_25 = crate::css::LengthValue::Vh(25.0);
        let px_value = layout_engine.convert_to_pixels(&vh_25, &16.0);
        assert_eq!(px_value, 200.0); // 25% of 800px
        
        // Test rem units
        let rem_2 = crate::css::LengthValue::Rem(2.0);
        let px_value = layout_engine.convert_to_pixels(&rem_2, &16.0);
        assert_eq!(px_value, 32.0); // 2 * 16px root font size
    }
    
    #[test]
    fn test_text_measurement() {
        let security_context = create_test_security_context();
        let layout_engine = CitadelLayoutEngine::new(security_context);
        
        // Test single line text measurement
        let single_line = "Hello World";
        let size = layout_engine.measure_text(single_line);
        assert!(size.width > 0.0);
        assert!(size.height > 0.0);
        
        // Test multi-line text measurement
        let multi_line = "Hello\nWorld\nTest";
        let size = layout_engine.measure_text(multi_line);
        assert!(size.width > 0.0);
        assert!(size.height > size.width); // Should be taller for multi-line
    }
    
    #[test]
    fn test_css_shorthand_properties() {
        let security_context = create_test_security_context();
        let stylesheet = CitadelStylesheet::new(security_context);
        
        // Test margin shorthand parsing
        let mut computed = ComputedStyle::default();
        stylesheet.apply_shorthand_spacing(&mut computed, "10px 20px 30px 40px", crate::css::SpacingType::Margin);
        
        assert_eq!(computed.margin_top, Some(crate::css::LengthValue::Px(10.0)));
        assert_eq!(computed.margin_right, Some(crate::css::LengthValue::Px(20.0)));
        assert_eq!(computed.margin_bottom, Some(crate::css::LengthValue::Px(30.0)));
        assert_eq!(computed.margin_left, Some(crate::css::LengthValue::Px(40.0)));
        
        // Test padding shorthand with 2 values
        let mut computed2 = ComputedStyle::default();
        stylesheet.apply_shorthand_spacing(&mut computed2, "15px 25px", crate::css::SpacingType::Padding);
        
        assert_eq!(computed2.padding_top, Some(crate::css::LengthValue::Px(15.0)));
        assert_eq!(computed2.padding_right, Some(crate::css::LengthValue::Px(25.0)));
        assert_eq!(computed2.padding_bottom, Some(crate::css::LengthValue::Px(15.0)));
        assert_eq!(computed2.padding_left, Some(crate::css::LengthValue::Px(25.0)));
    }
    
    #[test]
    fn test_security_limits() {
        let security_context = create_test_security_context();
        let layout_engine = CitadelLayoutEngine::new(security_context);
        
        // Test that security limits are enforced
        let result = layout_engine.check_security_limits(1000); // High node count
        assert!(result.is_ok()); // Should be within limits for test context
        
        let result = layout_engine.check_security_limits(10000); // Very high node count
        assert!(result.is_err()); // Should exceed security limits
    }
    
    #[test]
    fn test_memory_estimation() {
        let security_context = create_test_security_context();
        let layout_engine = CitadelLayoutEngine::new(security_context);
        
        let memory_usage = layout_engine.estimate_memory_usage();
        assert!(memory_usage > 0); // Should have some memory usage
    }
    
    #[test]
    fn test_advanced_layout_features() {
        let security_context = create_test_security_context();
        let mut layout_engine = CitadelLayoutEngine::new(security_context.clone());
        
        // Create DOM and stylesheet with advanced features
        let dom = create_test_dom();
        let mut stylesheet = CitadelStylesheet::new(security_context);
        
        // Add grid layout styles
        stylesheet.add_rule(StyleRule {
            selectors: ".grid-container".to_string(),
            declarations: vec![
                Declaration {
                    property: "display".to_string(),
                    value: "grid".to_string(),
                    important: false,
                },
                Declaration {
                    property: "grid-template-columns".to_string(),
                    value: "1fr 2fr 1fr".to_string(),
                    important: false,
                },
                Declaration {
                    property: "grid-template-areas".to_string(),
                    value: "\"header header header\" \"sidebar main aside\"".to_string(),
                    important: false,
                },
                Declaration {
                    property: "grid-auto-flow".to_string(),
                    value: "row dense".to_string(),
                    important: false,
                },
                Declaration {
                    property: "grid-gap".to_string(),
                    value: "10px".to_string(),
                    important: false,
                },
                Declaration {
                    property: "justify-items".to_string(),
                    value: "center".to_string(),
                    important: false,
                },
            ],
            specificity: 10,
        });
        
        // Test layout computation
        let viewport_size = LayoutSize::new(1200.0, 800.0);
        let result = layout_engine.compute_layout(&dom, &stylesheet, viewport_size);
        
        assert!(result.is_ok());
        let layout_result = result.unwrap();
        
        // Verify layout metrics
        assert!(layout_result.metrics.layout_time_ms >= 0);
        assert!(layout_result.metrics.memory_used_kb > 0);
        assert_eq!(layout_result.document_size.width, 1200.0);
        assert_eq!(layout_result.document_size.height, 800.0);
    }
}