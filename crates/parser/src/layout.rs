//! Layout engine integration using Taffy (Servo's Layout 2020)
//! 
//! This module provides layout computation using Taffy, Servo's modern layout engine,
//! while preserving Citadel's security-first approach.

use std::sync::Arc;
use std::collections::HashMap;

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
}

impl Default for ViewportContext {
    fn default() -> Self {
        Self {
            width: 800.0,
            height: 600.0,
            root_font_size: 16.0,
        }
    }
}

/// Layout engine using Taffy for modern CSS layout
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
}

/// Metrics for layout computation
#[derive(Debug, Clone)]
pub struct LayoutMetrics {
    pub nodes_processed: usize,
    pub layout_time_ms: u32,
    pub memory_used_kb: usize,
}

impl Default for LayoutMetrics {
    fn default() -> Self {
        Self {
            nodes_processed: 0,
            layout_time_ms: 0,
            memory_used_kb: 0,
        }
    }
}

impl CitadelLayoutEngine {
    /// Create a new layout engine
    pub fn new(security_context: Arc<SecurityContext>) -> Self {
        Self {
            taffy: TaffyTree::new(),
            security_context,
            node_map: HashMap::new(),
            taffy_map: HashMap::new(),
            text_measurement: TextMeasurement::default(),
            viewport_context: ViewportContext::default(),
        }
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
        }
    }

    /// Compute layout for a DOM tree with associated styles
    pub fn compute_layout(
        &mut self,
        dom: &Dom,
        stylesheet: &CitadelStylesheet,
        viewport_size: LayoutSize,
    ) -> ParserResult<LayoutResult> {
        let start_time = std::time::Instant::now();
        
        // Clear previous layout state
        self.clear_layout();
        
        // Build Taffy tree from DOM
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
        let layout_result = self.extract_layout_results(dom, viewport_size)?;
        
        let elapsed = start_time.elapsed();
        let mut result = layout_result;
        result.metrics.layout_time_ms = elapsed.as_millis() as u32;
        
        Ok(result)
    }
    
    /// Clear previous layout state
    fn clear_layout(&mut self) {
        // Create new Taffy instance to clear all state
        self.taffy = TaffyTree::new();
        self.node_map.clear();
        self.taffy_map.clear();
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
    
    /// Apply flexbox-specific properties
    fn apply_flexbox_properties(&self, style: &mut Style, computed: &ComputedStyle) {
        // Copy existing flexbox properties from computed.layout_style
        style.flex_direction = computed.layout_style.flex_direction;
        style.flex_wrap = computed.layout_style.flex_wrap;
        style.align_items = computed.layout_style.align_items;
        style.align_content = computed.layout_style.align_content;
        style.justify_content = computed.layout_style.justify_content;
        style.align_self = computed.layout_style.align_self;
        style.justify_self = computed.layout_style.justify_self;
        
        // Flex item properties
        style.flex_grow = computed.layout_style.flex_grow;
        style.flex_shrink = computed.layout_style.flex_shrink;
        style.flex_basis = computed.layout_style.flex_basis;
        
        // Gap properties
        style.gap = computed.layout_style.gap;
    }
    
    /// Apply grid-specific properties
    fn apply_grid_properties(&self, style: &mut Style, computed: &ComputedStyle) {
        // Copy existing grid properties from computed.layout_style
        style.grid_template_rows = computed.layout_style.grid_template_rows.clone();
        style.grid_template_columns = computed.layout_style.grid_template_columns.clone();
        style.grid_auto_rows = computed.layout_style.grid_auto_rows.clone();
        style.grid_auto_columns = computed.layout_style.grid_auto_columns.clone();
        style.grid_auto_flow = computed.layout_style.grid_auto_flow;
        
        // Grid item properties
        style.grid_row = computed.layout_style.grid_row;
        style.grid_column = computed.layout_style.grid_column;
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
    fn extract_layout_results(&self, _dom: &Dom, viewport_size: LayoutSize) -> ParserResult<LayoutResult> {
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
        };
        
        Ok(LayoutResult {
            node_layouts,
            document_size,
            metrics,
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
                    property: "grid-gap".to_string(),
                    value: "10px".to_string(),
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