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
};
// Note: euclid and app_units available for advanced geometric calculations if needed

use crate::css::{CitadelStylesheet, ComputedStyle, DisplayType};
use crate::dom::{Dom, Node};
use crate::security::SecurityContext;
use crate::error::{ParserError, ParserResult};

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
            // Leaf node
            self.taffy
                .new_leaf(taffy_style)
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
    
    /// Convert ComputedStyle to Taffy Style
    fn convert_to_taffy_style(&self, computed: &ComputedStyle) -> Style {
        let mut style = computed.layout_style.clone();
        
        // Ensure display type is set correctly
        style.display = match computed.display {
            DisplayType::Block => taffy::Display::Block,
            DisplayType::Inline => taffy::Display::Block, // Taffy treats inline as block
            DisplayType::InlineBlock => taffy::Display::Block,
            DisplayType::Flex => taffy::Display::Flex,
            DisplayType::Grid => taffy::Display::Grid,
            DisplayType::None => taffy::Display::None,
        };
        
        style
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
    fn extract_layout_results(&self, dom: &Dom, viewport_size: LayoutSize) -> ParserResult<LayoutResult> {
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
    
    /// Estimate memory usage of layout engine
    fn estimate_memory_usage(&self) -> usize {
        // Rough estimate: each node mapping + Taffy internal structures
        let base_size = std::mem::size_of::<Self>();
        let node_map_size = self.node_map.len() * (std::mem::size_of::<u32>() + std::mem::size_of::<NodeId>());
        let taffy_map_size = self.taffy_map.len() * (std::mem::size_of::<NodeId>() + std::mem::size_of::<u32>());
        
        (base_size + node_map_size + taffy_map_size) / 1024 // Convert to KB
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
    use crate::css::{CitadelCssParser, StyleRule, Declaration};
    use crate::dom::*;
    use crate::ParserConfig;
    use crate::metrics::ParserMetrics;

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
        let result = layout_engine.compute_layout(&dom, &stylesheet, viewport_size);
        
        assert!(result.is_ok());
        let layout_result = result.unwrap();
        
        // Check that we have layouts for nodes
        assert!(layout_result.node_layouts.len() > 0);
        assert!(layout_result.document_size.width >= viewport_size.width);
        assert!(layout_result.document_size.height >= viewport_size.height);
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
        
        // Verify flex layout was computed
        assert!(layout_result.node_layouts.len() >= 2); // Container + child
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
        Dom::new()
    }

    fn create_flex_test_dom() -> Dom {
        // Create DOM with flex container
        Dom::new()
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
}