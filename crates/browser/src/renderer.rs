//! Advanced HTML/CSS renderer for Citadel Browser using computed layout
//!
//! This module provides sophisticated visual rendering of HTML/CSS content using
//! computed layout positions from Taffy and applying CSS styles to Iced widgets.
//! This brings the DESIGN.md vision to life with proper web page rendering.

use std::sync::Arc;
use std::collections::HashMap;
use std::time::Instant;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use iced::{
    widget::{container, text, scrollable, Space, Column, container::Appearance, container::StyleSheet, text_input, button, checkbox, pick_list},
    Element, Length, Color, Background, theme, Padding, Font
};
use citadel_parser::{
    Dom, CitadelStylesheet, compute_layout,
    LayoutResult, ComputedStyle
};
use citadel_parser::layout::LayoutRect;
use citadel_parser::dom::{Node, NodeData};
use crate::app::Message;
// WORKAROUND: Remove performance imports for now to fix build
use citadel_parser::css::{ColorValue, LengthValue, PositionType as CssPositionType};

/// Result of a rendering operation
#[derive(Debug, Clone)]
pub struct RenderResult {
    pub success: bool,
    pub elements_rendered: usize,
    pub render_time_ms: u64,
    pub viewport_width: f32,
    pub viewport_height: f32,
    pub warnings: Vec<String>,
}

impl RenderResult {
    pub fn success(elements_rendered: usize, render_time_ms: u64, viewport_width: f32, viewport_height: f32) -> Self {
        Self {
            success: true,
            elements_rendered,
            render_time_ms,
            viewport_width,
            viewport_height,
            warnings: Vec::new(),
        }
    }

    pub fn with_warnings(elements_rendered: usize, render_time_ms: u64, viewport_width: f32, viewport_height: f32, warnings: Vec<String>) -> Self {
        Self {
            success: true,
            elements_rendered,
            render_time_ms,
            viewport_width,
            viewport_height,
            warnings,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            elements_rendered: 0,
            render_time_ms: 0,
            viewport_width: 0.0,
            viewport_height: 0.0,
            warnings: vec![message],
        }
    }
}

/// Sticky direction for sticky positioning
#[derive(Debug, Clone)]
pub enum StickyDirection {
    Top(f32),
    Bottom(f32),
    Left(f32),
    Right(f32),
}

/// Sticky element state for viewport-relative positioning
#[derive(Debug, Clone)]
pub struct StickyElementState {
    pub original_position: PositionContext,
    pub stick_threshold: f32,
    pub is_stuck: bool,
    pub stick_direction: StickyDirection,
}


// Enhanced custom stylesheet for comprehensive visual rendering
#[derive(Clone, Debug)]
struct EnhancedContainerStyle {
    background: Option<Background>,
    border: iced::Border,
    shadow: Option<iced::Shadow>,
    text_color: Option<Color>,
}

// Font weight enumeration for text rendering
#[derive(Debug, Clone, PartialEq)]
enum FontWeight {
    Normal,
    Bold,
    Light,
    Medium,
    SemiBold,
    ExtraBold,
}

// Text decoration styles
#[derive(Debug, Clone, PartialEq)]
enum TextDecoration {
    None,
    Underline,
    LineThrough,
    Overline,
}

// Background type enumeration
#[derive(Debug, Clone)]
enum BackgroundType {
    Color(Color),
    Image(String), // URL to image
    LinearGradient(Vec<Color>),
    RadialGradient(Vec<Color>),
}

impl StyleSheet for EnhancedContainerStyle {
    type Style = iced::Theme;

    fn appearance(&self, _style: &Self::Style) -> Appearance {
        Appearance {
            background: self.background,
            border: self.border,
            shadow: self.shadow.unwrap_or_default(),
            text_color: self.text_color,
        }
    }
}

/// Position context for rendering positioned elements
#[derive(Debug, Clone)]
pub struct PositionContext {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub position_type: PositionType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PositionType {
    Static,
    Relative,
    Absolute,
    Fixed,
}

/// Form state for managing interactive form elements
#[derive(Debug, Clone)]
pub struct FormState {
    /// Input values keyed by element ID or generated key
    pub input_values: HashMap<String, String>,
    /// Checkbox states keyed by element ID or generated key
    pub checkbox_states: HashMap<String, bool>,
    /// Radio button selections keyed by group name
    pub radio_selections: HashMap<String, String>,
    /// Select dropdown selections keyed by element ID
    pub select_selections: HashMap<String, String>,
    /// Form submission data when a form is submitted
    pub pending_submission: Option<FormSubmission>,
}

/// Form submission data
#[derive(Debug, Clone)]
pub struct FormSubmission {
    pub action: String,
    pub method: String,
    pub data: HashMap<String, String>,
    pub form_id: String,
}

/// Form-related messages for handling user interactions
#[derive(Debug, Clone)]
pub enum FormMessage {
    /// Text input value changed
    TextInputChanged(String, String), // (element_id, value)
    /// Checkbox toggled
    CheckboxToggled(String, bool), // (element_id, checked)
    /// Radio button selected
    RadioSelected(String, String), // (group_name, value)
    /// Select dropdown changed
    SelectChanged(String, String), // (element_id, value)
    /// Button clicked
    ButtonClicked(String), // element_id
    /// Form submitted
    FormSubmitted(String), // form_id
}

/// Content size information
#[derive(Debug, Clone, Default)]
pub struct ContentSize {
    pub width: f32,
    pub height: f32,
}

/// Send-safe widget cache entry that stores render data instead of Elements
struct WidgetCacheEntry {
    /// Cached widget data that can be reconstructed
    widget_data: CachedWidgetData,
    /// When this cache entry was created
    timestamp: std::time::Instant,
    /// How many times this entry has been accessed
    access_count: std::sync::atomic::AtomicUsize,
    /// Hash of the DOM node this widget represents
    node_hash: u64,
}

/// Cached widget data that can be used to reconstruct Elements
#[derive(Debug, Clone)]
struct CachedWidgetData {
    /// Widget type for reconstruction
    widget_type: WidgetType,
    /// Content hash to detect changes
    content_hash: u64,
    /// Whether this element should be rendered
    is_visible: bool,
}

/// Types of widgets we can cache
#[derive(Debug, Clone)]
enum WidgetType {
    Text(TextWidgetData),
    Container(ContainerWidgetData),
    Image(ImageWidgetData),
    Space(SpaceWidgetData),
    FormInput(FormInputData),
}

/// Data for text widgets
#[derive(Debug, Clone)]
struct TextWidgetData {
    content: String,
    size: f32,
    color: Option<Color>,
    font_family: Option<String>,
}

/// Data for container widgets
#[derive(Debug, Clone)]
struct ContainerWidgetData {
    width: Option<Length>,
    height: Option<Length>,
    background_color: Option<Background>,
    padding: Option<Padding>,
}

/// Data for image widgets
#[derive(Debug, Clone)]
struct ImageWidgetData {
    source: String,
    width: Option<Length>,
    height: Option<Length>,
}

/// Data for space widgets
#[derive(Debug, Clone)]
struct SpaceWidgetData {
    width: Length,
    height: Length,
}

/// Data for form input widgets
#[derive(Debug, Clone)]
struct FormInputData {
    input_type: String,
    value: String,
    placeholder: Option<String>,
    width: Length,
}

impl std::fmt::Debug for WidgetCacheEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WidgetCacheEntry")
            .field("timestamp", &self.timestamp)
            .field("access_count", &self.access_count.load(std::sync::atomic::Ordering::Relaxed))
            .field("node_hash", &self.node_hash)
            .field("widget_type", &"WidgetType")
            .finish()
    }
}

impl Clone for WidgetCacheEntry {
    fn clone(&self) -> Self {
        Self {
            widget_data: self.widget_data.clone(),
            timestamp: self.timestamp,
            access_count: std::sync::atomic::AtomicUsize::new(
                self.access_count.load(std::sync::atomic::Ordering::Relaxed)
            ),
            node_hash: self.node_hash,
        }
    }
}

impl WidgetCacheEntry {
    /// Create a new cache entry
    fn new(widget_data: CachedWidgetData, node_hash: u64) -> Self {
        Self {
            widget_data,
            timestamp: std::time::Instant::now(),
            access_count: std::sync::atomic::AtomicUsize::new(1),
            node_hash,
        }
    }

    /// Increment access count and get current value
    fn increment_access(&self) -> usize {
        self.access_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
    }

    /// Check if this entry is stale (older than given duration)
    fn is_stale(&self, max_age: std::time::Duration) -> bool {
        self.timestamp.elapsed() > max_age
    }

    /// Reconstruct an Element from the cached data
    fn to_element(&self) -> Element<Message> {
        match &self.widget_data.widget_type {
            WidgetType::Text(data) => {
                let mut text_widget = text(&data.content);
                if let Some(size) = Some(data.size) {
                    text_widget = text_widget.size(size);
                }
                if let Some(color) = &data.color {
                    text_widget = text_widget.style(*color);
                }
                text_widget.into()
            }
            WidgetType::Container(data) => {
                let container = container(text(""));
                container.into()
            }
            WidgetType::Image(data) => {
                // Would need to load the image from source
                text(format!("[Image: {}]", data.source)).into()
            }
            WidgetType::Space(data) => {
                Space::new(data.width, data.height).into()
            }
            WidgetType::FormInput(data) => {
                text_input("Form inputs not yet cached", &data.value).into()
            }
        }
    }
}

// Note: WidgetCacheEntry cannot be cloned because Element doesn't implement Clone
// This is by design - cached elements should not be cloned, only referenced

/// Render performance metrics
#[derive(Debug, Clone, Default)]
pub struct RenderMetrics {
    pub widget_cache_hits: usize,
    pub widget_cache_misses: usize,
    pub nodes_rendered: usize,
    pub nodes_culled: usize,
    pub render_time_ms: u64,
    pub memory_allocated_kb: usize,
}

/// Viewport transformation for zoom and scroll
#[derive(Debug, Clone)]
pub struct ViewportTransform {
    pub zoom_factor: f32,
    pub scroll_x: f32,
    pub scroll_y: f32,
    pub viewport_width: f32,
    pub viewport_height: f32,
}

impl Default for ViewportTransform {
    fn default() -> Self {
        Self {
            zoom_factor: 1.0,
            scroll_x: 0.0,
            scroll_y: 0.0,
            viewport_width: 800.0,
            viewport_height: 600.0,
        }
    }
}

/// Advanced HTML/CSS renderer that converts DOM + computed layout into positioned Iced widgets
pub struct CitadelRenderer {
    /// Current DOM tree being rendered
    current_dom: Option<Arc<Dom>>,
    /// Current stylesheet
    current_stylesheet: Option<Arc<CitadelStylesheet>>,
    /// Current layout result with computed positions
    current_layout: Option<LayoutResult>,
    /// Viewport size
    viewport_size: (f32, f32),
    /// Security context for safe rendering
    security_violations: Vec<String>,
    /// Resource loading base URL for images and fonts
    base_url: Option<String>,
    /// Font cache for web fonts
    font_cache: std::collections::HashMap<String, Font>,
    /// Image cache for loaded images
    image_cache: std::collections::HashMap<String, iced::widget::image::Handle>,
    /// Form state management
    form_state: FormState,
    /// Form element counter for generating unique IDs
    form_element_counter: u32,
    /// Viewport transformation state
    viewport_transform: ViewportTransform,
    /// Computed content size for scrolling
    content_size: ContentSize,
    /// Sticky positioned elements tracking
    sticky_elements: HashMap<u32, StickyElementState>,
    /// Widget cache for render tree optimization
    widget_cache: HashMap<u64, WidgetCacheEntry>,
    /// Maximum widget cache size
    max_widget_cache_size: usize,
    /// Performance monitor (TODO: Fix circular import)
    // performance_monitor: Option<Arc<PerformanceMonitor>>,
    /// Render metrics for this renderer
    render_metrics: RenderMetrics,
    /// Viewport culling enabled
    viewport_culling_enabled: bool,
    /// Last DOM content hash for change detection
    last_dom_hash: Option<u64>,
    /// Last layout hash for change detection
    last_layout_hash: Option<u64>,
    /// Frame batching for smooth animations
    frame_batching_enabled: bool,
    /// Pending widget updates for batching
    pending_widget_updates: Vec<u32>,
}

impl CitadelRenderer {
    /// Create a new advanced renderer with performance optimizations
    pub fn new() -> Self {
        Self {
            current_dom: None,
            current_stylesheet: None,
            current_layout: None,
            viewport_size: (800.0, 600.0),
            security_violations: Vec::new(),
            base_url: None,
            font_cache: std::collections::HashMap::new(),
            image_cache: std::collections::HashMap::new(),
            form_state: FormState {
                input_values: HashMap::new(),
                checkbox_states: HashMap::new(),
                radio_selections: HashMap::new(),
                select_selections: HashMap::new(),
                pending_submission: None,
            },
            form_element_counter: 0,
            viewport_transform: ViewportTransform::default(),
            content_size: ContentSize::default(),
            sticky_elements: HashMap::new(),
            widget_cache: HashMap::new(),
            max_widget_cache_size: 1000, // Configurable cache size
            // performance_monitor: None,
            render_metrics: RenderMetrics::default(),
            viewport_culling_enabled: true,
            last_dom_hash: None,
            last_layout_hash: None,
            frame_batching_enabled: true,
            pending_widget_updates: Vec::new(),
        }
    }
    
    // Create renderer with performance monitor (TODO: Fix circular import)
    // pub fn new_with_performance_monitor(performance_monitor: Arc<PerformanceMonitor>) -> Self {
    //     let mut renderer = Self::new();
    //     renderer.performance_monitor = Some(performance_monitor);
    //     renderer
    // }

    /// Set the base URL for resource loading
    pub fn set_base_url(&mut self, url: String) {
        self.base_url = Some(url);
    }
    
    /// Update the content to render with full layout computation and caching
    pub fn update_content(
        &mut self,
        dom: Arc<Dom>,
        stylesheet: Arc<CitadelStylesheet>,
    ) -> Result<(), String> {
        let start_time = Instant::now();
        
        println!("📥 CitadelRenderer::update_content() called");
        println!("  DOM rules: {}", stylesheet.rules.len());
        let text_content = dom.get_text_content();
        println!("  DOM text length: {} chars", text_content.len());
        if text_content.len() > 0 {
            println!("  Text preview: '{}'", &text_content[..std::cmp::min(100, text_content.len())]);
        }

        // Check if we can do incremental update
        let dom_hash = self.hash_dom(&dom);
        let should_invalidate_cache = self.should_invalidate_widget_cache(dom_hash);
        
        if should_invalidate_cache {
            log::debug!("DOM changed, invalidating widget cache");
            self.clear_widget_cache();
        }

        // Compute layout using Taffy engine
        let layout_result = compute_layout(&dom, &stylesheet, self.viewport_size.0, self.viewport_size.1)
            .map_err(|e| format!("Advanced layout computation failed: {}", e))?;

        log::info!("Layout computed: {} nodes, {}ms, cache hits: {}, cache misses: {}",
                   layout_result.node_layouts.len(),
                   layout_result.metrics.layout_time_ms,
                   layout_result.metrics.cache_hits,
                   layout_result.metrics.cache_misses);

        // Update content size based on new layout
        self.update_content_size_from_layout(&layout_result);
        
        // Update performance metrics
        let render_time = start_time.elapsed();
        self.update_render_metrics(&layout_result, render_time);
        
        // Update memory usage if performance monitor is available
        // TODO: Re-enable performance monitoring
        // if let Some(monitor) = &self.performance_monitor {
        //     let memory_usage = self.estimate_memory_usage();
        //     monitor.update_memory_usage("renderer", memory_usage);
        //     monitor.add_measurement("render", render_time.as_millis() as u64);
        // }
        
        self.current_dom = Some(dom);
        self.current_stylesheet = Some(stylesheet);
        self.current_layout = Some(layout_result);
        self.last_dom_hash = Some(dom_hash);

        Ok(())
    }

    /// Update viewport size and recompute layout with caching optimization
    pub fn update_viewport_size(&mut self, width: f32, height: f32) {
        log::info!("Updating viewport size: {}x{}", width, height);
        
        // Check if viewport size actually changed
        if (self.viewport_size.0 - width).abs() < 1.0 && (self.viewport_size.1 - height).abs() < 1.0 {
            log::debug!("Viewport size unchanged, skipping layout recomputation");
            return;
        }
        
        self.viewport_size = (width, height);
        self.viewport_transform.viewport_width = width;
        self.viewport_transform.viewport_height = height;

        // Invalidate viewport-dependent cache entries
        self.invalidate_viewport_dependent_cache();

        // Recompute layout if we have content
        if let (Some(dom), Some(stylesheet)) = (&self.current_dom, &self.current_stylesheet) {
            let start_time = Instant::now();
            
            match compute_layout(dom, stylesheet, width, height) {
                Ok(layout_result) => {
                    // Update content size based on layout
                    self.update_content_size_from_layout(&layout_result);
                    
                    // Update performance metrics
                    let render_time = start_time.elapsed();
                    self.update_render_metrics(&layout_result, render_time);
                    
                    self.current_layout = Some(layout_result);
                }
                Err(e) => {
                    log::warn!("Failed to recompute layout for new viewport size: {}", e);
                }
            }
        }
    }
    
    /// Set zoom level for content rendering with cache optimization
    pub fn set_zoom_level(&mut self, zoom_factor: f32) {
        log::info!("Setting zoom level to {:.1}x", zoom_factor);
        
        // Check if zoom factor actually changed
        if (self.viewport_transform.zoom_factor - zoom_factor).abs() < 0.01 {
            log::debug!("Zoom factor unchanged, skipping layout recomputation");
            return;
        }
        
        self.viewport_transform.zoom_factor = zoom_factor;
        
        // Invalidate zoom-dependent cache entries
        self.invalidate_zoom_dependent_cache();
        
        // Recompute layout with new zoom factor
        if let (Some(dom), Some(stylesheet)) = (&self.current_dom, &self.current_stylesheet) {
            let effective_width = self.viewport_size.0 / zoom_factor;
            let effective_height = self.viewport_size.1 / zoom_factor;
            
            match compute_layout(dom, stylesheet, effective_width, effective_height) {
                Ok(layout_result) => {
                    self.update_content_size_from_layout(&layout_result);
                    self.current_layout = Some(layout_result);
                }
                Err(e) => {
                    log::warn!("Failed to recompute layout for zoom change: {}", e);
                }
            }
        }
    }
    
    /// Set scroll position
    pub fn set_scroll_position(&mut self, x: f32, y: f32) {
        self.viewport_transform.scroll_x = x;
        self.viewport_transform.scroll_y = y;
        
        // Update sticky element positions
        self.update_sticky_elements();
    }
    
    /// Get current content size for scrolling calculations
    pub fn get_content_size(&self) -> ContentSize {
        self.content_size.clone()
    }
    
    /// Update content size from layout result
    fn update_content_size_from_layout(&mut self, layout_result: &LayoutResult) {
        let mut max_width = self.viewport_size.0;
        let mut max_height = self.viewport_size.1;
        
        for layout_rect in layout_result.node_layouts.values() {
            let right = layout_rect.x + layout_rect.width;
            let bottom = layout_rect.y + layout_rect.height;
            
            if right > max_width {
                max_width = right;
            }
            if bottom > max_height {
                max_height = bottom;
            }
        }
        
        // Apply zoom factor to content size
        self.content_size.width = max_width * self.viewport_transform.zoom_factor;
        self.content_size.height = max_height * self.viewport_transform.zoom_factor;
        
        log::debug!("Content size updated: {}x{} (zoom: {:.1}x)", 
                   self.content_size.width, self.content_size.height, 
                   self.viewport_transform.zoom_factor);
    }

    /// Handle form-related messages (placeholder for full implementation)
    pub fn handle_form_message(&mut self, message: FormMessage) {
        log::info!("📝 Form message received: {:?}", message);
        match message {
            FormMessage::TextInputChanged(element_id, value) => {
                log::info!("📝 Text input changed: {} = '{}'", element_id, value);
                self.form_state.input_values.insert(element_id, value);
            }
            FormMessage::CheckboxToggled(element_id, checked) => {
                log::info!("☑️ Checkbox toggled: {} = {}", element_id, checked);
                self.form_state.checkbox_states.insert(element_id, checked);
            }
            FormMessage::RadioSelected(group_name, value) => {
                log::info!("🔘 Radio selected: {} = '{}'", group_name, value);
                self.form_state.radio_selections.insert(group_name, value);
            }
            FormMessage::SelectChanged(element_id, value) => {
                log::info!("📋 Select changed: {} = '{}'", element_id, value);
                self.form_state.select_selections.insert(element_id, value);
            }
            FormMessage::ButtonClicked(element_id) => {
                log::info!("🔲 Button clicked: {}", element_id);
                // Handle button click - might trigger form submission
                self.handle_button_click(&element_id);
            }
            FormMessage::FormSubmitted(form_id) => {
                log::info!("📤 Form submitted: {}", form_id);
                self.handle_form_submission(&form_id);
            }
        }
    }
    
    /// Get the current form state (for external access)
    pub fn get_form_state(&self) -> &FormState {
        &self.form_state
    }
    
    /// Clear form state
    pub fn clear_form_state(&mut self) {
        self.form_state = FormState {
            input_values: HashMap::new(),
            checkbox_states: HashMap::new(),
            radio_selections: HashMap::new(),
            select_selections: HashMap::new(),
            pending_submission: None,
        };
    }
    
    /// Render the current content using computed layout positions
    pub fn render(&self) -> Element<Message> {
        println!("🎨 CitadelRenderer::render() called");
        println!("  DOM present: {}", self.current_dom.is_some());
        println!("  Stylesheet present: {}", self.current_stylesheet.is_some());
        println!("  Layout present: {}", self.current_layout.is_some());
        
        // Log detailed content information
        if let Some(dom) = &self.current_dom {
            let text_content = dom.get_text_content();
            log::info!("  📝 DOM text content length: {} chars", text_content.len());
            if text_content.len() > 0 {
                log::info!("  📚 Text preview: '{}'", &text_content[..std::cmp::min(300, text_content.len())]);
            } else {
                log::warn!("  ⚠️ DOM text content is EMPTY! Investigating DOM structure...");
                
                // Deep DOM structure investigation
                log::warn!("  ⚠️ DOM appears to have no text content. This suggests either:");
                log::warn!("      1. HTML parsing failed to create proper DOM structure");
                log::warn!("      2. Text extraction is not working correctly");
                log::warn!("      3. The content is nested too deeply or in unexpected elements");
            }
        }
        
        match (&self.current_dom, &self.current_stylesheet, &self.current_layout) {
            (Some(dom), Some(stylesheet), Some(layout_result)) => {
                println!("🎨 Rendering with computed layout: {} positioned elements", layout_result.node_layouts.len());
                println!("📊 Stylesheet has {} rules", stylesheet.rules.len());
                
                // Render properly processed content from ZKVM pipeline
                log::info!("🎨 Rendering content processed through ZKVM security boundary");
                
                // Debug: Log DOM structure
                let root_handle = dom.root();
                let root_node = root_handle.read().unwrap();
                log::info!("🌳 DOM root has {} children", root_node.children().len());
                
                // Debug: Check if we have actual content
                let text_content = dom.get_text_content();
                log::info!("📝 Total text content in DOM: {} chars", text_content.len());
                if text_content.len() > 0 {
                    log::info!("📖 Text preview: {}", &text_content[..std::cmp::min(100, text_content.len())]);
                }

                // Render DOM tree as structured widgets
                let root_handle = dom.root();
                
                // The root is the document node - we need to find the HTML element
                let root_node = root_handle.read().unwrap();
                let mut html_element = None;
                
                // Find the <html> element among the document's children
                for child in root_node.children() {
                    let child_node = child.read().unwrap();
                    if let NodeData::Element(elem) = &child_node.data {
                        if elem.local_name() == "html" {
                            html_element = Some(child.clone());
                            break;
                        }
                    }
                }
                
                // Render from the HTML element if found, otherwise from root
                let rendered_content = if let Some(html_handle) = html_element {
                    log::info!("🎯 Found HTML element, rendering from there");
                    let html_node = html_handle.read().unwrap();
                    log::info!("📊 HTML element has {} direct children", html_node.children().len());
                    
                    // Log the structure of HTML element's children
                    for (i, child) in html_node.children().iter().enumerate() {
                        let child_node = child.read().unwrap();
                        match &child_node.data {
                            NodeData::Element(e) => {
                                log::info!("  HTML child {}: <{}> with {} children", i, e.local_name(), child_node.children().len());
                            }
                            NodeData::Text(t) => {
                                log::info!("  HTML child {}: Text({} chars)", i, t.len());
                            }
                            _ => {
                                log::info!("  HTML child {}: Other node type", i);
                            }
                        }
                    }
                    drop(html_node);
                    
                    self.render_with_positioning(&html_handle, dom, stylesheet, layout_result)
                } else {
                    log::warn!("⚠️ No HTML element found, rendering from document root");
                    self.render_with_positioning(&root_handle, dom, stylesheet, layout_result)
                };

                // Create viewport-aware scrollable container
                self.create_viewport_aware_container(rendered_content)
            }
            (Some(dom), Some(stylesheet), None) => {
                log::error!("❌ CRITICAL: Layout computation failed - this should not happen with proper ZKVM processing");
                let _stylesheet_rules = stylesheet.rules.len();
                
                // Layout computation failed, show text content as fallback
                log::error!("❌ Layout unavailable, falling back to text display");
                let text_content = dom.get_text_content();
                let content = if text_content.is_empty() {
                    "No layout available and no text content extracted".to_string()
                } else {
                    text_content
                };
                
                container(
                    Column::new()
                        .push(text("⚠️ LAYOUT UNAVAILABLE - Text Display").size(12).style(Color::from_rgb(1.0, 0.6, 0.0)))
                        .push(scrollable(text(content).size(14)).height(Length::Fill).width(Length::Fill))
                        .spacing(5)
                )
                .width(Length::Fill)
                .height(Length::Fill)
                .padding(10)
                .into()
            }
            (Some(_dom), None, _) => {
                log::error!("❌ CRITICAL: DOM loaded but no stylesheet - this should not happen with proper engine processing");
                
                container(
                    Column::new()
                        .push(text("❌ STYLESHEET MISSING").size(14).style(Color::from_rgb(1.0, 0.4, 0.4)))
                        .push(text("This indicates a critical CSS processing failure").size(12).style(Color::from_rgb(0.8, 0.6, 0.6)))
                        .push(text("Check engine CSS extraction and parsing pipeline").size(12).style(Color::from_rgb(0.8, 0.6, 0.6)))
                        .spacing(5)
                        .align_items(iced::Alignment::Center)
                )
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x()
                .center_y()
                .into()
            }
            _ => {
                log::info!("📋 Renderer waiting for content processing through ZKVM pipeline");
                
                // Show loading state while waiting for ZKVM processed content
                container(
                    Column::new()
                        .push(text("🔒 Citadel Browser").size(24).style(Color::from_rgb(0.2, 0.6, 1.0)))
                        .push(Space::with_height(20))
                        .push(text("🔄 Processing content through security isolation...").size(16).style(Color::from_rgb(0.7, 0.7, 0.7)))
                        .push(Space::with_height(10))
                        .push(text("Content is being securely processed in isolated ZKVM environment").size(12).style(Color::from_rgb(0.6, 0.6, 0.6)))
                        .push(text("This ensures complete tab isolation and security").size(12).style(Color::from_rgb(0.6, 0.6, 0.6)))
                        .spacing(5)
                        .align_items(iced::Alignment::Center)
                )
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x()
                .center_y()
                .into()
            }
        }
    }

    /// Render DOM tree with proper positioning using layout results
    fn render_with_positioning<'a>(
        &'a self,
        node_handle: &citadel_parser::dom::NodeHandle,
        dom: &'a Dom,
        stylesheet: &'a CitadelStylesheet,
        layout_result: &'a LayoutResult,
    ) -> Element<'a, Message> {
        log::info!("🎨 Starting positioned rendering");
        
        // Create a container for absolutely positioned elements
        let positioned_elements = self.collect_positioned_elements(node_handle, dom, stylesheet, layout_result);
        
        if positioned_elements.is_empty() {
            log::warn!("No positioned elements found, falling back to flow layout");
            return self.render_node_recursive(node_handle, dom, stylesheet, layout_result);
        }
        
        log::info!("🎯 Rendering {} positioned elements", positioned_elements.len());
        
        // Create canvas-like rendering using containers with absolute positioning
        let canvas = self.create_positioned_canvas(positioned_elements);
        
        container(canvas)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
    
    /// Collect all elements with their computed positions
    fn collect_positioned_elements<'a>(
        &'a self,
        node_handle: &citadel_parser::dom::NodeHandle,
        dom: &'a Dom,
        stylesheet: &'a CitadelStylesheet,
        layout_result: &'a LayoutResult,
    ) -> Vec<(PositionContext, Element<'a, Message>)> {
        let mut positioned_elements = Vec::new();
        self.collect_elements_recursive(node_handle, dom, stylesheet, layout_result, &mut positioned_elements);
        positioned_elements
    }
    
    /// Recursively collect positioned elements
    fn collect_elements_recursive<'a>(
        &'a self,
        node_handle: &citadel_parser::dom::NodeHandle,
        dom: &'a Dom,
        stylesheet: &'a CitadelStylesheet,
        layout_result: &'a LayoutResult,
        positioned_elements: &mut Vec<(PositionContext, Element<'a, Message>)>,
    ) {
        let node = node_handle.read().unwrap();
        
        // Get layout for this node
        if let Some(layout) = layout_result.node_layouts.get(&node.id()) {
            match &node.data {
                NodeData::Element(element) => {
                    let tag_name = element.local_name();
                    
                    // Skip container elements that don't render content
                    if !matches!(tag_name, "html" | "head" | "meta" | "title" | "script" | "style") {
                        let computed_style = self.compute_node_styles(&node, stylesheet);
                        
                        let position_context = PositionContext {
                            x: layout.x,
                            y: layout.y,
                            width: layout.width,
                            height: layout.height,
                            position_type: self.get_position_type(&computed_style),
                        };
                        
                        // Create the widget for this element with enhanced visual rendering
                        let element_widget = self.create_enhanced_element_widget(&node, element, dom, stylesheet, layout_result, &computed_style);
                        
                        log::info!("📍 Positioned {}: x={:.1}, y={:.1}, w={:.1}, h={:.1}", 
                            tag_name, layout.x, layout.y, layout.width, layout.height);
                        
                        positioned_elements.push((position_context, element_widget));
                    }
                }
                NodeData::Text(_) => {
                    // Text nodes are handled by their parent elements
                }
                _ => {}
            }
        }
        
        // Process children
        for child_handle in node.children() {
            self.collect_elements_recursive(child_handle, dom, stylesheet, layout_result, positioned_elements);
        }
    }
    
    /// Create a canvas with positioned elements
    fn create_positioned_canvas<'a>(
        &'a self,
        positioned_elements: Vec<(PositionContext, Element<'a, Message>)>,
    ) -> Element<'a, Message> {
        // Sort by z-index (for now, render in DOM order)
        let mut sorted_elements = positioned_elements;
        sorted_elements.sort_by(|a, b| a.0.y.partial_cmp(&b.0.y).unwrap_or(std::cmp::Ordering::Equal));
        
        // For now, we'll use a simplified approach with containers and padding to simulate positioning
        // This is a limitation of Iced - true absolute positioning requires custom layout
        let mut column_elements = Vec::new();
        let mut current_y = 0.0;
        
        for (position, element) in sorted_elements {
            // Add vertical spacing to simulate y position
            if position.y > current_y {
                let spacing = (position.y - current_y).max(0.0) as u16;
                if spacing > 0 {
                    column_elements.push(Space::with_height(spacing).into());
                }
            }
            
            // Wrap element in container with horizontal positioning
            let positioned_element = if position.x > 0.0 {
                let x_padding = position.x as u16;
                container(element)
                    .padding(Padding::from([0, 0, 0, x_padding]))
                    .width(Length::Fill)
                    .into()
            } else {
                element
            };
            
            column_elements.push(positioned_element);
            current_y = position.y + position.height;
        }
        
        if column_elements.is_empty() {
            text("No content to render").into()
        } else {
            Column::with_children(column_elements)
                .spacing(0)
                .width(Length::Fill)
                .into()
        }
    }
    
    /// Get position type from computed style
    fn get_position_type(&self, computed_style: &ComputedStyle) -> PositionType {
        match computed_style.position {
            CssPositionType::Static => PositionType::Static,
            CssPositionType::Relative => PositionType::Relative,
            CssPositionType::Absolute => PositionType::Absolute,
            CssPositionType::Fixed => PositionType::Fixed,
            CssPositionType::Sticky => PositionType::Relative, // Sticky treated as relative for now
        }
    }
    
    /// Create enhanced widget for an element with comprehensive visual styling
    fn create_enhanced_element_widget<'a>(
        &'a self,
        node: &Node,
        element: &citadel_parser::dom::Element,
        dom: &'a Dom,
        _stylesheet: &'a CitadelStylesheet,
        layout_result: &'a LayoutResult,
        computed_style: &ComputedStyle,
    ) -> Element<'a, Message> {
        let tag_name = element.local_name();
        
        // Skip dangerous elements
        if self.is_dangerous_element(tag_name) {
            return text("[Blocked for security]")
                .size(12)
                .style(Color::from_rgb(0.8, 0.4, 0.4))
                .into();
        }
        
        // Handle special elements first
        match tag_name {
            "img" => return self.create_image_widget(element, computed_style),
            "br" => return Space::with_height(self.get_line_height_from_style(computed_style) as u16).into(),
            _ => {}
        }
        
        // Extract text content for the element
        let text_content = self.extract_text_content(node, dom);
        
        if !text_content.is_empty() {
            // Get comprehensive styling from computed CSS
            let font_size = self.get_comprehensive_font_size(tag_name, computed_style);
            let text_color = self.get_comprehensive_text_color(tag_name, computed_style);
            let font_weight = self.get_font_weight_from_style(computed_style);
            let _text_decoration = self.get_text_decoration_from_style(computed_style);
            
            log::info!("📝 Creating enhanced text widget for {}: '{}' (size: {}, weight: {:?})", 
                tag_name, text_content, font_size, font_weight);
            
            // Create enhanced text widget with comprehensive styling
            let mut text_widget: iced::widget::Text<iced::Theme> = if tag_name == "a" {
                if let Some(href) = element.get_attribute("href") {
                    text(format!("{} [{}]", text_content, href))
                        .size(font_size)
                        .style(iced::theme::Text::Color(text_color))
                } else {
                    text(text_content)
                        .size(font_size)
                        .style(iced::theme::Text::Color(text_color))
                }
            } else {
                text(text_content)
                    .size(font_size)
                    .style(iced::theme::Text::Color(text_color))
            };
            
            // Apply font if available
            if let Some(font) = self.get_font_from_style(computed_style) {
                text_widget = text_widget.font(font);
            }
            
            // Create enhanced container with comprehensive styling
            let enhanced_style = self.create_enhanced_container_style(computed_style, tag_name);
            let padding = self.get_comprehensive_padding(tag_name, computed_style);
            
            let mut text_container = container(text_widget)
                .padding(padding)
                .style(theme::Container::Custom(Box::new(enhanced_style)));
            
            // Apply layout dimensions if available
            if let Some(layout) = layout_result.node_layouts.get(&node.id()) {
                if layout.width > 0.0 {
                    text_container = text_container.width(Length::Fixed(layout.width));
                }
                if layout.height > 0.0 {
                    text_container = text_container.height(Length::Fixed(layout.height));
                }
            }
            
            text_container.into()
        } else {
            // Element with no text content - create styled container
            let enhanced_style = self.create_enhanced_container_style(computed_style, tag_name);
            let padding = self.get_comprehensive_padding(tag_name, computed_style);
            
            let mut empty_container = container(Space::with_height(0))
                .padding(padding)
                .style(theme::Container::Custom(Box::new(enhanced_style)));
                
            // Apply layout dimensions if available
            if let Some(layout) = layout_result.node_layouts.get(&node.id()) {
                if layout.width > 0.0 {
                    empty_container = empty_container.width(Length::Fixed(layout.width));
                }
                if layout.height > 0.0 {
                    empty_container = empty_container.height(Length::Fixed(layout.height));
                }
            }
            
            empty_container.into()
        }
    }
    
    /// Recursively render DOM nodes as structured Iced widgets (fallback method)
    fn render_node_recursive<'a>(
        &'a self,
        node_handle: &citadel_parser::dom::NodeHandle,
        dom: &'a Dom,
        stylesheet: &'a CitadelStylesheet,
        layout_result: &'a LayoutResult,
    ) -> Element<'a, Message> {
        let node = node_handle.read().unwrap();
        match &node.data {
            NodeData::Element(element) => {
                let tag_name = element.local_name();
                log::info!("🏷️ Rendering element: <{}> with {} children", tag_name, node.children().len());

                // Skip non-visual elements like <style> and metadata
                if self.is_non_visual_element(tag_name) {
                    return Space::with_height(0).into();
                }
                
                // Debug: Check if this is body element
                if tag_name == "body" {
                    log::info!("🎯 Found body element! Has {} children", node.children().len());
                    for (i, child) in node.children().iter().enumerate() {
                        let child_node = child.read().unwrap();
                        match &child_node.data {
                            NodeData::Element(e) => log::info!("  Body child {}: <{}> with {} children", i, e.local_name(), child_node.children().len()),
                            NodeData::Text(t) => log::info!("  Body child {}: Text '{}' ({} chars)", i, t.trim(), t.len()),
                            _ => log::info!("  Body child {}: Other", i),
                        }
                    }
                }
                
                // Debug all elements with their content
                if matches!(tag_name, "h1" | "h2" | "h3" | "p" | "div") {
                    log::info!("🔍 Examining {} element with {} children", tag_name, node.children().len());
                    let text_content = self.extract_text_content(&node, dom);
                    if !text_content.is_empty() {
                        log::info!("  📄 {} text content: '{}'", tag_name, text_content);
                    } else {
                        log::warn!("  ⚠️ {} element has no text content!", tag_name);
                    }
                }
                
                self.render_element(&node, element, dom, stylesheet, layout_result)
            }
            NodeData::Text(text_content) => {
                // Don't trim the text content itself, only check if it's worth rendering
                if !text_content.trim().is_empty() {
                    let preview = if text_content.len() > 50 {
                        format!("{}...", &text_content[..50])
                    } else {
                        text_content.clone()
                    };
                    log::info!("📄 Rendering text node: '{}' ({} chars)", 
                        preview,
                        text_content.len()
                    );
                    text(text_content.as_str())
                        .size(14)
                        .into()
                } else {
                    log::debug!("📄 Skipping empty/whitespace text node: '{}'", text_content);
                    Space::with_height(0).into()
                }
            }
            _ => {
                log::debug!("📄 Skipping non-element, non-text node type");
                Space::with_height(0).into() // Skip other node types
            }
        }
    }

    /// Render an HTML element with proper styling and structure
    fn render_element<'a>(
        &'a self,
        node: &Node,
        element: &citadel_parser::dom::Element,
        dom: &'a Dom,
        stylesheet: &'a CitadelStylesheet,
        layout_result: &'a LayoutResult,
    ) -> Element<'a, Message> {
        let tag_name = element.local_name();
        let computed_style = self.compute_node_styles(node, stylesheet);

        // Skip dangerous or blocked elements for security
        if self.is_dangerous_element(tag_name) {
            return text("[Blocked for security]")
                .size(12)
                .style(Color::from_rgb(0.8, 0.4, 0.4))
                .into();
        }

        // Render children first
        let mut children_widgets = Vec::new();
        for child_handle in node.children() {
            let child_widget = self.render_node_recursive(child_handle, dom, stylesheet, layout_result);
            children_widgets.push(child_widget);
        }

        // Convert to appropriate Iced widget based on HTML element type
        let mut element_widget: Element<Message> = match tag_name {
            "html" | "body" => {
                log::info!("🏗️ Building widget for <{}> with {} children widgets", tag_name, children_widgets.len());
                if children_widgets.is_empty() {
                    log::warn!("⚠️ {} element has no children widgets! Creating fallback content.", tag_name);
                    
                    // For debugging: create a visible indicator
                    if tag_name == "body" {
                        text("[DEBUG: Body element found but has no visible content]") 
                            .size(16)
                            .style(Color::from_rgb(0.8, 0.4, 0.4))
                            .into()
                    } else {
                        Space::with_height(0).into()
                    }
                } else {
                    // Debug: Log what widgets we're adding
                    println!("  📦 Adding {} child widgets to {}", children_widgets.len(), tag_name);
                    for (i, _) in children_widgets.iter().enumerate() {
                        println!("    - Child widget {} added to {}", i, tag_name);
                    }
                    Column::with_children(children_widgets)
                        .spacing(5)
                        .width(Length::Fill)
                        .into()
                }
            }
            "div" => {
                let div_container = if children_widgets.is_empty() {
                    Column::new().spacing(2)
                } else {
                    Column::with_children(children_widgets).spacing(2)
                };

                let enhanced_style = self.create_enhanced_container_style(&computed_style, tag_name);
                let padding = self.get_comprehensive_padding(tag_name, &computed_style);

                let mut div_widget = container(div_container)
                    .width(Length::Fill)
                    .padding(padding)
                    .style(theme::Container::Custom(Box::new(enhanced_style)));
                    
                // Apply layout dimensions if available
                if let Some(layout) = layout_result.node_layouts.get(&node.id()) {
                    if layout.width > 0.0 {
                        div_widget = div_widget.width(Length::Fixed(layout.width));
                    }
                    if layout.height > 0.0 {
                        div_widget = div_widget.height(Length::Fixed(layout.height));
                    }
                }
                
                div_widget.into()
            }
            "p" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "a" | "span" | "em" | "strong" | "b" | "i" | "blockquote" | "pre" => {
                // Always try to extract text content first
                let text_content = self.extract_text_content(node, dom);
                println!("🔍 {} element text extraction: '{}' ({} chars)", tag_name, text_content, text_content.len());
                
                // If we have actual text content, render it
                if !text_content.is_empty() {
                    let font_size = match tag_name {
                        "h1" => 32,
                        "h2" => 28,
                        "h3" => 24,
                        "h4" => 20,
                        "h5" => 18,
                        "h6" => 16,
                        _ => self.get_font_size_from_style(&computed_style),
                    };
                    let color = self.get_text_color_from_style(&computed_style);
                    
                    println!("✅ Creating text widget for {}: '{}' (size: {}, color: {:?})", tag_name, text_content, font_size, color);
                    
                    let text_widget = if tag_name == "a" {
                        if let Some(href) = element.get_attribute("href") {
                            text(format!("{} [{}]", text_content, href))
                                .size(font_size)
                                .style(iced::theme::Text::Color(Color::from_rgb(0.0, 0.4, 0.8)))
                        } else {
                            text(text_content)
                                .size(font_size)
                                .style(iced::theme::Text::Color(Color::from_rgb(0.0, 0.4, 0.8)))
                        }
                    } else {
                        text(text_content).size(font_size).style(iced::theme::Text::Color(color))
                    };
                    
                    let padding = match tag_name {
                        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => [0, 0, 16, 0],
                        "p" | "blockquote" => [0, 0, 12, 0],
                        _ => [0, 0, 6, 0],
                    };
                    
                    container(text_widget)
                        .width(Length::Fill)
                        .padding(padding)
                        .into()
                } else if !children_widgets.is_empty() {
                    // No direct text, but we have child widgets, render them
                    let padding = match tag_name {
                        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => [0, 0, 16, 0],
                        "p" | "blockquote" => [0, 0, 12, 0],
                        _ => [0, 0, 6, 0],
                    };
                    
                    let content = Column::with_children(children_widgets)
                        .spacing(2)
                        .width(Length::Fill);
                    
                    container(content)
                        .width(Length::Fill)
                        .padding(padding)
                        .into()
                } else {
                    log::warn!("⚠️ {} element has no text content or children to render!", tag_name);
                    Space::with_height(0).into()
                }
            }
            "br" => {
                Space::with_height(14).into()
            }
            "img" => {
                self.create_image_widget(element, &computed_style)
            }
            "form" => {
                log::debug!("🏗️ Rendering form element with {} children", children_widgets.len());
                if children_widgets.is_empty() {
                    Space::with_height(0).into()
                } else {
                    let _form_id = element.get_attribute("id").unwrap_or_else(|| format!("form_{}", self.form_element_counter));
                    
                    let enhanced_style = self.create_enhanced_container_style(&computed_style, tag_name);
                    let padding = self.get_comprehensive_padding(tag_name, &computed_style);
                    
                    let form_container = Column::with_children(children_widgets)
                        .spacing(8) // Forms need more spacing between elements
                        .width(Length::Fill);
                    
                    container(form_container)
                        .width(Length::Fill)
                        .padding(padding)
                        .style(theme::Container::Custom(Box::new(enhanced_style)))
                        .into()
                }
            }
            "input" | "textarea" | "select" | "button" => {
                // These should be handled by create_form_widget, but fallback to text if not
                let text_content = self.extract_text_content(node, dom);
                if !text_content.is_empty() {
                    text(text_content).size(14).into()
                } else {
                    // Create a placeholder for the form element
                    let element_type = element.get_attribute("type").unwrap_or_else(|| tag_name.to_string());
                    text(format!("[{} element]", element_type))
                        .size(12)
                        .style(Color::from_rgb(0.6, 0.6, 0.6))
                        .into()
                }
            }
            "label" => {
                log::debug!("🏷️ Rendering label element");
                let text_content = self.extract_text_content(node, dom);
                if !text_content.is_empty() {
                    let font_size = self.get_comprehensive_font_size(tag_name, &computed_style);
                    let text_color = self.get_comprehensive_text_color(tag_name, &computed_style);
                    
                    text(text_content)
                        .size(font_size)
                        .style(iced::theme::Text::Color(text_color))
                        .into()
                } else if !children_widgets.is_empty() {
                    Column::with_children(children_widgets)
                        .spacing(4)
                        .width(Length::Fill)
                        .into()
                } else {
                    Space::with_height(0).into()
                }
            }
            "header" | "main" | "section" | "footer" | "article" | "aside" | "nav" => {
                log::debug!("🏗️ Rendering structural element <{}> with {} children", tag_name, children_widgets.len());
                if children_widgets.is_empty() {
                    Space::with_height(0).into()
                } else {
                    Column::with_children(children_widgets)
                        .spacing(5)
                        .width(Length::Fill)
                        .into()
                }
            }
            "ul" | "ol" => {
                log::debug!("📋 Rendering list <{}> with {} items", tag_name, children_widgets.len());
                if children_widgets.is_empty() {
                    Space::with_height(0).into()
                } else {
                    Column::with_children(children_widgets)
                        .spacing(2)
                        .padding([0, 0, 0, 20])
                        .width(Length::Fill)
                        .into()
                }
            }
            "li" => {
                log::debug!("• Rendering list item with {} children", children_widgets.len());
                if children_widgets.is_empty() {
                    text("•").into()
                } else {
                    Column::with_children(children_widgets)
                        .spacing(0)
                        .width(Length::Fill)
                        .into()
                }
            }
            _ => {
                log::debug!("🔧 Rendering generic element <{}> with {} children", tag_name, children_widgets.len());
                if children_widgets.is_empty() {
                    Space::with_height(0).into()
                } else {
                    Column::with_children(children_widgets)
                        .spacing(2)
                        .width(Length::Fill)
                        .into()
                }
            }
        };

        // Apply layout dimensions if available
        if let Some(layout) = layout_result.node_layouts.get(&node.id()) {
            log::debug!("📐 Applying layout dimensions to {}: {}x{} at ({}, {})", 
                element.local_name(), layout.width, layout.height, layout.x, layout.y);
            
            // Note: Iced doesn't support absolute positioning directly,
            // so we only apply width constraints where meaningful
            if layout.width > 0.0 && layout.width < self.viewport_size.0 {
                element_widget = container(element_widget)
                    .width(Length::Fixed(layout.width))
                    .into();
            }
        }

        element_widget
    }

    /// Extract text content from a node and its children
    fn extract_text_content(&self, node: &Node, _dom: &Dom) -> String {
        let mut text_content = String::new();
        
        log::debug!("🔍 extract_text_content: Starting extraction from node with {} children", node.children().len());
        
        // First check if this node itself has direct text content
        match &node.data {
            NodeData::Text(text) => {
                // Skip style/script contents when rendering text
                // (handled at the element level to avoid leaking raw CSS/JS)
                let trimmed = text.trim();
                log::debug!("  📄 Direct text node found: '{}' ({} chars, {} trimmed)", text, text.len(), trimmed.len());
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
            _ => {}
        }
        
        // Recursively collect text from all child nodes
        for (i, child_handle) in node.children().iter().enumerate() {
            if let Ok(child_node) = child_handle.read() {
                match &child_node.data {
                    NodeData::Text(text) => {
                        let trimmed = text.trim();
                        log::debug!("  📄 Child {}: Found text node '{}' ({} chars, {} trimmed)", i, text, text.len(), trimmed.len());
                        if !trimmed.is_empty() {
                            text_content.push_str(trimmed);
                            text_content.push(' ');
                        }
                    }
                    NodeData::Element(element) => {
                        let child_tag = element.local_name();
                        if self.is_non_visual_element(child_tag) || child_tag == "script" {
                            log::debug!("  🛑 Child {}: Skipping non-visual element <{}>", i, child_tag);
                            continue;
                        }

                        log::debug!("  🏷️ Child {}: Found element <{}> with {} children", i, child_tag, child_node.children().len());
                        // Recursively get text from element's children
                        let child_text = self.extract_text_content(&child_node, _dom);
                        if !child_text.is_empty() {
                            log::debug!("    ✅ Element <{}> contributed text: '{}'", child_tag, child_text);
                            text_content.push_str(&child_text);
                            text_content.push(' ');
                        } else {
                            log::debug!("    ⚠️ Element <{}> contributed no text", child_tag);
                        }
                    }
                    _ => {
                        log::debug!("  🔄 Child {}: Other node type (skipped)", i);
                    }
                }
            }
        }
        
        let result = text_content.trim().to_string();
        log::debug!("🔍 extract_text_content: Final result '{}' ({} chars)", result, result.len());
        result
    }

    /// Compute styles for a DOM node using the stylesheet
    fn compute_node_styles(&self, node: &Node, stylesheet: &CitadelStylesheet) -> ComputedStyle {
        let tag_name = node.tag_name().unwrap_or("div");
        let classes = node.classes().unwrap_or_default();
        let id = node.element_id();

        stylesheet.compute_styles(tag_name, &classes, id.as_deref())
    }

    /// Get padding from computed style
    fn get_padding_from_style(&self, _style: &ComputedStyle) -> u16 {
        // TODO: Implement padding extraction from style.layout_style.padding
        0
    }

    /// Get background from computed style
    fn get_background_from_style(&self, style: &ComputedStyle) -> Option<Background> {
        style.background_color.as_ref().and_then(|c| self.color_value_to_iced_color(c)).map(Background::from)
    }

    /// Get border from computed style
    fn get_border_from_style(&self, style: &ComputedStyle) -> iced::Border {
        iced::Border {
            color: style.border_color.as_ref().and_then(|c| self.color_value_to_iced_color(c)).unwrap_or(Color::TRANSPARENT),
            width: style.border_width.as_ref().map_or(0.0, |w| match w {
                LengthValue::Px(px) => *px,
                _ => 0.0,
            }),
            radius: 0.0.into(), // TODO: Implement border-radius
        }
    }

    /// Get font size from computed style
    fn get_font_size_from_style(&self, style: &ComputedStyle) -> u16 {
        style.font_size.as_ref().map_or(16, |f| match f {
            LengthValue::Px(px) => *px as u16,
            LengthValue::Em(em) => (em * 16.0) as u16, // Assuming 1em = 16px
            _ => 16,
        })
    }

    /// Get text color from computed style (updated signature)
    fn get_text_color_from_style(&self, style: &ComputedStyle) -> Color {
        style.color.as_ref().and_then(|c| self.color_value_to_iced_color(c)).unwrap_or(Color::BLACK)
    }

    fn color_value_to_iced_color(&self, color: &ColorValue) -> Option<Color> {
        match color {
            ColorValue::Rgb(r, g, b) => Some(Color::from_rgb8(*r, *g, *b)),
            ColorValue::Hex(hex) => {
                let hex = hex.trim_start_matches('#');
                if hex.len() == 6 {
                    let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                    let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                    let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                    Some(Color::from_rgb8(r, g, b))
                } else if hex.len() == 3 {
                    let r = u8::from_str_radix(&hex[0..1], 16).ok()? * 17;
                    let g = u8::from_str_radix(&hex[1..2], 16).ok()? * 17;
                    let b = u8::from_str_radix(&hex[2..3], 16).ok()? * 17;
                    Some(Color::from_rgb8(r, g, b))
                } else {
                    None
                }
            }
            ColorValue::Named(name) => {
                match name.to_lowercase().as_str() {
                    "black" => Some(Color::BLACK),
                    "white" => Some(Color::WHITE),
                    "red" => Some(Color::from_rgb8(255, 0, 0)),
                    "green" => Some(Color::from_rgb8(0, 128, 0)),
                    "blue" => Some(Color::from_rgb8(0, 0, 255)),
                    "yellow" => Some(Color::from_rgb8(255, 255, 0)),
                    "transparent" => Some(Color::TRANSPARENT),
                    // Add more colors as needed
                    _ => None
                }
            }
        }
    }

    /// Check if an element is dangerous and should be blocked
    fn is_dangerous_element(&self, tag_name: &str) -> bool {
        matches!(tag_name, "script" | "iframe" | "object" | "embed")
    }

    /// Elements that should not produce visual output
    fn is_non_visual_element(&self, tag_name: &str) -> bool {
        matches!(tag_name, "style" | "link" | "meta" | "head" | "title" | "noscript")
    }
    
    // ==================== ENHANCED VISUAL RENDERING METHODS ====================
    
    /// Create enhanced container style with comprehensive CSS support
    fn create_enhanced_container_style(&self, computed_style: &ComputedStyle, tag_name: &str) -> EnhancedContainerStyle {
        let background = self.get_enhanced_background_from_style(computed_style);
        let border = self.get_enhanced_border_from_style(computed_style);
        let shadow = self.get_box_shadow_from_style(computed_style);
        let text_color = self.get_text_color_from_style(computed_style);
        
        log::debug!("🎨 Creating enhanced style for {}: bg={:?}, border={:?}", 
            tag_name, background.is_some(), border.width > 0.0);
        
        EnhancedContainerStyle {
            background,
            border,
            shadow,
            text_color: Some(text_color),
        }
    }
    
    /// Get comprehensive font size with fallbacks
    fn get_comprehensive_font_size(&self, tag_name: &str, computed_style: &ComputedStyle) -> u16 {
        // Try CSS font-size first
        if let Some(font_size) = &computed_style.font_size {
            match font_size {
                LengthValue::Px(px) => *px as u16,
                LengthValue::Em(em) => (em * 16.0) as u16,
                LengthValue::Rem(rem) => (rem * 16.0) as u16,
                _ => self.get_default_font_size_for_tag(tag_name),
            }
        } else {
            self.get_default_font_size_for_tag(tag_name)
        }
    }
    
    /// Get default font size for HTML tags
    fn get_default_font_size_for_tag(&self, tag_name: &str) -> u16 {
        match tag_name {
            "h1" => 32,
            "h2" => 28,
            "h3" => 24,
            "h4" => 20,
            "h5" => 18,
            "h6" => 16,
            "p" | "div" => 16,
            "small" => 12,
            _ => 14,
        }
    }
    
    /// Get comprehensive text color with fallbacks
    fn get_comprehensive_text_color(&self, tag_name: &str, computed_style: &ComputedStyle) -> Color {
        // Try CSS color first - get_text_color_from_style always returns a Color
        let color = self.get_text_color_from_style(computed_style);
        if color != Color::BLACK {
            return color;
        }
        
        // Fallback to semantic colors
        match tag_name {
            "a" => Color::from_rgb(0.0, 0.4, 0.8),
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => Color::from_rgb(0.1, 0.1, 0.1),
            _ => Color::from_rgb(0.0, 0.0, 0.0),
        }
    }
    
    /// Get font weight from computed style
    fn get_font_weight_from_style(&self, computed_style: &ComputedStyle) -> FontWeight {
        if let Some(weight) = &computed_style.font_weight {
            match weight.to_lowercase().as_str() {
                "bold" | "700" => FontWeight::Bold,
                "800" | "900" => FontWeight::ExtraBold,
                "light" | "100" | "200" | "300" => FontWeight::Light,
                "medium" | "500" => FontWeight::Medium,
                "semibold" | "600" => FontWeight::SemiBold,
                "extrabold" => FontWeight::ExtraBold,
                _ => FontWeight::Normal,
            }
        } else {
            FontWeight::Normal
        }
    }
    
    /// Get text decoration from computed style
    fn get_text_decoration_from_style(&self, _computed_style: &ComputedStyle) -> TextDecoration {
        // TODO: Implement text-decoration parsing when available in CSS parser
        TextDecoration::None
    }
    
    /// Get font from computed style
    fn get_font_from_style(&self, _computed_style: &ComputedStyle) -> Option<Font> {
        // TODO: Implement font-family parsing and web font loading
        None
    }
    
    /// Get line height from computed style
    fn get_line_height_from_style(&self, computed_style: &ComputedStyle) -> f32 {
        // Calculate line height based on font size
        let font_size = self.get_comprehensive_font_size("", computed_style) as f32;
        font_size * 1.2 // Default line height is 1.2 times font size
    }
    
    /// Get comprehensive padding with CSS support
    fn get_comprehensive_padding(&self, tag_name: &str, computed_style: &ComputedStyle) -> Padding {
        // Try CSS padding values first
        let top = self.length_value_to_pixels(computed_style.padding_top.as_ref());
        let right = self.length_value_to_pixels(computed_style.padding_right.as_ref());
        let bottom = self.length_value_to_pixels(computed_style.padding_bottom.as_ref());
        let left = self.length_value_to_pixels(computed_style.padding_left.as_ref());
        
        // If any padding is specified in CSS, use it
        if top > 0.0 || right > 0.0 || bottom > 0.0 || left > 0.0 {
            return Padding::from([top as u16, right as u16, bottom as u16, left as u16]);
        }
        
        // Fallback to semantic padding
        match tag_name {
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => Padding::from([0, 0, 16, 0]),
            "p" | "blockquote" => Padding::from([0, 0, 12, 0]),
            "div" => Padding::from([0, 0, 8, 0]),
            _ => Padding::from([0, 0, 4, 0]),
        }
    }
    
    /// Convert length value to pixels
    fn length_value_to_pixels(&self, length: Option<&LengthValue>) -> f32 {
        match length {
            Some(LengthValue::Px(px)) => *px,
            Some(LengthValue::Em(em)) => em * 16.0, // Assume 1em = 16px
            Some(LengthValue::Rem(rem)) => rem * 16.0, // Assume 1rem = 16px
            Some(LengthValue::Percent(percent)) => {
                // Convert percentage to pixels based on viewport or parent
                (percent / 100.0) * self.viewport_size.0
            }
            Some(LengthValue::Vh(vh)) => (vh / 100.0) * self.viewport_size.1,
            Some(LengthValue::Vw(vw)) => (vw / 100.0) * self.viewport_size.0,
            Some(LengthValue::Zero) => 0.0,
            _ => 0.0,
        }
    }
    
    /// Get enhanced background with support for colors, images, and gradients
    fn get_enhanced_background_from_style(&self, computed_style: &ComputedStyle) -> Option<Background> {
        // TODO: Add support for background-image and gradients
        computed_style.background_color.as_ref()
            .and_then(|c| self.color_value_to_iced_color(c))
            .map(Background::from)
    }
    
    /// Get enhanced border with support for all border properties
    fn get_enhanced_border_from_style(&self, computed_style: &ComputedStyle) -> iced::Border {
        let width = computed_style.border_width.as_ref().map_or(0.0, |w| match w {
            LengthValue::Px(px) => *px,
            _ => 0.0,
        });
        
        let color = computed_style.border_color.as_ref()
            .and_then(|c| self.color_value_to_iced_color(c))
            .unwrap_or(Color::TRANSPARENT);
        
        // TODO: Add border-radius support when available in ComputedStyle
        iced::Border {
            color,
            width,
            radius: 0.0.into(),
        }
    }
    
    /// Get box shadow from computed style
    fn get_box_shadow_from_style(&self, _computed_style: &ComputedStyle) -> Option<iced::Shadow> {
        // TODO: Implement box-shadow parsing when available in CSS parser
        None
    }
    
    /// Create image widget with comprehensive styling
    fn create_image_widget<'a>(
        &'a self,
        element: &citadel_parser::dom::Element,
        computed_style: &ComputedStyle,
    ) -> Element<'a, Message> {
        let alt_text = element.get_attribute("alt").unwrap_or_else(|| "Image".to_string());
        let src = element.get_attribute("src");
        
        // Check if we have the image in cache or can load it
        if let Some(src_url) = src {
            if let Some(_image_handle) = self.image_cache.get(&src_url) {
                // TODO: Create actual image widget when image is cached
                log::info!("🖼️ Image found in cache: {}", src_url);
            } else {
                log::info!("🖼️ Image not in cache, showing placeholder for: {}", src_url);
            }
        }
        
        // For now, create styled placeholder
        let enhanced_style = EnhancedContainerStyle {
            background: Some(Background::Color(Color::from_rgb(0.95, 0.95, 0.95))),
            border: iced::Border {
                color: Color::from_rgb(0.8, 0.8, 0.8),
                width: 1.0,
                radius: 3.0.into(),
            },
            shadow: None,
            text_color: Some(Color::from_rgb(0.5, 0.5, 0.5)),
        };
        
        let padding = self.get_comprehensive_padding("img", computed_style);
        
        container(
            text(format!("🖼️ [{}]", alt_text))
                .size(14)
                .style(Color::from_rgb(0.5, 0.5, 0.5))
        )
        .padding(padding)
        .style(theme::Container::Custom(Box::new(enhanced_style)))
        .into()
    }
    
    /// Create viewport-aware container with scroll and zoom support
    fn create_viewport_aware_container<'a>(&'a self, content: Element<'a, Message>) -> Element<'a, Message> {
        // Apply zoom transformation if needed
        let transformed_content = if self.viewport_transform.zoom_factor != 1.0 {
            self.apply_zoom_transform(content)
        } else {
            content
        };
        
        // Create scrollable container with viewport awareness
        let scrollable_container = scrollable(transformed_content)
            .height(Length::Fill)
            .width(Length::Fill)
            .direction(scrollable::Direction::Both {
                vertical: scrollable::Properties::new(),
                horizontal: scrollable::Properties::new(),
            });
        
        // Apply scroll offset if needed
        let positioned_container = if self.viewport_transform.scroll_x != 0.0 || self.viewport_transform.scroll_y != 0.0 {
            // Note: Iced doesn't directly support scroll offset in containers
            // In a full implementation, this would require custom widgets
            container(scrollable_container)
                .width(Length::Fill)
                .height(Length::Fill)
        } else {
            container(scrollable_container)
                .width(Length::Fill)
                .height(Length::Fill)
        };
        
        positioned_container
            .padding(10)
            .into()
    }
    
    /// Apply zoom transformation to content
    fn apply_zoom_transform<'a>(&'a self, content: Element<'a, Message>) -> Element<'a, Message> {
        // Note: Iced doesn't have native zoom transform support
        // In a full implementation, this would involve:
        // 1. Custom widgets with scale transforms
        // 2. Adjusting all size/position calculations
        // 3. High-DPI rendering support
        
        log::debug!("Applying zoom transform: {:.1}x (simulated)", self.viewport_transform.zoom_factor);
        
        // For now, wrap in a container that could be extended with transform support
        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
    
    /// Update sticky elements based on current scroll position
    fn update_sticky_elements(&mut self) {
        let scroll_y = self.viewport_transform.scroll_y;
        
        for (node_id, sticky_state) in &mut self.sticky_elements {
            match &sticky_state.stick_direction {
                StickyDirection::Top(threshold) => {
                    let should_stick = scroll_y > sticky_state.original_position.y - threshold;
                    if should_stick != sticky_state.is_stuck {
                        sticky_state.is_stuck = should_stick;
                        log::debug!("Sticky element {} top state changed: stuck={}", node_id, should_stick);
                    }
                }
                StickyDirection::Bottom(threshold) => {
                    let viewport_bottom = scroll_y + self.viewport_transform.viewport_height;
                    let element_bottom = sticky_state.original_position.y + sticky_state.original_position.height;
                    let should_stick = viewport_bottom < element_bottom + threshold;
                    if should_stick != sticky_state.is_stuck {
                        sticky_state.is_stuck = should_stick;
                        log::debug!("Sticky element {} bottom state changed: stuck={}", node_id, should_stick);
                    }
                }
                StickyDirection::Left(_) | StickyDirection::Right(_) => {
                    // Horizontal sticky positioning (less common)
                    // Implementation would be similar to vertical
                }
            }
        }
    }
    
    /// Register sticky element for viewport tracking
    fn register_sticky_element(&mut self, node_id: u32, position: PositionContext, computed_style: &ComputedStyle) {
        // Determine sticky direction from CSS properties
        let stick_direction = if let Some(top) = &computed_style.top {
            if let Ok(threshold) = self.length_value_to_pixels_with_error(Some(top)) {
                StickyDirection::Top(threshold)
            } else {
                StickyDirection::Top(0.0)
            }
        } else if let Some(bottom) = &computed_style.bottom {
            if let Ok(threshold) = self.length_value_to_pixels_with_error(Some(bottom)) {
                StickyDirection::Bottom(threshold)
            } else {
                StickyDirection::Bottom(0.0)
            }
        } else {
            StickyDirection::Top(0.0) // Default
        };
        
        let sticky_state = StickyElementState {
            original_position: position,
            stick_threshold: 0.0,
            is_stuck: false,
            stick_direction,
        };
        
        self.sticky_elements.insert(node_id, sticky_state);
        log::debug!("Registered sticky element: {}", node_id);
    }
    
    /// Check if element should be rendered as sticky
    fn is_element_sticky(&self, node_id: u32) -> bool {
        self.sticky_elements.get(&node_id)
            .map(|state| state.is_stuck)
            .unwrap_or(false)
    }
    
    /// Get effective position for sticky elements
    fn get_effective_position(&self, node_id: u32, original_position: &PositionContext) -> PositionContext {
        if let Some(sticky_state) = self.sticky_elements.get(&node_id) {
            if sticky_state.is_stuck {
                match &sticky_state.stick_direction {
                    StickyDirection::Top(offset) => {
                        let mut new_position = original_position.clone();
                        new_position.y = self.viewport_transform.scroll_y + offset;
                        new_position.position_type = PositionType::Fixed;
                        return new_position;
                    }
                    StickyDirection::Bottom(offset) => {
                        let mut new_position = original_position.clone();
                        new_position.y = self.viewport_transform.scroll_y + self.viewport_transform.viewport_height - new_position.height - offset;
                        new_position.position_type = PositionType::Fixed;
                        return new_position;
                    }
                    _ => {}
                }
            }
        }
        
        original_position.clone()
    }
    
    /// Enhanced overflow handling for scrollable content
    fn handle_overflow<'a>(&self, computed_style: &ComputedStyle, content: Element<'a, Message>) -> Element<'a, Message> {
        // Extract overflow properties
        let overflow = computed_style.overflow.as_deref().unwrap_or("visible");
        
        match overflow {
            "hidden" => {
                // Clip content
                container(content)
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .into()
            }
            "scroll" | "auto" => {
                // Show scrollbars when needed
                scrollable(content)
                    .direction(scrollable::Direction::Both {
                        vertical: scrollable::Properties::new(),
                        horizontal: scrollable::Properties::new(),
                    })
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .into()
            }
            _ => {
                // Default to visible (no clipping)
                content
            }
        }
    }
    
    /// Enhanced layout computation with viewport units
    fn compute_viewport_relative_length(&self, length: &LengthValue) -> f32 {
        match length {
            LengthValue::Vh(vh) => (vh / 100.0) * self.viewport_transform.viewport_height,
            LengthValue::Vw(vw) => (vw / 100.0) * self.viewport_transform.viewport_width,
            LengthValue::Vmin(vmin) => {
                let min_dimension = self.viewport_transform.viewport_width.min(self.viewport_transform.viewport_height);
                (vmin / 100.0) * min_dimension
            }
            LengthValue::Vmax(vmax) => {
                let max_dimension = self.viewport_transform.viewport_width.max(self.viewport_transform.viewport_height);
                (vmax / 100.0) * max_dimension
            }
            _ => 0.0, // Not a viewport unit
        }
    }
    
    /// High-DPI rendering support
    fn apply_device_pixel_ratio(&self, size: f32) -> f32 {
        // In a full implementation, this would adjust rendering for high-DPI displays
        size // For now, return as-is
    }
    
    /// Create responsive breakpoint-aware container
    fn create_responsive_container<'a>(&'a self, content: Element<'a, Message>, computed_style: &ComputedStyle) -> Element<'a, Message> {
        // Check if this is a responsive container based on media queries or viewport units
        let has_viewport_units = computed_style.width.as_ref().map_or(false, |w| {
            matches!(w, LengthValue::Vh(_) | LengthValue::Vw(_) | LengthValue::Vmin(_) | LengthValue::Vmax(_))
        }) || computed_style.height.as_ref().map_or(false, |h| {
            matches!(h, LengthValue::Vh(_) | LengthValue::Vw(_) | LengthValue::Vmin(_) | LengthValue::Vmax(_))
        });
        
        if has_viewport_units {
            log::debug!("Creating responsive container with viewport units");
            // Apply viewport-relative sizing
            container(content)
                .width(Length::Fill)
                .height(Length::Fill)
                .into()
        } else {
            content
        }
    }
    
    /// Helper method to convert length values to pixels with proper error handling
    fn length_value_to_pixels_with_error(&self, length: Option<&LengthValue>) -> Result<f32, String> {
        match length {
            Some(LengthValue::Px(px)) => Ok(*px),
            Some(LengthValue::Em(em)) => Ok(em * 16.0), // Assume 1em = 16px
            Some(LengthValue::Rem(rem)) => Ok(rem * 16.0), // Assume 1rem = 16px
            Some(LengthValue::Vh(vh)) => Ok((vh / 100.0) * self.viewport_transform.viewport_height),
            Some(LengthValue::Vw(vw)) => Ok((vw / 100.0) * self.viewport_transform.viewport_width),
            Some(LengthValue::Zero) => Ok(0.0),
            Some(_) => Ok(0.0),
            None => Err("No length value provided".to_string()),
        }
    }
    
    /// Get current viewport metrics for debugging
    pub fn get_viewport_metrics(&self) -> String {
        format!(
            "Viewport: {}x{} | Zoom: {:.1}x | Scroll: ({:.0}, {:.0}) | Content: {}x{}",
            self.viewport_transform.viewport_width,
            self.viewport_transform.viewport_height,
            self.viewport_transform.zoom_factor,
            self.viewport_transform.scroll_x,
            self.viewport_transform.scroll_y,
            self.content_size.width,
            self.content_size.height
        )
    }
    
    /// Handle button click events
    fn handle_button_click(&mut self, element_id: &str) {
        // Find the button element in the DOM to determine its type and form association
        if let Some(dom) = &self.current_dom {
            if let Some(button_element) = self.find_element_by_id(dom, element_id) {
                if let Ok(button_node) = button_element.read() {
                    if let NodeData::Element(element) = &button_node.data {
                        let button_type = element.get_attribute("type").unwrap_or_else(|| "button".to_string());
                        
                        match button_type.as_str() {
                            "submit" => {
                                // Find the parent form and submit it
                                if let Some(form_id) = self.find_parent_form(&button_element) {
                                    self.handle_form_submission(&form_id);
                                }
                            }
                            "reset" => {
                                // Reset the parent form
                                if let Some(form_id) = self.find_parent_form(&button_element) {
                                    self.reset_form(&form_id);
                                }
                            }
                            _ => {
                                // Regular button - just log for now
                                log::info!("🔳 Regular button clicked: {}", element_id);
                            }
                        }
                    }
                }
            }
        }
    }
    
    /// Handle form submission
    fn handle_form_submission(&mut self, form_id: &str) {
        log::info!("📤 Processing form submission for form: {}", form_id);
        
        // Find the form element in the DOM
        if let Some(dom) = &self.current_dom {
            if let Some(form_element) = self.find_element_by_id(dom, form_id) {
                if let Ok(form_node) = form_element.read() {
                    if let NodeData::Element(element) = &form_node.data {
                        let action = element.get_attribute("action").unwrap_or_else(|| "#".to_string());
                        let method = element.get_attribute("method").unwrap_or_else(|| "GET".to_string()).to_uppercase();
                        
                        // Validate form submission security
                        if !self.validate_form_submission(&action, &method) {
                            log::warn!("🛡️ Form submission blocked for security reasons: {}", action);
                            return;
                        }
                        
                        // Collect form data
                        let form_data = self.collect_form_data(form_id, &form_element);
                        
                        // Create form submission
                        let submission = FormSubmission {
                            action,
                            method,
                            data: form_data,
                            form_id: form_id.to_string(),
                        };
                        
                        self.form_state.pending_submission = Some(submission);
                        log::info!("✅ Form submission prepared and ready for network layer");
                    }
                }
            }
        }
    }
    
    /// Validate form submission for security
    fn validate_form_submission(&self, action: &str, method: &str) -> bool {
        // Only allow HTTPS submissions (except for localhost/file)
        if !action.starts_with("https://") && 
           !action.starts_with("http://localhost") && 
           !action.starts_with("http://127.0.0.1") &&
           !action.starts_with("file://") &&
           action != "#" {
            log::warn!("🛡️ Blocking insecure form submission to: {}", action);
            return false;
        }
        
        // Validate HTTP method
        if !matches!(method, "GET" | "POST") {
            log::warn!("🛡️ Blocking form submission with unsupported method: {}", method);
            return false;
        }
        
        true
    }
    
    /// Reset form values
    fn reset_form(&mut self, form_id: &str) {
        log::info!("🔄 Resetting form: {}", form_id);
        
        // Remove all form data for this form
        // Note: In a real implementation, we'd need to track which inputs belong to which form
        self.form_state.input_values.clear();
        self.form_state.checkbox_states.clear();
        self.form_state.radio_selections.clear();
        self.form_state.select_selections.clear();
    }
    
    /// Collect form data from all form elements
    fn collect_form_data(&self, form_id: &str, form_element: &citadel_parser::dom::NodeHandle) -> HashMap<String, String> {
        let mut form_data = HashMap::new();
        
        // Collect data from all form controls within this form
        if let Ok(form_node) = form_element.read() {
            self.collect_form_data_recursive(&form_node, &mut form_data);
        }
        
        log::info!("📊 Collected {} form fields for form {}", form_data.len(), form_id);
        form_data
    }
    
    /// Recursively collect form data from form elements
    fn collect_form_data_recursive(&self, node: &Node, form_data: &mut HashMap<String, String>) {
        if let NodeData::Element(element) = &node.data {
            let tag_name = element.local_name();
            
            match tag_name {
                "input" => {
                    let input_type = element.get_attribute("type").unwrap_or_else(|| "text".to_string());
                    let name = element.get_attribute("name");
                    let id = element.get_attribute("id");
                    
                    let key = name.or(id).unwrap_or_else(|| format!("input_{}", self.form_element_counter));
                    
                    match input_type.as_str() {
                        "text" | "email" | "password" | "number" | "url" | "tel" => {
                            if let Some(value) = self.form_state.input_values.get(&key) {
                                form_data.insert(key, value.clone());
                            }
                        }
                        "checkbox" => {
                            if let Some(&checked) = self.form_state.checkbox_states.get(&key) {
                                if checked {
                                    let value = element.get_attribute("value").unwrap_or_else(|| "on".to_string());
                                    form_data.insert(key, value);
                                }
                            }
                        }
                        "radio" => {
                            if let Some(group_name) = element.get_attribute("name") {
                                if let Some(selected_value) = self.form_state.radio_selections.get(&group_name) {
                                    if let Some(value) = element.get_attribute("value") {
                                        if value == *selected_value {
                                            form_data.insert(group_name, value);
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                "textarea" => {
                    let name = element.get_attribute("name");
                    let id = element.get_attribute("id");
                    let key = name.or(id).unwrap_or_else(|| format!("textarea_{}", self.form_element_counter));
                    
                    if let Some(value) = self.form_state.input_values.get(&key) {
                        form_data.insert(key, value.clone());
                    }
                }
                "select" => {
                    let name = element.get_attribute("name");
                    let id = element.get_attribute("id");
                    let key = name.or(id).unwrap_or_else(|| format!("select_{}", self.form_element_counter));
                    
                    if let Some(value) = self.form_state.select_selections.get(&key) {
                        form_data.insert(key, value.clone());
                    }
                }
                _ => {}
            }
        }
        
        // Recursively process children
        for child in &node.children {
            if let Ok(child_node) = child.read() {
                self.collect_form_data_recursive(&child_node, form_data);
            }
        }
    }
    
    /// Find element by ID in the DOM
    fn find_element_by_id(&self, dom: &Dom, element_id: &str) -> Option<citadel_parser::dom::NodeHandle> {
        dom.get_element_by_id(element_id)
    }
    
    /// Find the parent form element for a given element
    fn find_parent_form(&self, element: &citadel_parser::dom::NodeHandle) -> Option<String> {
        // This is a simplified implementation
        // In a real browser, we'd traverse up the DOM tree to find the parent form
        // For now, we'll use a basic approach
        
        // Check if the element has a form attribute
        if let Ok(node) = element.read() {
            if let NodeData::Element(elem) = &node.data {
                if let Some(form_id) = elem.get_attribute("form") {
                    return Some(form_id);
                }
            }
        }
        
        // TODO: Implement proper form ancestor traversal
        None
    }
    
    /// Create form input widgets
    fn create_form_widget<'a>(
        &'a self,
        element: &citadel_parser::dom::Element,
        computed_style: &ComputedStyle,
    ) -> Option<Element<'a, Message>> {
        let tag_name = element.local_name();
        let font_size = computed_style
            .font_size
            .as_ref()
            .and_then(|len| match len {
                citadel_parser::css::LengthValue::Px(px) => Some(*px as u16),
                citadel_parser::css::LengthValue::Em(em) => Some((em * 16.0) as u16),
                _ => None,
            })
            .unwrap_or(14);
        
        match tag_name {
            "input" => {
                let input_type = element.get_attribute("type").unwrap_or_else(|| "text".to_string());
                let id = element.get_attribute("id").unwrap_or_else(|| {
                    let name = element.get_attribute("name").unwrap_or_else(|| format!("input_{}", self.form_element_counter));
                    name
                });
                
                match input_type.as_str() {
                    "text" | "email" | "password" | "url" | "tel" => {
                        self.create_text_input_widget(element, &id, &input_type, font_size)
                    }
                    "number" => {
                        self.create_number_input_widget(element, &id)
                    }
                    "checkbox" => {
                        self.create_checkbox_widget(element, &id)
                    }
                    "radio" => {
                        self.create_radio_widget(element, &id)
                    }
                    "submit" => {
                        self.create_submit_button_widget(element, &id)
                    }
                    "reset" => {
                        self.create_reset_button_widget(element, &id)
                    }
                    "button" => {
                        self.create_button_widget(element, &id)
                    }
                    _ => {
                        // Unsupported input type - show placeholder
                        Some(text(format!("[{} input]", input_type))
                            .size(12)
                            .style(Color::from_rgb(0.6, 0.6, 0.6))
                            .into())
                    }
                }
            }
            "textarea" => {
                let id = element.get_attribute("id").unwrap_or_else(|| {
                    let name = element.get_attribute("name").unwrap_or_else(|| format!("textarea_{}", self.form_element_counter));
                    name
                });
                self.create_textarea_widget(element, &id)
            }
            "button" => {
                let id = element.get_attribute("id").unwrap_or_else(|| format!("button_{}", self.form_element_counter));
                self.create_button_widget(element, &id)
            }
            "select" => {
                let id = element.get_attribute("id").unwrap_or_else(|| {
                    let name = element.get_attribute("name").unwrap_or_else(|| format!("select_{}", self.form_element_counter));
                    name
                });
                self.create_select_widget(element, &id)
            }
            _ => None,
        }
    }
    
    /// Create text input widget
    fn create_text_input_widget<'a>(
        &'a self,
        element: &citadel_parser::dom::Element,
        element_id: &str,
        input_type: &str,
        font_size: u16,
    ) -> Option<Element<'a, Message>> {
        let placeholder = element.get_attribute("placeholder").unwrap_or_default();
        let current_value = self.form_state.input_values.get(element_id).cloned().unwrap_or_default();
        
        let mut input = text_input(&placeholder, &current_value)
            .padding(8)
            .width(Length::Fixed(200.0))
            .size(font_size);
        
        // Handle password masking
        if input_type == "password" {
            input = input.secure(true);
        }
        
        // Note: In a real implementation, we'd need to convert FormMessage to Message
        // For now, we'll create a static input
        log::info!("📝 Creating {} input: {}", input_type, element_id);
        
        Some(container(input)
            .padding(4)
            .into())
    }
    
    /// Create number input widget
    fn create_number_input_widget<'a>(
        &'a self,
        element: &citadel_parser::dom::Element,
        element_id: &str,
    ) -> Option<Element<'a, Message>> {
        let placeholder = element.get_attribute("placeholder").unwrap_or_else(|| "0".to_string());
        let current_value = self.form_state.input_values.get(element_id).cloned().unwrap_or_default();
        
        let input = text_input(&placeholder, &current_value)
            .padding(8)
            .width(Length::Fixed(120.0));
        
        log::info!("🔢 Creating number input: {}", element_id);
        
        Some(container(input)
            .padding(4)
            .into())
    }
    
    /// Create checkbox widget
    fn create_checkbox_widget<'a>(
        &'a self,
        element: &citadel_parser::dom::Element,
        element_id: &str,
    ) -> Option<Element<'a, Message>> {
        let checked = self.form_state.checkbox_states.get(element_id).copied().unwrap_or(false);
        let label_text = element.get_attribute("value").unwrap_or_else(|| "Checkbox".to_string());
        
        let checkbox_widget = checkbox(label_text, checked);
        
        log::info!("☑️ Creating checkbox: {} (checked: {})", element_id, checked);
        
        Some(container(checkbox_widget)
            .padding(4)
            .into())
    }
    
    /// Create radio button widget
    fn create_radio_widget<'a>(
        &'a self,
        element: &citadel_parser::dom::Element,
        element_id: &str,
    ) -> Option<Element<'a, Message>> {
        let value = element.get_attribute("value").unwrap_or_default();
        let group_name = element.get_attribute("name").unwrap_or_else(|| "radio_group".to_string());
        let selected = self.form_state.radio_selections.get(&group_name)
            .map(|selected_value| selected_value == &value)
            .unwrap_or(false);
        
        // Note: Iced doesn't have a built-in radio button, so we'll use a checkbox for now
        let radio_widget = checkbox(format!("🔘 {}", value), selected);
        
        log::info!("🔘 Creating radio button: {} = '{}' (selected: {})", group_name, value, selected);
        
        Some(container(radio_widget)
            .padding(4)
            .into())
    }
    
    /// Create submit button widget
    fn create_submit_button_widget<'a>(
        &'a self,
        element: &citadel_parser::dom::Element,
        element_id: &str,
    ) -> Option<Element<'a, Message>> {
        let button_text = element.get_attribute("value").unwrap_or_else(|| "Submit".to_string());
        
        let submit_button = button(text(button_text))
            .padding([8, 16])
            .style(theme::Button::Primary);
        
        log::info!("📤 Creating submit button: {}", element_id);
        
        Some(container(submit_button)
            .padding(4)
            .into())
    }
    
    /// Create reset button widget
    fn create_reset_button_widget<'a>(
        &'a self,
        element: &citadel_parser::dom::Element,
        element_id: &str,
    ) -> Option<Element<'a, Message>> {
        let button_text = element.get_attribute("value").unwrap_or_else(|| "Reset".to_string());
        
        let reset_button = button(text(button_text))
            .padding([8, 16])
            .style(theme::Button::Secondary);
        
        log::info!("🔄 Creating reset button: {}", element_id);
        
        Some(container(reset_button)
            .padding(4)
            .into())
    }
    
    /// Create regular button widget
    fn create_button_widget<'a>(
        &'a self,
        element: &citadel_parser::dom::Element,
        element_id: &str,
    ) -> Option<Element<'a, Message>> {
        let button_text = element.get_attribute("value")
            .or_else(|| element.get_attribute("innerHTML"))
            .unwrap_or_else(|| "Button".to_string());
        
        let button_widget = button(text(button_text))
            .padding([8, 16]);
        
        log::info!("🔳 Creating button: {}", element_id);
        
        Some(container(button_widget)
            .padding(4)
            .into())
    }
    
    /// Create textarea widget
    fn create_textarea_widget<'a>(
        &'a self,
        element: &citadel_parser::dom::Element,
        element_id: &str,
    ) -> Option<Element<'a, Message>> {
        let placeholder = element.get_attribute("placeholder").unwrap_or_default();
        let current_value = self.form_state.input_values.get(element_id).cloned().unwrap_or_default();
        
        let rows = element.get_attribute("rows")
            .and_then(|r| r.parse::<u32>().ok())
            .unwrap_or(3);
        
        let textarea_height = (rows * 20 + 16) as f32; // Approximate height calculation
        
        let textarea = text_input(&placeholder, &current_value)
            .padding(8)
            .width(Length::Fixed(300.0));
            // Note: Iced text_input doesn't support height directly
            // Using line_height as approximation for textarea appearance
        
        log::info!("📝 Creating textarea: {} ({}x{})", element_id, 300, textarea_height);
        
        Some(container(textarea)
            .padding(4)
            .into())
    }
    
    /// Create select dropdown widget
    fn create_select_widget<'a>(
        &'a self,
        _element: &citadel_parser::dom::Element,
        element_id: &str,
    ) -> Option<Element<'a, Message>> {
        // Note: Iced's pick_list needs static options, so this is a simplified implementation
        // In a real browser, we'd need to parse the option elements from the DOM
        
        let options = vec!["Option 1".to_string(), "Option 2".to_string(), "Option 3".to_string()];
        let selected = self.form_state.select_selections.get(element_id).cloned();
        
        let select_widget = pick_list(options, selected, |selection| {
            // Note: This would need to be converted to Message type
            Message::UI(crate::ui::UIMessage::AddressBarChanged(selection))
        })
        .padding(8)
        .width(Length::Fixed(150.0));
        
        log::info!("📋 Creating select dropdown: {}", element_id);
        
        Some(container(select_widget)
            .padding(4)
            .into())
    }
    
    // ==================== PERFORMANCE OPTIMIZATION METHODS ====================
    
    /// Hash DOM structure for change detection
    fn hash_dom(&self, dom: &Dom) -> u64 {
        let mut hasher = DefaultHasher::new();
        
        // Hash text content and basic structure
        let text_content = dom.get_text_content();
        text_content.hash(&mut hasher);
        
        // Hash title for additional differentiation
        let title = dom.get_title();
        title.hash(&mut hasher);
        
        hasher.finish()
    }
    
    /// Check if widget cache should be invalidated
    fn should_invalidate_widget_cache(&self, dom_hash: u64) -> bool {
        self.last_dom_hash.is_none() || self.last_dom_hash != Some(dom_hash)
    }
    
    /// Clear widget cache
    fn clear_widget_cache(&mut self) {
        log::debug!("Clearing widget cache: {} entries", self.widget_cache.len());
        self.widget_cache.clear();
        self.render_metrics.widget_cache_misses += 1;
    }
    
    /// Invalidate viewport-dependent cache entries
    fn invalidate_viewport_dependent_cache(&mut self) {
        // Remove cache entries that depend on viewport size
        let viewport_dependent_keys: Vec<u64> = self.widget_cache
            .keys()
            .cloned()
            .collect();
        
        for key in viewport_dependent_keys {
            self.widget_cache.remove(&key);
        }
        
        log::debug!("Invalidated viewport-dependent cache entries");
    }
    
    /// Invalidate zoom-dependent cache entries
    fn invalidate_zoom_dependent_cache(&mut self) {
        // Similar to viewport invalidation - all cached widgets depend on zoom
        self.clear_widget_cache();
        log::debug!("Invalidated zoom-dependent cache entries");
    }
    
    /// Update render metrics
    fn update_render_metrics(&mut self, layout_result: &LayoutResult, render_time: std::time::Duration) {
        self.render_metrics.nodes_rendered = layout_result.node_layouts.len();
        self.render_metrics.nodes_culled = layout_result.metrics.nodes_culled;
        self.render_metrics.render_time_ms = render_time.as_millis() as u64;
        self.render_metrics.memory_allocated_kb = self.estimate_memory_usage() / 1024;
        
        // Update cache hit/miss ratio
        let total_cache_requests = self.render_metrics.widget_cache_hits + self.render_metrics.widget_cache_misses;
        if total_cache_requests > 0 {
            let _hit_ratio = self.render_metrics.widget_cache_hits as f64 / total_cache_requests as f64;
            
            // TODO: Re-enable performance monitoring
            // if let Some(monitor) = &self.performance_monitor {
            //     monitor.set_cache_hit_ratio("renderer_widgets", hit_ratio);
            // }
        }
    }
    
    /// Estimate memory usage of renderer
    fn estimate_memory_usage(&self) -> usize {
        let mut total_memory = std::mem::size_of::<Self>();
        
        // Font cache memory
        total_memory += self.font_cache.len() * std::mem::size_of::<Font>();
        
        // Image cache memory (estimated)
        total_memory += self.image_cache.len() * 1024 * 100; // Estimate 100KB per image
        
        // Widget cache memory
        total_memory += self.widget_cache.len() * std::mem::size_of::<WidgetCacheEntry>();
        
        // Form state memory
        total_memory += self.form_state.input_values.len() * 100; // Estimate 100 bytes per input
        
        // Sticky elements memory
        total_memory += self.sticky_elements.len() * std::mem::size_of::<StickyElementState>();
        
        total_memory
    }
    
    /// Enable or disable viewport culling
    pub fn set_viewport_culling(&mut self, enabled: bool) {
        self.viewport_culling_enabled = enabled;
        log::info!("Viewport culling {}", if enabled { "enabled" } else { "disabled" });
    }
    
    /// Enable or disable frame batching
    pub fn set_frame_batching(&mut self, enabled: bool) {
        self.frame_batching_enabled = enabled;
        log::info!("Frame batching {}", if enabled { "enabled" } else { "disabled" });
    }
    
    /// Set widget cache size
    pub fn set_widget_cache_size(&mut self, max_size: usize) {
        self.max_widget_cache_size = max_size;
        
        // Evict entries if cache is too large
        if self.widget_cache.len() > max_size {
            self.evict_lru_widget_cache_entries();
        }
        
        log::info!("Widget cache size set to {}", max_size);
    }
    
    /// Evict least recently used widget cache entries
    fn evict_lru_widget_cache_entries(&mut self) {
        let mut entries_by_age: Vec<(u64, Instant)> = self.widget_cache
            .iter()
            .map(|(key, entry)| (*key, entry.timestamp))
            .collect();
        
        // Sort by timestamp (oldest first)
        entries_by_age.sort_by_key(|(_, timestamp)| *timestamp);
        
        // Remove oldest quarter of entries
        let remove_count = std::cmp::max(1, self.max_widget_cache_size / 4);
        for (key, _) in entries_by_age.into_iter().take(remove_count) {
            self.widget_cache.remove(&key);
        }
        
        log::debug!("Evicted {} LRU widget cache entries", remove_count);
    }
    
    /// Check if node is visible in viewport for culling
    fn is_node_visible_in_viewport(&self, node_id: u32) -> bool {
        if !self.viewport_culling_enabled {
            return true;
        }
        
        if let Some(layout) = &self.current_layout {
            if let Some(layout_rect) = layout.node_layouts.get(&node_id) {
                let viewport_rect = LayoutRect::new(
                    self.viewport_transform.scroll_x,
                    self.viewport_transform.scroll_y,
                    self.viewport_transform.viewport_width,
                    self.viewport_transform.viewport_height,
                );
                
                // Check intersection with viewport (with margin for smooth scrolling)
                let margin = 100.0;
                return layout_rect.x + layout_rect.width >= viewport_rect.x - margin &&
                       layout_rect.x <= viewport_rect.x + viewport_rect.width + margin &&
                       layout_rect.y + layout_rect.height >= viewport_rect.y - margin &&
                       layout_rect.y <= viewport_rect.y + viewport_rect.height + margin;
            }
        }
        
        true // Assume visible if we can't determine
    }
    
    /// Force resource cleanup (TODO: Fix circular import)
    pub fn force_cleanup(&mut self, _priority: &str) {
        // TODO: Restore performance priority enum once circular import is fixed
        log::info!("Forcing renderer cleanup");
        
        // For now, just do a basic cleanup
        self.clear_widget_cache();
        
        // Clear some other caches
        if self.image_cache.len() > 100 {
            let image_keys: Vec<String> = self.image_cache.keys().cloned().collect();
            for key in image_keys.into_iter().take(self.image_cache.len() / 2) {
                self.image_cache.remove(&key);
            }
        }
        
        log::info!("Renderer cleanup completed");
    }
    
    /// Get render performance metrics
    pub fn get_render_metrics(&self) -> &RenderMetrics {
        &self.render_metrics
    }
    
    /// Reset render metrics
    pub fn reset_render_metrics(&mut self) {
        self.render_metrics = RenderMetrics::default();
    }
    
    // Set performance monitor (TODO: Fix circular import)
    // pub fn set_performance_monitor(&mut self, monitor: Arc<PerformanceMonitor>) {
    //     self.performance_monitor = Some(monitor);
    // }
    
    /// Get cache statistics
    pub fn get_cache_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("widget_cache_entries".to_string(), self.widget_cache.len());
        stats.insert("image_cache_entries".to_string(), self.image_cache.len());
        stats.insert("font_cache_entries".to_string(), self.font_cache.len());
        stats.insert("widget_cache_hits".to_string(), self.render_metrics.widget_cache_hits);
        stats.insert("widget_cache_misses".to_string(), self.render_metrics.widget_cache_misses);
        stats
    }
}

impl Default for CitadelRenderer {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper trait for layout rectangle operations
trait LayoutRectExt {
    /// Check if this rectangle intersects with another
    fn intersects(&self, other: &LayoutRect) -> bool;
    
    /// Calculate area of rectangle
    fn area(&self) -> f32;
}

impl LayoutRectExt for LayoutRect {
    /// Check if this rectangle intersects with another
    fn intersects(&self, other: &LayoutRect) -> bool {
        self.x < other.x + other.width &&
        self.x + self.width > other.x &&
        self.y < other.y + other.height &&
        self.y + self.height > other.y
    }
    
    /// Calculate area of rectangle
    fn area(&self) -> f32 {
        self.width * self.height
    }
}

// Form types are already defined above and don't need re-export
