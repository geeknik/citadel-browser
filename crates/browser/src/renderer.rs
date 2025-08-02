//! Advanced HTML/CSS renderer for Citadel Browser using computed layout
//!
//! This module provides sophisticated visual rendering of HTML/CSS content using
//! computed layout positions from Taffy and applying CSS styles to Iced widgets.
//! This brings the DESIGN.md vision to life with proper web page rendering.

use std::sync::Arc;
use iced::{
    widget::{container, text, scrollable, Space, Column, container::Appearance, container::StyleSheet},
    Element, Length, Color, Background, theme
};
use citadel_parser::{
    Dom, CitadelStylesheet, compute_layout,
    LayoutResult, ComputedStyle
};
use citadel_parser::dom::{Node, NodeData};
use crate::app::Message;
use citadel_parser::css::{ColorValue, LengthValue};


// Custom stylesheet for containers to avoid lifetime issues with closures
#[derive(Clone, Copy, Debug)]
struct CustomStyle {
    background: Option<Background>,
    border: iced::Border,
}

impl StyleSheet for CustomStyle {
    type Style = iced::Theme;

    fn appearance(&self, _style: &Self::Style) -> Appearance {
        Appearance {
            background: self.background,
            border: self.border,
            ..Default::default()
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
}

impl CitadelRenderer {
    /// Create a new advanced renderer
    pub fn new() -> Self {
        Self {
            current_dom: None,
            current_stylesheet: None,
            current_layout: None,
            viewport_size: (800.0, 600.0),
            security_violations: Vec::new(),
        }
    }

    /// Update the content to render with full layout computation
    pub fn update_content(
        &mut self,
        dom: Arc<Dom>,
        stylesheet: Arc<CitadelStylesheet>,
    ) -> Result<(), String> {
        println!("📥 CitadelRenderer::update_content() called");
        println!("  DOM rules: {}", stylesheet.rules.len());
        let text_content = dom.get_text_content();
        println!("  DOM text length: {} chars", text_content.len());
        if text_content.len() > 0 {
            println!("  Text preview: '{}'", &text_content[..std::cmp::min(100, text_content.len())]);
        }

        // Compute layout using Taffy engine
        let layout_result = compute_layout(&dom, &stylesheet, self.viewport_size.0, self.viewport_size.1)
            .map_err(|e| format!("Advanced layout computation failed: {}", e))?;

        log::info!("Layout computed: {} nodes, {}ms",
                   layout_result.node_layouts.len(),
                   layout_result.metrics.layout_time_ms);

        self.current_dom = Some(dom);
        self.current_stylesheet = Some(stylesheet);
        self.current_layout = Some(layout_result);

        Ok(())
    }

    /// Update viewport size and recompute layout
    pub fn update_viewport_size(&mut self, width: f32, height: f32) {
        log::info!("Updating viewport size: {}x{}", width, height);
        self.viewport_size = (width, height);

        // Recompute layout if we have content
        if let (Some(dom), Some(stylesheet)) = (&self.current_dom, &self.current_stylesheet) {
            match compute_layout(dom, stylesheet, width, height) {
                Ok(layout_result) => {
                    self.current_layout = Some(layout_result);
                }
                Err(e) => {
                    log::warn!("Failed to recompute layout for new viewport size: {}", e);
                }
            }
        }
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
                    
                    self.render_node_recursive(&html_handle, dom, stylesheet, layout_result)
                } else {
                    log::warn!("⚠️ No HTML element found, rendering from document root");
                    self.render_node_recursive(&root_handle, dom, stylesheet, layout_result)
                };

                container(
                    scrollable(rendered_content)
                        .height(Length::Fill)
                        .width(Length::Fill)
                )
                .width(Length::Fill)
                .height(Length::Fill)
                .padding(10)
                .into()
            }
            (Some(dom), Some(stylesheet), None) => {
                log::error!("❌ CRITICAL: Layout computation failed - this should not happen with proper ZKVM processing");
                
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

    /// Recursively render DOM nodes as structured Iced widgets
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
                    log::info!("📄 Rendering text node: '{}' ({} chars)", 
                        if text_content.len() > 50 { &format!("{}...", &text_content[..50]) } else { text_content },
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

                let custom_style = CustomStyle {
                    background: self.get_background_from_style(&computed_style),
                    border: self.get_border_from_style(&computed_style),
                };

                container(div_container)
                    .width(Length::Fill)
                    .padding(self.get_padding_from_style(&computed_style))
                    .style(theme::Container::Custom(Box::new(custom_style)))
                    .into()
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
                                .style(Color::from_rgb(0.0, 0.4, 0.8))
                        } else {
                            text(text_content)
                                .size(font_size)
                                .style(Color::from_rgb(0.0, 0.4, 0.8))
                        }
                    } else {
                        text(text_content).size(font_size).style(color)
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
                let alt_text = element.get_attribute("alt").unwrap_or_else(|| "Image".to_string());
                let custom_style = CustomStyle {
                    background: None,
                    border: iced::Border {
                        color: Color::from_rgb(0.8, 0.8, 0.8),
                        width: 1.0,
                        radius: 3.0.into(),
                    },
                };
                container(
                    text(format!("[Image: {}]", alt_text))
                        .size(14)
                        .style(Color::from_rgb(0.5, 0.5, 0.5))
                )
                .padding(5)
                .style(theme::Container::Custom(Box::new(custom_style)))
                .into()
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

        if let Some(layout) = layout_result.node_layouts.get(&node.id()) {
            element_widget = container(element_widget)
                .width(Length::Fixed(layout.width))
                .height(Length::Fixed(layout.height))
                .into();
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
                        log::debug!("  🏷️ Child {}: Found element <{}> with {} children", i, element.local_name(), child_node.children().len());
                        // Recursively get text from element's children
                        let child_text = self.extract_text_content(&child_node, _dom);
                        if !child_text.is_empty() {
                            log::debug!("    ✅ Element <{}> contributed text: '{}'", element.local_name(), child_text);
                            text_content.push_str(&child_text);
                            text_content.push(' ');
                        } else {
                            log::debug!("    ⚠️ Element <{}> contributed no text", element.local_name());
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

    /// Get text color from computed style
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
    
}

impl Default for CitadelRenderer {
    fn default() -> Self {
        Self::new()
    }
}
