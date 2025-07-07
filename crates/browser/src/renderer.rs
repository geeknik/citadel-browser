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
        log::info!("Updating renderer content with advanced layout computation");

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
        match (&self.current_dom, &self.current_stylesheet, &self.current_layout) {
            (Some(dom), Some(stylesheet), Some(layout_result)) => {
                log::debug!("Rendering with computed layout: {} positioned elements", layout_result.node_layouts.len());

                // Render DOM tree as structured widgets
                let root_handle = dom.root();
                let rendered_content = self.render_node_recursive(&root_handle, dom, stylesheet, layout_result);

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
            _ => {
                // No content to render
                container(
                    text("No content loaded")
                        .size(16)
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
                self.render_element(&node, element, dom, stylesheet, layout_result)
            }
            NodeData::Text(text_content) => {
                // Render text nodes with proper styling
                let text_content = text_content.trim();
                if !text_content.is_empty() {
                    text(text_content)
                        .size(14)
                        .into()
                } else {
                    Space::with_height(0).into()
                }
            }
            _ => Space::with_height(0).into(), // Skip other node types
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
                if children_widgets.is_empty() {
                    Space::with_height(0).into()
                } else {
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
                let text_content = self.extract_text_content(node, dom);
                let font_size = self.get_font_size_from_style(&computed_style);
                let color = self.get_text_color_from_style(&computed_style);

                let mut text_widget = text(text_content).size(font_size).style(color);

                if tag_name == "a" {
                    if let Some(href) = element.get_attribute("href") {
                        // TODO: Add click functionality
                        text_widget = text(format!("{} ({})", self.extract_text_content(node, dom), href))
                            .size(font_size)
                            .style(Color::from_rgb(0.0, 0.4, 0.8));
                    }
                }

                container(text_widget)
                    .width(Length::Fill)
                    .padding([0, 0, 10, 0])
                    .into()
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
            _ => {
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
        node.text_content()
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
