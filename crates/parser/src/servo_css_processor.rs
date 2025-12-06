//! Servo-style CSS Processor with CSSOM Integration
//!
//! This module provides an enhanced CSS processor that bridges Citadel's existing
//! CSS system with Servo's CSS Object Model and advanced parsing capabilities.

use std::sync::Arc;
use std::collections::HashMap;
use crate::css::{CitadelStylesheet, StyleRule, Declaration, ComputedStyle, ColorValue, LengthValue, DisplayType, PositionType};
use crate::cssom::{CSSOMManager, CSSStyleSheet, CSSOrigin, CSSValue, CSSComputedStyle, CSSCascadeData};
use crate::css_security::CssSecurityFilter;
use crate::dom::Dom;
use crate::error::ParserError;
use crate::security::SecurityContext;
use crate::config::ParserConfig;
use crate::metrics::ParserMetrics;
use crate::Parser;

/// Servo-style CSS processor with full CSSOM integration
pub struct ServoCssProcessor {
    /// CSSOM manager for handling CSS Object Model operations
    cssom_manager: CSSOMManager,
    /// Security context for CSS operations
    security_context: Arc<SecurityContext>,
    /// Security filter for CSS content
    security_filter: CssSecurityFilter,
    /// Parser configuration
    config: ParserConfig,
    /// Parser metrics
    metrics: Arc<ParserMetrics>,
    /// Computed style cache for DOM elements
    style_cache: HashMap<String, Arc<CSSComputedStyle>>,
    /// Whether CSSOM is enabled
    cssom_enabled: bool,
}

/// CSS processing result with enhanced metadata
#[derive(Debug, Clone)]
pub struct ServoCssResult {
    /// Processed stylesheet
    pub stylesheet: CitadelStylesheet,
    /// CSSOM representation
    pub cssom_stylesheet: Option<Arc<CSSStyleSheet>>,
    /// Security analysis results
    pub security_analysis: Option<crate::css_security::CssSecurityAnalysis>,
    /// Processing statistics
    pub stats: CssProcessingStats,
}

/// CSS processing statistics
#[derive(Debug, Clone, Default)]
pub struct CssProcessingStats {
    /// Total rules processed
    pub rules_processed: usize,
    /// Total declarations processed
    pub declarations_processed: usize,
    /// Security violations detected
    pub security_violations: usize,
    /// Stylesheets processed
    pub stylesheets_processed: usize,
    /// Computed styles generated
    pub computed_styles_generated: usize,
    /// Processing time in microseconds
    pub processing_time_us: u64,
}

impl ServoCssProcessor {
    /// Create a new Servo-style CSS processor
    pub fn new(config: ParserConfig, metrics: Arc<ParserMetrics>) -> Self {
        let security_context = Arc::new(SecurityContext::new(config.max_depth));
        let cssom_manager = CSSOMManager::new(security_context.clone());
        let security_filter = CssSecurityFilter::new(security_context.clone());

        Self {
            cssom_manager,
            security_context,
            security_filter,
            config,
            metrics,
            style_cache: HashMap::new(),
            cssom_enabled: true,
        }
    }

    /// Process CSS content with full Servo integration
    pub fn process_css(&mut self, css_content: &str) -> Result<ServoCssResult, ParserError> {
        let start_time = std::time::Instant::now();
        let mut stats = CssProcessingStats::default();

        // Security analysis first
        let security_analysis = self.security_filter.analyze_css(css_content)?;
        stats.security_violations = security_analysis.violations_count;

        // Parse CSS using enhanced parser
        let stylesheet = self.parse_css_enhanced(&security_analysis.sanitized_css)?;
        stats.rules_processed = stylesheet.rules.len();
        stats.declarations_processed = stylesheet.rules.iter()
            .map(|rule| rule.declarations.len())
            .sum();

        // Convert to CSSOM if enabled
        let cssom_stylesheet = if self.cssom_enabled {
            let cssom = CSSStyleSheet::from_citadel_stylesheet(
                &stylesheet,
                CSSOrigin::Author,
                self.security_context.clone()
            )?;
            let arc_cssom = Arc::new(cssom);
            self.cssom_manager.add_stylesheet(CSSStyleSheet::from_citadel_stylesheet(
                &stylesheet,
                CSSOrigin::Author,
                self.security_context.clone()
            )?);
            Some(arc_cssom)
        } else {
            None
        };

        stats.stylesheets_processed = 1;
        stats.processing_time_us = start_time.elapsed().as_micros() as u64;

        Ok(ServoCssResult {
            stylesheet,
            cssom_stylesheet,
            security_analysis: Some(security_analysis),
            stats,
        })
    }

    /// Process multiple CSS stylesheets (for cascading)
    pub fn process_multiple_css(&mut self, css_contents: Vec<(String, CSSOrigin)>) -> Result<ServoCssResult, ParserError> {
        let start_time = std::time::Instant::now();
        let mut stats = CssProcessingStats::default();
        let mut combined_stylesheet = CitadelStylesheet::new(self.security_context.clone());

        for (css_content, origin) in css_contents {
            // Security analysis
            let security_analysis = self.security_filter.analyze_css(&css_content)?;
            stats.security_violations += security_analysis.violations_count;

            // Parse CSS
            let stylesheet = self.parse_css_enhanced(&security_analysis.sanitized_css)?;
            stats.rules_processed += stylesheet.rules.len();
            stats.declarations_processed += stylesheet.rules.iter()
                .map(|rule| rule.declarations.len())
                .sum::<usize>();

            // Convert to CSSOM and add to manager
            if self.cssom_enabled {
                let cssom = CSSStyleSheet::from_citadel_stylesheet(
                    &stylesheet,
                    origin.clone(),
                    self.security_context.clone()
                )?;
                self.cssom_manager.add_stylesheet(cssom);
            }

            // Combine stylesheets (in origin order)
            combined_stylesheet.rules.extend(stylesheet.rules);
            stats.stylesheets_processed += 1;
        }

        stats.processing_time_us = start_time.elapsed().as_micros() as u64;

        Ok(ServoCssResult {
            stylesheet: combined_stylesheet,
            cssom_stylesheet: None,
            security_analysis: None,
            stats,
        })
    }

    /// Compute styles for a DOM tree using CSSOM
    pub fn compute_dom_styles(&mut self, dom: &Dom) -> Result<HashMap<String, Arc<CSSComputedStyle>>, ParserError> {
        let mut element_styles = HashMap::new();
        let mut style_count = 0;

        // Process DOM tree recursively
        self.compute_element_styles_recursive(dom, None, &mut element_styles, &mut style_count)?;

        for _ in 0..style_count {
            self.metrics.increment_sanitizations();
        }
        Ok(element_styles)
    }

    /// Compute styles for a single element
    pub fn compute_element_style(
        &mut self,
        element_tag: &str,
        element_classes: &[String],
        element_id: Option<&str>,
        parent_style: Option<&Arc<CSSComputedStyle>>,
    ) -> Result<Arc<CSSComputedStyle>, ParserError> {
        let computed_style = self.cssom_manager.compute_computed_style(
            element_tag,
            element_classes,
            element_id,
            parent_style,
        );

        self.metrics.increment_sanitizations();
        Ok(computed_style)
    }

    /// Apply computed styles to a DOM element
    pub fn apply_styles_to_dom(&mut self, dom: &mut Dom) -> Result<(), ParserError> {
        let element_styles = self.compute_dom_styles(dom)?;

        // Apply styles to each DOM node
        for (element_path, computed_style) in element_styles {
            self.apply_style_to_dom_element(dom, &element_path, &computed_style)?;
        }

        Ok(())
    }

    /// Enhanced CSS parsing with better error handling
    fn parse_css_enhanced(&self, css_content: &str) -> Result<CitadelStylesheet, ParserError> {
        // Use existing Citadel CSS parser with enhanced error handling
        let config = ParserConfig::default();
        let mut parser = crate::css::CitadelCssParser::new(config, self.metrics.clone());
        
        match parser.parse(css_content) {
            Ok(stylesheet) => Ok(stylesheet),
            Err(e) => {
                // Try to recover by parsing in tolerant mode
                self.parse_css_tolerant(css_content, e)
            }
        }
    }

    /// Tolerant CSS parsing that attempts recovery
    fn parse_css_tolerant(&self, css_content: &str, original_error: ParserError) -> Result<CitadelStylesheet, ParserError> {
        let mut stylesheet = CitadelStylesheet::new(self.security_context.clone());
        
        // Split by rules and attempt to parse each individually
        let rule_blocks: Vec<&str> = css_content.split('}').collect();
        
        for rule_block in rule_blocks {
            let rule_block = rule_block.trim();
            if rule_block.is_empty() {
                continue;
            }

            if let Some(brace_pos) = rule_block.find('{') {
                let selector = rule_block[..brace_pos].trim();
                let declarations_str = rule_block[brace_pos + 1..].trim();

                if selector.is_empty() || declarations_str.is_empty() {
                    continue;
                }

                // Parse declarations individually
                let mut valid_declarations = Vec::new();
                for decl_str in declarations_str.split(';') {
                    let decl_str = decl_str.trim();
                    if decl_str.is_empty() {
                        continue;
                    }

                    if let Some(colon_pos) = decl_str.find(':') {
                        let property = decl_str[..colon_pos].trim().to_string();
                        let value_part = decl_str[colon_pos + 1..].trim();

                        let (value, important) = if let Some(stripped) = value_part.strip_suffix("!important") {
                            (stripped.trim().to_string(), true)
                        } else {
                            (value_part.to_string(), false)
                        };

                        // Basic validation
                        if !property.is_empty() && !value.is_empty() {
                            valid_declarations.push(Declaration {
                                property,
                                value,
                                important,
                            });
                        }
                    }
                }

                if !valid_declarations.is_empty() {
                    let style_rule = StyleRule {
                        selectors: selector.to_string(),
                        declarations: valid_declarations,
                        specificity: self.calculate_selector_specificity(selector),
                    };

                    stylesheet.rules.push(style_rule);
                }
            }
        }

        if stylesheet.rules.is_empty() {
            Err(original_error) // Return original error if we couldn't recover anything
        } else {
            Ok(stylesheet)
        }
    }

    /// Calculate CSS selector specificity (following CSS standards)
    fn calculate_selector_specificity(&self, selector: &str) -> u32 {
        let mut specificity = 0u32;

        // IDs: 100 points each
        specificity += selector.matches('#').count() as u32 * 100;

        // Classes, attributes, and pseudo-classes: 10 points each
        specificity += selector.matches(['.', '[', ':']).count() as u32 * 10;

        // Elements and pseudo-elements: 1 point each
        specificity += selector.chars()
            .filter(|c| c.is_alphabetic())
            .count() as u32;

        specificity
    }

    /// Recursively compute styles for DOM elements
    fn compute_element_styles_recursive(
        &mut self,
        dom: &Dom,
        parent_style: Option<&Arc<CSSComputedStyle>>,
        element_styles: &mut HashMap<String, Arc<CSSComputedStyle>>,
        style_count: &mut usize,
    ) -> Result<(), ParserError> {
        // Get DOM node info (simplified - in real implementation, this would iterate through actual DOM nodes)
        let element_info = self.get_element_info_from_dom(dom)?;
        
        // Compute style for this element
        let computed_style = self.compute_element_style(
            &element_info.tag_name,
            &element_info.classes,
            element_info.id.as_deref(),
            parent_style,
        )?;

        element_styles.insert(element_info.path.clone(), computed_style.clone());
        *style_count += 1;

        // Recursively process children (simplified - would need actual DOM traversal)
        // This is a placeholder for recursive DOM traversal logic
        // In a real implementation, you'd traverse the DOM tree structure

        Ok(())
    }

    /// Get element information from DOM (simplified implementation)
    fn get_element_info_from_dom(&self, dom: &Dom) -> Result<ElementInfo, ParserError> {
        // This is a simplified implementation
        // In a real implementation, you'd extract this from the actual DOM structure
        Ok(ElementInfo {
            tag_name: "div".to_string(), // Placeholder
            classes: vec![],
            id: None,
            path: "/div".to_string(), // Placeholder path
        })
    }

    /// Apply computed style to a specific DOM element
    fn apply_style_to_dom_element(
        &mut self,
        dom: &mut Dom,
        element_path: &str,
        computed_style: &Arc<CSSComputedStyle>,
    ) -> Result<(), ParserError> {
        // This would apply the computed style to the actual DOM element
        // For now, this is a placeholder implementation
        // In a real implementation, you'd:
        // 1. Find the element by path
        // 2. Convert CSSValue types to DOM-compatible format
        // 3. Apply styles to the element's style attribute or computed style cache

        let _ = (dom, element_path, computed_style); // Suppress unused warnings
        Ok(())
    }

    /// Enable or disable CSSOM functionality
    pub fn set_cssom_enabled(&mut self, enabled: bool) {
        self.cssom_enabled = enabled;
    }

    /// Get CSSOM manager reference
    pub fn cssom_manager(&self) -> &CSSOMManager {
        &self.cssom_manager
    }

    /// Get mutable CSSOM manager reference
    pub fn cssom_manager_mut(&mut self) -> &mut CSSOMManager {
        &mut self.cssom_manager
    }

    /// Clear style cache
    pub fn clear_style_cache(&mut self) {
        self.style_cache.clear();
        self.cssom_manager.clear_computed_style_cache();
    }

    /// Get processing statistics
    pub fn get_stats(&self) -> &CssProcessingStats {
        // This would return the most recent stats
        // For now, return a default implementation
        static DEFAULT_STATS: std::sync::OnceLock<CssProcessingStats> = std::sync::OnceLock::new();
        DEFAULT_STATS.get_or_init(Default::default)
    }
}

/// Element information extracted from DOM
#[derive(Debug, Clone)]
struct ElementInfo {
    /// Tag name of the element
    tag_name: String,
    /// CSS classes of the element
    classes: Vec<String>,
    /// ID of the element (if any)
    id: Option<String>,
    /// Path in the DOM tree (for caching)
    path: String,
}

/// Conversions between Citadel and Servo CSS types
impl From<&CSSComputedStyle> for ComputedStyle {
    fn from(cssom_style: &CSSComputedStyle) -> Self {
        let mut citadel_style = ComputedStyle::default();

        // Convert properties
        for (property, value) in &cssom_style.properties {
            match property.as_str() {
                "color" => {
                    if let CSSValue::Color(color) = value {
                        citadel_style.color = Some(color.clone());
                    }
                }
                "background-color" => {
                    if let CSSValue::Color(color) = value {
                        citadel_style.background_color = Some(color.clone());
                    }
                }
                "font-size" => {
                    if let CSSValue::Length(length) = value {
                        citadel_style.font_size = Some(length.clone());
                    }
                }
                "margin-top" => {
                    if let CSSValue::Length(length) = value {
                        citadel_style.margin_top = Some(length.clone());
                    }
                }
                "margin-right" => {
                    if let CSSValue::Length(length) = value {
                        citadel_style.margin_right = Some(length.clone());
                    }
                }
                "margin-bottom" => {
                    if let CSSValue::Length(length) = value {
                        citadel_style.margin_bottom = Some(length.clone());
                    }
                }
                "margin-left" => {
                    if let CSSValue::Length(length) = value {
                        citadel_style.margin_left = Some(length.clone());
                    }
                }
                "padding-top" => {
                    if let CSSValue::Length(length) = value {
                        citadel_style.padding_top = Some(length.clone());
                    }
                }
                "padding-right" => {
                    if let CSSValue::Length(length) = value {
                        citadel_style.padding_right = Some(length.clone());
                    }
                }
                "padding-bottom" => {
                    if let CSSValue::Length(length) = value {
                        citadel_style.padding_bottom = Some(length.clone());
                    }
                }
                "padding-left" => {
                    if let CSSValue::Length(length) = value {
                        citadel_style.padding_left = Some(length.clone());
                    }
                }
                "display" => {
                    if let CSSValue::Keyword(display) = value {
                        citadel_style.display = DisplayType::from_keyword(display);
                    }
                }
                "position" => {
                    if let CSSValue::Keyword(position) = value {
                        citadel_style.position = PositionType::from_keyword(position);
                    }
                }
                _ => {
                    // Handle other properties as needed
                }
            }
        }

        citadel_style
    }
}

/// Additional conversion helpers
impl DisplayType {
    fn from_keyword(keyword: &str) -> Self {
        match keyword.to_lowercase().as_str() {
            "block" => DisplayType::Block,
            "inline" => DisplayType::Inline,
            "inline-block" => DisplayType::InlineBlock,
            "flex" => DisplayType::Flex,
            "grid" => DisplayType::Grid,
            _ => DisplayType::Inline,
        }
    }
}

impl PositionType {
    fn from_keyword(keyword: &str) -> Self {
        match keyword.to_lowercase().as_str() {
            "static" => PositionType::Static,
            "relative" => PositionType::Relative,
            "absolute" => PositionType::Absolute,
            "fixed" => PositionType::Fixed,
            "sticky" => PositionType::Sticky,
            _ => PositionType::Static,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_processor() -> ServoCssProcessor {
        let config = ParserConfig::default();
        let metrics = Arc::new(ParserMetrics::default());
        ServoCssProcessor::new(config, metrics)
    }

    #[test]
    fn test_servo_css_processing() {
        let mut processor = create_test_processor();
        
        let css = r#"
        body {
            font-family: Arial, sans-serif;
            background-color: #ffffff;
        }
        
        .container {
            display: flex;
            margin: 20px;
        }
        
        #header {
            position: absolute;
            top: 0;
            left: 0;
        }
        "#;

        let result = processor.process_css(css).unwrap();
        assert!(!result.stylesheet.rules.is_empty());
        assert_eq!(result.stats.rules_processed, 3);
        assert_eq!(result.stats.stylesheets_processed, 1);
    }

    #[test]
    fn test_multiple_stylesheet_processing() {
        let mut processor = create_test_processor();
        
        let css_contents = vec![
            ("body { font-size: 16px; }".to_string(), CSSOrigin::UserAgent),
            (".test { color: red; }".to_string(), CSSOrigin::Author),
            ("#id { margin: 10px; }".to_string(), CSSOrigin::User),
        ];

        let result = processor.process_multiple_css(css_contents).unwrap();
        assert_eq!(result.stats.stylesheets_processed, 3);
        assert_eq!(result.stats.rules_processed, 3);
    }

    #[test]
    fn test_cssom_integration() {
        let mut processor = create_test_processor();
        
        let css = r#"
        .test {
            color: blue;
            font-size: 14px;
        }
        "#;

        let result = processor.process_css(css).unwrap();
        assert!(result.cssom_stylesheet.is_some());
    }

    #[test]
    fn test_element_style_computation() {
        let mut processor = create_test_processor();
        
        // Add some CSS first
        let css = r#"
        .highlight {
            color: red;
            background-color: yellow;
        }
        
        div {
            display: block;
            margin: 10px;
        }
        "#;
        
        processor.process_css(css).unwrap();

        // Compute style for an element
        let style = processor.compute_element_style(
            "div",
            &["highlight".to_string()],
            None,
            None,
        ).unwrap();

        // Verify the computed style
        assert!(style.properties.contains_key("color"));
        assert!(style.properties.contains_key("background-color"));
        assert!(style.properties.contains_key("display"));
    }

    #[test]
    fn test_tolerant_css_parsing() {
        let mut processor = create_test_processor();
        
        // CSS with some syntax errors
        let malformed_css = r#"
        body {
            font-family: Arial;
            background-color: #fff;
        }
        
        .test {
            color: red;  // Valid
            font-size:    // Missing value - should be skipped
            margin: 10px  // Missing semicolon - should be handled
        }
        #valid {
            border: 1px solid black;
        }
        "#;

        let result = processor.process_css(malformed_css).unwrap();
        
        // Should parse the valid rules despite syntax errors
        assert!(result.stylesheet.rules.len() >= 2); // body and #valid rules
    }

    #[test]
    fn test_security_integration() {
        let mut processor = create_test_processor();
        
        let dangerous_css = r#"
        body {
            background: url('javascript:alert(1)');
            behavior: url(#default#time2);
        }
        "#;

        let result = processor.process_css(dangerous_css).unwrap();
        
        // Should detect and handle security violations
        assert!(result.security_analysis.is_some());
        let analysis = result.security_analysis.unwrap();
        assert!(analysis.violations_count > 0);
        assert!(analysis.attack_types.len() > 0);
    }
}
