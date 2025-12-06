//! CSS Object Model (CSSOM) Integration with Servo
//!
//! This module provides the CSS Object Model implementation that bridges
//! Servo's CSS engine with Citadel's parser and security systems.

use std::sync::Arc;
use std::collections::HashMap;
use crate::css::{CitadelStylesheet, StyleRule, Declaration, ComputedStyle, ColorValue, LengthValue, DisplayType, PositionType};
use crate::css_security::{CssSecurityFilter, CssSecurityAnalysis};
use crate::error::ParserError;
use crate::security::SecurityContext;

/// CSS StyleSheet interface (Servo-compatible)
#[derive(Debug, Clone)]
pub struct CSSStyleSheet {
    /// Owner CSS rule list
    pub css_rules: Vec<CSSRule>,
    /// Security context for this stylesheet
    pub security_context: Arc<SecurityContext>,
    /// Origin of the stylesheet (user agent, author, user)
    pub origin: CSSOrigin,
    /// Whether this stylesheet is disabled
    pub disabled: bool,
}

/// CSS rule types (following Servo's CSSRule interface)
#[derive(Debug, Clone)]
pub enum CSSRule {
    /// Style rule (selector + declarations)
    StyleRule(CSSStyleRule),
    /// Media rule
    MediaRule(CSSMediaRule),
    /// Font face rule
    FontFaceRule(CSSFontFaceRule),
    /// Keyframes rule
    KeyframesRule(CSSKeyframesRule),
    /// Import rule
    ImportRule(CSSImportRule),
}

/// CSS Style Rule (CSSStyleRule interface)
#[derive(Debug, Clone)]
pub struct CSSStyleRule {
    /// Selector text
    pub selector_text: String,
    /// Style declarations
    pub style: CSSStyleDeclaration,
    /// Specificity of the selector
    pub specificity: u32,
    /// Rule index in the stylesheet
    pub rule_index: usize,
}

/// CSS Style Declaration (CSSStyleDeclaration interface)
#[derive(Debug, Clone)]
pub struct CSSStyleDeclaration {
    /// List of CSS declarations
    pub declarations: Vec<CSSDeclaration>,
    /// Parent rule reference
    pub parent_rule: Option<usize>,
}

/// CSS Declaration (CSSProperty interface)
#[derive(Debug, Clone)]
pub struct CSSDeclaration {
    /// Property name
    pub property: String,
    /// Property value
    pub value: CSSValue,
    /// Whether this is important
    pub important: bool,
}

/// CSS Value types (Servo-compatible)
#[derive(Debug, Clone, PartialEq)]
pub enum CSSValue {
    /// Keyword value (e.g., "auto", "inherit", "initial")
    Keyword(String),
    /// Length value with unit
    Length(LengthValue),
    /// Color value
    Color(ColorValue),
    /// String value
    String(String),
    /// URL value
    Url(String),
    /// Number value
    Number(f32),
    /// Percentage value
    Percentage(f32),
    /// Custom property (CSS variable)
    CustomProperty(String, Box<CSSValue>),
    /// List of values
    List(Vec<CSSValue>),
    /// Function value (e.g., "rgb()", "calc()")
    Function(String, Vec<CSSValue>),
}

/// CSS Media Rule (@media)
#[derive(Debug, Clone)]
pub struct CSSMediaRule {
    /// Media query list
    pub media: MediaList,
    /// Nested CSS rules
    pub css_rules: Vec<CSSRule>,
}

/// CSS Font Face Rule (@font-face)
#[derive(Debug, Clone)]
pub struct CSSFontFaceRule {
    /// Font family
    pub family: Option<String>,
    /// Font source URL
    pub src: Option<String>,
    /// Font weight
    pub weight: Option<String>,
    /// Font style
    pub style: Option<String>,
    /// Font stretch
    pub stretch: Option<String>,
    /// Unicode range
    pub unicode_range: Option<String>,
}

/// CSS Keyframes Rule (@keyframes)
#[derive(Debug, Clone)]
pub struct CSSKeyframesRule {
    /// Animation name
    pub name: String,
    /// Keyframe rules
    pub keyframes: Vec<CSSKeyframeRule>,
}

/// CSS Keyframe Rule
#[derive(Debug, Clone)]
pub struct CSSKeyframeRule {
    /// Keyframe selector (e.g., "0%", "50%", "100%")
    pub key: String,
    /// Style declarations for this keyframe
    pub style: CSSStyleDeclaration,
}

/// CSS Import Rule (@import)
#[derive(Debug, Clone)]
pub struct CSSImportRule {
    /// URL to import
    pub href: String,
    /// Media query for conditional import
    pub media: MediaList,
    /// Imported stylesheet (if loaded)
    pub stylesheet: Option<Arc<CSSStyleSheet>>,
}

/// Media List for media queries
#[derive(Debug, Clone)]
pub struct MediaList {
    /// List of media queries
    pub media: Vec<String>,
}

/// CSS Origin levels (following Servo's model)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CSSOrigin {
    /// User agent stylesheet (browser default)
    UserAgent = 0,
    /// User stylesheet (user preferences)
    User = 1,
    /// Author stylesheet (website styles)
    Author = 2,
}

/// CSS Cascade Data for style computation
#[derive(Debug, Clone)]
pub struct CSSCascadeData {
    /// Normal property values
    pub normal_properties: HashMap<String, CSSValue>,
    /// Important property values
    pub important_properties: HashMap<String, CSSValue>,
    /// Origin of each property
    pub property_origins: HashMap<String, CSSOrigin>,
}

/// CSS Computed Style Result
#[derive(Debug, Clone)]
pub struct CSSComputedStyle {
    /// Computed property values
    pub properties: HashMap<String, CSSValue>,
    /// Used values (after layout)
    pub used_values: HashMap<String, CSSValue>,
    /// Parent computed style (for inheritance)
    pub parent_style: Option<Arc<CSSComputedStyle>>,
}

/// CSSOM Manager for handling CSS Object Model operations
pub struct CSSOMManager {
    /// Security context for CSS operations
    security_context: Arc<SecurityContext>,
    /// Security filter for CSS content
    security_filter: CssSecurityFilter,
    /// Loaded stylesheets
    stylesheets: Vec<Arc<CSSStyleSheet>>,
    /// Computed style cache
    computed_style_cache: HashMap<String, Arc<CSSComputedStyle>>,
}

impl CSSStyleSheet {
    /// Create a new CSS stylesheet from CitadelStylesheet
    pub fn from_citadel_stylesheet(
        stylesheet: &CitadelStylesheet,
        origin: CSSOrigin,
        security_context: Arc<SecurityContext>,
    ) -> Result<Self, ParserError> {
        let mut css_rules = Vec::new();

        for (rule_index, style_rule) in stylesheet.rules.iter().enumerate() {
            let css_style_rule = CSSStyleRule {
                selector_text: style_rule.selectors.clone(),
                style: CSSStyleDeclaration::from_declarations(&style_rule.declarations),
                specificity: style_rule.specificity,
                rule_index,
            };

            css_rules.push(CSSRule::StyleRule(css_style_rule));
        }

        Ok(Self {
            css_rules,
            security_context,
            origin,
            disabled: false,
        })
    }

    /// Get all style rules in this stylesheet
    pub fn get_style_rules(&self) -> Vec<&CSSStyleRule> {
        self.css_rules
            .iter()
            .filter_map(|rule| match rule {
                CSSRule::StyleRule(style_rule) => Some(style_rule),
                _ => None,
            })
            .collect()
    }

    /// Insert a new rule into the stylesheet
    pub fn insert_rule(&mut self, rule: &str, index: Option<usize>) -> Result<usize, ParserError> {
        // Parse the rule and insert at specified index
        // This is a simplified implementation
        let new_index = index.unwrap_or(self.css_rules.len());
        
        // For now, just append a dummy rule
        // In a full implementation, we'd parse the rule string
        self.css_rules.insert(new_index, CSSRule::StyleRule(CSSStyleRule {
            selector_text: rule.to_string(),
            style: CSSStyleDeclaration {
                declarations: Vec::new(),
                parent_rule: None,
            },
            specificity: 0,
            rule_index: new_index,
        }));

        Ok(new_index)
    }

    /// Delete a rule from the stylesheet
    pub fn delete_rule(&mut self, index: usize) -> Result<(), ParserError> {
        if index >= self.css_rules.len() {
            return Err(ParserError::CssError("Index out of bounds".to_string()));
        }

        self.css_rules.remove(index);
        Ok(())
    }
}

impl CSSStyleDeclaration {
    /// Create from Citadel declarations
    pub fn from_declarations(declarations: &[Declaration]) -> Self {
        let css_declarations = declarations
            .iter()
            .map(|decl| CSSDeclaration {
                property: decl.property.clone(),
                value: CSSValue::from_string(&decl.value),
                important: decl.important,
            })
            .collect();

        Self {
            declarations: css_declarations,
            parent_rule: None,
        }
    }

    /// Get property value
    pub fn get_property_value(&self, property: &str) -> Option<&CSSValue> {
        self.declarations
            .iter()
            .find(|decl| decl.property.eq_ignore_ascii_case(property))
            .map(|decl| &decl.value)
    }

    /// Set property value
    pub fn set_property(&mut self, property: &str, value: &str, important: bool) -> Result<(), ParserError> {
        let css_value = CSSValue::from_string(value);
        
        // Remove existing property
        self.declarations.retain(|decl| !decl.property.eq_ignore_ascii_case(property));
        
        // Add new declaration
        self.declarations.push(CSSDeclaration {
            property: property.to_string(),
            value: css_value,
            important,
        });

        Ok(())
    }

    /// Remove property
    pub fn remove_property(&mut self, property: &str) -> Option<CSSValue> {
        let index = self.declarations
            .iter()
            .position(|decl| decl.property.eq_ignore_ascii_case(property))?;

        Some(self.declarations.remove(index).value)
    }

    /// Get CSS text representation
    pub fn css_text(&self) -> String {
        self.declarations
            .iter()
            .map(|decl| {
                let important = if decl.important { " !important" } else { "" };
                format!("{}: {}{};", decl.property, decl.value.to_css_string(), important)
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl CSSValue {
    /// Create CSS value from string
    pub fn from_string(value: &str) -> Self {
        let value = value.trim();

        // Check for keywords
        if matches!(value.to_lowercase().as_str(), "auto" | "inherit" | "initial" | "unset" | "none" | "transparent") {
            return CSSValue::Keyword(value.to_lowercase());
        }

        // Check for colors
        if value.starts_with('#') || value.starts_with("rgb") || value.starts_with("hsl") {
            if let Some(color) = Self::parse_color(value) {
                return CSSValue::Color(color);
            }
        }

        // Check for URLs
        if value.starts_with("url(") {
            if let Some(url) = Self::parse_url(value) {
                return CSSValue::Url(url);
            }
        }

        // Check for functions
        if value.contains('(') && value.contains(')') {
            if let Some((func_name, args)) = Self::parse_function(value) {
                return CSSValue::Function(func_name, args);
            }
        }

        // Check for custom properties
        if value.starts_with("--") {
            return CSSValue::CustomProperty(value.to_string(), Box::new(CSSValue::Keyword("initial".to_string())));
        }

        // Check for percentages
        if value.ends_with('%') {
            if let Ok(num) = value[..value.len()-1].parse::<f32>() {
                return CSSValue::Percentage(num);
            }
        }

        // Check for length values
        if let Some(length) = Self::parse_length(value) {
            return CSSValue::Length(length);
        }

        // Check for numbers
        if let Ok(num) = value.parse::<f32>() {
            return CSSValue::Number(num);
        }

        // Default to string
        CSSValue::String(value.to_string())
    }

    /// Convert to CSS string
    pub fn to_css_string(&self) -> String {
        match self {
            CSSValue::Keyword(kw) => kw.clone(),
            CSSValue::Length(len) => len.to_css_string(),
            CSSValue::Color(color) => color.to_css_string(),
            CSSValue::String(s) => s.clone(),
            CSSValue::Url(url) => format!("url({})", url),
            CSSValue::Number(n) => n.to_string(),
            CSSValue::Percentage(p) => format!("{}%", p),
            CSSValue::CustomProperty(name, value) => format!("var({})", name),
            CSSValue::List(values) => values
                .iter()
                .map(|v| v.to_css_string())
                .collect::<Vec<_>>()
                .join(" "),
            CSSValue::Function(name, args) => {
                let args_str = args
                    .iter()
                    .map(|v| v.to_css_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{}({})", name, args_str)
            }
        }
    }

    /// Parse color value
    fn parse_color(value: &str) -> Option<ColorValue> {
        let value = value.trim().to_lowercase();

        // Hex colors
        if value.starts_with('#') {
            let hex = value.trim_start_matches('#');
            if hex.len() == 6 {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                return Some(ColorValue::Rgb(r, g, b));
            } else if hex.len() == 3 {
                let r = u8::from_str_radix(&hex[0..1], 16).ok()? * 17;
                let g = u8::from_str_radix(&hex[1..2], 16).ok()? * 17;
                let b = u8::from_str_radix(&hex[2..3], 16).ok()? * 17;
                return Some(ColorValue::Rgb(r, g, b));
            }
        }

        // Named colors
        match value.as_str() {
            "black" => Some(ColorValue::Rgb(0, 0, 0)),
            "white" => Some(ColorValue::Rgb(255, 255, 255)),
            "red" => Some(ColorValue::Rgb(255, 0, 0)),
            "green" => Some(ColorValue::Rgb(0, 128, 0)),
            "blue" => Some(ColorValue::Rgb(0, 0, 255)),
            "yellow" => Some(ColorValue::Rgb(255, 255, 0)),
            "cyan" => Some(ColorValue::Rgb(0, 255, 255)),
            "magenta" => Some(ColorValue::Rgb(255, 0, 255)),
            "gray" | "grey" => Some(ColorValue::Rgb(128, 128, 128)),
            "transparent" => Some(ColorValue::Named("transparent".to_string())),
            _ => None,
        }
    }

    /// Parse URL value
    fn parse_url(value: &str) -> Option<String> {
        if value.starts_with("url(") && value.ends_with(')') {
            let url = value[4..value.len()-1].trim();
            let url = url.trim_matches('"').trim_matches('\'');
            Some(url.to_string())
        } else {
            None
        }
    }

    /// Parse function value
    fn parse_function(value: &str) -> Option<(String, Vec<CSSValue>)> {
        if !value.contains('(') || !value.ends_with(')') {
            return None;
        }

        let paren_pos = value.find('(')?;
        let func_name = value[..paren_pos].trim().to_string();
        let args_str = &value[paren_pos+1..value.len()-1];

        let args = args_str
            .split(',')
            .map(|arg| CSSValue::from_string(arg.trim()))
            .collect();

        Some((func_name, args))
    }

    /// Parse length value
    fn parse_length(value: &str) -> Option<LengthValue> {
        let value = value.trim();

        if value == "auto" {
            return Some(LengthValue::Auto);
        }
        if value == "0" {
            return Some(LengthValue::Zero);
        }

        // Try different units
        if let Some(px) = value.strip_suffix("px") {
            if let Ok(px) = px.parse::<f32>() {
                return Some(LengthValue::Px(px));
            }
        } else if let Some(em) = value.strip_suffix("em") {
            if let Ok(em) = em.parse::<f32>() {
                return Some(LengthValue::Em(em));
            }
        } else if let Some(rem) = value.strip_suffix("rem") {
            if let Ok(rem) = rem.parse::<f32>() {
                return Some(LengthValue::Rem(rem));
            }
        } else if let Some(pct) = value.strip_suffix('%') {
            if let Ok(pct) = pct.parse::<f32>() {
                return Some(LengthValue::Percent(pct));
            }
        } else if let Some(vh) = value.strip_suffix("vh") {
            if let Ok(vh) = vh.parse::<f32>() {
                return Some(LengthValue::Vh(vh));
            }
        } else if let Some(vw) = value.strip_suffix("vw") {
            if let Ok(vw) = vw.parse::<f32>() {
                return Some(LengthValue::Vw(vw));
            }
        }

        // Try parsing as unitless number
        if let Ok(num) = value.parse::<f32>() {
            if num == 0.0 {
                return Some(LengthValue::Zero);
            } else {
                return Some(LengthValue::Px(num));
            }
        }

        None
    }
}

impl CSSOMManager {
    /// Create new CSSOM manager
    pub fn new(security_context: Arc<SecurityContext>) -> Self {
        Self {
            security_filter: CssSecurityFilter::new(security_context.clone()),
            security_context,
            stylesheets: Vec::new(),
            computed_style_cache: HashMap::new(),
        }
    }

    /// Add a stylesheet to the manager
    pub fn add_stylesheet(&mut self, stylesheet: CSSStyleSheet) {
        self.stylesheets.push(Arc::new(stylesheet));
        self.clear_computed_style_cache();
    }

    /// Add Citadel stylesheet with security processing
    pub fn add_citadel_stylesheet(
        &mut self,
        citadel_stylesheet: &CitadelStylesheet,
        origin: CSSOrigin,
    ) -> Result<(), ParserError> {
        // Convert to CSSOM stylesheet
        let css_stylesheet = CSSStyleSheet::from_citadel_stylesheet(citadel_stylesheet, origin, self.security_context.clone())?;
        self.add_stylesheet(css_stylesheet);
        Ok(())
    }

    /// Compute cascade data for an element
    pub fn compute_cascade(
        &self,
        element_tag: &str,
        element_classes: &[String],
        element_id: Option<&str>,
    ) -> CSSCascadeData {
        let mut normal_properties = HashMap::new();
        let mut important_properties = HashMap::new();
        let mut property_origins = HashMap::new();

        // Sort stylesheets by origin (UserAgent < User < Author)
        let mut sorted_stylesheets = self.stylesheets.clone();
        sorted_stylesheets.sort_by_key(|s| s.origin.clone());

        for stylesheet in &sorted_stylesheets {
            if stylesheet.disabled {
                continue;
            }

            for rule in &stylesheet.css_rules {
                if let CSSRule::StyleRule(style_rule) = rule {
                    if self.selector_matches(&style_rule.selector_text, element_tag, element_classes, element_id) {
                        for decl in &style_rule.style.declarations {
                            let property_name = decl.property.to_lowercase();

                            if decl.important {
                                // Important properties override normal ones
                                if !property_origins.contains_key(&property_name) || 
                                   property_origins[&property_name] <= stylesheet.origin {
                                    important_properties.insert(property_name.clone(), decl.value.clone());
                                    property_origins.insert(property_name, stylesheet.origin.clone());
                                }
                            } else if !important_properties.contains_key(&property_name) {
                                // Normal properties only apply if no important version exists
                                if !property_origins.contains_key(&property_name) || 
                                   property_origins[&property_name] <= stylesheet.origin {
                                    normal_properties.insert(property_name.clone(), decl.value.clone());
                                    property_origins.insert(property_name, stylesheet.origin.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        CSSCascadeData {
            normal_properties,
            important_properties,
            property_origins,
        }
    }

    /// Compute final style for an element
    pub fn compute_computed_style(
        &mut self,
        element_tag: &str,
        element_classes: &[String],
        element_id: Option<&str>,
        parent_style: Option<&Arc<CSSComputedStyle>>,
    ) -> Arc<CSSComputedStyle> {
        // Generate cache key
        let cache_key = format!("{}:{}:{}:{}", 
            element_tag,
            element_classes.join(","),
            element_id.unwrap_or(""),
            parent_style.map(|s| format!("{:p}", s.as_ref() as *const _)).unwrap_or_default()
        );

        // Check cache
        if let Some(cached_style) = self.computed_style_cache.get(&cache_key) {
            return cached_style.clone();
        }

        // Compute cascade
        let cascade_data = self.compute_cascade(element_tag, element_classes, element_id);

        // Convert to computed values
        let mut computed_properties = HashMap::new();

        // Important properties take precedence
        for (property, value) in &cascade_data.important_properties {
            computed_properties.insert(property.clone(), self.compute_value(property, value, parent_style));
        }

        // Normal properties fill in gaps
        for (property, value) in &cascade_data.normal_properties {
            if !computed_properties.contains_key(property) {
                computed_properties.insert(property.clone(), self.compute_value(property, value, parent_style));
            }
        }

        // Apply inheritance
        self.apply_inheritance(&mut computed_properties, element_tag, parent_style);

        let computed_style = CSSComputedStyle {
            properties: computed_properties.clone(),
            used_values: HashMap::new(), // Will be filled during layout
            parent_style: parent_style.cloned(),
        };

        let arc_style = Arc::new(computed_style);
        self.computed_style_cache.insert(cache_key, arc_style.clone());
        arc_style
    }

    /// Check if selector matches element
    fn selector_matches(
        &self,
        selector: &str,
        element_tag: &str,
        element_classes: &[String],
        element_id: Option<&str>,
    ) -> bool {
        let selector = selector.trim();

        // Universal selector
        if selector == "*" {
            return true;
        }

        // Tag selector
        if selector == element_tag {
            return true;
        }

        // ID selector
        if let Some(element_id) = element_id {
            if selector.strip_prefix('#') == Some(element_id) {
                return true;
            }
        }

        // Class selector
        if let Some(class_name) = selector.strip_prefix('.') {
            return element_classes.contains(&class_name.to_string());
        }

        // Compound selectors (simplified)
        if selector.contains('.') && !selector.starts_with('.') {
            let parts: Vec<&str> = selector.split('.').collect();
            if parts.len() == 2 && parts[0] == element_tag {
                let class_name = parts[1];
                return element_classes.contains(&class_name.to_string());
            }
        }

        false
    }

    /// Compute final value for a property
    fn compute_value(
        &self,
        property: &str,
        value: &CSSValue,
        parent_style: Option<&Arc<CSSComputedStyle>>,
    ) -> CSSValue {
        match value {
            CSSValue::Keyword(kw) => {
                match kw.as_str() {
                    "inherit" => {
                        if let Some(parent) = parent_style {
                            parent.properties.get(property).cloned().unwrap_or(CSSValue::Keyword("initial".to_string()))
                        } else {
                            CSSValue::Keyword("initial".to_string())
                        }
                    }
                    "initial" => self.get_initial_value(property),
                    "unset" => {
                        // Use inherited if inheritable, otherwise initial
                        if self.is_inheritable_property(property) {
                            if let Some(parent) = parent_style {
                                parent.properties.get(property).cloned().unwrap_or(self.get_initial_value(property))
                            } else {
                                self.get_initial_value(property)
                            }
                        } else {
                            self.get_initial_value(property)
                        }
                    }
                    _ => value.clone(),
                }
            }
            CSSValue::CustomProperty(name, default_value) => {
                // Handle CSS variables (simplified)
                if let Some(parent) = parent_style {
                    parent.properties.get(name).cloned().unwrap_or(*default_value.clone())
                } else {
                    *default_value.clone()
                }
            }
            _ => value.clone(),
        }
    }

    /// Get initial value for a property
    fn get_initial_value(&self, property: &str) -> CSSValue {
        match property {
            "display" => CSSValue::Keyword("inline".to_string()),
            "color" => CSSValue::Color(ColorValue::Named("black".to_string())),
            "background-color" => CSSValue::Color(ColorValue::Named("transparent".to_string())),
            "font-size" => CSSValue::Length(LengthValue::Px(16.0)),
            "font-weight" => CSSValue::Keyword("normal".to_string()),
            "line-height" => CSSValue::Keyword("normal".to_string()),
            "margin" | "padding" => CSSValue::Length(LengthValue::Px(0.0)),
            "width" | "height" => CSSValue::Keyword("auto".to_string()),
            "position" => CSSValue::Keyword("static".to_string()),
            _ => CSSValue::Keyword("initial".to_string()),
        }
    }

    /// Check if property is inheritable
    fn is_inheritable_property(&self, property: &str) -> bool {
        match property {
            // Text properties are inheritable
            "color" | "font-family" | "font-size" | "font-weight" | "font-style" | 
            "line-height" | "text-align" | "text-indent" | "text-transform" | 
            "letter-spacing" | "word-spacing" | "white-space" | "direction" | 
            "visibility" | "cursor" => true,

            // List properties
            "list-style" | "list-style-type" | "list-style-position" | "list-style-image" => true,

            // Table border properties
            "border-collapse" | "border-spacing" | "caption-side" | "empty-cells" => true,

            // Other inheritable properties
            "quotes" | "orphans" | "widows" | "page-break-inside" | "page-break-after" | "page-break-before" => true,

            // Non-inheritable properties
            _ => false,
        }
    }

    /// Apply inheritance to computed properties
    fn apply_inheritance(
        &self,
        properties: &mut HashMap<String, CSSValue>,
        element_tag: &str,
        parent_style: Option<&Arc<CSSComputedStyle>>,
    ) {
        if let Some(parent) = parent_style {
            for (property, value) in &parent.properties {
                if !properties.contains_key(property) && self.is_inheritable_property(property) {
                    properties.insert(property.clone(), value.clone());
                }
            }
        }

        // Apply default values for missing properties
        self.apply_default_values(properties, element_tag);
    }

    /// Apply default values based on element type
    fn apply_default_values(&self, properties: &mut HashMap<String, CSSValue>, element_tag: &str) {
        // Default display values based on element type
        if !properties.contains_key("display") {
            let display_value = match element_tag {
                "div" | "p" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | 
                "ul" | "ol" | "li" | "table" | "tr" | "thead" | "tbody" | 
                "tfoot" | "header" | "footer" | "main" | "section" | "article" | 
                "aside" | "nav" => CSSValue::Keyword("block".to_string()),
                
                "span" | "a" | "strong" | "em" | "b" | "i" | "u" | 
                "small" | "code" | "pre" | "td" | "th" => CSSValue::Keyword("inline".to_string()),
                
                "img" | "br" | "hr" | "input" | "button" | "select" | "textarea" => CSSValue::Keyword("inline-block".to_string()),
                
                _ => CSSValue::Keyword("inline".to_string()),
            };
            properties.insert("display".to_string(), display_value);
        }

        // Default font properties
        if !properties.contains_key("font-size") {
            properties.insert("font-size".to_string(), CSSValue::Length(LengthValue::Px(16.0)));
        }

        if !properties.contains_key("color") {
            properties.insert("color".to_string(), CSSValue::Color(ColorValue::Named("black".to_string())));
        }

        if !properties.contains_key("line-height") {
            properties.insert("line-height".to_string(), CSSValue::Keyword("normal".to_string()));
        }
    }

    /// Clear computed style cache
    pub fn clear_computed_style_cache(&mut self) {
        self.computed_style_cache.clear();
    }

    /// Get loaded stylesheets
    pub fn get_stylesheets(&self) -> &[Arc<CSSStyleSheet>] {
        &self.stylesheets
    }

    /// Remove a stylesheet
    pub fn remove_stylesheet(&mut self, index: usize) -> Result<(), ParserError> {
        if index >= self.stylesheets.len() {
            return Err(ParserError::CssError("Index out of bounds".to_string()));
        }

        self.stylesheets.remove(index);
        self.clear_computed_style_cache();
        Ok(())
    }
}

// Implement conversions between Citadel and CSSOM types
impl ColorValue {
    /// Convert to CSS string
    pub fn to_css_string(&self) -> String {
        match self {
            ColorValue::Named(name) => name.clone(),
            ColorValue::Hex(hex) => format!("#{}", hex),
            ColorValue::Rgb(r, g, b) => format!("rgb({}, {}, {})", r, g, b),
        }
    }
}

impl LengthValue {
    /// Convert to CSS string
    pub fn to_css_string(&self) -> String {
        match self {
            LengthValue::Px(px) => format!("{}px", px),
            LengthValue::Em(em) => format!("{}em", em),
            LengthValue::Rem(rem) => format!("{}rem", rem),
            LengthValue::Percent(pct) => format!("{}%", pct),
            LengthValue::Vh(vh) => format!("{}vh", vh),
            LengthValue::Vw(vw) => format!("{}vw", vw),
            LengthValue::Vmin(vmin) => format!("{}vmin", vmin),
            LengthValue::Vmax(vmax) => format!("{}vmax", vmax),
            LengthValue::Ch(ch) => format!("{}ch", ch),
            LengthValue::Ex(ex) => format!("{}ex", ex),
            LengthValue::Auto => "auto".to_string(),
            LengthValue::Zero => "0".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_css_value_parsing() {
        assert_eq!(CSSValue::from_string("auto"), CSSValue::Keyword("auto".to_string()));
        assert_eq!(CSSValue::from_string("16px"), CSSValue::Length(LengthValue::Px(16.0)));
        assert_eq!(CSSValue::from_string("red"), CSSValue::Color(ColorValue::Named("red".to_string())));
        assert_eq!(CSSValue::from_string("#ff0000"), CSSValue::Color(ColorValue::Hex("ff0000".to_string())));
        assert_eq!(CSSValue::from_string("50%"), CSSValue::Percentage(50.0));
    }

    #[test]
    fn test_cssom_stylesheet_creation() {
        let security_context = crate::security::SecurityContext::new(10);
        let citadel_stylesheet = CitadelStylesheet::new(std::sync::Arc::new(security_context));
        
        let css_stylesheet = CSSStyleSheet::from_citadel_stylesheet(
            &citadel_stylesheet,
            CSSOrigin::Author,
            std::sync::Arc::new(crate::security::SecurityContext::new(10))
        ).unwrap();

        assert_eq!(css_stylesheet.css_rules.len(), 0);
        assert_eq!(css_stylesheet.origin, CSSOrigin::Author);
    }

    #[test]
    fn test_selector_matching() {
        let manager = CSSOMManager::new(std::sync::Arc::new(crate::security::SecurityContext::new(10)));

        assert!(manager.selector_matches("div", "div", &[], None));
        assert!(manager.selector_matches("p", "p", &[], None));
        assert!(manager.selector_matches("#test", "div", &[], Some("test")));
        assert!(manager.selector_matches(".highlight", "div", &["highlight".to_string()], None));
        assert!(manager.selector_matches("div.highlight", "div", &["highlight".to_string()], None));
        
        assert!(!manager.selector_matches("span", "div", &[], None));
        assert!(!manager.selector_matches("#wrong", "div", &[], Some("test")));
        assert!(!manager.selector_matches(".missing", "div", &["highlight".to_string()], None));
    }
}
