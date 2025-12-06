//! Nation-State Level CSS Security Module
//!
//! This module implements comprehensive CSS security controls designed to neutralize
//! advanced nation-state attack vectors including:
//! - CSS injection and data exfiltration
//! - Fingerprinting through font loading and media queries
//! - Side-channel attacks via CSS animations and transitions
//! - Memory exhaustion through complex selectors
//! - Timing attacks leveraging CSS performance characteristics

use std::collections::HashSet;
use std::sync::Arc;
use regex::Regex;
use crate::error::ParserError;
use crate::css::{StyleRule, Declaration};
use crate::security::SecurityContext;

/// Nation-state level CSS threat categories
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CssThreatLevel {
    /// No threat detected
    Safe,
    /// Potentially suspicious but within acceptable bounds
    Suspicious,
    /// Clear attack pattern detected
    Dangerous,
    /// Critical nation-state level attack vector
    Critical,
}

/// CSS attack pattern types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CssAttackType {
    /// Data exfiltration via CSS selectors
    DataExfiltration,
    /// Fingerprinting via @font-face or media queries
    Fingerprinting,
    /// Memory exhaustion via complex selectors
    ResourceExhaustion,
    /// Timing attack via animations/transitions
    TimingAttack,
    /// JavaScript injection via CSS
    ScriptInjection,
    /// Network request via CSS imports
    NetworkExfiltration,
    /// Side-channel attack via CSS features
    SideChannel,
}

/// Security analysis result for CSS content
#[derive(Debug, Clone)]
pub struct CssSecurityAnalysis {
    /// Overall threat level assessment
    pub threat_level: CssThreatLevel,
    /// Specific attack types detected
    pub attack_types: Vec<CssAttackType>,
    /// Sanitized CSS content
    pub sanitized_css: String,
    /// Blocked rules (removed)
    pub blocked_rules: Vec<usize>,
    /// Modified rules (sanitized)
    pub modified_rules: Vec<usize>,
    /// Security violations count
    pub violations_count: usize,
    /// Analysis metadata
    pub metadata: SecurityMetadata,
}

/// Security metadata for analysis
#[derive(Debug, Clone)]
pub struct SecurityMetadata {
    /// Total selectors processed
    pub selectors_processed: usize,
    /// Total declarations processed
    pub declarations_processed: usize,
    /// Processing time in microseconds
    pub processing_time_us: u64,
    /// Memory usage estimate in bytes
    pub memory_usage_bytes: usize,
}

/// Nation-state grade CSS security filter
pub struct CssSecurityFilter {
    /// Security context for policy enforcement
    security_context: Arc<SecurityContext>,
    /// High-risk patterns for immediate blocking
    high_risk_patterns: Vec<Regex>,
    /// Medium-risk patterns for sanitization
    medium_risk_patterns: Vec<Regex>,
    /// Fingerprinting detection patterns
    fingerprinting_patterns: Vec<Regex>,
    /// Resource exhaustion limits
    resource_limits: ResourceLimits,
    /// Allowed safe CSS properties whitelist
    allowed_properties: HashSet<String>,
    /// Blocked CSS properties blacklist
    blocked_properties: HashSet<String>,
    /// Font fingerprinting protection
    font_protection: FontProtection,
}

/// Resource limits to prevent DoS attacks
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum number of CSS rules
    pub max_rules: usize,
    /// Maximum selector complexity score
    pub max_selector_complexity: u32,
    /// Maximum declaration count per rule
    pub max_declarations_per_rule: usize,
    /// Maximum CSS file size in bytes
    pub max_css_size_bytes: usize,
    /// Maximum nesting depth for selectors
    pub max_selector_depth: usize,
}

/// Font fingerprinting protection settings
#[derive(Debug, Clone)]
pub struct FontProtection {
    /// Block external font loading
    block_external_fonts: bool,
    /// Allow only safe system fonts
    safe_fonts_only: bool,
    /// Font metrics randomization enabled
    randomize_metrics: bool,
    /// Allowed font families whitelist
    allowed_font_families: HashSet<String>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_rules: 10000,
            max_selector_complexity: 1000,
            max_declarations_per_rule: 100,
            max_css_size_bytes: 1024 * 1024, // 1MB
            max_selector_depth: 10,
        }
    }
}

impl Default for FontProtection {
    fn default() -> Self {
        let mut safe_fonts = HashSet::new();
        safe_fonts.insert("serif".to_string());
        safe_fonts.insert("sans-serif".to_string());
        safe_fonts.insert("monospace".to_string());
        safe_fonts.insert("cursive".to_string());
        safe_fonts.insert("fantasy".to_string());
        safe_fonts.insert("system-ui".to_string());
        safe_fonts.insert("ui-serif".to_string());
        safe_fonts.insert("ui-sans-serif".to_string());
        safe_fonts.insert("ui-monospace".to_string());
        safe_fonts.insert("ui-rounded".to_string());

        Self {
            block_external_fonts: true,
            safe_fonts_only: true,
            randomize_metrics: true,
            allowed_font_families: safe_fonts,
        }
    }
}

impl CssSecurityFilter {
    /// Create a new CSS security filter with nation-state grade protection
    pub fn new(security_context: Arc<SecurityContext>) -> Self {
        let high_risk_patterns = vec![
            // JavaScript injection attempts
            Regex::new(r"(?i)javascript\s*:").unwrap(),
            Regex::new(r"(?i)vbscript\s*:").unwrap(),
            Regex::new(r"(?i)data\s*:\s*text/html").unwrap(),
            Regex::new(r"(?i)expression\s*\(").unwrap(),
            // Dangerous behaviors
            Regex::new(r"(?i)behavior\s*:").unwrap(),
            Regex::new(r"(?i)-moz-binding\s*:").unwrap(),
            Regex::new(r"(?i)binding\s*:").unwrap(),
            // Script execution via CSS
            Regex::new(r"(?i)eval\s*\(").unwrap(),
            Regex::new(r"(?i)settimeout\s*\(").unwrap(),
            Regex::new(r"(?i)setinterval\s*\(").unwrap(),
        ];

        let medium_risk_patterns = vec![
            // Potential data exfiltration
            Regex::new(r"(?i)background\s*:\s*url\s*\(").unwrap(),
            Regex::new(r"(?i)content\s*:\s*url\s*\(").unwrap(),
            Regex::new(r"(?i)cursor\s*:\s*url\s*\(").unwrap(),
            // Network requests
            Regex::new(r"(?i)@import\s").unwrap(),
            Regex::new(r"(?i)@charset\s").unwrap(),
            // Dynamic properties
            Regex::new(r"(?i)filter\s*:").unwrap(),
            Regex::new(r"(?i)transform\s*:").unwrap(),
        ];

        let fingerprinting_patterns = vec![
            // Font fingerprinting
            Regex::new(r"(?i)@font-face").unwrap(),
            Regex::new(r"(?i)font-family\s*:").unwrap(),
            Regex::new(r"(?i)src\s*:\s*url\s*\(").unwrap(),
            // Media query fingerprinting
            Regex::new(r"(?i)@media.*width").unwrap(),
            Regex::new(r"(?i)@media.*height").unwrap(),
            Regex::new(r"(?i)@media.*resolution").unwrap(),
            Regex::new(r"(?i)@media.*orientation").unwrap(),
            // Device fingerprinting
            Regex::new(r"(?i)@media.*device-pixel-ratio").unwrap(),
            Regex::new(r"(?i)@media.*color").unwrap(),
            Regex::new(r"(?i)@media.*color-gamut").unwrap(),
            // Timing attack vectors
            Regex::new(r"(?i)transition\s*:").unwrap(),
            Regex::new(r"(?i)animation\s*:").unwrap(),
            Regex::new(r"(?i)will-change\s*:").unwrap(),
        ];

        let mut allowed_properties = HashSet::new();
        // Safe layout properties
        allowed_properties.extend(vec![
            "display".to_string(), "position".to_string(), "top".to_string(), "right".to_string(), "bottom".to_string(), "left".to_string(),
            "width".to_string(), "height".to_string(), "min-width".to_string(), "min-height".to_string(), "max-width".to_string(), "max-height".to_string(),
            "margin".to_string(), "margin-top".to_string(), "margin-right".to_string(), "margin-bottom".to_string(), "margin-left".to_string(),
            "padding".to_string(), "padding-top".to_string(), "padding-right".to_string(), "padding-bottom".to_string(), "padding-left".to_string(),
            "overflow".to_string(), "visibility".to_string(), "z-index".to_string(), "float".to_string(), "clear".to_string(),
        ]);
        // Safe flexbox properties (subset)
        allowed_properties.extend(vec![
            "flex-direction".to_string(), "flex-wrap".to_string(), "justify-content".to_string(), "align-items".to_string(), "align-content".to_string(),
            "flex-grow".to_string(), "flex-shrink".to_string(), "flex-basis".to_string(), "order".to_string(),
        ]);
        // Safe text properties (subset)
        allowed_properties.extend(vec![
            "color".to_string(), "background-color".to_string(), "font-size".to_string(), "font-weight".to_string(), "text-align".to_string(),
            "text-decoration".to_string(), "text-transform".to_string(), "line-height".to_string(), "letter-spacing".to_string(), "word-spacing".to_string(),
        ]);
        // Safe border properties (subset)
        allowed_properties.extend(vec![
            "border-width".to_string(), "border-color".to_string(), "border-style".to_string(), "border-radius".to_string(),
        ]);

        let mut blocked_properties = HashSet::new();
        // Dangerous properties
        blocked_properties.extend(vec![
            "behavior".to_string(), "-moz-binding".to_string(), "binding".to_string(), "filter".to_string(), "transform".to_string(), "animation".to_string(),
            "transition".to_string(), "will-change".to_string(), "content".to_string(), "cursor".to_string(), "list-style".to_string(), "quotes".to_string(),
        ]);

        Self {
            security_context,
            high_risk_patterns,
            medium_risk_patterns,
            fingerprinting_patterns,
            resource_limits: ResourceLimits::default(),
            allowed_properties,
            blocked_properties,
            font_protection: FontProtection::default(),
        }
    }

    /// Analyze and sanitize CSS content with nation-state level protection
    pub fn analyze_css(&self, css_content: &str) -> Result<CssSecurityAnalysis, ParserError> {
        let start_time = std::time::Instant::now();

        // Initial size validation
        if css_content.len() > self.resource_limits.max_css_size_bytes {
            return Err(ParserError::SecurityViolation(
                format!("CSS content too large: {} bytes", css_content.len())
            ));
        }

        let mut analysis = CssSecurityAnalysis {
            threat_level: CssThreatLevel::Safe,
            attack_types: Vec::new(),
            sanitized_css: String::new(),
            blocked_rules: Vec::new(),
            modified_rules: Vec::new(),
            violations_count: 0,
            metadata: SecurityMetadata {
                selectors_processed: 0,
                declarations_processed: 0,
                processing_time_us: 0,
                memory_usage_bytes: 0,
            },
        };

        // Parse CSS into rules for analysis
        let rules = self.parse_css_rules(css_content)?;

        // Check overall rule count
        if rules.len() > self.resource_limits.max_rules {
            analysis.threat_level = CssThreatLevel::Critical;
            analysis.attack_types.push(CssAttackType::ResourceExhaustion);
            return Ok(analysis);
        }

        let mut sanitized_rules = Vec::new();

        for (rule_index, rule) in rules.iter().enumerate() {
            let rule_analysis = self.analyze_rule(rule, rule_index)?;

            analysis.metadata.selectors_processed += 1;
            analysis.metadata.declarations_processed += rule.declarations.len();

            match rule_analysis.threat_level {
                CssThreatLevel::Critical | CssThreatLevel::Dangerous => {
                    analysis.blocked_rules.push(rule_index);
                    analysis.violations_count += 1;
                    analysis.attack_types.extend(rule_analysis.attack_types);
                }
                CssThreatLevel::Suspicious => {
                    analysis.modified_rules.push(rule_index);
                    sanitized_rules.push(rule_analysis.sanitized_rule);
                    analysis.violations_count += rule_analysis.violations_count;
                    analysis.attack_types.extend(rule_analysis.attack_types);
                }
                CssThreatLevel::Safe => {
                    sanitized_rules.push(rule.clone());
                }
            }
        }

        // Update overall threat level
        if analysis.violations_count > 0 {
            analysis.threat_level = if analysis.attack_types.contains(&CssAttackType::ScriptInjection) {
                CssThreatLevel::Critical
            } else if analysis.violations_count > 10 {
                CssThreatLevel::Dangerous
            } else {
                CssThreatLevel::Suspicious
            };
        }

        // Generate sanitized CSS
        analysis.sanitized_css = self.reconstruct_css(&sanitized_rules);

        // Update metadata
        let elapsed = start_time.elapsed();
        analysis.metadata.processing_time_us = elapsed.as_micros() as u64;
        analysis.metadata.memory_usage_bytes = self.estimate_memory_usage(&analysis);

        Ok(analysis)
    }

    /// Parse CSS content into rules (simplified parser)
    fn parse_css_rules(&self, css_content: &str) -> Result<Vec<StyleRule>, ParserError> {
        let mut rules = Vec::new();

        // Simple rule extraction - split by closing braces
        let rule_chunks: Vec<&str> = css_content.split('}').collect();

        for chunk in rule_chunks {
            let chunk = chunk.trim();
            if chunk.is_empty() {
                continue;
            }

            if let Some(brace_pos) = chunk.find('{') {
                let selector = chunk[..brace_pos].trim();
                let declarations_str = chunk[brace_pos + 1..].trim();

                if selector.is_empty() {
                    continue;
                }

                // Analyze selector complexity
                let complexity = self.calculate_selector_complexity(selector);
                if complexity > self.resource_limits.max_selector_complexity {
                    return Err(ParserError::SecurityViolation(
                        format!("Selector too complex: {}", selector)
                    ));
                }

                let declarations = self.parse_declarations(declarations_str)?;

                if declarations.len() > self.resource_limits.max_declarations_per_rule {
                    return Err(ParserError::SecurityViolation(
                        format!("Too many declarations in rule: {}", selector)
                    ));
                }

                rules.push(StyleRule {
                    selectors: selector.to_string(),
                    declarations,
                    specificity: self.calculate_specificity(selector),
                });
            }
        }

        Ok(rules)
    }

    /// Parse CSS declarations
    fn parse_declarations(&self, declarations_str: &str) -> Result<Vec<Declaration>, ParserError> {
        let mut declarations = Vec::new();

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

                declarations.push(Declaration {
                    property,
                    value,
                    important,
                });
            }
        }

        Ok(declarations)
    }

    /// Analyze individual CSS rule for threats
    fn analyze_rule(&self, rule: &StyleRule, rule_index: usize) -> Result<RuleAnalysis, ParserError> {
        let mut analysis = RuleAnalysis {
            threat_level: CssThreatLevel::Safe,
            attack_types: Vec::new(),
            sanitized_rule: rule.clone(),
            violations_count: 0,
        };

        // Analyze selector
        let selector_analysis = self.analyze_selector(&rule.selectors)?;
        if selector_analysis.threat_level != CssThreatLevel::Safe {
            analysis.threat_level = std::cmp::max(&analysis.threat_level, &selector_analysis.threat_level).clone();
            analysis.attack_types.extend(selector_analysis.attack_types);
            analysis.violations_count += selector_analysis.violations_count;
        }

        // Analyze declarations
        let mut safe_declarations = Vec::new();
        for declaration in &rule.declarations {
            let decl_analysis = self.analyze_declaration(declaration)?;

            if decl_analysis.threat_level == CssThreatLevel::Safe {
                safe_declarations.push(declaration.clone());
            } else {
                analysis.threat_level = std::cmp::max(&analysis.threat_level, &decl_analysis.threat_level).clone();
                analysis.attack_types.extend(decl_analysis.attack_types);
                analysis.violations_count += 1;

                // If suspicious, try to sanitize
                if decl_analysis.threat_level == CssThreatLevel::Suspicious {
                    if let Some(sanitized) = decl_analysis.sanitized_declaration {
                        safe_declarations.push(sanitized);
                    }
                }
            }
        }

        // Update sanitized rule
        analysis.sanitized_rule.declarations = safe_declarations;

        Ok(analysis)
    }

    /// Analyze CSS selector for threats
    fn analyze_selector(&self, selector: &str) -> Result<RuleAnalysis, ParserError> {
        let mut analysis = RuleAnalysis {
            threat_level: CssThreatLevel::Safe,
            attack_types: Vec::new(),
            sanitized_rule: StyleRule {
                selectors: selector.to_string(),
                declarations: Vec::new(),
                specificity: 0,
            },
            violations_count: 0,
        };

        // Check for dangerous patterns in selector
        for pattern in &self.high_risk_patterns {
            if pattern.is_match(selector) {
                analysis.threat_level = CssThreatLevel::Critical;
                analysis.attack_types.push(CssAttackType::ScriptInjection);
                analysis.violations_count += 1;
                return Ok(analysis);
            }
        }

        // Check selector depth
        let depth = self.calculate_selector_depth(selector);
        if depth > self.resource_limits.max_selector_depth {
            analysis.threat_level = CssThreatLevel::Dangerous;
            analysis.attack_types.push(CssAttackType::ResourceExhaustion);
            analysis.violations_count += 1;
        }

        // Check for attribute selectors that could be used for data exfiltration
        if selector.contains("[") && selector.contains("]") {
            // Check for dangerous attribute selectors
            if selector.contains("href") || selector.contains("src") || selector.contains("data-") {
                analysis.threat_level = CssThreatLevel::Suspicious;
                analysis.attack_types.push(CssAttackType::DataExfiltration);
                analysis.violations_count += 1;
            }
        }

        Ok(analysis)
    }

    /// Analyze CSS declaration for threats
    fn analyze_declaration(&self, declaration: &Declaration) -> Result<DeclarationAnalysis, ParserError> {
        let mut analysis = DeclarationAnalysis {
            threat_level: CssThreatLevel::Safe,
            attack_types: Vec::new(),
            sanitized_declaration: None,
            violations_count: 0,
        };

        let property_lower = declaration.property.to_lowercase();

        // Check blocked properties
        if self.blocked_properties.contains(&property_lower) {
            analysis.threat_level = CssThreatLevel::Dangerous;
            analysis.attack_types.push(CssAttackType::SideChannel);
            analysis.violations_count += 1;
            return Ok(analysis);
        }

        // Check for high-risk patterns in value
        for pattern in &self.high_risk_patterns {
            if pattern.is_match(&declaration.value) {
                analysis.threat_level = CssThreatLevel::Critical;
                analysis.attack_types.push(CssAttackType::ScriptInjection);
                analysis.violations_count += 1;
                return Ok(analysis);
            }
        }

        // Check for fingerprinting patterns
        for pattern in &self.fingerprinting_patterns {
            if pattern.is_match(&declaration.property) || pattern.is_match(&declaration.value) {
                analysis.threat_level = CssThreatLevel::Suspicious;
                analysis.attack_types.push(CssAttackType::Fingerprinting);
                analysis.violations_count += 1;

                // Try to sanitize fingerprinting attempts
                if property_lower == "font-family" {
                    if let Some(sanitized_value) = self.sanitize_font_family(&declaration.value) {
                        analysis.sanitized_declaration = Some(Declaration {
                            property: declaration.property.clone(),
                            value: sanitized_value,
                            important: declaration.important,
                        });
                        analysis.threat_level = CssThreatLevel::Safe;
                    }
                }
                break;
            }
        }

        // Check for medium-risk patterns
        for pattern in &self.medium_risk_patterns {
            if pattern.is_match(&declaration.value) {
                if analysis.threat_level == CssThreatLevel::Safe {
                    analysis.threat_level = CssThreatLevel::Suspicious;
                }
                analysis.attack_types.push(CssAttackType::NetworkExfiltration);
                analysis.violations_count += 1;
                break;
            }
        }

        // Only allow whitelisted properties
        if !self.allowed_properties.contains(&property_lower) {
            if analysis.threat_level == CssThreatLevel::Safe {
                analysis.threat_level = CssThreatLevel::Suspicious;
            }
            analysis.violations_count += 1;
        }

        Ok(analysis)
    }

    /// Sanitize font-family values to prevent fingerprinting
    fn sanitize_font_family(&self, font_value: &str) -> Option<String> {
        let fonts: Vec<&str> = font_value.split(',').map(|s| s.trim().trim_matches('"').trim_matches('\'')).collect();
        let mut safe_fonts = Vec::new();

        for font in fonts {
            if self.font_protection.allowed_font_families.contains(font) {
                safe_fonts.push(font);
            }
        }

        if safe_fonts.is_empty() {
            Some("sans-serif".to_string())
        } else {
            Some(safe_fonts.join(", "))
        }
    }

    /// Calculate CSS selector complexity score
    fn calculate_selector_complexity(&self, selector: &str) -> u32 {
        let mut complexity = 0u32;

        // IDs have high complexity
        complexity += selector.matches('#').count() as u32 * 100;

        // Classes have medium complexity
        complexity += selector.matches('.').count() as u32 * 10;

        // Attribute selectors have high complexity
        complexity += selector.matches('[').count() as u32 * 50;

        // Pseudo-classes have medium complexity
        complexity += selector.matches(':').count() as u32 * 15;

        // Pseudo-elements have low complexity
        complexity += selector.matches("::").count() as u32 * 5;

        // Combinators increase complexity
        complexity += selector.matches(['>', '+', '~']).count() as u32 * 20;

        complexity
    }

    /// Calculate selector depth
    fn calculate_selector_depth(&self, selector: &str) -> usize {
        let mut depth = 0;
        let mut max_depth = 0;

        for char in selector.chars() {
            match char {
                '>' | '+' | '~' => {
                    depth += 1;
                    max_depth = max_depth.max(depth);
                }
                ' ' => {
                    // Descendant combinator
                    depth += 1;
                    max_depth = max_depth.max(depth);
                }
                ',' => {
                    // Reset depth for new selector
                    depth = 0;
                }
                _ => {}
            }
        }

        max_depth
    }

    /// Calculate CSS specificity
    fn calculate_specificity(&self, selector: &str) -> u32 {
        let mut specificity = 0u32;

        // IDs: 100 points each
        specificity += selector.matches('#').count() as u32 * 100;

        // Classes and attributes: 10 points each
        specificity += selector.matches(['.', '[']).count() as u32 * 10;

        // Elements: 1 point each
        specificity += selector.matches(|c: char| c.is_alphabetic()).count() as u32;

        specificity
    }

    /// Reconstruct CSS from sanitized rules
    fn reconstruct_css(&self, rules: &[StyleRule]) -> String {
        let mut css = String::new();

        for rule in rules {
            css.push_str(&rule.selectors);
            css.push_str(" {");

            for declaration in &rule.declarations {
                css.push_str(&declaration.property);
                css.push_str(": ");
                css.push_str(&declaration.value);
                if declaration.important {
                    css.push_str(" !important");
                }
                css.push_str("; ");
            }

            css.push_str("}\n");
        }

        css
    }

    /// Estimate memory usage for security analysis
    fn estimate_memory_usage(&self, analysis: &CssSecurityAnalysis) -> usize {
        let base_size = std::mem::size_of::<CssSecurityAnalysis>();
        let css_size = analysis.sanitized_css.len();
        let rules_size = analysis.blocked_rules.len() * std::mem::size_of::<usize>();
        let metadata_size = std::mem::size_of::<SecurityMetadata>();

        base_size + css_size + rules_size + metadata_size
    }
}

/// Analysis result for individual rules
struct RuleAnalysis {
    threat_level: CssThreatLevel,
    attack_types: Vec<CssAttackType>,
    sanitized_rule: StyleRule,
    violations_count: usize,
}

/// Analysis result for individual declarations
struct DeclarationAnalysis {
    threat_level: CssThreatLevel,
    attack_types: Vec<CssAttackType>,
    sanitized_declaration: Option<Declaration>,
    violations_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_security_context() -> Arc<SecurityContext> {
        Arc::new(SecurityContext::new(10))
    }

    #[test]
    fn test_safe_css_analysis() {
        let security_context = create_test_security_context();
        let filter = CssSecurityFilter::new(security_context);

        let safe_css = r#"
            body {
                color: #333;
                background-color: #fff;
                font-size: 16px;
                margin: 0;
                padding: 20px;
            }

            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
        "#;

        let result = filter.analyze_css(safe_css).unwrap();
        assert_eq!(result.threat_level, CssThreatLevel::Safe);
        assert_eq!(result.violations_count, 0);
        assert!(result.blocked_rules.is_empty());
        assert!(result.modified_rules.is_empty());
    }

    #[test]
    fn test_script_injection_blocking() {
        let security_context = create_test_security_context();
        let filter = CssSecurityFilter::new(security_context);

        let malicious_css = r#"
            body {
                background: url('javascript:alert(1)');
                behavior: url(#default#time2);
            }
        "#;

        let result = filter.analyze_css(malicious_css).unwrap();
        assert_eq!(result.threat_level, CssThreatLevel::Critical);
        assert!(result.attack_types.contains(&CssAttackType::ScriptInjection));
        assert!(result.blocked_rules.len() > 0);
    }

    #[test]
    fn test_fingerprinting_detection() {
        let security_context = create_test_security_context();
        let filter = CssSecurityFilter::new(security_context);

        let fingerprinting_css = r#"
            @font-face {
                font-family: 'CustomFont';
                src: url('https://evil.com/font.woff2');
            }

            @media (min-width: 1920px) {
                body { font-size: 18px; }
            }
        "#;

        let result = filter.analyze_css(fingerprinting_css).unwrap();
        assert_eq!(result.threat_level, CssThreatLevel::Suspicious);
        assert!(result.attack_types.contains(&CssAttackType::Fingerprinting));
    }

    #[test]
    fn test_resource_exhaustion_prevention() {
        let security_context = create_test_security_context();
        let filter = CssSecurityFilter::new(security_context);

        // Create CSS with too many rules
        let mut excessive_css = String::new();
        for i in 0..15000 {
            excessive_css.push_str(&format!(".class{} {{ color: red; }}\n", i));
        }

        let result = filter.analyze_css(&excessive_css).unwrap();
        assert_eq!(result.threat_level, CssThreatLevel::Critical);
        assert!(result.attack_types.contains(&CssAttackType::ResourceExhaustion));
    }

    #[test]
    fn test_font_sanitization() {
        let security_context = create_test_security_context();
        let filter = CssSecurityFilter::new(security_context);

        let font_css = r#"
            body {
                font-family: 'CustomEvilFont', 'AnotherBadFont', sans-serif;
            }
        "#;

        let result = filter.analyze_css(font_css).unwrap();
        assert_eq!(result.threat_level, CssThreatLevel::Safe);

        // Should be sanitized to only safe fonts
        assert!(result.sanitized_css.contains("sans-serif"));
        assert!(!result.sanitized_css.contains("CustomEvilFont"));
    }
}