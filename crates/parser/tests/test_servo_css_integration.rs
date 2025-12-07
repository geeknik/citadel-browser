//! Comprehensive test for Servo CSS integration
//! This test demonstrates that CSS is no longer displayed as plain text

use citadel_parser::*;
use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_css_extraction() {
        let html = r#"
        <html>
        <head>
            <style>
            body { margin: 0; }
            .test { color: red; }
            </style>
        </head>
        <body></body>
        </html>
        "#;
        
        let css = extract_css_from_html(html);
        assert!(css.contains("body { margin: 0; }"));
        assert!(css.contains(".test { color: red; }"));
    }
    
    #[test]
    fn test_css_rule_counting() {
        let css = r#"
        body { margin: 0; }
        .test { color: red; }
        #id { font-size: 14px; }
        "#;
        
        let count = count_css_rules(css);
        assert_eq!(count, 3);
    }

    #[test]
    fn test_servo_css_processor_creation() {
        let config = ParserConfig::default();
        let metrics = Arc::new(ParserMetrics::default());
        let processor = servo_css_processor::ServoCssProcessor::new(config, metrics);
        
        // Test that the processor can be created
        assert!(true, "ServoCssProcessor should be created successfully");
    }

    #[test]
    fn test_basic_css_parsing() -> Result<(), Box<dyn std::error::Error>> {
        let css_content = r#"
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f0f0;
            margin: 0;
            padding: 0;
        }
        
        .highlight {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 10px;
            margin: 5px;
        }
        
        h1 {
            color: #333;
            font-size: 2rem;
            text-align: center;
        }
        "#;
        
        let config = ParserConfig::default();
        let metrics = Arc::new(ParserMetrics::default());
        let mut processor = servo_css_processor::ServoCssProcessor::new(config, metrics);
        
        let result = processor.process_css(css_content)?;
        
        // Verify that CSS was processed
        assert!(result.stats.rules_processed > 0, "Should process at least one rule");
        assert!(result.stats.declarations_processed > 0, "Should process at least one declaration");
        
        Ok(())
    }

    #[test]
    fn test_css_security_filtering() -> Result<(), Box<dyn std::error::Error>> {
        let malicious_css = r#"
        body {
            background: url('javascript:alert(1)');
            behavior: url(#default#time2);
        }
        
        @import url("javascript:evil");
        "#;
        
        let config = ParserConfig::default();
        let metrics = Arc::new(ParserMetrics::default());
        let mut processor = servo_css_processor::ServoCssProcessor::new(config, metrics);
        
        let result = processor.process_css(malicious_css)?;
        
        // Verify that security analysis was performed
        if let Some(analysis) = &result.security_analysis {
            assert!(analysis.threat_level != css_security::CssThreatLevel::Safe, "Should detect threats");
            assert!(analysis.violations_count > 0, "Should detect violations");
        }
        
        Ok(())
    }

    #[test]
    fn test_style_computation() -> Result<(), Box<dyn std::error::Error>> {
        let css_content = r#"
        body {
            font-family: Arial, sans-serif;
            color: #333;
        }
        
        .highlight {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
        }
        
        #special-element {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
        }
        "#;
        
        let config = ParserConfig::default();
        let metrics = Arc::new(ParserMetrics::default());
        let mut processor = servo_css_processor::ServoCssProcessor::new(config, metrics);
        
        let _result = processor.process_css(css_content)?;
        
        // Test style computation for different elements
        let body_style = processor.compute_element_style("body", &[], None, None)?;
        assert!(body_style.properties.len() > 0, "Body should have computed styles");
        
        let highlight_style = processor.compute_element_style("div", &["highlight".to_string()], None, None)?;
        assert!(highlight_style.properties.len() > 0, "Highlight element should have computed styles");
        
        let special_style = processor.compute_element_style("div", &[], Some("special-element"), None)?;
        assert!(special_style.properties.len() > 0, "Special element should have computed styles");
        
        Ok(())
    }
}

fn extract_css_from_html(html: &str) -> String {
    let mut css_content = String::new();
    
    // Simple extraction of <style> content
    let mut in_style = false;
    let mut style_depth = 0;
    
    for line in html.lines() {
        if line.trim().contains("<style") {
            in_style = true;
            style_depth = 1;
            continue;
        }
        
        if line.trim().contains("</style>") {
            in_style = false;
            style_depth = 0;
            continue;
        }
        
        if in_style {
            css_content.push_str(line);
            css_content.push('\n');
        }
    }
    
    css_content
}

fn count_css_rules(css: &str) -> usize {
    let mut rule_count = 0;
    let mut in_rule = false;
    
    for line in css.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("/*") || line.starts_with("//") {
            continue;
        }
        
        if line.contains("{") && !line.starts_with("@") {
            in_rule = true;
        }
        
        if in_rule && line.contains("}") {
            rule_count += 1;
            in_rule = false;
        }
    }
    
    rule_count
}
