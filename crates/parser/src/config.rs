use html5ever::tree_builder::TreeBuilderOpts;
use html5ever::tokenizer::TokenizerOpts;
use crate::SecurityLevel;

/// Configuration for the parser
#[derive(Debug, Clone)]
pub struct ParserConfig {
    /// Security level
    pub security_level: SecurityLevel,
    /// Maximum depth for nested elements
    pub max_depth: usize,
    /// Maximum length for attribute values
    pub max_attr_length: usize,
    /// Whether to allow comments
    pub allow_comments: bool,
    /// Whether to allow processing instructions
    pub allow_processing_instructions: bool,
    /// Whether to allow script execution
    pub allow_scripts: bool,
    /// Whether to allow external resources
    pub allow_external_resources: bool,
    /// Maximum nesting depth for elements
    pub max_nesting_depth: usize,
    /// Maximum allowed CSS size in bytes
    pub max_css_size: usize,
}

impl Default for ParserConfig {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::default(),
            max_depth: 100,
            max_attr_length: 1024,
            allow_comments: true,
            allow_processing_instructions: false,
            allow_scripts: false,
            allow_external_resources: false,
            max_nesting_depth: 32, // Reasonable default for nesting depth
            max_css_size: 512 * 1024, // 512KB CSS limit by default
        }
    }
}

impl ParserConfig {
    /// Create tree builder options based on configuration
    pub fn tree_builder_opts(&self) -> TreeBuilderOpts {
        TreeBuilderOpts {
            drop_doctype: true,
            scripting_enabled: self.allow_scripts,
            iframe_srcdoc: false,
            ..Default::default()
        }
    }

    /// Create tokenizer options based on configuration
    pub fn tokenizer_opts(&self) -> TokenizerOpts {
        TokenizerOpts {
            ..Default::default()
        }
    }

    /// Get the maximum nesting depth
    pub fn max_nesting_depth(&self) -> usize {
        self.max_nesting_depth
    }

    /// Check if an element is allowed based on security settings
    pub fn is_element_allowed(&self, tag_name: &str) -> bool {
        match self.security_level {
            SecurityLevel::Maximum => {
                // Only allow basic structural and text elements
                matches!(tag_name.to_lowercase().as_str(),
                    "div" | "span" | "p" | "br" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6")
            },
            SecurityLevel::High => {
                // Allow most safe elements, but no scripts or frames
                !matches!(tag_name.to_lowercase().as_str(),
                    "script" | "iframe" | "frame" | "object" | "embed" | "applet")
            },
            SecurityLevel::Balanced => {
                // Block known dangerous elements
                !matches!(tag_name.to_lowercase().as_str(),
                    "script" | "object" | "embed" | "applet")
            },
            SecurityLevel::Custom => {
                // Use custom rules (to be implemented)
                true
            }
        }
    }

    /// Check if an attribute is allowed based on security settings
    pub fn is_attribute_allowed(&self, attr_name: &str) -> bool {
        // Convert to lowercase for case-insensitive comparison
        let attr_name = attr_name.to_lowercase();
        
        // Never allow these attributes regardless of security level
        if attr_name.starts_with("on") || // Event handlers
           attr_name == "href" && !self.allow_external_resources ||
           attr_name == "src" && !self.allow_external_resources ||
           attr_name == "style" // Inline styles (potential CSS injection)
        {
            return false;
        }

        match self.security_level {
            SecurityLevel::Maximum => {
                // Only allow basic attributes
                matches!(attr_name.as_str(),
                    "class" | "id" | "title" | "alt" | "lang")
            },
            SecurityLevel::High => {
                // Block potentially dangerous attributes
                !matches!(attr_name.as_str(),
                    "style" | "href" | "src" | "data" | "formaction")
            },
            SecurityLevel::Balanced => {
                // Block known dangerous attributes
                !matches!(attr_name.as_str(),
                    "javascript:" | "data:" | "vbscript:")
            },
            SecurityLevel::Custom => {
                // Use custom rules (to be implemented)
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ParserConfig::default();
        assert_eq!(config.security_level, SecurityLevel::Balanced);
        assert_eq!(config.max_depth, 100);
        assert_eq!(config.max_attr_length, 1024);
        assert!(config.allow_comments);
        assert!(!config.allow_processing_instructions);
        assert!(!config.allow_scripts);
        assert!(!config.allow_external_resources);
        assert_eq!(config.max_nesting_depth(), 32);
        assert_eq!(config.max_css_size, 512 * 1024);
    }

    #[test]
    fn test_element_security_levels() {
        let mut config = ParserConfig::default();
        
        // Test Maximum security
        config.security_level = SecurityLevel::Maximum;
        assert!(config.is_element_allowed("div"));
        assert!(config.is_element_allowed("p"));
        assert!(!config.is_element_allowed("script"));
        assert!(!config.is_element_allowed("iframe"));
        
        // Test High security
        config.security_level = SecurityLevel::High;
        assert!(config.is_element_allowed("div"));
        assert!(config.is_element_allowed("img"));
        assert!(!config.is_element_allowed("script"));
        assert!(!config.is_element_allowed("iframe"));
        
        // Test Balanced security
        config.security_level = SecurityLevel::Balanced;
        assert!(config.is_element_allowed("div"));
        assert!(config.is_element_allowed("img"));
        assert!(!config.is_element_allowed("script"));
        assert!(config.is_element_allowed("iframe"));
    }

    #[test]
    fn test_attribute_security_levels() {
        let mut config = ParserConfig::default();
        
        // Test Maximum security
        config.security_level = SecurityLevel::Maximum;
        assert!(config.is_attribute_allowed("class"));
        assert!(config.is_attribute_allowed("id"));
        assert!(!config.is_attribute_allowed("onclick"));
        assert!(!config.is_attribute_allowed("style"));
        
        // Test High security
        config.security_level = SecurityLevel::High;
        assert!(config.is_attribute_allowed("class"));
        assert!(!config.is_attribute_allowed("onclick"));
        assert!(!config.is_attribute_allowed("style"));
        
        // Test Balanced security
        config.security_level = SecurityLevel::Balanced;
        assert!(config.is_attribute_allowed("class"));
        assert!(!config.is_attribute_allowed("onclick"));
        assert!(!config.is_attribute_allowed("javascript:"));
    }
} 
