//! Citadel's privacy-focused HTML/CSS parser
//! 
//! This module implements a secure HTML and CSS parser with built-in
//! privacy protections and security measures.

use std::fmt::Debug;
use std::sync::atomic::Ordering;

pub mod css;
pub mod dom;
pub mod error;
pub mod html;
pub mod security;
pub mod metrics;
pub mod config;

use error::ParserResult;

/// Re-export common types
pub use error::ParserError;
pub use dom::node::{Node, NodeData};
pub use html::parse_html;
pub use css::CitadelCssParser as CssParser;
pub use metrics::{ParserMetrics, DocumentMetrics, ParseTimer};
pub use config::ParserConfig;

/// Security level for the parser
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Maximum security - most restrictive
    Maximum,
    /// High security - very restrictive
    High,
    /// Balanced security - moderate restrictions
    Balanced,
    /// Custom security settings
    Custom,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::Balanced
    }
}

/// Parse mode options to control parsing behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseMode {
    /// Standard parsing mode with normal error handling
    Standard,
    /// Strict parsing mode that fails on any error
    Strict,
    /// Tolerant parsing mode that attempts to recover from all errors
    Tolerant,
    /// Maximum security mode with additional security checks
    Secure,
}

/// Sanitization level for parsed content
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizationLevel {
    /// No sanitization
    None,
    /// Basic sanitization of dangerous elements and attributes
    Basic,
    /// Standard sanitization (balanced security and functionality)
    Standard,
    /// Strict sanitization for highest security
    Strict,
}

/// URL resolver for handling resource URLs during parsing
pub trait UrlResolver {
    /// Resolve a URL relative to the document base URL
    fn resolve(&self, url: &str) -> Result<url::Url, error::ParserError>;
    
    /// Check if a URL should be blocked based on security policies
    fn should_block(&self, url: &url::Url) -> bool;
}

/// Trait for parsers in the Citadel browser
pub trait Parser {
    /// Type of the parser output
    type Output;

    /// Parse content with the given configuration
    fn parse(&self, content: &str) -> ParserResult<Self::Output>;

    /// Get parser metrics
    fn metrics(&self) -> &ParserMetrics;
}

/// Citadel parser context with shared state
pub struct ParseContext<R: UrlResolver> {
    /// Parser configuration
    pub config: ParserConfig,
    /// Base URL for the document
    pub base_url: Option<url::Url>,
    /// URL resolver for handling resources
    pub url_resolver: R,
    /// Current parsing depth
    pub current_depth: usize,
    /// Total tokens processed
    pub tokens_processed: usize,
}

impl<R: UrlResolver> ParseContext<R> {
    /// Create a new parsing context with the given configuration and URL resolver
    pub fn new(config: ParserConfig, resolver: R, base_url: Option<url::Url>) -> Self {
        Self {
            config,
            base_url,
            url_resolver: resolver,
            current_depth: 0,
            tokens_processed: 0,
        }
    }
    
    /// Increment the current parsing depth
    pub fn increment_depth(&mut self) -> Result<(), error::ParserError> {
        if self.current_depth >= self.config.max_depth {
            return Err(error::ParserError::NestingTooDeep(self.current_depth));
        }
        self.current_depth += 1;
        Ok(())
    }
    
    /// Decrement the current parsing depth
    pub fn decrement_depth(&mut self) {
        if self.current_depth > 0 {
            self.current_depth -= 1;
        }
    }
    
    /// Increment the token counter and check limits
    pub fn count_token(&mut self) -> Result<(), error::ParserError> {
        self.tokens_processed += 1;
        if self.tokens_processed > self.config.max_attr_length {
            return Err(error::ParserError::TooManyTokens(self.config.max_attr_length));
        }
        Ok(())
    }
    
    /// Reset the token counter
    pub fn reset_token_count(&mut self) {
        self.tokens_processed = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    struct TestUrlResolver;
    
    impl UrlResolver for TestUrlResolver {
        fn resolve(&self, url: &str) -> Result<url::Url, error::ParserError> {
            url::Url::parse(url).map_err(|e| error::ParserError::InvalidUrl(e))
        }
        
        fn should_block(&self, url: &url::Url) -> bool {
            url.host_str().map_or(false, |host| {
                host.contains("tracker") || host.contains("ads")
            })
        }
    }
    
    #[test]
    fn test_security_level_default() {
        assert_eq!(SecurityLevel::default(), SecurityLevel::Balanced);
    }
    
    #[test]
    fn test_parser_config_default() {
        let config = ParserConfig::default();
        assert_eq!(config.security_level, SecurityLevel::Balanced);
        assert_eq!(config.max_depth, 100);
        assert_eq!(config.max_attr_length, 1024);
        assert!(config.allow_comments);
        assert!(!config.allow_processing_instructions);
    }
    
    #[test]
    fn test_parser_metrics() {
        let metrics = ParserMetrics::default();
        metrics.increment_elements();
        metrics.increment_attributes();
        metrics.increment_violations();
        metrics.increment_sanitizations();

        assert_eq!(metrics.elements_parsed.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.attributes_parsed.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.security_violations.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.sanitization_actions.load(Ordering::Relaxed), 1);
    }
    
    #[test]
    fn test_parse_context() {
        let config = ParserConfig::default();
        let resolver = TestUrlResolver;
        let base_url = url::Url::parse("https://example.com").ok();
        
        let mut context = ParseContext::new(config, resolver, base_url);
        
        // Test depth tracking
        assert_eq!(context.current_depth, 0);
        context.increment_depth().unwrap();
        assert_eq!(context.current_depth, 1);
        context.decrement_depth();
        assert_eq!(context.current_depth, 0);
        
        // Test token counting
        assert_eq!(context.tokens_processed, 0);
        context.count_token().unwrap();
        assert_eq!(context.tokens_processed, 1);
        context.reset_token_count();
        assert_eq!(context.tokens_processed, 0);

        // Test token counting limit
        context.tokens_processed = context.config.max_attr_length;
        assert!(context.count_token().is_err());
        context.reset_token_count();
    }
}

// Re-export common types
pub type Document = Node; 