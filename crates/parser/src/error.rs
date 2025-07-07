use std::fmt;
use std::error::Error;
use url::ParseError as UrlParseError;

/// Error types for the parser
#[derive(Debug)]
pub enum ParserError {
    /// HTML parsing error
    HtmlParseError(String),
    /// CSS parsing error
    CssError(String),
    /// URL parsing error
    InvalidUrl(UrlParseError),
    /// Security violation
    SecurityViolation(String),
    /// Nesting too deep
    NestingTooDeep(usize),
    /// Too many tokens
    TooManyTokens(usize),
    /// IO Error
    IoError(String),
    /// JavaScript execution error
    JsError(String),
    /// Layout error
    LayoutError(String),
    /// Unknown error
    Unknown(String),
}

impl fmt::Display for ParserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParserError::HtmlParseError(msg) => write!(f, "HTML parse error: {}", msg),
            ParserError::CssError(msg) => write!(f, "CSS parse error: {}", msg),
            ParserError::InvalidUrl(e) => write!(f, "Invalid URL: {}", e),
            ParserError::SecurityViolation(msg) => write!(f, "Security violation: {}", msg),
            ParserError::NestingTooDeep(depth) => write!(f, "Nesting too deep: {}", depth),
            ParserError::TooManyTokens(count) => write!(f, "Too many tokens: {}", count),
            ParserError::IoError(msg) => write!(f, "IO Error: {}", msg),
            ParserError::JsError(msg) => write!(f, "JavaScript error: {}", msg),
            ParserError::LayoutError(msg) => write!(f, "Layout error: {}", msg),
            ParserError::Unknown(msg) => write!(f, "Unknown error: {}", msg),
        }
    }
}

impl Error for ParserError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ParserError::InvalidUrl(e) => Some(e),
            _ => None,
        }
    }
}

/// Result type for parser operations
pub type ParserResult<T> = Result<T, ParserError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ParserError::HtmlParseError("invalid tag".to_string());
        assert_eq!(err.to_string(), "HTML parse error: invalid tag");

        let err = ParserError::SecurityViolation("script tag not allowed".to_string());
        assert_eq!(err.to_string(), "Security violation: script tag not allowed");

        let err = ParserError::NestingTooDeep(100);
        assert_eq!(err.to_string(), "Nesting too deep: 100");
    }

    #[test]
    fn test_error_source() {
        let url_err = url::ParseError::EmptyHost;
        let err = ParserError::InvalidUrl(url_err);
        assert!(err.source().is_some());

        let err = ParserError::Unknown("test".to_string());
        assert!(err.source().is_none());
    }
} 