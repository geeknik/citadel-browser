use crate::error::ParseError;
use crate::{ParseContext, UrlResolver};

/// Types of HTML tokens
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// Document type declaration
    Doctype {
        /// Name
        name: String,
        /// Public identifier
        public_id: String,
        /// System identifier
        system_id: String,
    },
    /// Start tag
    StartTag {
        /// Tag name
        name: String,
        /// Attributes
        attributes: Vec<(String, String)>,
        /// Self-closing flag
        self_closing: bool,
    },
    /// End tag
    EndTag {
        /// Tag name
        name: String,
    },
    /// Comment
    Comment {
        /// Comment data
        data: String,
    },
    /// Character data
    Character {
        /// Character data
        data: String,
    },
    /// Processing instruction
    ProcessingInstruction {
        /// Target
        target: String,
        /// Data
        data: String,
    },
    /// End of file
    EOF,
}

/// HTML tokenizer that emits tokens from an HTML document
pub struct Tokenizer<R: UrlResolver> {
    /// Parsing context
    context: ParseContext<R>,
    /// Input text
    input: String,
    /// Current position
    position: usize,
    /// Current line
    line: usize,
    /// Current column
    column: usize,
    /// Stack of open tags (for security checks)
    open_tags: Vec<String>,
}

impl<R: UrlResolver> Tokenizer<R> {
    /// Create a new tokenizer with the given context and input
    pub fn new(context: ParseContext<R>, input: String) -> Self {
        Self {
            context,
            input,
            position: 0,
            line: 1,
            column: 1,
            open_tags: Vec::new(),
        }
    }
    
    /// Get the next token from the input
    pub fn next_token(&mut self) -> Result<Token, ParseError> {
        self.context.count_token()?;
        
        // Skip whitespace
        self.skip_whitespace();
        
        // Check if we're at the end of the input
        if self.position >= self.input.len() {
            return Ok(Token::EOF);
        }
        
        // Look at the current character to determine what kind of token we're parsing
        let c = self.current_char()?;
        
        match c {
            '<' => self.parse_tag(),
            _ => self.parse_character_data(),
        }
    }
    
    /// Parse all tokens from the input
    pub fn tokenize(&mut self) -> Result<Vec<Token>, ParseError> {
        let mut tokens = Vec::new();
        
        loop {
            let token = self.next_token()?;
            
            // Check for security issues
            self.check_security(&token)?;
            
            // Add the token to the list
            tokens.push(token.clone());
            
            // Break if we reached the end of the input
            if token == Token::EOF {
                break;
            }
        }
        
        Ok(tokens)
    }
    
    /// Get the current character
    fn current_char(&self) -> Result<char, ParseError> {
        if self.position >= self.input.len() {
            return Err(ParseError::UnexpectedToken("Unexpected end of input".to_string()));
        }
        
        self.input[self.position..].chars().next().ok_or_else(|| {
            ParseError::UnexpectedToken("Invalid UTF-8 sequence".to_string())
        })
    }
    
    /// Advance the position by one character
    fn advance(&mut self) {
        if self.position < self.input.len() {
            let c = self.input[self.position..].chars().next().unwrap();
            self.position += c.len_utf8();
            
            if c == '\n' {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
        }
    }
    
    /// Skip whitespace characters
    fn skip_whitespace(&mut self) {
        while self.position < self.input.len() {
            let c = self.input[self.position..].chars().next().unwrap();
            if !c.is_whitespace() {
                break;
            }
            self.advance();
        }
    }
    
    /// Parse a tag (start tag, end tag, comment, or doctype)
    fn parse_tag(&mut self) -> Result<Token, ParseError> {
        // Skip the '<' character
        self.advance();
        
        // Check what kind of tag we're parsing
        if self.position >= self.input.len() {
            return Err(ParseError::MalformedHtml("Unexpected end of input after '<'".to_string()));
        }
        
        let c = self.current_char()?;
        
        match c {
            '/' => self.parse_end_tag(),
            '!' => self.parse_comment_or_doctype(),
            '?' => self.parse_processing_instruction(),
            _ => self.parse_start_tag(),
        }
    }
    
    /// Parse a start tag
    fn parse_start_tag(&mut self) -> Result<Token, ParseError> {
        let mut name = String::new();
        let mut attributes = Vec::new();
        let mut self_closing = false;
        
        // Parse the tag name
        while self.position < self.input.len() {
            let c = self.current_char()?;
            
            if c.is_whitespace() || c == '>' || c == '/' {
                break;
            }
            
            name.push(c);
            self.advance();
        }
        
        // Parse attributes
        while self.position < self.input.len() {
            self.skip_whitespace();
            
            let c = self.current_char()?;
            
            if c == '>' {
                self.advance();
                break;
            } else if c == '/' {
                self.advance();
                
                if self.position < self.input.len() && self.current_char()? == '>' {
                    self_closing = true;
                    self.advance();
                    break;
                } else {
                    return Err(ParseError::MalformedHtml("Expected '>' after '/'".to_string()));
                }
            } else if !c.is_whitespace() {
                // Parse an attribute
                let (attr_name, attr_value) = self.parse_attribute()?;
                attributes.push((attr_name, attr_value));
            } else {
                self.advance();
            }
        }
        
        // Update the open tags stack
        if !self_closing {
            // Check for nesting security
            if self.open_tags.len() >= self.context.config.max_nesting_depth {
                return Err(ParseError::NestingTooDeep(self.open_tags.len()));
            }
            
            self.open_tags.push(name.clone());
        }
        
        // Check attribute count
        if attributes.len() > self.context.config.max_attributes {
            return Err(ParseError::TooManyAttributes(attributes.len()));
        }
        
        Ok(Token::StartTag {
            name,
            attributes,
            self_closing,
        })
    }
    
    /// Parse an end tag
    fn parse_end_tag(&mut self) -> Result<Token, ParseError> {
        // Skip the '/' character
        self.advance();
        
        let mut name = String::new();
        
        // Parse the tag name
        while self.position < self.input.len() {
            let c = self.current_char()?;
            
            if c.is_whitespace() || c == '>' {
                break;
            }
            
            name.push(c);
            self.advance();
        }
        
        // Skip to the end of the tag
        while self.position < self.input.len() && self.current_char()? != '>' {
            self.advance();
        }
        
        // Skip the '>' character
        if self.position < self.input.len() {
            self.advance();
        }
        
        // Update the open tags stack
        if let Some(pos) = self.open_tags.iter().rposition(|tag| tag == &name) {
            // Remove all tags up to and including this one
            self.open_tags.truncate(pos);
        }
        
        Ok(Token::EndTag { name })
    }
    
    /// Parse a comment or doctype
    fn parse_comment_or_doctype(&mut self) -> Result<Token, ParseError> {
        // Skip the '!' character
        self.advance();
        
        // Check if it's a comment or doctype
        if self.position + 2 <= self.input.len() && &self.input[self.position..self.position + 2] == "--" {
            // Skip the "--" characters
            self.advance();
            self.advance();
            
            // Parse a comment
            let mut data = String::new();
            
            while self.position + 2 <= self.input.len() {
                if &self.input[self.position..self.position + 2] == "--" {
                    self.advance();
                    self.advance();
                    
                    if self.position < self.input.len() && self.current_char()? == '>' {
                        self.advance();
                        break;
                    } else {
                        return Err(ParseError::MalformedHtml("Expected '>' after '--'".to_string()));
                    }
                }
                
                data.push(self.current_char()?);
                self.advance();
            }
            
            Ok(Token::Comment { data })
        } else if self.position + 7 <= self.input.len() && self.input[self.position..self.position + 7].to_uppercase() == "DOCTYPE" {
            // Skip the "DOCTYPE" characters
            for _ in 0..7 {
                self.advance();
            }
            
            // Parse a doctype
            self.skip_whitespace();
            
            let mut name = String::new();
            let mut public_id = String::new();
            let mut system_id = String::new();
            
            // Parse the doctype name
            while self.position < self.input.len() {
                let c = self.current_char()?;
                
                if c.is_whitespace() || c == '>' {
                    break;
                }
                
                name.push(c);
                self.advance();
            }
            
            // Skip to the end of the doctype
            while self.position < self.input.len() && self.current_char()? != '>' {
                self.advance();
            }
            
            // Skip the '>' character
            if self.position < self.input.len() {
                self.advance();
            }
            
            Ok(Token::Doctype {
                name,
                public_id,
                system_id,
            })
        } else {
            Err(ParseError::MalformedHtml("Invalid markup after '!'".to_string()))
        }
    }
    
    /// Parse a processing instruction
    fn parse_processing_instruction(&mut self) -> Result<Token, ParseError> {
        // Skip the '?' character
        self.advance();
        
        let mut target = String::new();
        
        // Parse the target
        while self.position < self.input.len() {
            let c = self.current_char()?;
            
            if c.is_whitespace() {
                break;
            }
            
            target.push(c);
            self.advance();
        }
        
        // Skip whitespace
        self.skip_whitespace();
        
        let mut data = String::new();
        
        // Parse the data
        while self.position + 1 < self.input.len() {
            if &self.input[self.position..self.position + 2] == "?>" {
                self.advance();
                self.advance();
                break;
            }
            
            data.push(self.current_char()?);
            self.advance();
        }
        
        Ok(Token::ProcessingInstruction { target, data })
    }
    
    /// Parse an attribute
    fn parse_attribute(&mut self) -> Result<(String, String), ParseError> {
        let mut name = String::new();
        
        // Parse the attribute name
        while self.position < self.input.len() {
            let c = self.current_char()?;
            
            if c.is_whitespace() || c == '=' || c == '>' || c == '/' {
                break;
            }
            
            name.push(c);
            self.advance();
        }
        
        // Skip whitespace
        self.skip_whitespace();
        
        // Check if there's a value
        let value = if self.position < self.input.len() && self.current_char()? == '=' {
            // Skip the '=' character
            self.advance();
            
            // Skip whitespace
            self.skip_whitespace();
            
            // Parse the attribute value
            let quote = if self.position < self.input.len() {
                let c = self.current_char()?;
                if c == '"' || c == '\'' {
                    self.advance();
                    Some(c)
                } else {
                    None
                }
            } else {
                None
            };
            
            let mut value = String::new();
            
            match quote {
                Some(q) => {
                    // Parse a quoted value
                    while self.position < self.input.len() {
                        let c = self.current_char()?;
                        
                        if c == q {
                            self.advance();
                            break;
                        }
                        
                        value.push(c);
                        self.advance();
                    }
                }
                None => {
                    // Parse an unquoted value
                    while self.position < self.input.len() {
                        let c = self.current_char()?;
                        
                        if c.is_whitespace() || c == '>' || c == '/' {
                            break;
                        }
                        
                        value.push(c);
                        self.advance();
                    }
                }
            }
            
            value
        } else {
            // Empty value
            String::new()
        };
        
        Ok((name, value))
    }
    
    /// Parse character data
    fn parse_character_data(&mut self) -> Result<Token, ParseError> {
        let mut data = String::new();
        
        while self.position < self.input.len() {
            let c = self.current_char()?;
            
            if c == '<' {
                break;
            }
            
            data.push(c);
            self.advance();
        }
        
        Ok(Token::Character { data })
    }
    
    /// Check for security issues in a token
    fn check_security(&self, token: &Token) -> Result<(), ParseError> {
        match token {
            Token::StartTag { name, attributes, .. } => {
                // Check for potentially dangerous tags
                if self.context.config.sanitization == crate::SanitizationLevel::Strict {
                    match name.to_lowercase().as_str() {
                        "script" | "iframe" | "object" | "embed" | "applet" => {
                            return Err(ParseError::SecurityError(format!("Dangerous tag: {}", name)));
                        }
                        _ => {}
                    }
                }
                
                // Check for potentially dangerous attributes
                for (attr_name, attr_value) in attributes {
                    // Check for event handlers
                    if attr_name.to_lowercase().starts_with("on") {
                        return Err(ParseError::SecurityError(format!("Event handler attribute: {}", attr_name)));
                    }
                    
                    // Check for javascript: URLs
                    if attr_name.to_lowercase() == "href" || attr_name.to_lowercase() == "src" {
                        if attr_value.to_lowercase().starts_with("javascript:") {
                            return Err(ParseError::SecurityError(format!("JavaScript URL in {}", attr_name)));
                        }
                    }
                }
            }
            _ => {}
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ParserConfig;
    
    struct TestUrlResolver;
    
    impl UrlResolver for TestUrlResolver {
        fn resolve(&self, url: &str) -> Result<url::Url, ParseError> {
            url::Url::parse(url).map_err(|e| ParseError::InvalidUrl(e))
        }
        
        fn should_block(&self, url: &url::Url) -> bool {
            url.host_str().map_or(false, |host| {
                host.contains("tracker") || host.contains("ads")
            })
        }
    }
    
    #[test]
    fn test_tokenize_simple_html() {
        let html = "<html><body>Hello, world!</body></html>";
        let config = ParserConfig::default();
        let resolver = TestUrlResolver;
        let context = ParseContext::new(config, resolver, None);
        let mut tokenizer = Tokenizer::new(context, html.to_string());
        
        let tokens = tokenizer.tokenize().unwrap();
        
        assert_eq!(tokens.len(), 6);
        assert_eq!(tokens[0], Token::StartTag { name: "html".to_string(), attributes: vec![], self_closing: false });
        assert_eq!(tokens[1], Token::StartTag { name: "body".to_string(), attributes: vec![], self_closing: false });
        assert_eq!(tokens[2], Token::Character { data: "Hello, world!".to_string() });
        assert_eq!(tokens[3], Token::EndTag { name: "body".to_string() });
        assert_eq!(tokens[4], Token::EndTag { name: "html".to_string() });
        assert_eq!(tokens[5], Token::EOF);
    }
    
    #[test]
    fn test_tokenize_with_attributes() {
        let html = r#"<div id="container" class="main">Content</div>"#;
        let config = ParserConfig::default();
        let resolver = TestUrlResolver;
        let context = ParseContext::new(config, resolver, None);
        let mut tokenizer = Tokenizer::new(context, html.to_string());
        
        let tokens = tokenizer.tokenize().unwrap();
        
        assert_eq!(tokens.len(), 4);
        assert_eq!(tokens[0], Token::StartTag {
            name: "div".to_string(),
            attributes: vec![
                ("id".to_string(), "container".to_string()),
                ("class".to_string(), "main".to_string()),
            ],
            self_closing: false
        });
        assert_eq!(tokens[1], Token::Character { data: "Content".to_string() });
        assert_eq!(tokens[2], Token::EndTag { name: "div".to_string() });
        assert_eq!(tokens[3], Token::EOF);
    }
    
    #[test]
    fn test_tokenize_with_comment() {
        let html = "<!-- This is a comment --><p>Text</p>";
        let config = ParserConfig::default();
        let resolver = TestUrlResolver;
        let context = ParseContext::new(config, resolver, None);
        let mut tokenizer = Tokenizer::new(context, html.to_string());
        
        let tokens = tokenizer.tokenize().unwrap();
        
        assert_eq!(tokens.len(), 5);
        assert_eq!(tokens[0], Token::Comment { data: " This is a comment ".to_string() });
        assert_eq!(tokens[1], Token::StartTag { name: "p".to_string(), attributes: vec![], self_closing: false });
        assert_eq!(tokens[2], Token::Character { data: "Text".to_string() });
        assert_eq!(tokens[3], Token::EndTag { name: "p".to_string() });
        assert_eq!(tokens[4], Token::EOF);
    }
    
    #[test]
    fn test_tokenize_doctype() {
        let html = "<!DOCTYPE html><html></html>";
        let config = ParserConfig::default();
        let resolver = TestUrlResolver;
        let context = ParseContext::new(config, resolver, None);
        let mut tokenizer = Tokenizer::new(context, html.to_string());
        
        let tokens = tokenizer.tokenize().unwrap();
        
        assert_eq!(tokens.len(), 4);
        assert_eq!(tokens[0], Token::Doctype {
            name: "html".to_string(),
            public_id: "".to_string(),
            system_id: "".to_string(),
        });
        assert_eq!(tokens[1], Token::StartTag { name: "html".to_string(), attributes: vec![], self_closing: false });
        assert_eq!(tokens[2], Token::EndTag { name: "html".to_string() });
        assert_eq!(tokens[3], Token::EOF);
    }
    
    #[test]
    fn test_security_checks() {
        let html = r#"<script>alert("XSS")</script>"#;
        let mut config = ParserConfig::default();
        config.sanitization = crate::SanitizationLevel::Strict;
        let resolver = TestUrlResolver;
        let context = ParseContext::new(config, resolver, None);
        let mut tokenizer = Tokenizer::new(context, html.to_string());
        
        let result = tokenizer.tokenize();
        assert!(result.is_err());
        
        if let Err(ParseError::SecurityError(_)) = result {
            // Expected error
        } else {
            panic!("Expected SecurityError, got {:?}", result);
        }
    }
} 