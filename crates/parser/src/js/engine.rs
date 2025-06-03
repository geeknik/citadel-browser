//! JavaScript execution engine
//! 
//! This module provides the core JavaScript execution functionality
//! integrated with Citadel's security and DOM systems.

use rquickjs::{Context, Result as QjsResult};
use crate::dom::Dom;
use crate::error::ParserResult;
use super::{CitadelJSEngine, security};

impl CitadelJSEngine {
    /// Execute JavaScript found in script tags during HTML parsing
    pub fn execute_script_tags(&mut self, dom: &Dom) -> ParserResult<Vec<String>> {
        let mut results = Vec::new();
        
        // Extract script content from DOM
        let script_contents = self.extract_script_contents(dom)?;
        
        for script in script_contents {
            // Validate the script before execution
            security::validate_js_code(&script)?;
            
            // Execute with security context
            match self.execute_simple(&script) {
                Ok(result) => results.push(result),
                Err(e) => {
                    eprintln!("[JS Engine] Script execution failed: {}", e);
                    // Continue with other scripts
                }
            }
        }
        
        Ok(results)
    }
    
    /// Extract JavaScript content from script tags in the DOM
    fn extract_script_contents(&self, _dom: &Dom) -> ParserResult<Vec<String>> {
        // TODO: Actually extract script tags from DOM
        // For now, return empty vector
        Ok(vec![])
    }
    
    /// Execute JavaScript with full browser-like bindings
    pub fn execute_browser_script(&self, statement: &str, dom: &Dom) -> ParserResult<String> {
        if !self.security_context.allows_scripts() {
            return Err(crate::error::ParserError::SecurityViolation(
                "JavaScript execution is disabled".to_string()
            ));
        }
        
        // Validate the script
        security::validate_js_code(statement)?;
        
        let context = Context::full(&self.runtime).map_err(|e| {
            crate::error::ParserError::JsError(format!("Failed to create context: {}", e))
        })?;
        
        context.with(|ctx| {
            // Set up basic DOM bindings (simplified)
            println!("[JS] Setting up DOM for script execution with title: {}", dom.get_title());
            
            // Execute the script
            let result: QjsResult<rquickjs::Value> = ctx.eval(statement);
            
            match result {
                Ok(value) => {
                    // Convert the result to a string representation
                    let string_result = if value.is_string() {
                        value.as_string().unwrap().to_string().unwrap()
                    } else if value.is_number() {
                        value.as_number().unwrap().to_string()
                    } else if value.is_bool() {
                        value.as_bool().unwrap().to_string()
                    } else if value.is_null() {
                        "null".to_string()
                    } else if value.is_undefined() {
                        "undefined".to_string()
                    } else {
                        format!("{:?}", value)
                    };
                    Ok(string_result)
                },
                Err(e) => Err(crate::error::ParserError::JsError(format!("Execution error: {}", e)))
            }
        })
    }
    
    /// Execute with a timeout (placeholder for future implementation)
    pub fn execute_with_timeout(&self, code: &str, _timeout_ms: u64) -> ParserResult<String> {
        // For now, delegate to simple execution
        // TODO: Implement actual timeout mechanism
        self.execute_simple(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityContext;
    use std::sync::Arc;
    
    fn create_test_engine() -> CitadelJSEngine {
        let mut security_context = SecurityContext::new(10);
        security_context.enable_scripts();
        CitadelJSEngine::new(Arc::new(security_context)).unwrap()
    }
    
    #[test]
    fn test_script_tag_extraction() {
        let engine = create_test_engine();
        let dom = Dom::new();
        
        let result = engine.extract_script_contents(&dom);
        assert!(result.is_ok());
        // Should be empty for now since we haven't implemented actual extraction
        assert_eq!(result.unwrap().len(), 0);
    }
    
    #[test]
    fn test_browser_script_execution() {
        let engine = create_test_engine();
        let dom = Dom::new();
        
        let result = engine.execute_browser_script("1 + 1", &dom);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "2");
    }
    
    #[test]
    fn test_timeout_execution() {
        let engine = create_test_engine();
        
        let result = engine.execute_with_timeout("5 * 5", 1000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "25");
    }
} 