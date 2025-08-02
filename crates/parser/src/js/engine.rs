//! JavaScript execution engine
//! 
//! This module provides the core JavaScript execution functionality
//! integrated with Citadel's security and DOM systems.

use rquickjs::{Context, Result as QjsResult};
use crate::dom::Dom;
use crate::error::ParserResult;
use super::{CitadelJSEngine, security, dom_bindings};

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
            // Use the new enhanced DOM context execution
            match super::dom_bindings::execute_with_dom_context(ctx.clone(), dom, statement) {
                Ok(result) => return Ok(result),
                Err(e) => {
                    eprintln!("[JS] Enhanced execution failed, falling back to basic execution: {}", e);
                }
            }
            
            println!("[JS] Executing script in basic context with title: {}", dom.get_title());
            
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
    
    /// Execute JavaScript with interactive DOM manipulation capabilities
    pub fn execute_interactive_script(&self, statement: &str, dom: &Dom) -> ParserResult<(String, Vec<String>)> {
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
        
        let console_logs = Vec::new();
        
        context.with(|ctx| {
            // Use the enhanced DOM context execution for interactive scripts
            match super::dom_bindings::execute_with_dom_context(ctx.clone(), dom, statement) {
                Ok(result) => return Ok((result, console_logs)),
                Err(e) => {
                    eprintln!("[JS] Enhanced interactive execution failed: {}", e);
                }
            }
            
            println!("[JS] Executing interactive script with basic context");
            
            // Execute the script
            let result: QjsResult<rquickjs::Value> = ctx.eval(statement);
            
            match result {
                Ok(value) => {
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
                    Ok((string_result, console_logs))
                },
                Err(e) => Err(crate::error::ParserError::JsError(format!("Interactive execution error: {}", e)))
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
    fn test_dom_api_integration() {
        let engine = create_test_engine();
        let dom = Dom::new();
        
        // Test basic DOM API calls
        let result = engine.execute_browser_script("document.title", &dom);
        assert!(result.is_ok());
        
        // Test element creation
        let result = engine.execute_browser_script("document.createElement('div').tagName", &dom);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "DIV");
    }
    
    #[test]
    fn test_console_integration() {
        let engine = create_test_engine();
        let dom = Dom::new();
        
        // Test console methods
        let result = engine.execute_browser_script("console.log('test'); 'success'", &dom);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
    }
    
    #[test]
    fn test_interactive_script_execution() {
        let engine = create_test_engine();
        let dom = Dom::new();
        
        // Test interactive script execution with DOM manipulation
        let script = r#"
            var element = document.createElement('div');
            element.setAttribute('id', 'test-element');
            element.innerHTML = 'Hello World';
            element.id
        "#;
        
        let result = engine.execute_interactive_script(script, &dom);
        assert!(result.is_ok());
        let (output, _logs) = result.unwrap();
        assert_eq!(output, "test-element");
    }
    
    #[test]
    fn test_event_system_integration() {
        let engine = create_test_engine();
        let dom = Dom::new();
        
        let script = r#"
            var button = document.createElement('button');
            button.addEventListener('click', function() {
                console.log('Button clicked!');
            });
            button.tagName
        "#;
        
        let result = engine.execute_browser_script(script, &dom);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "BUTTON");
    }
    
    #[test]
    fn test_timeout_execution() {
        let engine = create_test_engine();
        
        let result = engine.execute_with_timeout("5 * 5", 1000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "25");
    }
} 