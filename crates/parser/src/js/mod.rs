//! JavaScript engine integration for Citadel Browser
//! 
//! This module provides secure JavaScript execution using QuickJS with ZKVM isolation.

pub mod engine;
pub mod dom_bindings;
pub mod security;

use std::sync::Arc;
use rquickjs::{Context, Runtime};
use crate::dom::Dom;
use crate::security::SecurityContext;
use crate::error::ParserResult;

/// Main JavaScript engine for Citadel
pub struct CitadelJSEngine {
    /// QuickJS runtime
    runtime: Runtime,
    /// Security context for JavaScript execution
    security_context: Arc<SecurityContext>,
    /// Whether the engine is running in ZKVM isolation
    zkvm_isolated: bool,
}

impl CitadelJSEngine {
    /// Create a new JavaScript engine with security isolation
    pub fn new(security_context: Arc<SecurityContext>) -> ParserResult<Self> {
        let runtime = Runtime::new().map_err(|e| {
            crate::error::ParserError::JsError(format!("Failed to create QuickJS runtime: {}", e))
        })?;
        
        Ok(Self {
            runtime,
            security_context,
            zkvm_isolated: false,
        })
    }
    
    /// Enable ZKVM isolation for this engine
    pub fn enable_zkvm_isolation(&mut self) -> ParserResult<()> {
        // TODO: Integration with citadel-zkvm crate
        // For now, we'll just mark it as isolated
        self.zkvm_isolated = true;
        Ok(())
    }
    
    /// Execute JavaScript code with basic security checks
    pub fn execute_simple(&self, code: &str) -> ParserResult<String> {
        if !self.security_context.allows_scripts() {
            return Err(crate::error::ParserError::SecurityViolation(
                "JavaScript execution is disabled by security policy".to_string()
            ));
        }
        
        // Basic validation
        security::validate_js_code(code)?;
        
        let context = Context::full(&self.runtime).map_err(|e| {
            crate::error::ParserError::JsError(format!("Failed to create JS context: {}", e))
        })?;
        
        context.with(|ctx| {
            // Simple execution without complex bindings for now
            let result: rquickjs::Result<rquickjs::Value> = ctx.eval(code);
            
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
                Err(e) => Err(crate::error::ParserError::JsError(format!("JS execution error: {}", e)))
            }
        })
    }
    
    /// Execute JavaScript in a sandboxed environment
    pub fn execute_sandboxed(&self, code: &str) -> ParserResult<String> {
        if !self.zkvm_isolated {
            return Err(crate::error::ParserError::SecurityViolation(
                "Attempting to execute JavaScript without ZKVM isolation".to_string()
            ));
        }
        
        // For now, delegate to simple execution
        self.execute_simple(code)
    }
    
    /// Check if JavaScript execution is allowed by security policy
    pub fn is_js_allowed(&self) -> bool {
        self.security_context.allows_scripts()
    }
    
    /// Get JavaScript engine statistics
    pub fn get_stats(&self) -> JSEngineStats {
        JSEngineStats {
            zkvm_isolated: self.zkvm_isolated,
            scripts_executed: 0, // TODO: Add tracking
            security_violations: 0, // TODO: Add tracking
        }
    }
}

/// Statistics for JavaScript engine usage
#[derive(Debug, Clone)]
pub struct JSEngineStats {
    pub zkvm_isolated: bool,
    pub scripts_executed: u64,
    pub security_violations: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_security_context() -> Arc<SecurityContext> {
        let mut context = SecurityContext::new(10);
        context.enable_scripts(); // Enable for testing
        Arc::new(context)
    }
    
    #[test]
    fn test_js_engine_creation() {
        let security_context = create_test_security_context();
        let engine = CitadelJSEngine::new(security_context);
        assert!(engine.is_ok());
    }
    
    #[test]
    fn test_js_execution_basic() {
        let security_context = create_test_security_context();
        let engine = CitadelJSEngine::new(security_context).unwrap();
        
        // Test basic JavaScript execution
        let result = engine.execute_simple("2 + 2");
        if let Err(ref e) = result {
            eprintln!("JS execution error: {}", e);
        }
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "4");
    }
    
    #[test]
    fn test_zkvm_isolation_requirement() {
        let security_context = create_test_security_context();
        let engine = CitadelJSEngine::new(security_context).unwrap();
        
        // Should require ZKVM isolation for sandboxed execution
        let result = engine.execute_sandboxed("2 + 2");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ZKVM isolation"));
    }
    
    #[test]
    fn test_zkvm_isolation_enabled() {
        let security_context = create_test_security_context();
        let mut engine = CitadelJSEngine::new(security_context).unwrap();
        
        // Enable ZKVM isolation
        engine.enable_zkvm_isolation().unwrap();
        
        // Now sandboxed execution should work
        let result = engine.execute_sandboxed("3 + 3");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "6");
    }
} 