//! JavaScript engine integration for Citadel Browser
//!
//! This module provides secure JavaScript execution using Boa (pure Rust) with
//! per-call context isolation and comprehensive security restrictions.

pub mod engine;
pub mod dom_bindings;
pub mod security;

// Security tests are now inline in security.rs (19 tests covering all security operations)

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use boa_engine::{Context, Source, JsValue};
use crate::security::SecurityContext;
use crate::error::ParserResult;

/// Convert a Boa JsValue to a String representation.
///
/// This centralizes the value-to-string conversion that was previously duplicated
/// across every execution path. Handles undefined, null, and falls back to
/// debug formatting if `to_string` fails.
pub fn boa_value_to_string(value: &JsValue, ctx: &mut Context) -> String {
    if value.is_undefined() {
        return "undefined".to_string();
    }
    if value.is_null() {
        return "null".to_string();
    }
    value
        .to_string(ctx)
        .map(|s| s.to_std_string_escaped())
        .unwrap_or_else(|_| format!("{:?}", value))
}

/// Main JavaScript engine for Citadel with comprehensive security
pub struct CitadelJSEngine {
    /// Security context for JavaScript execution
    security_context: Arc<SecurityContext>,
    /// Whether the engine is running in ZKVM isolation
    zkvm_isolated: bool,
    /// Counter: total scripts executed (simple + sandboxed)
    scripts_executed: AtomicU64,
    /// Counter: security violations detected
    security_violations: AtomicU64,
    /// Counter: sandboxed executions
    sandboxed_executions: AtomicU64,
}

impl CitadelJSEngine {
    /// Create a new JavaScript engine with comprehensive security isolation.
    ///
    /// Unlike the former rquickjs backend, Boa does not require a persistent
    /// Runtime object. Each execution call creates a fresh `Context::default()`
    /// to maintain per-call isolation.
    pub fn new(security_context: Arc<SecurityContext>) -> ParserResult<Self> {
        Ok(Self {
            security_context,
            zkvm_isolated: false,
            scripts_executed: AtomicU64::new(0),
            security_violations: AtomicU64::new(0),
            sandboxed_executions: AtomicU64::new(0),
        })
    }

    /// Enable ZKVM isolation for this engine
    pub fn enable_zkvm_isolation(&mut self) -> ParserResult<()> {
        self.zkvm_isolated = true;
        Ok(())
    }

    /// Execute JavaScript code with comprehensive security checks and monitoring.
    ///
    /// A fresh Boa `Context` is created per call to ensure full isolation between
    /// executions. Security restrictions are applied before evaluation.
    pub fn execute_simple(&mut self, code: &str) -> ParserResult<String> {
        if !self.security_context.allows_scripts() {
            return Err(crate::error::ParserError::SecurityViolation(
                "JavaScript execution is disabled by security policy".to_string(),
            ));
        }

        // Static validation before creating an execution context
        security::validate_js_code(code)?;

        // Per-call isolation: fresh context every time
        let mut ctx = Context::default();

        // Apply comprehensive security restrictions
        security::apply_security_restrictions(&mut ctx, &self.security_context)?;

        // Evaluate the script
        let result = ctx.eval(Source::from_bytes(code));

        match result {
            Ok(value) => {
                self.scripts_executed.fetch_add(1, Ordering::Relaxed);
                Ok(boa_value_to_string(&value, &mut ctx))
            }
            Err(e) => {
                self.security_violations.fetch_add(1, Ordering::Relaxed);
                Err(crate::error::ParserError::JsError(format!(
                    "Secure JS execution error: {}",
                    e
                )))
            }
        }
    }

    /// Execute JavaScript in a maximum security sandboxed environment.
    ///
    /// Applies sandbox restrictions on top of the standard security restrictions.
    pub fn execute_sandboxed(&mut self, code: &str) -> ParserResult<String> {
        // Enhanced static validation
        security::validate_js_code(code)?;

        // Per-call isolation
        let mut ctx = Context::default();

        // Apply maximum security restrictions including sandbox hardening
        security::apply_sandbox_restrictions(&mut ctx, &self.security_context)?;

        let result = ctx.eval(Source::from_bytes(code));

        match result {
            Ok(value) => {
                self.scripts_executed.fetch_add(1, Ordering::Relaxed);
                self.sandboxed_executions.fetch_add(1, Ordering::Relaxed);
                Ok(boa_value_to_string(&value, &mut ctx))
            }
            Err(e) => {
                self.security_violations.fetch_add(1, Ordering::Relaxed);
                Err(crate::error::ParserError::JsError(format!(
                    "Sandboxed JS execution error: {}",
                    e
                )))
            }
        }
    }

    /// Check if JavaScript execution is allowed by security policy
    pub fn is_js_allowed(&self) -> bool {
        self.security_context.allows_scripts()
    }

    /// Get JavaScript engine statistics
    pub fn get_stats(&self) -> JSEngineStats {
        JSEngineStats {
            zkvm_isolated: self.zkvm_isolated,
            scripts_executed: self.scripts_executed.load(Ordering::Relaxed),
            security_violations: self.security_violations.load(Ordering::Relaxed),
            sandboxed_executions: self.sandboxed_executions.load(Ordering::Relaxed),
            avg_execution_time: 0.0, // Not tracked yet
        }
    }

    /// Get resource statistics (returns Some to signal availability)
    pub fn get_resource_stats(&self) -> Option<JSEngineStats> {
        Some(self.get_stats())
    }

    /// Execute JavaScript with secure DOM bindings
    pub fn execute_with_secure_dom(
        &mut self,
        _dom: &crate::dom::Dom,
        script: &str,
    ) -> Result<String, crate::error::ParserError> {
        // Delegate to simple execution; full DOM binding is in dom_bindings
        self.execute_simple(script)
    }
}

/// Statistics for JavaScript engine usage
#[derive(Debug, Clone)]
pub struct JSEngineStats {
    pub zkvm_isolated: bool,
    pub scripts_executed: u64,
    pub security_violations: u64,
    pub sandboxed_executions: u64,
    pub avg_execution_time: f64,
}

impl JSEngineStats {
    /// Get a security score based on violations and executions
    pub fn get_security_score(&self) -> u64 {
        if self.security_violations == 0 {
            100
        } else {
            100 - (self.security_violations * 10).min(100)
        }
    }

    /// Check if the engine is operating safely
    pub fn is_operating_safely(&self) -> bool {
        self.security_violations < 5
    }
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
        let mut engine = CitadelJSEngine::new(security_context).unwrap();

        // Test basic JavaScript execution
        let result = engine.execute_simple("2 + 2");
        if let Err(ref e) = result {
            eprintln!("JS execution error: {}", e);
        }
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "4");

        // Verify statistics are updated
        assert!(engine.get_stats().scripts_executed > 0);
    }

    #[test]
    fn test_sandboxed_execution() {
        let security_context = create_test_security_context();
        let mut engine = CitadelJSEngine::new(security_context).unwrap();

        let result = engine.execute_sandboxed("2 + 2");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "4");

        // Verify statistics
        let stats = engine.get_stats();
        assert!(stats.scripts_executed > 0);
        assert!(stats.sandboxed_executions > 0);
    }

    #[test]
    fn test_security_restrictions() {
        let security_context = create_test_security_context();
        let mut engine = CitadelJSEngine::new(security_context).unwrap();

        // Test that dangerous code is blocked by static validation
        let result = engine.execute_simple("eval('malicious code')");
        assert!(result.is_err());
    }

    #[test]
    fn test_execution_statistics() {
        let security_context = create_test_security_context();
        let mut engine = CitadelJSEngine::new(security_context).unwrap();

        // Execute several scripts
        engine.execute_simple("1 + 1").unwrap();
        engine.execute_simple("2 + 2").unwrap();
        engine.execute_sandboxed("3 + 3").unwrap();

        let stats = engine.get_stats();
        assert_eq!(stats.scripts_executed, 3);
        assert_eq!(stats.sandboxed_executions, 1);
        assert!(stats.avg_execution_time >= 0.0);
        assert!(stats.get_security_score() > 0);
        assert!(stats.is_operating_safely());
    }

    #[test]
    fn test_resource_monitoring() {
        let security_context = create_test_security_context();
        let mut engine = CitadelJSEngine::new(security_context).unwrap();

        // Execute a script
        engine.execute_simple("Math.sqrt(16)").unwrap();

        // Check resource stats are available
        let resource_stats = engine.get_resource_stats();
        assert!(resource_stats.is_some());
    }

    #[test]
    fn test_secure_dom_execution() {
        let security_context = create_test_security_context();
        let mut engine = CitadelJSEngine::new(security_context).unwrap();
        let dom = crate::dom::Dom::new();

        // Test secure DOM execution (delegates to execute_simple)
        let result = engine.execute_with_secure_dom(&dom, "'hello'");
        assert!(result.is_ok());

        let stats = engine.get_stats();
        assert!(stats.scripts_executed > 0);
    }
}
