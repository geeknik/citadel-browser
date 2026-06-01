//! JavaScript is disabled in Citadel (no-JS-by-default privacy posture).
//!
//! The Boa engine was removed (dependency-budget Tier-3): it pulled a large
//! dependency tree and a CVE (thin-vec), and scripts are already pruned at the
//! ZKVM rendering boundary rather than executed. This module keeps a minimal,
//! INERT surface so the public API and its callers still compile — every
//! execution entry point reports that JavaScript is off. A sandboxed engine may
//! be re-added later as an explicit opt-in.

use crate::error::{ParserError, ParserResult};
use crate::security::SecurityContext;
use std::sync::Arc;

/// The error every JS entry point returns now that no engine is built in.
fn js_disabled<T>() -> ParserResult<T> {
    Err(ParserError::SecurityViolation(
        "JavaScript execution is disabled (no JS engine is built in)".to_string(),
    ))
}

/// Inert JavaScript engine — never executes any script.
pub struct CitadelJSEngine {
    #[allow(dead_code)]
    security_context: Arc<SecurityContext>,
    zkvm_isolated: bool,
}

impl CitadelJSEngine {
    /// Construct the inert engine.
    pub fn new(security_context: Arc<SecurityContext>) -> ParserResult<Self> {
        Ok(Self {
            security_context,
            zkvm_isolated: false,
        })
    }

    /// Mark the engine as ZKVM-isolated (no behavioural effect — JS is off).
    pub fn enable_zkvm_isolation(&mut self) -> ParserResult<()> {
        self.zkvm_isolated = true;
        Ok(())
    }

    /// JS is disabled.
    pub fn execute_simple(&mut self, _code: &str) -> ParserResult<String> {
        js_disabled()
    }

    /// JS is disabled.
    pub fn execute_sandboxed(&mut self, _code: &str) -> ParserResult<String> {
        js_disabled()
    }

    /// JS is disabled.
    pub fn execute_browser_script(
        &self,
        _code: &str,
        _dom: &crate::dom::Dom,
    ) -> ParserResult<String> {
        js_disabled()
    }

    /// JS is disabled.
    pub fn execute_with_secure_dom(
        &mut self,
        _dom: &crate::dom::Dom,
        _script: &str,
    ) -> Result<String, ParserError> {
        js_disabled()
    }

    /// Always false — no engine is built in.
    pub fn is_js_allowed(&self) -> bool {
        false
    }

    /// Engine statistics (always zero — nothing executes).
    pub fn get_stats(&self) -> JSEngineStats {
        JSEngineStats {
            zkvm_isolated: self.zkvm_isolated,
            ..JSEngineStats::default()
        }
    }

    /// Resource statistics (returns `Some` to signal availability).
    pub fn get_resource_stats(&self) -> Option<JSEngineStats> {
        Some(self.get_stats())
    }
}

/// Statistics for JavaScript engine usage (all zero — JS is off).
#[derive(Debug, Clone, Default)]
pub struct JSEngineStats {
    pub zkvm_isolated: bool,
    pub scripts_executed: u64,
    pub security_violations: u64,
    pub sandboxed_executions: u64,
    pub avg_execution_time: f64,
}

impl JSEngineStats {
    /// No scripts run, so the security score is perfect.
    pub fn get_security_score(&self) -> u64 {
        100
    }

    /// Always operating safely — nothing executes.
    pub fn is_operating_safely(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Arc<SecurityContext> {
        Arc::new(SecurityContext::new(10))
    }

    #[test]
    fn js_is_disabled() {
        let mut engine = CitadelJSEngine::new(ctx()).expect("constructs");
        assert!(!engine.is_js_allowed());
        assert!(engine.execute_simple("2 + 2").is_err());
        assert!(engine.execute_sandboxed("2 + 2").is_err());
        let dom = crate::dom::Dom::new();
        assert!(engine.execute_with_secure_dom(&dom, "1").is_err());
        assert!(engine.get_stats().is_operating_safely());
    }
}
