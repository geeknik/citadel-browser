//! JavaScript execution engine
//!
//! This module provides the core JavaScript execution functionality
//! integrated with Citadel's security and DOM systems.
//!
//! All methods create a fresh `boa_engine::Context` per call for isolation.

use boa_engine::{Context, Source};
use crate::dom::Dom;
use crate::error::ParserResult;
use super::{CitadelJSEngine, boa_value_to_string, security};

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

    /// Extract JavaScript content from script tags in the DOM.
    ///
    /// Walks the DOM tree looking for `<script>` elements without a `src`
    /// attribute (inline scripts only). External scripts are skipped since
    /// they would need to be fetched via the networking layer.
    fn extract_script_contents(&self, dom: &Dom) -> ParserResult<Vec<String>> {
        let scripts = dom.get_elements_by_tag_name("script");
        let mut results = Vec::new();

        for script_handle in &scripts {
            if let Ok(node) = script_handle.read() {
                // Skip external scripts that reference a src attribute
                if let crate::dom::node::NodeData::Element(ref el) = node.data {
                    let has_src = el
                        .attributes
                        .iter()
                        .any(|a| a.name.local.as_ref() == "src");
                    if has_src {
                        continue;
                    }
                }

                let content = node.text_content();
                if !content.trim().is_empty() {
                    results.push(content);
                }
            }
        }

        Ok(results)
    }

    /// Execute JavaScript with full browser-like bindings.
    ///
    /// Creates a fresh Boa context, sets up DOM bindings via `dom_bindings`,
    /// and evaluates the statement. Falls back to plain evaluation when the
    /// enhanced DOM context setup fails.
    pub fn execute_browser_script(&self, statement: &str, dom: &Dom) -> ParserResult<String> {
        if !self.security_context.allows_scripts() {
            return Err(crate::error::ParserError::SecurityViolation(
                "JavaScript execution is disabled".to_string(),
            ));
        }

        // Static validation
        security::validate_js_code(statement)?;

        // Per-call isolation
        let mut ctx = Context::default();

        // Attempt enhanced DOM-context execution first
        match super::dom_bindings::execute_with_dom_context(&mut ctx, dom, statement) {
            Ok(result) => return Ok(result),
            Err(e) => {
                eprintln!(
                    "[JS] Enhanced execution failed, falling back to basic execution: {}",
                    e
                );
            }
        }

        // Fallback: plain evaluation
        let result = ctx.eval(Source::from_bytes(statement));

        match result {
            Ok(value) => Ok(boa_value_to_string(&value, &mut ctx)),
            Err(e) => Err(crate::error::ParserError::JsError(format!(
                "Execution error: {}",
                e
            ))),
        }
    }

    /// Execute JavaScript with interactive DOM manipulation capabilities.
    ///
    /// Returns the script result plus a (currently empty) list of console logs.
    pub fn execute_interactive_script(
        &self,
        statement: &str,
        dom: &Dom,
    ) -> ParserResult<(String, Vec<String>)> {
        if !self.security_context.allows_scripts() {
            return Err(crate::error::ParserError::SecurityViolation(
                "JavaScript execution is disabled".to_string(),
            ));
        }

        security::validate_js_code(statement)?;

        let mut ctx = Context::default();
        let console_logs: Vec<String> = Vec::new();

        // Attempt enhanced DOM-context execution
        match super::dom_bindings::execute_with_dom_context(&mut ctx, dom, statement) {
            Ok(result) => return Ok((result, console_logs)),
            Err(e) => {
                eprintln!("[JS] Enhanced interactive execution failed: {}", e);
            }
        }

        // Fallback
        let result = ctx.eval(Source::from_bytes(statement));

        match result {
            Ok(value) => {
                let string_result = boa_value_to_string(&value, &mut ctx);
                Ok((string_result, console_logs))
            }
            Err(e) => Err(crate::error::ParserError::JsError(format!(
                "Interactive execution error: {}",
                e
            ))),
        }
    }

    /// Execute with a timeout (placeholder for future implementation)
    pub fn execute_with_timeout(&mut self, code: &str, _timeout_ms: u64) -> ParserResult<String> {
        // Delegate to simple execution for now
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
        CitadelJSEngine::new(Arc::new(security_context))
            .expect("Failed to create test JS engine - this is a test setup issue")
    }

    #[test]
    fn test_script_tag_extraction() {
        let engine = create_test_engine();
        let dom = Dom::new();

        let result = engine.extract_script_contents(&dom);
        assert!(result.is_ok());
        // Empty DOM has no script tags
        assert_eq!(result.expect("Script extraction should succeed").len(), 0);
    }

    #[test]
    fn test_browser_script_execution() {
        let engine = create_test_engine();
        let dom = Dom::new();

        let result = engine.execute_browser_script("1 + 1", &dom);
        assert!(result.is_ok());
        assert_eq!(
            result.expect("Browser script execution should succeed"),
            "2"
        );
    }

    #[test]
    fn test_dom_api_integration() {
        let engine = create_test_engine();
        let dom = Dom::new();

        // Test basic DOM API calls (document.title from bindings)
        let result = engine.execute_browser_script("document.title", &dom);
        assert!(result.is_ok());

        // Test element creation via DOM bindings
        let result =
            engine.execute_browser_script("document.createElement('div').tagName", &dom);
        assert!(result.is_ok());
        assert_eq!(
            result.expect("DOM API integration should work"),
            "DIV"
        );
    }

    #[test]
    fn test_console_integration() {
        let engine = create_test_engine();
        let dom = Dom::new();

        // console.log is a no-op; the expression result is 'success'
        let result = engine.execute_browser_script("console.log('test'); 'success'", &dom);
        assert!(result.is_ok());
        assert_eq!(
            result.expect("Console integration should work"),
            "success"
        );
    }

    #[test]
    fn test_interactive_script_execution() {
        let engine = create_test_engine();
        let dom = Dom::new();

        // Test createElement returns an object with the correct tagName
        let script = r#"
            var element = document.createElement('div');
            element.tagName
        "#;

        let result = engine.execute_interactive_script(script, &dom);
        assert!(result.is_ok());
        let (output, _logs) = result.expect("Interactive script execution should succeed");
        assert_eq!(output, "DIV");
    }

    #[test]
    fn test_event_system_integration() {
        let engine = create_test_engine();
        let dom = Dom::new();

        // Test createElement + addEventListener (no-op) + tagName access
        let script = r#"
            var button = document.createElement('button');
            button.addEventListener('click', 42);
            button.tagName
        "#;

        let result = engine.execute_browser_script(script, &dom);
        assert!(result.is_ok());
        assert_eq!(
            result.expect("Event system integration should work"),
            "BUTTON"
        );
    }

    #[test]
    fn test_timeout_execution() {
        let mut engine = create_test_engine();

        let result = engine.execute_with_timeout("5 * 5", 1000);
        assert!(result.is_ok());
        assert_eq!(result.expect("Timeout execution should work"), "25");
    }
}
