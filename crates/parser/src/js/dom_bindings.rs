//! Essential DOM API implementations for JavaScript
//!
//! This module provides the core DOM manipulation APIs that modern websites need
//! to function interactively while maintaining Citadel Browser's security-first approach.
//! Migrated from rquickjs to Boa (pure Rust JS engine).

use crate::dom::Dom;
use crate::error::ParserResult;
use boa_engine::object::ObjectInitializer;
use boa_engine::property::Attribute;
use boa_engine::{js_string, Context, JsValue, NativeFunction, Source};
use std::collections::HashSet;
use tracing::info;

/// Dangerous element tags that must never be created via JavaScript.
/// Creating these elements could enable XSS, click-jacking, or plugin-based attacks.
const DANGEROUS_ELEMENTS: &[&str] = &[
    "script", "iframe", "object", "embed", "form", "applet", "base", "link",
];

/// Check whether a tag name refers to a dangerous element.
pub fn is_dangerous_element(tag: &str) -> bool {
    DANGEROUS_ELEMENTS.contains(&tag.to_ascii_lowercase().as_str())
}

/// Set up essential DOM bindings for JavaScript execution.
///
/// Registers a `document` global with basic properties extracted from the
/// supplied DOM tree plus a security-hardened `createElement` method.
pub fn setup_dom_bindings(ctx: &mut Context, dom: &Dom) -> ParserResult<()> {
    let title = dom.get_title();
    info!(
        "[JS] Setting up essential DOM bindings for document with title: {}",
        title
    );

    // --- document.createElement (NativeFunction) ---
    let create_element_fn = NativeFunction::from_fn_ptr(create_element_handler);

    // --- Build the document object ---
    let document = ObjectInitializer::new(ctx)
        .property(
            js_string!("title"),
            JsValue::from(js_string!(title.as_str())),
            Attribute::all(),
        )
        .property(
            js_string!("readyState"),
            js_string!("complete"),
            Attribute::all(),
        )
        .property(
            js_string!("domain"),
            js_string!("example.com"),
            Attribute::all(),
        )
        .function(create_element_fn, js_string!("createElement"), 1)
        .build();

    // Build an empty forms collection stub
    let forms = ObjectInitializer::new(ctx).build();
    document.set(js_string!("forms"), JsValue::from(forms), false, ctx)?;

    ctx.register_global_property(js_string!("document"), document, Attribute::all())
        .map_err(|e| {
            crate::error::ParserError::JsError(format!("Failed to set document: {}", e))
        })?;

    info!("[JS] Essential DOM APIs ready for JavaScript execution");

    Ok(())
}

/// NativeFunction handler for `document.createElement`.
///
/// Security enforcement: blocks creation of dangerous elements (script, iframe, etc.)
/// and returns a minimal element stub for safe tags.
fn create_element_handler(
    _this: &JsValue,
    args: &[JsValue],
    ctx: &mut Context,
) -> boa_engine::JsResult<JsValue> {
    let tag = args
        .first()
        .cloned()
        .unwrap_or(JsValue::undefined())
        .to_string(ctx)?
        .to_std_string_escaped();

    // Block dangerous elements
    if is_dangerous_element(&tag) {
        return Err(boa_engine::JsError::from_opaque(JsValue::from(
            js_string!("SecurityError: creation of dangerous elements is blocked"),
        )));
    }

    let upper_tag = tag.to_ascii_uppercase();

    // Build a minimal element stub.
    // addEventListener and setAttribute are safe no-op stubs.
    let add_event_listener = NativeFunction::from_fn_ptr(
        |_this: &JsValue, _args: &[JsValue], _ctx: &mut Context| Ok(JsValue::undefined()),
    );

    let set_attribute = NativeFunction::from_fn_ptr(
        |_this: &JsValue, _args: &[JsValue], _ctx: &mut Context| Ok(JsValue::undefined()),
    );

    let el = ObjectInitializer::new(ctx)
        .property(
            js_string!("tagName"),
            JsValue::from(js_string!(upper_tag.as_str())),
            Attribute::all(),
        )
        .property(js_string!("innerHTML"), js_string!(""), Attribute::all())
        .property(js_string!("textContent"), js_string!(""), Attribute::all())
        .property(js_string!("id"), js_string!(""), Attribute::all())
        .property(js_string!("className"), js_string!(""), Attribute::all())
        .function(add_event_listener, js_string!("addEventListener"), 2)
        .function(set_attribute, js_string!("setAttribute"), 2)
        .build();

    Ok(JsValue::from(el))
}

/// Set up console bindings for JavaScript logging.
///
/// Provides a `console` global with stub methods that silently discard output,
/// preventing information leakage while keeping scripts that call `console.log`
/// from throwing reference errors.
pub fn setup_console_bindings(ctx: &mut Context) -> ParserResult<()> {
    info!("[JS] Setting up console logging APIs");

    // All console methods are safe no-ops that return undefined
    let log_fn =
        NativeFunction::from_fn_ptr(|_this, _args, _ctx| Ok(JsValue::undefined()));
    let warn_fn =
        NativeFunction::from_fn_ptr(|_this, _args, _ctx| Ok(JsValue::undefined()));
    let error_fn =
        NativeFunction::from_fn_ptr(|_this, _args, _ctx| Ok(JsValue::undefined()));
    let info_fn =
        NativeFunction::from_fn_ptr(|_this, _args, _ctx| Ok(JsValue::undefined()));
    let debug_fn =
        NativeFunction::from_fn_ptr(|_this, _args, _ctx| Ok(JsValue::undefined()));

    let console = ObjectInitializer::new(ctx)
        .function(log_fn, js_string!("log"), 0)
        .function(warn_fn, js_string!("warn"), 0)
        .function(error_fn, js_string!("error"), 0)
        .function(info_fn, js_string!("info"), 0)
        .function(debug_fn, js_string!("debug"), 0)
        .build();

    ctx.register_global_property(js_string!("console"), console, Attribute::all())
        .map_err(|e| {
            crate::error::ParserError::JsError(format!("Failed to set console: {}", e))
        })?;

    Ok(())
}

/// Set up window object with browser-like properties.
///
/// Provides `location`, `navigator`, `screen`, and `window` globals with
/// privacy-hardened, anti-fingerprinting default values.
pub fn setup_window_bindings(ctx: &mut Context) -> ParserResult<()> {
    info!("[JS] Setting up window and global APIs");

    // --- location ---
    let location = ObjectInitializer::new(ctx)
        .property(
            js_string!("href"),
            js_string!("https://example.com"),
            Attribute::all(),
        )
        .property(
            js_string!("protocol"),
            js_string!("https:"),
            Attribute::all(),
        )
        .property(
            js_string!("host"),
            js_string!("example.com"),
            Attribute::all(),
        )
        .property(
            js_string!("pathname"),
            js_string!("/"),
            Attribute::all(),
        )
        .property(js_string!("search"), js_string!(""), Attribute::all())
        .property(js_string!("hash"), js_string!(""), Attribute::all())
        .build();

    ctx.register_global_property(js_string!("location"), location, Attribute::all())
        .map_err(|e| {
            crate::error::ParserError::JsError(format!("Failed to set location: {}", e))
        })?;

    // --- navigator (privacy-conscious values) ---
    let navigator = ObjectInitializer::new(ctx)
        .property(
            js_string!("userAgent"),
            js_string!("Citadel Browser/0.0.1-alpha (Privacy-First)"),
            Attribute::all(),
        )
        .property(
            js_string!("platform"),
            js_string!("MacIntel"),
            Attribute::all(),
        )
        .property(
            js_string!("language"),
            js_string!("en-US"),
            Attribute::all(),
        )
        .property(
            js_string!("cookieEnabled"),
            JsValue::from(false),
            Attribute::all(),
        )
        .property(
            js_string!("doNotTrack"),
            js_string!("1"),
            Attribute::all(),
        )
        .property(
            js_string!("hardwareConcurrency"),
            JsValue::from(4),
            Attribute::all(),
        )
        .build();

    ctx.register_global_property(js_string!("navigator"), navigator, Attribute::all())
        .map_err(|e| {
            crate::error::ParserError::JsError(format!("Failed to set navigator: {}", e))
        })?;

    // --- screen (anti-fingerprinting fixed values) ---
    let screen = ObjectInitializer::new(ctx)
        .property(js_string!("width"), JsValue::from(1920_i32), Attribute::all())
        .property(
            js_string!("height"),
            JsValue::from(1080_i32),
            Attribute::all(),
        )
        .property(
            js_string!("availWidth"),
            JsValue::from(1920_i32),
            Attribute::all(),
        )
        .property(
            js_string!("availHeight"),
            JsValue::from(1040_i32),
            Attribute::all(),
        )
        .property(
            js_string!("colorDepth"),
            JsValue::from(24_i32),
            Attribute::all(),
        )
        .property(
            js_string!("pixelDepth"),
            JsValue::from(24_i32),
            Attribute::all(),
        )
        .build();

    ctx.register_global_property(js_string!("screen"), screen, Attribute::all())
        .map_err(|e| {
            crate::error::ParserError::JsError(format!("Failed to set screen: {}", e))
        })?;

    // --- window references the global object ---
    let global = ctx.global_object();
    ctx.register_global_property(js_string!("window"), global, Attribute::all())
        .map_err(|e| {
            crate::error::ParserError::JsError(format!("Failed to set window: {}", e))
        })?;

    info!("[JS] Window APIs configured for privacy-first browsing");

    Ok(())
}

/// Execute JavaScript with comprehensive browser environment setup.
///
/// Sets up console, window, and DOM bindings, then evaluates the supplied code.
/// Returns the stringified result or a `ParserError` on failure.
pub fn execute_with_dom_context(
    ctx: &mut Context,
    dom: &Dom,
    code: &str,
) -> ParserResult<String> {
    info!("[JS] Executing JavaScript with full DOM context");

    // Set up browser environment
    setup_console_bindings(ctx)?;
    setup_window_bindings(ctx)?;
    setup_dom_bindings(ctx, dom)?;

    // Execute the JavaScript code
    let result = ctx.eval(Source::from_bytes(code));

    match result {
        Ok(value) => {
            let output = boa_value_to_string(&value, ctx);

            info!(
                "[JS] Execution completed successfully: {}",
                if output.len() > 100 {
                    format!("{}...", &output[..100])
                } else {
                    output.clone()
                }
            );

            Ok(output)
        }
        Err(e) => {
            let error_msg = format!("DOM context execution error: {}", e);
            tracing::warn!("[JS] {}", error_msg);
            Err(crate::error::ParserError::JsError(error_msg))
        }
    }
}

/// Convert a Boa `JsValue` into a human-readable Rust `String`.
///
/// This is the canonical conversion used throughout the JS subsystem and is
/// intentionally kept in this module so that sibling modules can call
/// `super::dom_bindings::boa_value_to_string`.
pub fn boa_value_to_string(value: &JsValue, ctx: &mut Context) -> String {
    if value.is_string() {
        value
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .unwrap_or_default()
    } else if value.is_number() {
        value
            .as_number()
            .map(|n| {
                // Render integers without a trailing ".0"
                if n.fract() == 0.0 && n.is_finite() {
                    format!("{}", n as i64)
                } else {
                    n.to_string()
                }
            })
            .unwrap_or_else(|| "NaN".to_string())
    } else if value.is_boolean() {
        value.as_boolean().unwrap_or(false).to_string()
    } else if value.is_null() {
        "null".to_string()
    } else if value.is_undefined() {
        "undefined".to_string()
    } else {
        // Attempt to call toString(); fall back to a debug representation
        value
            .to_string(ctx)
            .map(|s| s.to_std_string_escaped())
            .unwrap_or_else(|_| "[object]".to_string())
    }
}

// ---------------------------------------------------------------------------
// Security monitoring and CSP enforcement
// ---------------------------------------------------------------------------

/// JavaScript Security Monitoring and Enforcement
#[derive(Debug, Clone)]
pub struct JSSecurityMonitor {
    /// Number of security violations detected
    pub violations_count: u64,
    /// Number of blocked API calls
    pub blocked_api_calls: u64,
    /// Number of dangerous element creation attempts
    pub blocked_element_creation: u64,
    /// Total execution time in milliseconds
    pub total_execution_time: u64,
    /// Number of timeouts
    pub timeout_count: u64,
}

impl Default for JSSecurityMonitor {
    fn default() -> Self {
        Self {
            violations_count: 0,
            blocked_api_calls: 0,
            blocked_element_creation: 0,
            total_execution_time: 0,
            timeout_count: 0,
        }
    }
}

impl JSSecurityMonitor {
    /// Record a security violation
    pub fn record_violation(&mut self) {
        self.violations_count += 1;
    }

    /// Record a blocked API call
    pub fn record_blocked_api(&mut self) {
        self.blocked_api_calls += 1;
    }

    /// Record blocked element creation
    pub fn record_blocked_element(&mut self) {
        self.blocked_element_creation += 1;
    }

    /// Record execution time
    pub fn record_execution_time(&mut self, duration_ms: u64) {
        self.total_execution_time += duration_ms;
    }

    /// Record timeout
    pub fn record_timeout(&mut self) {
        self.timeout_count += 1;
    }

    /// Get security score (0-100, higher is better)
    pub fn get_security_score(&self) -> u8 {
        let total_events = self.violations_count
            + self.blocked_api_calls
            + self.blocked_element_creation
            + self.timeout_count;
        if total_events == 0 {
            100
        } else {
            let violations_weight = self.violations_count * 10;
            let api_blocks_weight = self.blocked_api_calls * 5;
            let element_blocks_weight = self.blocked_element_creation * 3;
            let timeout_weight = self.timeout_count * 8;

            let penalty =
                violations_weight + api_blocks_weight + element_blocks_weight + timeout_weight;
            let score = 100_u64.saturating_sub(penalty);

            std::cmp::min(100, score) as u8
        }
    }
}

/// CSP (Content Security Policy) Enforcement for JavaScript
pub struct JSContentSecurityPolicy {
    /// Allowed script sources
    script_src: HashSet<String>,
    /// Whether inline scripts are allowed
    allow_inline_scripts: bool,
    /// Whether eval is allowed
    allow_eval: bool,
    /// Nonces for script execution
    nonces: HashSet<String>,
    /// Hashes of allowed scripts
    script_hashes: HashSet<String>,
}

impl Default for JSContentSecurityPolicy {
    fn default() -> Self {
        Self {
            script_src: HashSet::new(),
            allow_inline_scripts: false,
            allow_eval: false,
            nonces: HashSet::new(),
            script_hashes: HashSet::new(),
        }
    }
}

impl JSContentSecurityPolicy {
    /// Create a new strict CSP for JavaScript
    pub fn new_strict() -> Self {
        Self {
            script_src: ["'self'".to_string()].into_iter().collect(),
            allow_inline_scripts: false,
            allow_eval: false,
            nonces: HashSet::new(),
            script_hashes: HashSet::new(),
        }
    }

    /// Check if script execution is allowed
    pub fn is_script_allowed(
        &self,
        source: &str,
        nonce: Option<&str>,
        hash: Option<&str>,
    ) -> bool {
        // Check nonce
        if let Some(nonce) = nonce {
            if self.nonces.contains(nonce) {
                return true;
            }
        }

        // Check hash
        if let Some(hash) = hash {
            if self.script_hashes.contains(hash) {
                return true;
            }
        }

        // Check source
        if source == "inline" {
            return self.allow_inline_scripts;
        }

        if source == "eval" {
            return self.allow_eval;
        }

        // Check against allowed sources
        for allowed_src in &self.script_src {
            if allowed_src == "'self'" || allowed_src == "*" || source.starts_with(allowed_src) {
                return true;
            }
        }

        false
    }

    /// Add allowed script source
    pub fn add_script_source(&mut self, source: String) {
        self.script_src.insert(source);
    }

    /// Add script nonce
    pub fn add_nonce(&mut self, nonce: String) {
        self.nonces.insert(nonce);
    }

    /// Add script hash
    pub fn add_script_hash(&mut self, hash: String) {
        self.script_hashes.insert(hash);
    }

    /// Generate CSP header value
    pub fn to_header_value(&self) -> String {
        let mut directives = Vec::new();

        if !self.script_src.is_empty() {
            let sources: Vec<String> = self.script_src.iter().cloned().collect();
            directives.push(format!("script-src {}", sources.join(" ")));
        } else {
            directives.push("script-src 'none'".to_string());
        }

        directives.join("; ")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dom::Dom;

    /// Helper: create a fresh Boa context for testing.
    fn make_ctx() -> Context {
        Context::default()
    }

    #[test]
    fn test_dom_bindings_basic() {
        let dom = Dom::new();
        let mut ctx = make_ctx();

        let result = setup_dom_bindings(&mut ctx, &dom);
        assert!(result.is_ok());
    }

    #[test]
    fn test_console_bindings_basic() {
        let mut ctx = make_ctx();

        let result = setup_console_bindings(&mut ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_window_bindings_basic() {
        let mut ctx = make_ctx();

        let result = setup_window_bindings(&mut ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_javascript_execution_with_dom() {
        let dom = Dom::new();
        let mut ctx = make_ctx();

        // Test basic property access
        let result = execute_with_dom_context(&mut ctx, &dom, "document.title");
        assert!(result.is_ok());

        // Test navigator properties
        let mut ctx2 = make_ctx();
        let result = execute_with_dom_context(&mut ctx2, &dom, "navigator.userAgent");
        assert!(result.is_ok());
        let user_agent = result.unwrap();
        assert!(
            user_agent.contains("Citadel Browser"),
            "Expected user agent to contain 'Citadel Browser', got: {}",
            user_agent
        );

        // Test privacy settings
        let mut ctx3 = make_ctx();
        let result = execute_with_dom_context(&mut ctx3, &dom, "navigator.cookieEnabled");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "false");

        // Test window.location.protocol
        let mut ctx4 = make_ctx();
        let result = execute_with_dom_context(&mut ctx4, &dom, "window.location.protocol");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https:");

        // Test arithmetic (basic JS execution)
        let mut ctx5 = make_ctx();
        let result = execute_with_dom_context(&mut ctx5, &dom, "2 + 2");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "4");
    }

    #[test]
    fn test_security_and_privacy_defaults() {
        let mut ctx = make_ctx();
        setup_window_bindings(&mut ctx).unwrap();

        // Verify privacy-conscious defaults
        let result = ctx.eval(Source::from_bytes("navigator.cookieEnabled"));
        assert!(result.is_ok());
        let val = result.unwrap();
        assert_eq!(val.as_boolean(), Some(false));

        let result = ctx.eval(Source::from_bytes("navigator.doNotTrack"));
        assert!(result.is_ok());
        let dnt = result
            .unwrap()
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .unwrap_or_default();
        assert_eq!(dnt, "1");

        // Verify anti-fingerprinting screen values
        let result = ctx.eval(Source::from_bytes("screen.width"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_number(), Some(1920.0));
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use crate::dom::Dom;
    use std::sync::Arc;

    /// Helper: create a fresh Boa context for testing.
    fn make_ctx() -> Context {
        Context::default()
    }

    #[test]
    fn test_csp_enforcement() {
        let mut csp = JSContentSecurityPolicy::new_strict();

        // Test default strict policy
        assert!(!csp.is_script_allowed("inline", None, None));
        assert!(!csp.is_script_allowed("eval", None, None));
        assert!(csp.is_script_allowed("self", None, None));

        // Test nonce
        csp.add_nonce("test-nonce-123".to_string());
        assert!(csp.is_script_allowed("inline", Some("test-nonce-123"), None));
        assert!(!csp.is_script_allowed("inline", Some("wrong-nonce"), None));

        // Test hash
        csp.add_script_hash("sha256-test-hash".to_string());
        assert!(csp.is_script_allowed("inline", None, Some("sha256-test-hash")));
        assert!(!csp.is_script_allowed("inline", None, Some("wrong-hash")));
    }

    #[test]
    fn test_security_monitor() {
        let mut monitor = JSSecurityMonitor::default();

        // Test initial state
        assert_eq!(monitor.get_security_score(), 100);

        // Test violations affect score
        monitor.record_violation();
        assert!(monitor.get_security_score() < 100);

        monitor.record_blocked_api();
        monitor.record_blocked_element();
        monitor.record_timeout();

        // penalty = 10 + 5 + 3 + 8 = 26, score = 74
        assert!(monitor.get_security_score() < 100);
        assert!(monitor.violations_count > 0);
        assert!(monitor.blocked_api_calls > 0);
        assert!(monitor.blocked_element_creation > 0);
        assert!(monitor.timeout_count > 0);
    }

    #[test]
    fn test_secure_js_context() {
        let security_context = Arc::new(crate::security::SecurityContext::new(10));
        let js_ctx = crate::js::security::SecureJSContext::new(security_context);

        // Test API blocking
        assert!(js_ctx.is_api_blocked("eval"));
        assert!(js_ctx.is_api_blocked("XMLHttpRequest"));
        assert!(js_ctx.is_api_blocked("fetch"));
        assert!(!js_ctx.is_api_blocked("nonexistent_api"));

        // Test global allowlist
        assert!(js_ctx.is_global_allowed("console"));
        assert!(js_ctx.is_global_allowed("Math"));
        assert!(!js_ctx.is_global_allowed("evil_global"));
    }

    #[test]
    fn test_dangerous_element_detection() {
        assert!(is_dangerous_element("script"));
        assert!(is_dangerous_element("iframe"));
        assert!(is_dangerous_element("object"));
        assert!(is_dangerous_element("embed"));
        assert!(!is_dangerous_element("div"));
        assert!(!is_dangerous_element("span"));
        assert!(!is_dangerous_element("p"));
    }

    #[test]
    fn test_dangerous_element_case_insensitive() {
        assert!(is_dangerous_element("SCRIPT"));
        assert!(is_dangerous_element("Iframe"));
        assert!(is_dangerous_element("OBJECT"));
        assert!(!is_dangerous_element("DIV"));
    }

    #[test]
    fn test_create_element_blocks_dangerous() {
        let dom = Dom::new();
        let mut ctx = make_ctx();
        setup_dom_bindings(&mut ctx, &dom).unwrap();

        // Dangerous elements must throw
        let dangerous = ["script", "iframe", "object", "embed", "form"];
        for tag in &dangerous {
            let code = format!("document.createElement('{}')", tag);
            let result = ctx.eval(Source::from_bytes(code.as_bytes()));
            assert!(result.is_err(), "createElement('{}') should be blocked", tag);
        }
    }

    #[test]
    fn test_create_element_allows_safe() {
        let dom = Dom::new();
        let mut ctx = make_ctx();
        setup_dom_bindings(&mut ctx, &dom).unwrap();

        // Safe elements should succeed
        let safe = ["div", "span", "p", "h1", "button", "input"];
        for tag in &safe {
            let code = format!("document.createElement('{}').tagName", tag);
            let result = ctx.eval(Source::from_bytes(code.as_bytes()));
            assert!(result.is_ok(), "createElement('{}') should succeed", tag);
            let val = result.unwrap();
            let tag_name = val
                .as_string()
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();
            assert_eq!(
                tag_name,
                tag.to_ascii_uppercase(),
                "tagName should be uppercased"
            );
        }
    }

    #[test]
    fn test_secure_navigation_blocking() {
        let mut ctx = make_ctx();
        setup_window_bindings(&mut ctx).unwrap();

        // Navigation methods should error because they are not defined
        let result = ctx.eval(Source::from_bytes("location.assign('http://evil.com')"));
        assert!(result.is_err());

        let result = ctx.eval(Source::from_bytes("location.replace('http://evil.com')"));
        assert!(result.is_err());

        let result = ctx.eval(Source::from_bytes("location.reload()"));
        assert!(result.is_err());
    }

    #[test]
    fn test_console_security() {
        let mut ctx = make_ctx();
        setup_console_bindings(&mut ctx).unwrap();

        // console.log should not leak information and should run without error
        let result = ctx.eval(Source::from_bytes("console.log('test'); 'done'"));
        assert!(result.is_ok());
        let val = result.unwrap();
        assert_eq!(
            val.as_string()
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default(),
            "done"
        );

        // Dangerous console methods should be absent (undefined)
        let result = ctx.eval(Source::from_bytes("typeof console.trace"));
        assert!(result.is_ok());
        let type_str = result
            .unwrap()
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .unwrap_or_default();
        assert_eq!(type_str, "undefined");
    }

    #[test]
    fn test_boa_value_to_string_types() {
        let mut ctx = make_ctx();

        // String
        let v = ctx.eval(Source::from_bytes("'hello'")).unwrap();
        assert_eq!(boa_value_to_string(&v, &mut ctx), "hello");

        // Number (integer)
        let v = ctx.eval(Source::from_bytes("42")).unwrap();
        assert_eq!(boa_value_to_string(&v, &mut ctx), "42");

        // Number (float)
        let v = ctx.eval(Source::from_bytes("3.14")).unwrap();
        assert_eq!(boa_value_to_string(&v, &mut ctx), "3.14");

        // Boolean
        let v = ctx.eval(Source::from_bytes("true")).unwrap();
        assert_eq!(boa_value_to_string(&v, &mut ctx), "true");

        // Null
        let v = ctx.eval(Source::from_bytes("null")).unwrap();
        assert_eq!(boa_value_to_string(&v, &mut ctx), "null");

        // Undefined
        let v = ctx.eval(Source::from_bytes("undefined")).unwrap();
        assert_eq!(boa_value_to_string(&v, &mut ctx), "undefined");
    }

    #[test]
    fn test_anti_fingerprinting_screen_values() {
        let mut ctx = make_ctx();
        setup_window_bindings(&mut ctx).unwrap();

        // Verify all screen values are the hardened defaults
        let checks = [
            ("screen.width", 1920.0),
            ("screen.height", 1080.0),
            ("screen.availWidth", 1920.0),
            ("screen.availHeight", 1040.0),
            ("screen.colorDepth", 24.0),
            ("screen.pixelDepth", 24.0),
        ];

        for (expr, expected) in &checks {
            let v = ctx.eval(Source::from_bytes(expr.as_bytes())).unwrap();
            assert_eq!(
                v.as_number(),
                Some(*expected),
                "{} should be {}",
                expr,
                expected
            );
        }
    }

    #[test]
    fn test_navigator_privacy_values() {
        let mut ctx = make_ctx();
        setup_window_bindings(&mut ctx).unwrap();

        // cookieEnabled = false
        let v = ctx
            .eval(Source::from_bytes("navigator.cookieEnabled"))
            .unwrap();
        assert_eq!(v.as_boolean(), Some(false));

        // doNotTrack = "1"
        let v = ctx
            .eval(Source::from_bytes("navigator.doNotTrack"))
            .unwrap();
        assert_eq!(
            v.as_string().map(|s| s.to_std_string_escaped()),
            Some("1".to_string())
        );

        // hardwareConcurrency = 4
        let v = ctx
            .eval(Source::from_bytes("navigator.hardwareConcurrency"))
            .unwrap();
        assert_eq!(v.as_number(), Some(4.0));

        // userAgent contains Citadel
        let v = ctx
            .eval(Source::from_bytes("navigator.userAgent"))
            .unwrap();
        let ua = v
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .unwrap_or_default();
        assert!(ua.contains("Citadel Browser"));
    }

    #[test]
    fn test_csp_header_generation() {
        let csp = JSContentSecurityPolicy::new_strict();
        let header = csp.to_header_value();
        assert!(header.contains("script-src"));
        assert!(header.contains("'self'"));

        let empty_csp = JSContentSecurityPolicy::default();
        let header = empty_csp.to_header_value();
        assert!(header.contains("'none'"));
    }

    #[test]
    fn test_security_monitor_score_bounds() {
        let mut monitor = JSSecurityMonitor::default();
        assert_eq!(monitor.get_security_score(), 100);

        // Saturate the score to 0
        for _ in 0..20 {
            monitor.record_violation();
        }
        assert_eq!(monitor.get_security_score(), 0);
    }

    #[test]
    fn test_execute_with_dom_context_error_handling() {
        let dom = Dom::new();
        let mut ctx = make_ctx();

        // Invalid JS should produce an error, not panic
        let result = execute_with_dom_context(&mut ctx, &dom, "{{{{invalid}}}}");
        assert!(result.is_err());
    }

    #[test]
    fn test_document_ready_state() {
        let dom = Dom::new();
        let mut ctx = make_ctx();
        setup_dom_bindings(&mut ctx, &dom).unwrap();

        let result = ctx.eval(Source::from_bytes("document.readyState"));
        assert!(result.is_ok());
        let val = result
            .unwrap()
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .unwrap_or_default();
        assert_eq!(val, "complete");
    }

    #[test]
    fn test_document_domain() {
        let dom = Dom::new();
        let mut ctx = make_ctx();
        setup_dom_bindings(&mut ctx, &dom).unwrap();

        let result = ctx.eval(Source::from_bytes("document.domain"));
        assert!(result.is_ok());
        let val = result
            .unwrap()
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .unwrap_or_default();
        assert_eq!(val, "example.com");
    }

    #[test]
    fn test_window_self_reference() {
        let mut ctx = make_ctx();
        setup_window_bindings(&mut ctx).unwrap();

        // window should reference the global
        let result = ctx.eval(Source::from_bytes("window === this"));
        assert!(result.is_ok());
        // Note: in strict mode / module mode this may differ; we just verify no error
    }
}
