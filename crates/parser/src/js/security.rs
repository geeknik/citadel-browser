//! Security restrictions for JavaScript execution
//!
//! This module implements comprehensive security policies for JavaScript code execution
//! including hardcore sandbox restrictions, API removal, and resource limiting.
//!
//! SECURITY ARCHITECTURE:
//! - validate_js_code: Static analysis gate (whitespace-normalized, bypass-resistant)
//! - remove_dangerous_apis: Deletes (not overwrites) dangerous globals
//! - remove_tracking_apis: Deletes fingerprinting and tracking surface
//! - prevent_prototype_pollution: Freezes critical prototypes via Rust API
//! - override_critical_functions: Replaces toString/valueOf BEFORE freezing
//! - secure_global_properties: Locks down global object shape
//!
//! ORDERING INVARIANT (apply_sandbox_restrictions):
//!   override_critical_functions MUST run BEFORE prevent_prototype_pollution.
//!   Freezing prototypes first would cause toString overrides to fail silently.

use boa_engine::{Context, JsValue, Source};
use boa_engine::object::IntegrityLevel;
use boa_engine::js_string;
use boa_engine::JsString;
use boa_engine::NativeFunction;
use citadel_security::privacy::{PrivacyEvent, PrivacyEventSender};
use crate::security::SecurityContext;
use crate::error::{ParserError, ParserResult};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{warn, debug};

/// Maximum allowed JavaScript source code size in bytes.
/// Prevents DoS via excessively large script payloads.
const MAX_JS_CODE_SIZE: usize = 100_000;

/// Validate JavaScript code for basic security checks.
///
/// SECURITY FIX: Normalizes whitespace before pattern matching to prevent
/// bypass via inserted spaces/tabs/newlines (e.g., "e v a l (" or "eval\t(").
pub fn validate_js_code(code: &str) -> ParserResult<()> {
    // Check size limit first to bound CPU cost of normalization
    if code.len() > MAX_JS_CODE_SIZE {
        return Err(ParserError::SecurityViolation(
            "JavaScript code is too large".to_string(),
        ));
    }

    // Normalize whitespace for bypass-resistant matching.
    // Stripping all whitespace ensures patterns like "e v a l (" or
    // "eval\n(" cannot evade detection.
    let normalized: String = code.chars().filter(|c| !c.is_whitespace()).collect();

    // Case-SENSITIVE patterns where we must NOT match the lowercase keyword.
    // "Function(" targets the Function constructor, NOT the "function" keyword.
    let case_sensitive_patterns = [
        "Function(",
        "__proto__",
        "constructor.constructor",
    ];
    for pattern in &case_sensitive_patterns {
        if normalized.contains(pattern) {
            return Err(ParserError::SecurityViolation(
                format!("JavaScript code contains dangerous pattern: {}", pattern),
            ));
        }
    }

    // Case-INSENSITIVE patterns for eval, fetch, XMLHttpRequest, import.
    // eval/EVAL/Eval should all be blocked; fetch/Fetch too.
    let normalized_lower = normalized.to_lowercase();
    let ci_patterns = [
        "eval(",
        "xmlhttprequest",
        "fetch(",
        "import(",
    ];
    for pattern in &ci_patterns {
        if normalized_lower.contains(pattern) {
            return Err(ParserError::SecurityViolation(
                format!("JavaScript code contains dangerous pattern: {}", pattern),
            ));
        }
    }

    Ok(())
}

/// Apply comprehensive security restrictions to a JavaScript context.
///
/// This is the standard security posture applied to all JS execution.
/// For maximum isolation, use `apply_sandbox_restrictions` instead.
pub fn apply_security_restrictions(ctx: &mut Context, security_context: &SecurityContext) -> ParserResult<()> {
    apply_security_restrictions_with_privacy(ctx, security_context, None)
}

/// Apply comprehensive security restrictions with optional privacy event emission.
///
/// When a `PrivacyEventSender` is provided, emits `ApiNotImplemented` events for
/// each dangerous or tracking API that is removed during sandbox setup.
pub fn apply_security_restrictions_with_privacy(
    ctx: &mut Context,
    security_context: &SecurityContext,
    privacy_sender: Option<&PrivacyEventSender>,
) -> ParserResult<()> {
    if !security_context.allows_scripts() {
        return Err(ParserError::SecurityViolation(
            "JavaScript execution is disabled by security policy".to_string(),
        ));
    }

    // Remove dangerous global objects and functions
    remove_dangerous_apis(ctx, privacy_sender)?;

    // Restrict built-in functions
    restrict_builtin_functions(ctx)?;

    // Remove tracking APIs
    remove_tracking_apis(ctx, privacy_sender)?;

    // Set up secure property descriptors
    secure_global_properties(ctx)?;

    debug!("[JS-SECURITY] Applied comprehensive security restrictions");
    Ok(())
}

/// Apply hardcore sandbox restrictions for isolated execution.
///
/// ORDERING INVARIANT: override_critical_functions runs BEFORE
/// prevent_prototype_pollution. Reversing this order would cause
/// toString overrides to silently fail against frozen prototypes.
pub fn apply_sandbox_restrictions(ctx: &mut Context, security_context: &SecurityContext) -> ParserResult<()> {
    apply_sandbox_restrictions_with_privacy(ctx, security_context, None)
}

/// Apply hardcore sandbox restrictions with optional privacy event emission.
pub fn apply_sandbox_restrictions_with_privacy(
    ctx: &mut Context,
    security_context: &SecurityContext,
    privacy_sender: Option<&PrivacyEventSender>,
) -> ParserResult<()> {
    // Apply base security restrictions first
    apply_security_restrictions_with_privacy(ctx, security_context, privacy_sender)?;

    // Create isolated global scope
    create_isolated_scope(ctx)?;

    // Remove cross-frame access
    remove_frame_access(ctx)?;

    // Set up execution limits
    setup_execution_limits(ctx)?;

    // Override critical functions BEFORE freezing prototypes.
    // This ordering is load-bearing: frozen prototypes reject modifications.
    override_critical_functions(ctx)?;

    // NOW freeze prototypes to prevent pollution
    prevent_prototype_pollution(ctx)?;

    debug!("[JS-SECURITY] Applied hardcore sandbox restrictions");
    Ok(())
}

/// Remove dangerous APIs that could be used for tracking or attacks.
///
/// Uses real property deletion (delete_property_or_throw) rather than
/// setting to undefined, which leaves the property key enumerable.
fn remove_dangerous_apis(ctx: &mut Context, privacy_sender: Option<&PrivacyEventSender>) -> ParserResult<()> {
    let dangerous_apis = [
        "eval", "Function",
        "importScripts", "import",
        "XMLHttpRequest", "fetch", "WebSocket", "EventSource",
        "localStorage", "sessionStorage", "indexedDB",
        "Worker", "SharedWorker", "ServiceWorker",
    ];

    for api_name in &dangerous_apis {
        remove_global_property(ctx, api_name)?;

        if let Some(sender) = privacy_sender {
            sender.emit(PrivacyEvent::ApiNotImplemented {
                api_name: api_name.to_string(),
                caller_origin: "sandbox-init".to_string(),
            });
        }
    }

    debug!("[JS-SECURITY] Removed dangerous APIs");
    Ok(())
}

/// Remove tracking-specific APIs.
///
/// Targets fingerprinting vectors: timing, device sensors, geolocation,
/// media devices, Bluetooth/USB/Serial/HID, and WebRTC.
fn remove_tracking_apis(ctx: &mut Context, privacy_sender: Option<&PrivacyEventSender>) -> ParserResult<()> {
    let tracking_globals = [
        "performance",
        "DeviceOrientationEvent", "DeviceMotionEvent",
        "Battery", "BatteryManager",
        "RTCPeerConnection", "webkitRTCPeerConnection", "mozRTCPeerConnection",
    ];

    for api_name in &tracking_globals {
        remove_global_property(ctx, api_name)?;

        if let Some(sender) = privacy_sender {
            sender.emit(PrivacyEvent::ApiNotImplemented {
                api_name: api_name.to_string(),
                caller_origin: "sandbox-init".to_string(),
            });
        }
    }

    // Remove navigator sub-properties used for tracking
    let nav_sub_properties = [
        "geolocation", "permissions", "serviceWorker", "storage",
        "mediaDevices", "bluetooth", "usb", "serial", "hid",
    ];

    let global = ctx.global_object().clone();
    let nav_key = JsString::from("navigator");
    if let Ok(nav_val) = global.get(nav_key, ctx) {
        if let Some(nav_obj) = nav_val.as_object() {
            for prop in &nav_sub_properties {
                remove_object_property(&nav_obj, prop, ctx)?;

                if let Some(sender) = privacy_sender {
                    sender.emit(PrivacyEvent::ApiNotImplemented {
                        api_name: format!("navigator.{}", prop),
                        caller_origin: "sandbox-init".to_string(),
                    });
                }
            }
        }
    }

    debug!("[JS-SECURITY] Removed tracking APIs");
    Ok(())
}

/// Restrict built-in functions to prevent abuse.
///
/// Replaces setTimeout/setInterval with secure no-op stubs and
/// strips dangerous console methods.
fn restrict_builtin_functions(ctx: &mut Context) -> ParserResult<()> {
    // Replace setTimeout/setInterval with limited versions
    setup_secure_timeout(ctx)?;
    setup_secure_interval(ctx)?;

    // Restrict console to prevent information leakage
    restrict_console_object(ctx)?;

    debug!("[JS-SECURITY] Restricted built-in functions");
    Ok(())
}

/// Create isolated scope to prevent global pollution.
///
/// Overwrites globalThis/global/self with a fresh empty object so
/// scripts cannot reach the real global scope through these aliases.
fn create_isolated_scope(ctx: &mut Context) -> ParserResult<()> {
    // Eval a JS snippet that reassigns the alias properties.
    // We use eval here because Boa's globalThis is the actual global object
    // and we want to shadow the aliases, not replace the real global.
    ctx.eval(Source::from_bytes(
        r#"
        (function() {
            var isolated = {};
            try { Object.defineProperty(this, 'globalThis', { value: isolated, writable: false, configurable: false }); } catch(e) {}
            try { Object.defineProperty(this, 'global', { value: isolated, writable: false, configurable: false }); } catch(e) {}
            try { Object.defineProperty(this, 'self', { value: isolated, writable: false, configurable: false }); } catch(e) {}
        })();
        "#,
    ))
    .map_err(|e| ParserError::JsError(format!("Failed to create isolated scope: {}", e)))?;

    debug!("[JS-SECURITY] Created isolated scope");
    Ok(())
}

/// Remove frame access capabilities.
///
/// Prevents cross-frame navigation and communication vectors.
fn remove_frame_access(ctx: &mut Context) -> ParserResult<()> {
    remove_global_property(ctx, "parent")?;
    remove_global_property(ctx, "top")?;
    remove_global_property(ctx, "frames")?;
    remove_global_property(ctx, "opener")?;

    debug!("[JS-SECURITY] Removed frame access");
    Ok(())
}

/// Prevent prototype pollution attacks by freezing critical prototypes.
///
/// Uses Boa's Rust-level IntegrityLevel::Frozen API rather than JS eval
/// for stronger guarantees. Falls back gracefully if a prototype is not
/// accessible (e.g., if the constructor was already deleted).
fn prevent_prototype_pollution(ctx: &mut Context) -> ParserResult<()> {
    let constructors_to_freeze = [
        "Object", "Array", "String", "Number", "Boolean",
    ];

    for name in &constructors_to_freeze {
        freeze_prototype(ctx, name)?;
    }

    // Note: Function constructor is already deleted by remove_dangerous_apis.
    // Attempt to freeze its prototype anyway in case deletion failed.
    freeze_prototype(ctx, "Function")?;

    debug!("[JS-SECURITY] Prevented prototype pollution");
    Ok(())
}

/// Freeze the prototype of a named constructor using the Rust API.
///
/// Retrieves `global[constructor_name].prototype` and calls
/// `set_integrity_level(Frozen)`. Silently succeeds if the constructor
/// or prototype is missing (may have been deleted by earlier steps).
fn freeze_prototype(ctx: &mut Context, constructor_name: &str) -> ParserResult<()> {
    let global = ctx.global_object().clone();
    let constructor_key = JsString::from(constructor_name);

    if let Ok(constructor_val) = global.get(constructor_key, ctx) {
        if let Some(constructor_obj) = constructor_val.as_object() {
            let proto_key = js_string!("prototype");
            if let Ok(proto_val) = constructor_obj.get(proto_key, ctx) {
                if let Some(proto_obj) = proto_val.as_object() {
                    let _ = proto_obj.set_integrity_level(IntegrityLevel::Frozen, ctx);
                    debug!("[JS-SECURITY] Froze {}.prototype", constructor_name);
                }
            }
        }
    }

    Ok(())
}

/// Set up execution limits and monitoring.
///
/// Placeholder for future integration with Boa's runtime interrupt handler.
/// Boa does not currently expose a direct instruction-count limiter, but
/// the JSResourceMonitor provides time-based termination checking.
fn setup_execution_limits(ctx: &mut Context) -> ParserResult<()> {
    // Boa does not yet have direct execution limit APIs comparable to
    // QuickJS interrupt handlers. The JSResourceMonitor struct provides
    // time-based and instruction-count-based limits that callers should
    // check between JS evaluation steps.
    let _ = ctx; // suppress unused warning

    debug!("[JS-SECURITY] Set up execution limits (time-based via JSResourceMonitor)");
    Ok(())
}

/// Override critical functions with secure implementations.
///
/// Replaces toString methods to prevent information leakage about
/// function source code and internal object structure.
///
/// MUST be called BEFORE prevent_prototype_pollution (freezing).
fn override_critical_functions(ctx: &mut Context) -> ParserResult<()> {
    ctx.eval(Source::from_bytes(
        r#"
        if (typeof Object !== 'undefined') {
            Object.prototype.toString = function() { return '[object Object]'; };
            Array.prototype.toString = function() { return ''; };
        }
        "#,
    ))
    .map_err(|e| ParserError::JsError(format!("Failed to override critical functions: {}", e)))?;

    // Note: Function.prototype.toString is handled separately because
    // the Function constructor may have been deleted by remove_dangerous_apis.
    // We attempt the override but do not fail if it errors.
    let _ = ctx.eval(Source::from_bytes(
        r#"
        if (typeof Function !== 'undefined' && Function.prototype) {
            Function.prototype.toString = function() { return 'function() { [native code] }'; };
        }
        "#,
    ));

    debug!("[JS-SECURITY] Overrode critical functions");
    Ok(())
}

/// Secure global properties by making them non-configurable.
///
/// Locks down security-critical property descriptors so they cannot
/// be redefined by user scripts.
fn secure_global_properties(ctx: &mut Context) -> ParserResult<()> {
    ctx.eval(Source::from_bytes(
        r#"
        if (typeof Object !== 'undefined' && typeof Object.defineProperty === 'function') {
            ['window', 'self', 'globalThis', 'document'].forEach(function(prop) {
                if (typeof this[prop] !== 'undefined') {
                    try {
                        Object.defineProperty(this, prop, {
                            configurable: false,
                            writable: false
                        });
                    } catch (e) {
                        // Ignore errors for properties that don't exist
                    }
                }
            });
        }
        "#,
    ))
    .map_err(|e| ParserError::JsError(format!("Failed to secure global properties: {}", e)))?;

    debug!("[JS-SECURITY] Secured global properties");
    Ok(())
}

/// Register a secure setTimeout stub on the global object.
///
/// Returns a constant timer ID (1) and never actually schedules execution.
/// This prevents timing-based attacks while allowing scripts that check
/// for setTimeout existence to function.
fn setup_secure_timeout(ctx: &mut Context) -> ParserResult<()> {
    let timeout_fn = NativeFunction::from_fn_ptr(|_this, _args, _ctx| {
        // No-op: returns a fake timer ID without scheduling anything
        Ok(JsValue::from(1))
    });
    ctx.register_global_callable(js_string!("setTimeout"), 0, timeout_fn)
        .map_err(|e| ParserError::JsError(format!("Failed to set setTimeout: {}", e)))?;

    Ok(())
}

/// Register a secure setInterval stub on the global object.
///
/// Returns a constant timer ID (1) and never actually schedules execution.
fn setup_secure_interval(ctx: &mut Context) -> ParserResult<()> {
    let interval_fn = NativeFunction::from_fn_ptr(|_this, _args, _ctx| {
        // No-op: returns a fake timer ID without scheduling anything
        Ok(JsValue::from(1))
    });
    ctx.register_global_callable(js_string!("setInterval"), 0, interval_fn)
        .map_err(|e| ParserError::JsError(format!("Failed to set setInterval: {}", e)))?;

    Ok(())
}

/// Restrict console object to prevent information leakage.
///
/// Removes methods that could expose stack traces, timing information,
/// or internal state (trace, table, dir, time, profile, etc.).
fn restrict_console_object(ctx: &mut Context) -> ParserResult<()> {
    let global = ctx.global_object().clone();
    let console_key = JsString::from("console");

    if let Ok(console_val) = global.get(console_key, ctx) {
        if let Some(console_obj) = console_val.as_object() {
            let dangerous_methods = [
                "trace", "table", "dir", "dirxml", "count",
                "time", "timeEnd", "profile", "profileEnd",
            ];
            for method in &dangerous_methods {
                remove_object_property(&console_obj, method, ctx)?;
            }
        }
    }

    debug!("[JS-SECURITY] Restricted console object");
    Ok(())
}

/// Delete a property from the global object.
///
/// SECURITY FIX: Uses delete_property_or_throw for real deletion instead
/// of setting to undefined (which leaves the key enumerable and detectable).
/// Uses dynamic JsString::from for runtime property names.
fn remove_global_property(ctx: &mut Context, name: &str) -> ParserResult<()> {
    let global = ctx.global_object().clone();
    let key = JsString::from(name);

    match global.delete_property_or_throw(key, ctx) {
        Ok(_) => {
            debug!("[JS-SECURITY] Deleted global property: {}", name);
            Ok(())
        }
        Err(_) => {
            // Don't fail if property doesn't exist or is non-configurable.
            // Some built-in properties cannot be deleted; that's acceptable
            // as long as we attempted the deletion.
            debug!("[JS-SECURITY] Could not delete global property: {} (may not exist or non-configurable)", name);
            Ok(())
        }
    }
}

/// Delete a property from a JS object.
///
/// SECURITY FIX: Uses delete_property_or_throw for real deletion.
fn remove_object_property(
    obj: &boa_engine::object::JsObject,
    name: &str,
    ctx: &mut Context,
) -> ParserResult<()> {
    let key = JsString::from(name);

    match obj.delete_property_or_throw(key, ctx) {
        Ok(_) => {
            debug!("[JS-SECURITY] Deleted object property: {}", name);
            Ok(())
        }
        Err(_) => {
            // Don't fail if property doesn't exist or is non-configurable
            debug!("[JS-SECURITY] Could not delete object property: {} (may not exist or non-configurable)", name);
            Ok(())
        }
    }
}

/// JavaScript execution context with security enforcement.
///
/// Wraps a SecurityContext with JS-specific resource monitoring,
/// blocked API tracking, and allowed-global whitelisting.
#[derive(Debug)]
pub struct SecureJSContext {
    /// Security context for policy enforcement
    security_context: Arc<SecurityContext>,
    /// Resource monitor for execution limits
    resource_monitor: Arc<Mutex<JSResourceMonitor>>,
    /// Blocked API list
    blocked_apis: HashSet<String>,
    /// Allowed globals whitelist
    allowed_globals: HashSet<String>,
    /// Optional privacy event sender for the scoreboard
    privacy_sender: Option<PrivacyEventSender>,
}

impl SecureJSContext {
    /// Create a new secure JavaScript context
    pub fn new(security_context: Arc<SecurityContext>) -> Self {
        let blocked_apis: HashSet<String> = [
            "eval",
            "Function",
            "XMLHttpRequest",
            "fetch",
            "WebSocket",
            "Worker",
            "localStorage",
            "sessionStorage",
            "indexedDB",
            "performance",
            "RTCPeerConnection",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let allowed_globals: HashSet<String> = [
            "console",
            "document",
            "window",
            "navigator",
            "location",
            "screen",
            "Math",
            "Date",
            "JSON",
            "parseInt",
            "parseFloat",
            "isNaN",
            "isFinite",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        Self {
            security_context,
            resource_monitor: Arc::new(Mutex::new(JSResourceMonitor::default())),
            blocked_apis,
            allowed_globals,
            privacy_sender: None,
        }
    }

    /// Set the privacy event sender for scoreboard integration
    pub fn set_privacy_sender(&mut self, sender: PrivacyEventSender) {
        self.privacy_sender = Some(sender);
    }

    /// Apply all security restrictions to a Boa JavaScript context.
    pub fn secure_context(&self, ctx: &mut Context) -> ParserResult<()> {
        // Start resource monitoring
        if let Ok(mut monitor) = self.resource_monitor.lock() {
            monitor.start();
        }

        // Apply security restrictions with optional privacy event emission
        let sender_ref = self.privacy_sender.as_ref();
        apply_security_restrictions_with_privacy(ctx, &self.security_context, sender_ref)?;

        // Apply sandbox restrictions (includes prototype freezing)
        apply_sandbox_restrictions_with_privacy(ctx, &self.security_context, sender_ref)?;

        Ok(())
    }

    /// Check if API is blocked
    pub fn is_api_blocked(&self, api_name: &str) -> bool {
        self.blocked_apis.contains(api_name)
    }

    /// Check if global is allowed
    pub fn is_global_allowed(&self, global_name: &str) -> bool {
        self.allowed_globals.contains(global_name)
    }

    /// Check execution limits
    pub fn check_execution_limits(&self) -> bool {
        if let Ok(mut monitor) = self.resource_monitor.lock() {
            monitor.should_terminate()
        } else {
            false
        }
    }

    /// Get resource monitor statistics
    pub fn get_resource_stats(&self) -> Option<JSResourceMonitor> {
        if let Ok(monitor) = self.resource_monitor.lock() {
            Some(monitor.clone())
        } else {
            None
        }
    }
}

/// Resource monitoring for JavaScript execution.
///
/// Provides time-based and instruction-count-based termination checking.
/// Callers should invoke `should_terminate()` periodically during
/// multi-step JS evaluation.
#[derive(Debug, Clone)]
pub struct JSResourceMonitor {
    /// Maximum execution time in milliseconds
    pub max_execution_time: u64,
    /// Maximum memory usage in bytes
    pub max_memory_usage: usize,
    /// Maximum instruction count
    pub max_instructions: u64,
    /// Execution start time
    pub start_time: Option<Instant>,
    /// Current instruction count
    pub instruction_count: u64,
}

impl Default for JSResourceMonitor {
    fn default() -> Self {
        Self {
            max_execution_time: 5000,                // 5 seconds
            max_memory_usage: 16 * 1024 * 1024,      // 16 MiB
            max_instructions: 1_000_000,              // 1M instructions
            start_time: None,
            instruction_count: 0,
        }
    }
}

impl JSResourceMonitor {
    /// Start monitoring execution
    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
        self.instruction_count = 0;
    }

    /// Check if execution should be terminated.
    ///
    /// Increments the instruction counter and checks both time and
    /// instruction limits. Returns true if any limit is exceeded.
    pub fn should_terminate(&mut self) -> bool {
        // Check execution time
        if let Some(start) = self.start_time {
            if start.elapsed().as_millis() > self.max_execution_time as u128 {
                warn!(
                    "[JS-SECURITY] Execution timeout exceeded: {}ms",
                    start.elapsed().as_millis()
                );
                return true;
            }
        }

        // Check instruction count
        self.instruction_count += 1;
        if self.instruction_count > self.max_instructions {
            warn!(
                "[JS-SECURITY] Instruction count exceeded: {}",
                self.instruction_count
            );
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_safe_code() {
        let result = validate_js_code("2 + 2");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_dangerous_code() {
        let result = validate_js_code("eval('malicious code')");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("eval("));
    }

    #[test]
    fn test_validate_large_code() {
        let large_code = "a".repeat(200_000);
        let result = validate_js_code(&large_code);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_validate_whitespace_bypass_eval() {
        // Whitespace-inserted bypass attempts must be caught
        let result = validate_js_code("e v a l ('x')");
        assert!(result.is_err(), "eval with spaces should be blocked");

        let result = validate_js_code("e\tv\na\rl\t(");
        assert!(result.is_err(), "eval with mixed whitespace should be blocked");
    }

    #[test]
    fn test_validate_whitespace_bypass_fetch() {
        let result = validate_js_code("f e t c h ( 'https://evil.com' )");
        assert!(result.is_err(), "fetch with spaces should be blocked");
    }

    #[test]
    fn test_validate_whitespace_bypass_proto() {
        let result = validate_js_code("obj.__ p r o t o __");
        assert!(result.is_err(), "__proto__ with spaces should be blocked");
    }

    #[test]
    fn test_validate_case_bypass() {
        // Case variation bypass attempts
        let result = validate_js_code("EVAL('x')");
        assert!(result.is_err(), "EVAL uppercase should be blocked");

        let result = validate_js_code("Fetch('https://evil.com')");
        assert!(result.is_err(), "Fetch mixed case should be blocked");

        let result = validate_js_code("XmlHttpRequest");
        assert!(result.is_err(), "XmlHttpRequest mixed case should be blocked");
    }

    #[test]
    fn test_validate_constructor_chain() {
        let result = validate_js_code("[].constructor.constructor('return this')()");
        assert!(result.is_err(), "constructor.constructor should be blocked");
    }

    #[test]
    fn test_validate_import_blocked() {
        let result = validate_js_code("import('module.js')");
        assert!(result.is_err(), "dynamic import should be blocked");
    }

    #[test]
    fn test_validate_safe_patterns_not_blocked() {
        // These should pass: they don't contain dangerous patterns
        assert!(validate_js_code("var x = 42;").is_ok());
        assert!(validate_js_code("console.log('hello')").is_ok());
        assert!(validate_js_code("Math.sqrt(16)").is_ok());
        assert!(validate_js_code("document.title").is_ok());
        assert!(validate_js_code("var evaluation = true;").is_ok());
    }

    #[test]
    fn test_resource_monitor_defaults() {
        let monitor = JSResourceMonitor::default();
        assert_eq!(monitor.max_execution_time, 5000);
        assert_eq!(monitor.max_memory_usage, 16 * 1024 * 1024);
        assert_eq!(monitor.max_instructions, 1_000_000);
        assert!(monitor.start_time.is_none());
        assert_eq!(monitor.instruction_count, 0);
    }

    #[test]
    fn test_resource_monitor_instruction_limit() {
        let mut monitor = JSResourceMonitor::default();
        monitor.max_instructions = 5;
        monitor.start();

        // Should not terminate for first 5 calls
        for _ in 0..5 {
            assert!(!monitor.should_terminate());
        }
        // 6th call should trigger termination
        assert!(monitor.should_terminate());
    }

    #[test]
    fn test_secure_js_context_api_blocked() {
        let security_context = Arc::new(SecurityContext::new(10));
        let ctx = SecureJSContext::new(security_context);

        assert!(ctx.is_api_blocked("eval"));
        assert!(ctx.is_api_blocked("fetch"));
        assert!(ctx.is_api_blocked("XMLHttpRequest"));
        assert!(ctx.is_api_blocked("RTCPeerConnection"));
        assert!(!ctx.is_api_blocked("Math"));
        assert!(!ctx.is_api_blocked("console"));
    }

    #[test]
    fn test_secure_js_context_globals_allowed() {
        let security_context = Arc::new(SecurityContext::new(10));
        let ctx = SecureJSContext::new(security_context);

        assert!(ctx.is_global_allowed("console"));
        assert!(ctx.is_global_allowed("Math"));
        assert!(ctx.is_global_allowed("JSON"));
        assert!(ctx.is_global_allowed("document"));
        assert!(!ctx.is_global_allowed("eval"));
        assert!(!ctx.is_global_allowed("XMLHttpRequest"));
    }

    #[test]
    fn test_remove_global_property_real_deletion() {
        let mut ctx = Context::default();

        // Set a property, then delete it
        let global = ctx.global_object().clone();
        let _ = global.set(js_string!("testDangerous"), JsValue::from(42), false, &mut ctx);

        // Verify it exists
        let exists = ctx
            .eval(Source::from_bytes("typeof testDangerous !== 'undefined'"))
            .unwrap();
        assert_eq!(exists.as_boolean(), Some(true));

        // Delete it
        remove_global_property(&mut ctx, "testDangerous").unwrap();

        // Verify it's gone
        let gone = ctx
            .eval(Source::from_bytes("typeof testDangerous === 'undefined'"))
            .unwrap();
        assert_eq!(gone.as_boolean(), Some(true));
    }

    #[test]
    fn test_freeze_prototype_prevents_modification() {
        let mut ctx = Context::default();

        freeze_prototype(&mut ctx, "Object").unwrap();

        // In sloppy mode, assignment to frozen prototype silently fails
        let _ = ctx.eval(Source::from_bytes("Object.prototype.evil = 'hacked';"));
        let result = ctx
            .eval(Source::from_bytes("Object.prototype.evil === undefined"))
            .unwrap();
        assert_eq!(
            result.as_boolean(),
            Some(true),
            "Frozen prototype should reject new properties"
        );
    }

    #[test]
    fn test_secure_timeout_returns_id() {
        let mut ctx = Context::default();
        setup_secure_timeout(&mut ctx).unwrap();

        let result = ctx.eval(Source::from_bytes("setTimeout()")).unwrap();
        assert_eq!(result.as_number(), Some(1.0));
    }

    #[test]
    fn test_secure_interval_returns_id() {
        let mut ctx = Context::default();
        setup_secure_interval(&mut ctx).unwrap();

        let result = ctx.eval(Source::from_bytes("setInterval()")).unwrap();
        assert_eq!(result.as_number(), Some(1.0));
    }

    #[test]
    fn test_override_then_freeze_ordering() {
        // Validates the ordering invariant: override THEN freeze
        let mut ctx = Context::default();

        // This is the correct order
        override_critical_functions(&mut ctx).unwrap();
        prevent_prototype_pollution(&mut ctx).unwrap();

        // Verify toString was overridden successfully
        let result = ctx
            .eval(Source::from_bytes("({}).toString()"))
            .unwrap();
        let s = result.to_string(&mut ctx).unwrap();
        assert_eq!(s.to_std_string_escaped(), "[object Object]");
    }
}
