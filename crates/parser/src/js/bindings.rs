//! The privacy binding layer — the product.
//!
//! A bare Boa context exposes no environment to the page. Here we install only
//! the globals we author, each privacy-hardened. This module currently installs
//! the **normalized identity** (navigator/screen): every user presents the *same*
//! identity, so per-user fingerprints collapse. Future milestones add timing
//! clamps, fingerprint-poisoned canvas/WebGL/audio, a network exfil gate, and
//! isolated storage — all through this same gate.

use boa_engine::object::builtins::{JsArray, JsPromise};
use boa_engine::object::ObjectInitializer;
use boa_engine::property::Attribute;
use boa_engine::{js_string, Context, JsNativeError, JsResult, JsValue, NativeFunction, Source};
use std::time::Instant;
use url::Url;

/// Per-origin storage quota (UTF-16 code units ≈ bytes), matching the de-facto
/// 5 MiB browser limit. Bounds memory so a page cannot exhaust the heap via
/// `setItem` (availability is a security property).
const STORAGE_QUOTA: usize = 5 * 1024 * 1024;

/// Authored shim for `localStorage`/`sessionStorage`: in-memory, ephemeral,
/// first-party-isolated Storage. Running it in the sandbox (rather than binding
/// native code) means the store *cannot* touch disk or escape the cage, so it is
/// structurally incapable of being a persistent supercookie. The backing map is a
/// closure variable, wiped when the context dies (i.e. between executions today,
/// and on tab close once JS runs in a long-lived per-tab context).
const STORAGE_SHIM: &str = r#"
(function (QUOTA) {
  function makeStorage() {
    var data = Object.create(null);
    var size = 0;
    var api = {
      getItem: function (k) {
        k = String(k);
        return Object.prototype.hasOwnProperty.call(data, k) ? data[k] : null;
      },
      setItem: function (k, v) {
        k = String(k); v = String(v);
        var had = Object.prototype.hasOwnProperty.call(data, k);
        var old = had ? k.length + data[k].length : 0;
        var next = size - old + k.length + v.length;
        if (next > QUOTA) { throw new Error("QuotaExceededError"); }
        data[k] = v; size = next;
      },
      removeItem: function (k) {
        k = String(k);
        if (Object.prototype.hasOwnProperty.call(data, k)) {
          size -= k.length + data[k].length;
          delete data[k];
        }
      },
      clear: function () { data = Object.create(null); size = 0; },
      key: function (i) {
        var ks = Object.keys(data);
        return (i >= 0 && i < ks.length) ? ks[i] : null;
      }
    };
    // Proxy so legacy property access (localStorage.foo = 'x') also works.
    return new Proxy(api, {
      get: function (t, prop) {
        if (prop === "length") { return Object.keys(data).length; }
        if (prop in t) { return t[prop]; }
        return Object.prototype.hasOwnProperty.call(data, prop) ? data[prop] : undefined;
      },
      set: function (t, prop, val) {
        if (prop in t) { t[prop] = val; return true; }
        api.setItem(prop, val); return true;
      },
      has: function (t, prop) {
        return (prop in t) || Object.prototype.hasOwnProperty.call(data, prop);
      },
      deleteProperty: function (t, prop) {
        api.removeItem(prop); return true;
      }
    });
  }
  globalThis.localStorage = makeStorage();
  globalThis.sessionStorage = makeStorage();
})(QUOTA_PLACEHOLDER);
"#;

/// Maximum pixels a single `getImageData` readback will synthesize (bounds the
/// per-call allocation; real fingerprint canvases are tiny).
const FP_MAX_IMAGE_BYTES: u32 = 1024 * 1024;

/// Authored fingerprint-poisoning surface: canvas (2D + WebGL) and audio.
///
/// We have no real rasterizer/GPU/DSP, so draw/render calls are accepted but
/// produce nothing visible; every *readback* returns an authored value:
/// - WebGL identity params (vendor/renderer/version) are a single NORMALIZED set
///   — uniform for every user (a per-origin GPU would be inconsistent/suspicious).
/// - Canvas `toDataURL`/`getImageData`/`measureText` and audio buffers are seeded
///   by a deterministic PRNG keyed on the per-origin SEED: identical for all users
///   on a site (uniform), uncorrelated across sites, stable within a site.
const FINGERPRINT_SHIM: &str = r#"
(function (SEED, MAX_IMG) {
  function makeRng(seed) {
    var s = seed >>> 0;
    return function () {
      s = (s + 0x6D2B79F5) | 0;
      var t = Math.imul(s ^ (s >>> 15), 1 | s);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // ----- Canvas 2D: drawing is a no-op; readback is seeded ----------------
  function make2d(canvas) {
    var noop = function () {};
    var grad = function () { return { addColorStop: noop }; };
    return {
      canvas: canvas,
      fillRect: noop, clearRect: noop, strokeRect: noop, fillText: noop,
      strokeText: noop, beginPath: noop, closePath: noop, moveTo: noop,
      lineTo: noop, arc: noop, arcTo: noop, rect: noop, ellipse: noop,
      fill: noop, stroke: noop, clip: noop, save: noop, restore: noop,
      translate: noop, rotate: noop, scale: noop, transform: noop,
      setTransform: noop, resetTransform: noop, drawImage: noop,
      putImageData: noop, setLineDash: noop, bezierCurveTo: noop,
      quadraticCurveTo: noop, createLinearGradient: grad,
      createRadialGradient: grad, createPattern: function () { return {}; },
      getImageData: function (sx, sy, sw, sh) {
        var w = (sw | 0) || canvas.width || 1;
        var h = (sh | 0) || canvas.height || 1;
        var n = w * h * 4;
        if (n > MAX_IMG) { n = MAX_IMG; }
        if (n < 4) { n = 4; }
        var rng = makeRng(SEED ^ Math.imul(w, 73856093) ^ Math.imul(h, 19349663));
        var data = new Uint8ClampedArray(n);
        for (var i = 0; i < n; i++) { data[i] = (rng() * 256) | 0; }
        return { data: data, width: w, height: h };
      },
      measureText: function (t) {
        var len = t ? String(t).length : 0;
        var rng = makeRng(SEED ^ Math.imul(len, 2654435761));
        return { width: len * 8 + rng() };
      }
    };
  }

  // ----- WebGL: NORMALIZED, uniform for every user ------------------------
  function makeGL(canvas) {
    var P = {};
    P[0x1F00] = "WebKit";                                             // VENDOR
    P[0x1F01] = "WebKit WebGL";                                       // RENDERER
    P[0x1F02] = "WebGL 1.0 (OpenGL ES 2.0 Chromium)";                 // VERSION
    P[0x8B8C] = "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)"; // SHADING_LANGUAGE_VERSION
    P[0x9245] = "Google Inc. (Intel)";                               // UNMASKED_VENDOR_WEBGL
    P[0x9246] = "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"; // UNMASKED_RENDERER_WEBGL
    P[0x0D33] = 16384; P[0x851C] = 16384; P[0x8869] = 16; P[0x8DFB] = 1024;
    P[0x8B4D] = 32; P[0x8B4C] = 16; P[0x8872] = 16; P[0x846E] = new Int32Array([0, 16384]);
    var debugExt = { UNMASKED_VENDOR_WEBGL: 0x9245, UNMASKED_RENDERER_WEBGL: 0x9246 };
    return {
      canvas: canvas,
      getParameter: function (pname) { return (pname in P) ? P[pname] : null; },
      getExtension: function (name) {
        return name === "WEBGL_debug_renderer_info" ? debugExt : null;
      },
      getSupportedExtensions: function () {
        return ["WEBGL_debug_renderer_info", "OES_texture_float", "OES_standard_derivatives"];
      },
      getContextAttributes: function () {
        return { alpha: true, antialias: true, depth: true, stencil: false };
      },
      getShaderPrecisionFormat: function () {
        return { precision: 23, rangeMin: 127, rangeMax: 127 };
      },
      createShader: function () { return {}; }, createProgram: function () { return {}; },
      createBuffer: function () { return {}; }, createTexture: function () { return {}; },
      bindBuffer: function () {}, bufferData: function () {}, viewport: function () {}
    };
  }

  function makeCanvas() {
    var canvas = { width: 300, height: 150, nodeName: "CANVAS", style: {} };
    canvas.getContext = function (type) {
      type = String(type).toLowerCase();
      if (type === "2d") { return make2d(canvas); }
      if (type === "webgl" || type === "experimental-webgl" || type === "webgl2") {
        return makeGL(canvas);
      }
      return null;
    };
    canvas.toDataURL = function () {
      var rng = makeRng(SEED ^ Math.imul(canvas.width, 2654435761) ^ canvas.height);
      var abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      var s = "";
      for (var i = 0; i < 64; i++) { s += abc.charAt((rng() * 64) | 0); }
      return "data:image/png;base64,iVBORw0KGgo" + s;
    };
    canvas.toBlob = function (cb) { if (typeof cb === "function") { cb(null); } };
    canvas.setAttribute = function () {}; canvas.getAttribute = function () { return null; };
    canvas.addEventListener = function () {}; canvas.appendChild = function (c) { return c; };
    return canvas;
  }

  // ----- document.createElement (minimal — vehicle for canvas) ------------
  var doc = (typeof globalThis.document === "object" && globalThis.document) || {};
  doc.createElement = function (tag) {
    if (String(tag).toLowerCase() === "canvas") { return makeCanvas(); }
    return {
      tagName: String(tag).toUpperCase(), style: {}, setAttribute: function () {},
      getAttribute: function () { return null; }, appendChild: function (c) { return c; },
      addEventListener: function () {}, getContext: function () { return null; }
    };
  };
  globalThis.document = doc;

  // ----- Audio: graph is inert; readback is seeded ------------------------
  function seededFloat32(len, salt) {
    var rng = makeRng(SEED ^ salt);
    var a = new Float32Array(len);
    for (var i = 0; i < len; i++) { a[i] = rng() * 2 - 1; }
    return a;
  }
  function param() { return { value: 0, setValueAtTime: function () {}, setTargetAtTime: function () {}, linearRampToValueAtTime: function () {} }; }
  function makeNode() {
    return {
      connect: function (n) { return n; }, disconnect: function () {}, start: function () {}, stop: function () {},
      frequency: param(), gain: param(), Q: param(), detune: param(), threshold: param(),
      knee: param(), ratio: param(), attack: param(), release: param(),
      fftSize: 2048, frequencyBinCount: 1024,
      getFloatFrequencyData: function (arr) { var s = seededFloat32(arr.length, 7); for (var i = 0; i < arr.length; i++) { arr[i] = -100 + s[i] * 40; } },
      getByteFrequencyData: function (arr) { var s = seededFloat32(arr.length, 9); for (var i = 0; i < arr.length; i++) { arr[i] = ((s[i] * 0.5 + 0.5) * 255) | 0; } },
      getFloatTimeDomainData: function (arr) { var s = seededFloat32(arr.length, 11); for (var i = 0; i < arr.length; i++) { arr[i] = s[i]; } }
    };
  }
  function makeAudioCtx(length, rate) {
    var sr = rate || 44100;
    var ctx = {
      sampleRate: sr, currentTime: 0, destination: makeNode(),
      createOscillator: makeNode, createDynamicsCompressor: makeNode, createAnalyser: makeNode,
      createGain: makeNode, createBiquadFilter: makeNode, createBufferSource: makeNode,
      createScriptProcessor: function () { var n = makeNode(); n.onaudioprocess = null; return n; },
      createBuffer: function (ch, len, r) {
        return { length: len, numberOfChannels: ch, sampleRate: r, getChannelData: function () { return seededFloat32(len, 13); } };
      },
      close: function () { return Promise.resolve(); }, resume: function () { return Promise.resolve(); },
      startRendering: function () {
        var len = length || sr;
        return Promise.resolve({
          length: len, numberOfChannels: 1, sampleRate: sr,
          getChannelData: function () { return seededFloat32(len, 17); }
        });
      }
    };
    return ctx;
  }
  globalThis.AudioContext = function () { return makeAudioCtx(0, 44100); };
  globalThis.webkitAudioContext = globalThis.AudioContext;
  globalThis.OfflineAudioContext = function (ch, len, rate) { return makeAudioCtx(len, rate); };
  globalThis.webkitOfflineAudioContext = globalThis.OfflineAudioContext;
})(SEED_PLACEHOLDER, MAXIMG_PLACEHOLDER);
"#;

/// The identity and per-origin seed the bindings present to a page.
///
/// The defaults are a single, common, *normalized* identity — the whole point is
/// that everyone looks identical, so the page learns nothing that distinguishes
/// this user. `origin_seed` is reserved for per-origin fingerprint noise (so a
/// site sees a stable-but-fake value that another site cannot correlate).
#[derive(Debug, Clone)]
pub struct PrivacyProfile {
    pub user_agent: String,
    pub app_version: String,
    pub platform: String,
    pub vendor: String,
    pub languages: Vec<String>,
    pub hardware_concurrency: u32,
    pub device_memory: f64,
    pub max_touch_points: u32,
    pub timezone: String,
    pub screen_width: u32,
    pub screen_height: u32,
    pub color_depth: u32,
    /// Resolution (ms) that `performance.now()` is quantized to — kills high-res
    /// timing fingerprints/side-channels. Uniform across users.
    pub time_quantum_ms: u64,
    /// Per-first-party seed for fingerprint noise. 0 for the shared identity.
    pub origin_seed: u64,
}

impl PrivacyProfile {
    /// The single normalized identity served to everyone.
    pub fn normalized() -> Self {
        Self {
            user_agent:
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/120.0.0.0 Safari/537.36"
                    .to_string(),
            app_version:
                "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/120.0.0.0 Safari/537.36"
                    .to_string(),
            platform: "Win32".to_string(),
            vendor: "Google Inc.".to_string(),
            languages: vec!["en-US".to_string(), "en".to_string()],
            // Quantized to common values so they carry no entropy.
            hardware_concurrency: 4,
            device_memory: 8.0,
            max_touch_points: 0,
            timezone: "UTC".to_string(),
            screen_width: 1920,
            screen_height: 1080,
            color_depth: 24,
            // Tor-style coarse clock: the page cannot measure sub-100ms intervals.
            time_quantum_ms: 100,
            origin_seed: 0,
        }
    }

    /// The normalized identity plus a per-origin seed (for fingerprint noise).
    ///
    /// The seed is derived from the *origin* (scheme://host:port), not the full
    /// URL, so every page of a site shares one seed (first-party consistency) and
    /// two different sites get different seeds (no cross-site correlation). The
    /// seed carries no per-user/per-install entropy: all Citadel users on a site
    /// share it — uniform across users, uncorrelated across sites.
    pub fn for_origin(origin: &str) -> Self {
        let normalized = Url::parse(origin)
            .ok()
            .map(|u| u.origin().ascii_serialization())
            .unwrap_or_else(|| origin.to_string());
        Self {
            origin_seed: fnv1a(&normalized),
            ..Self::normalized()
        }
    }
}

/// Install the privacy binding layer into a fresh context.
pub fn install(ctx: &mut Context, profile: &PrivacyProfile) -> JsResult<()> {
    install_navigator(ctx, profile)?;
    install_screen(ctx, profile)?;
    install_timing(ctx, profile)?;
    install_network_gate(ctx)?;
    install_storage(ctx)?;
    install_fingerprint_surface(ctx, profile)?;
    Ok(())
}

/// Install the fingerprint-poisoning surface (canvas / WebGL / audio) by
/// evaluating the authored [`FINGERPRINT_SHIM`], seeded from the profile's
/// per-origin seed. Identity-like params (WebGL vendor/renderer) are normalized
/// (uniform for every user); high-entropy readback (canvas/audio) is seeded
/// per-origin (uniform across users, uncorrelated across sites). Sandboxed JS,
/// not native code: it cannot reach a real GPU/canvas/audio device.
fn install_fingerprint_surface(ctx: &mut Context, p: &PrivacyProfile) -> JsResult<()> {
    // Fold the 64-bit origin seed into the 32-bit space the shim's PRNG uses.
    let seed = (p.origin_seed ^ (p.origin_seed >> 32)) as u32;
    let shim = FINGERPRINT_SHIM
        .replace("SEED_PLACEHOLDER", &seed.to_string())
        .replace("MAXIMG_PLACEHOLDER", &FP_MAX_IMAGE_BYTES.to_string());
    ctx.eval(Source::from_bytes(&shim))?;
    Ok(())
}

/// Install ephemeral, first-party-isolated `localStorage`/`sessionStorage` by
/// evaluating the authored [`STORAGE_SHIM`] (see its doc for why a sandboxed
/// shim, not native code). No disk, no cross-origin sharing => no supercookies.
fn install_storage(ctx: &mut Context) -> JsResult<()> {
    let shim = STORAGE_SHIM.replace("QUOTA_PLACEHOLDER", &STORAGE_QUOTA.to_string());
    ctx.eval(Source::from_bytes(&shim))?;
    Ok(())
}

/// Install the network exfil gate. Every network-capable API is bound as
/// **present-but-denying**: the surface matches a mainstream browser (so its
/// *absence* is not itself a fingerprint), but no request ever leaves. Default
/// policy is deny; denials are shaped to look like ordinary network failures.
///
/// Covers the page's exfil/leak vectors: `fetch`, `XMLHttpRequest`, `WebSocket`,
/// `sendBeacon` (added to `navigator`), and WebRTC `RTCPeerConnection` — the last
/// of which, if left real, leaks the user's local/private IP via ICE candidates.
fn install_network_gate(ctx: &mut Context) -> JsResult<()> {
    // fetch() → a Promise that rejects like a blocked request ("Failed to fetch"),
    // so `fetch(x).catch(...)` and `await fetch(x)` both see a normal failure.
    let fetch_fn = NativeFunction::from_fn_ptr(|_this, _args, ctx| {
        let reason = JsNativeError::typ().with_message("Failed to fetch");
        Ok(JsPromise::reject(reason, ctx).into())
    });
    ctx.register_global_callable(js_string!("fetch"), 1, fetch_fn)?;

    // WebSocket / RTCPeerConnection / webkitRTCPeerConnection: construction throws
    // (deny). Critically, no RTCPeerConnection means no ICE gathering => the local
    // IP cannot leak past the gate.
    for name in ["WebSocket", "RTCPeerConnection", "webkitRTCPeerConnection"] {
        let blocked = NativeFunction::from_fn_ptr(|_this, _args, _ctx| {
            Err(JsNativeError::typ()
                .with_message("blocked by Citadel Privacy Shield")
                .into())
        });
        ctx.register_global_callable(js_string!(name), 1, blocked)?;
    }

    // XMLHttpRequest: present and constructible, but inert. open/send/etc. are
    // no-ops and readyState/status stay 0, so the page detects the API yet no
    // request is issued (a silent, fingerprint-neutral denial).
    let xhr_ctor = NativeFunction::from_fn_ptr(|_this, _args, ctx| {
        let noop = |_: &JsValue, _: &[JsValue], _: &mut Context| Ok(JsValue::undefined());
        let obj = ObjectInitializer::new(ctx)
            .function(NativeFunction::from_fn_ptr(noop), js_string!("open"), 5)
            .function(NativeFunction::from_fn_ptr(noop), js_string!("setRequestHeader"), 2)
            .function(NativeFunction::from_fn_ptr(noop), js_string!("send"), 1)
            .function(NativeFunction::from_fn_ptr(noop), js_string!("abort"), 0)
            .function(NativeFunction::from_fn_ptr(noop), js_string!("getAllResponseHeaders"), 0)
            .property(js_string!("readyState"), JsValue::from(0), Attribute::all())
            .property(js_string!("status"), JsValue::from(0), Attribute::all())
            .property(js_string!("responseText"), js_string!(""), Attribute::all())
            .build();
        Ok(obj.into())
    });
    ctx.register_global_callable(js_string!("XMLHttpRequest"), 0, xhr_ctor)?;

    Ok(())
}

/// Install a coarse `performance.now()` that quantizes elapsed time, so the page
/// cannot measure sub-quantum intervals (kills high-resolution timing
/// fingerprints and timing side-channels). Uniform resolution for every user.
fn install_timing(ctx: &mut Context, p: &PrivacyProfile) -> JsResult<()> {
    let start = Instant::now();
    let quantum = u128::from(p.time_quantum_ms.max(1));

    let now_fn = NativeFunction::from_copy_closure(move |_this, _args, _ctx| {
        let elapsed_ms = start.elapsed().as_millis();
        let clamped = (elapsed_ms / quantum) * quantum;
        Ok(JsValue::from(clamped as f64))
    });

    let performance = ObjectInitializer::new(ctx)
        .function(now_fn, js_string!("now"), 0)
        .build();

    ctx.register_global_property(js_string!("performance"), performance, Attribute::all())?;
    Ok(())
}

/// Install a normalized `navigator` — the page reads identity and gets *ours*.
fn install_navigator(ctx: &mut Context, p: &PrivacyProfile) -> JsResult<()> {
    let language = p.languages.first().map(String::as_str).unwrap_or("en-US");

    let navigator = ObjectInitializer::new(ctx)
        .property(js_string!("userAgent"), js_string!(p.user_agent.as_str()), Attribute::all())
        .property(js_string!("appVersion"), js_string!(p.app_version.as_str()), Attribute::all())
        .property(js_string!("appName"), js_string!("Netscape"), Attribute::all())
        .property(js_string!("appCodeName"), js_string!("Mozilla"), Attribute::all())
        .property(js_string!("product"), js_string!("Gecko"), Attribute::all())
        .property(js_string!("platform"), js_string!(p.platform.as_str()), Attribute::all())
        .property(js_string!("vendor"), js_string!(p.vendor.as_str()), Attribute::all())
        .property(js_string!("language"), js_string!(language), Attribute::all())
        .property(
            js_string!("hardwareConcurrency"),
            JsValue::from(p.hardware_concurrency),
            Attribute::all(),
        )
        .property(js_string!("deviceMemory"), JsValue::from(p.device_memory), Attribute::all())
        .property(
            js_string!("maxTouchPoints"),
            JsValue::from(p.max_touch_points),
            Attribute::all(),
        )
        // Privacy posture the page is allowed to observe.
        .property(js_string!("doNotTrack"), js_string!("1"), Attribute::all())
        .property(js_string!("webdriver"), JsValue::from(false), Attribute::all())
        .property(js_string!("cookieEnabled"), JsValue::from(false), Attribute::all())
        // navigator.sendBeacon: present, but denied — returns false ("not queued"),
        // which is exactly what a browser returns when the beacon is blocked.
        .function(
            NativeFunction::from_fn_ptr(|_this, _args, _ctx| Ok(JsValue::from(false))),
            js_string!("sendBeacon"),
            2,
        )
        .build();

    // navigator.languages as a real JS array.
    let langs = JsArray::new(ctx);
    for lang in &p.languages {
        langs.push(JsValue::from(js_string!(lang.as_str())), ctx)?;
    }
    navigator.set(js_string!("languages"), JsValue::from(langs), false, ctx)?;

    ctx.register_global_property(js_string!("navigator"), navigator, Attribute::all())?;
    Ok(())
}

/// Install a normalized `screen` object.
fn install_screen(ctx: &mut Context, p: &PrivacyProfile) -> JsResult<()> {
    let screen = ObjectInitializer::new(ctx)
        .property(js_string!("width"), JsValue::from(p.screen_width), Attribute::all())
        .property(js_string!("height"), JsValue::from(p.screen_height), Attribute::all())
        .property(js_string!("availWidth"), JsValue::from(p.screen_width), Attribute::all())
        .property(js_string!("availHeight"), JsValue::from(p.screen_height), Attribute::all())
        .property(js_string!("colorDepth"), JsValue::from(p.color_depth), Attribute::all())
        .property(js_string!("pixelDepth"), JsValue::from(p.color_depth), Attribute::all())
        .build();

    ctx.register_global_property(js_string!("screen"), screen, Attribute::all())?;
    Ok(())
}

/// FNV-1a hash for deriving a stable per-origin seed (no external dependency).
fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in s.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
