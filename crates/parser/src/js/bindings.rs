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

/// Hard cap on live JS DOM nodes a page may create, so a hostile script cannot
/// exhaust memory via `createElement`/`appendChild` loops (the loop-iteration
/// limit alone wouldn't bound per-node allocation). Availability is a security
/// property.
const DOM_MAX_LIVE_NODES: usize = 20000;

/// Authored, sandboxed **mirror DOM** for page scripts.
///
/// Seeded from a bounded JSON snapshot of the already-parsed (and sanitized) Rust
/// DOM, passed in via `__CITADEL_DOM_JSON__`. It is a *mirror*: scripts get a
/// real, mutable DOM API (query/read/mutate, `document`, `window`, events) and it
/// is internally consistent, but mutations do not yet re-render to the display
/// list (DOM-2). Canvas creation delegates to the prior (fingerprint-poisoned)
/// `document` so `createElement('canvas')` stays poisoned.
///
/// Deliberate limits (documented, not hidden): common CSS selector subset only
/// (tag / `#id` / `.class` / descendant / comma — no `>`, `[attr]`, pseudo);
/// `innerHTML` is get-only (set falls back to text — no HTML sub-parser in the
/// cage); no event loop (timers/rAF are no-ops); window metrics are normalized
/// (uniform) values.
const DOM_SHIM: &str = r##"
(function (MAX_NODES) {
  var TREE;
  try { TREE = JSON.parse(globalThis.__CITADEL_DOM_JSON__ || ""); }
  catch (e) { TREE = { tag: "#document", children: [] }; }
  try { delete globalThis.__CITADEL_DOM_JSON__; } catch (e2) {}
  var priorDoc = globalThis.document; // fingerprint-poisoned canvas vehicle (M4)
  var nodeCount = 0;

  function splitWs(s) { return String(s).split(/\s+/).filter(Boolean); }
  function hasClass(el, c) { return el.nodeType === 1 && splitWs(el._attrs["class"] || "").indexOf(c) >= 0; }
  function textOf(n) {
    if (n.nodeType === 3) { return n.data; }
    var s = ""; for (var i = 0; i < n.childNodes.length; i++) { s += textOf(n.childNodes[i]); } return s;
  }
  function detach(c) {
    var p = c.parentNode; if (!p) { return; }
    var i = p.childNodes.indexOf(c); if (i >= 0) { p.childNodes.splice(i, 1); } c.parentNode = null;
  }
  function sibling(el, dir, elementOnly) {
    var p = el.parentNode; if (!p) { return null; }
    for (var j = p.childNodes.indexOf(el) + dir; j >= 0 && j < p.childNodes.length; j += dir) {
      if (!elementOnly || p.childNodes[j].nodeType === 1) { return p.childNodes[j]; }
    }
    return null;
  }
  function fire(target, type, ev) {
    if (!type) { return true; }
    ev = ev || { type: type }; if (!ev.target) { ev.target = target; } ev.currentTarget = target;
    var a = target._listeners && target._listeners[type];
    if (a) { var copy = a.slice(); for (var i = 0; i < copy.length; i++) { try { copy[i].call(target, ev); } catch (e) {} } }
    var on = target["on" + type];
    if (typeof on === "function") { try { on.call(target, ev); } catch (e3) {} }
    return true;
  }

  function makeText(text) {
    return { nodeType: 3, nodeName: "#text", data: String(text), nodeValue: String(text),
             childNodes: [], children: [], parentNode: null, get textContent() { return this.data; } };
  }

  function parseCompound(s) {
    var c = { tag: null, id: null, classes: [] }, m, re = /([#.]?)([a-zA-Z0-9_-]+)/g;
    if (s.indexOf("*") >= 0) { c.tag = "*"; }
    while ((m = re.exec(s)) !== null) {
      if (m[1] === "#") { c.id = m[2]; } else if (m[1] === ".") { c.classes.push(m[2]); } else { c.tag = m[2].toLowerCase(); }
    }
    return c;
  }
  function matchCompound(el, c) {
    if (el.nodeType !== 1) { return false; }
    if (c.tag && c.tag !== "*" && el.localName !== c.tag) { return false; }
    if (c.id && (el._attrs.id || "") !== c.id) { return false; }
    for (var i = 0; i < c.classes.length; i++) { if (!hasClass(el, c.classes[i])) { return false; } }
    return true;
  }
  function matchChain(el, comps) {
    var i = comps.length - 1;
    if (!matchCompound(el, comps[i])) { return false; }
    i--; var n = el.parentNode;
    while (i >= 0 && n && n.nodeType === 1) { if (matchCompound(n, comps[i])) { i--; } n = n.parentNode; }
    return i < 0;
  }
  function parseSelector(sel) {
    return String(sel).split(",").map(function (s) { return splitWs(s.trim()).map(parseCompound); })
      .filter(function (p) { return p.length > 0; });
  }
  function matchesSel(el, sel) {
    var parts = parseSelector(sel);
    for (var p = 0; p < parts.length; p++) { if (matchChain(el, parts[p])) { return true; } }
    return false;
  }
  function descend(root, pred, firstOnly) {
    var out = [];
    (function walk(n) {
      for (var i = 0; i < n.childNodes.length; i++) {
        var c = n.childNodes[i];
        if (c.nodeType === 1) {
          if (pred(c)) { out.push(c); if (firstOnly) { return; } }
          walk(c); if (firstOnly && out.length) { return; }
        }
      }
    })(root);
    return out;
  }
  function query(root, sel, firstOnly) {
    var parts = parseSelector(sel);
    return descend(root, function (el) {
      for (var p = 0; p < parts.length; p++) { if (matchChain(el, parts[p])) { return true; } }
      return false;
    }, firstOnly);
  }

  function makeElement(tag) {
    if (++nodeCount > MAX_NODES) { throw new Error("Citadel DOM node budget exceeded"); }
    var lname = String(tag).toLowerCase();
    var el = {
      nodeType: 1, tagName: String(tag).toUpperCase(), nodeName: String(tag).toUpperCase(),
      localName: lname, _attrs: {}, childNodes: [], parentNode: null, _listeners: {}, _style: {}
    };
    function def(name, get, set) { Object.defineProperty(el, name, { get: get, set: set, configurable: true }); }
    def("children", function () { return el.childNodes.filter(function (n) { return n.nodeType === 1; }); });
    def("childElementCount", function () { return el.children.length; });
    def("firstChild", function () { return el.childNodes[0] || null; });
    def("lastChild", function () { return el.childNodes[el.childNodes.length - 1] || null; });
    def("firstElementChild", function () { return el.children[0] || null; });
    def("parentElement", function () { return el.parentNode && el.parentNode.nodeType === 1 ? el.parentNode : null; });
    def("nextSibling", function () { return sibling(el, 1, false); });
    def("previousSibling", function () { return sibling(el, -1, false); });
    def("nextElementSibling", function () { return sibling(el, 1, true); });
    def("previousElementSibling", function () { return sibling(el, -1, true); });
    def("id", function () { return el._attrs.id || ""; }, function (v) { el._attrs.id = String(v); });
    def("className", function () { return el._attrs["class"] || ""; }, function (v) { el._attrs["class"] = String(v); });
    def("attributes", function () { return Object.keys(el._attrs).map(function (k) { return { name: k, value: el._attrs[k] }; }); });
    def("style", function () { return el._style; });
    def("classList", function () {
      function lst() { return splitWs(el._attrs["class"] || ""); }
      function save(a) { el._attrs["class"] = a.join(" "); }
      return {
        add: function () { var a = lst(); for (var i = 0; i < arguments.length; i++) { if (a.indexOf(arguments[i]) < 0) { a.push(arguments[i]); } } save(a); },
        remove: function () { var a = lst(); for (var i = 0; i < arguments.length; i++) { var k = a.indexOf(arguments[i]); if (k >= 0) { a.splice(k, 1); } } save(a); },
        toggle: function (c) { var a = lst(), k = a.indexOf(c); if (k >= 0) { a.splice(k, 1); save(a); return false; } a.push(c); save(a); return true; },
        contains: function (c) { return lst().indexOf(c) >= 0; },
        item: function (i) { return lst()[i] || null; }
      };
    });
    def("textContent", function () { return textOf(el); }, function (v) { el.childNodes = [makeText(v)]; el.childNodes[0].parentNode = el; });
    def("innerText", function () { return textOf(el); }, function (v) { el.childNodes = [makeText(v)]; el.childNodes[0].parentNode = el; });
    def("innerHTML", function () { return serializeHTML(el); }, function (v) { el.childNodes = [makeText(v)]; el.childNodes[0].parentNode = el; });
    def("outerHTML", function () { return openTag(el) + serializeHTML(el) + "</" + el.localName + ">"; });
    def("value", function () { return el._attrs.value || ""; }, function (v) { el._attrs.value = String(v); });

    el.getAttribute = function (n) { n = String(n).toLowerCase(); return Object.prototype.hasOwnProperty.call(el._attrs, n) ? el._attrs[n] : null; };
    el.setAttribute = function (n, v) { el._attrs[String(n).toLowerCase()] = String(v); };
    el.setAttributeNS = function (ns, n, v) { el.setAttribute(n, v); };
    el.removeAttribute = function (n) { delete el._attrs[String(n).toLowerCase()]; };
    el.hasAttribute = function (n) { return Object.prototype.hasOwnProperty.call(el._attrs, String(n).toLowerCase()); };
    el.appendChild = function (c) { detach(c); c.parentNode = el; el.childNodes.push(c); return c; };
    el.append = function () { for (var i = 0; i < arguments.length; i++) { var a = arguments[i]; el.appendChild(typeof a === "string" ? makeText(a) : a); } };
    el.removeChild = function (c) { var i = el.childNodes.indexOf(c); if (i >= 0) { el.childNodes.splice(i, 1); c.parentNode = null; } return c; };
    el.remove = function () { detach(el); };
    el.insertBefore = function (c, ref) { detach(c); var i = ref ? el.childNodes.indexOf(ref) : -1; if (i < 0) { el.childNodes.push(c); } else { el.childNodes.splice(i, 0, c); } c.parentNode = el; return c; };
    el.replaceChild = function (nw, old) { var i = el.childNodes.indexOf(old); if (i >= 0) { detach(nw); el.childNodes[i] = nw; nw.parentNode = el; old.parentNode = null; } return old; };
    el.cloneNode = function (deep) {
      var c = makeElement(el.localName); Object.keys(el._attrs).forEach(function (k) { c._attrs[k] = el._attrs[k]; });
      if (deep) { for (var i = 0; i < el.childNodes.length; i++) { var ch = el.childNodes[i]; c.appendChild(ch.nodeType === 3 ? makeText(ch.data) : ch.cloneNode(true)); } }
      return c;
    };
    el.contains = function (n) { while (n) { if (n === el) { return true; } n = n.parentNode; } return false; };
    el.getElementsByTagName = function (t) { t = String(t).toLowerCase(); return descend(el, function (n) { return t === "*" || n.localName === t; }, false); };
    el.getElementsByClassName = function (c) { var cls = splitWs(c); return descend(el, function (n) { return cls.every(function (x) { return hasClass(n, x); }); }, false); };
    el.querySelector = function (s) { return query(el, s, true)[0] || null; };
    el.querySelectorAll = function (s) { return query(el, s, false); };
    el.matches = function (s) { return matchesSel(el, s); };
    el.closest = function (s) { var n = el; while (n && n.nodeType === 1) { if (matchesSel(n, s)) { return n; } n = n.parentNode; } return null; };
    el.addEventListener = function (t, fn) { (el._listeners[t] = el._listeners[t] || []).push(fn); };
    el.removeEventListener = function (t, fn) { var a = el._listeners[t]; if (a) { var i = a.indexOf(fn); if (i >= 0) { a.splice(i, 1); } } };
    el.dispatchEvent = function (ev) { return fire(el, ev && ev.type, ev); };
    el.click = function () { fire(el, "click", { type: "click", target: el }); };
    el.focus = function () {}; el.blur = function () {};
    el.getBoundingClientRect = function () { return { x: 0, y: 0, top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0 }; };
    return el;
  }

  function openTag(el) {
    var s = "<" + el.localName;
    Object.keys(el._attrs).forEach(function (k) { s += " " + k + '="' + el._attrs[k] + '"'; });
    return s + ">";
  }
  function serializeHTML(el) {
    var s = "";
    for (var i = 0; i < el.childNodes.length; i++) {
      var c = el.childNodes[i];
      s += c.nodeType === 3 ? c.data : openTag(c) + serializeHTML(c) + "</" + c.localName + ">";
    }
    return s;
  }

  function build(node, parent) {
    if (node.text !== undefined) { var t = makeText(node.text); t.parentNode = parent; return t; }
    var el = makeElement(node.tag || "div");
    if (node.attrs) { Object.keys(node.attrs).forEach(function (k) { el._attrs[String(k).toLowerCase()] = String(node.attrs[k]); }); }
    el.parentNode = parent;
    if (node.children) { for (var i = 0; i < node.children.length; i++) { var ch = build(node.children[i], el); if (ch) { el.childNodes.push(ch); } } }
    return el;
  }
  function findTag(nodes, tag) {
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].nodeType === 1 && nodes[i].localName === tag) { return nodes[i]; }
      var r = findTag(nodes[i].childNodes || [], tag); if (r) { return r; }
    }
    return null;
  }

  var roots = [];
  if (TREE.children) { for (var i = 0; i < TREE.children.length; i++) { roots.push(build(TREE.children[i], null)); } }
  var elementRoots = roots.filter(function (n) { return n.nodeType === 1; });
  var docEl = findTag(roots, "html") || elementRoots[0] || makeElement("html");
  var headEl = findTag([docEl], "head") || makeElement("head");
  var bodyEl = findTag([docEl], "body") || makeElement("body");

  // ----- location (minimal parse; navigation is inert) --------------------
  function parseURL(u) {
    var m = /^([a-zA-Z][a-zA-Z0-9+.-]*:)\/\/([^\/:?#]+)(:[0-9]+)?([^?#]*)(\?[^#]*)?(#.*)?$/.exec(u || "") || [];
    var protocol = m[1] || "https:", host = m[2] || "localhost", port = (m[3] || "").replace(":", "");
    return {
      href: u || "https://localhost/", protocol: protocol, hostname: host, host: host + (m[3] || ""),
      port: port, pathname: m[4] || "/", search: m[5] || "", hash: m[6] || "",
      origin: protocol + "//" + host + (m[3] || ""),
      assign: function () {}, replace: function () {}, reload: function () {}, toString: function () { return this.href; }
    };
  }
  var location = parseURL(TREE.url);

  // ----- document ---------------------------------------------------------
  var docListeners = {};
  var document = {
    nodeType: 9, nodeName: "#document", documentElement: docEl, head: headEl, body: bodyEl,
    readyState: "complete", location: location, characterSet: "UTF-8", compatMode: "CSS1Compat",
    getElementById: function (id) {
      if ((docEl._attrs.id || "") === id) { return docEl; }
      return query(docEl, "#" + id, true)[0] || null;
    },
    getElementsByTagName: function (t) { return docEl.getElementsByTagName(t); },
    getElementsByClassName: function (c) { return docEl.getElementsByClassName(c); },
    querySelector: function (s) { return matchesSel(docEl, s) ? docEl : (query(docEl, s, true)[0] || null); },
    querySelectorAll: function (s) { var r = query(docEl, s, false); if (matchesSel(docEl, s)) { r.unshift(docEl); } return r; },
    createElement: function (t) {
      if (String(t).toLowerCase() === "canvas" && priorDoc && typeof priorDoc.createElement === "function") {
        return priorDoc.createElement("canvas"); // keep fingerprint-poisoned canvas
      }
      return makeElement(t);
    },
    createElementNS: function (ns, t) { return makeElement(t); },
    createTextNode: function (t) { return makeText(t); },
    createDocumentFragment: function () { var f = makeElement("#fragment"); f.nodeType = 11; return f; },
    createComment: function (t) { var c = makeText(t); c.nodeType = 8; c.nodeName = "#comment"; return c; },
    createEvent: function () { return { type: "", initEvent: function (t) { this.type = t; } }; },
    addEventListener: function (t, fn) { (docListeners[t] = docListeners[t] || []).push(fn); },
    removeEventListener: function (t, fn) { var a = docListeners[t]; if (a) { var i = a.indexOf(fn); if (i >= 0) { a.splice(i, 1); } } },
    dispatchEvent: function (ev) { return fire({ _listeners: docListeners }, ev && ev.type, ev); }
  };
  Object.defineProperty(document, "cookie", { get: function () { return ""; }, set: function () {}, configurable: true });
  Object.defineProperty(document, "title", {
    get: function () { var t = findTag([headEl], "title"); return t ? textOf(t) : ""; },
    set: function () {}, configurable: true
  });
  globalThis.document = document;

  // ----- window (== globalThis) ; normalized metrics ----------------------
  var win = globalThis;
  win.window = win; win.self = win; win.top = win; win.parent = win; win.frames = win;
  win.document = document; win.location = location; win.name = "";
  win.innerWidth = 1920; win.innerHeight = 1080; win.outerWidth = 1920; win.outerHeight = 1080;
  win.devicePixelRatio = 1; win.scrollX = 0; win.scrollY = 0; win.pageXOffset = 0; win.pageYOffset = 0;
  var winListeners = {};
  win.addEventListener = function (t, fn) { (winListeners[t] = winListeners[t] || []).push(fn); };
  win.removeEventListener = function (t, fn) { var a = winListeners[t]; if (a) { var i = a.indexOf(fn); if (i >= 0) { a.splice(i, 1); } } };
  win.dispatchEvent = function (ev) { return fire({ _listeners: winListeners }, ev && ev.type, ev); };
  win.getComputedStyle = function (el) { return (el && el._style) || {}; };
  win.matchMedia = function (q) { return { matches: false, media: String(q), addListener: function () {}, removeListener: function () {}, addEventListener: function () {}, removeEventListener: function () {} }; };
  win.scrollTo = function () {}; win.scroll = function () {}; win.scrollBy = function () {};
  win.alert = function () {}; win.confirm = function () { return false; }; win.prompt = function () { return null; };
  win.open = function () { return null; }; win.close = function () {}; win.focus = function () {}; win.blur = function () {};
  // No event loop yet: timers/rAF are inert (documented limitation).
  win.setTimeout = function () { return 0; }; win.setInterval = function () { return 0; };
  win.clearTimeout = function () {}; win.clearInterval = function () {};
  win.requestAnimationFrame = function () { return 0; }; win.cancelAnimationFrame = function () {};
  win.requestIdleCallback = function () { return 0; }; win.cancelIdleCallback = function () {};

  // ----- fire ready events (called by the host after all scripts run) -----
  globalThis.__citadelFireReady__ = function () {
    document.readyState = "complete";
    fire({ _listeners: docListeners }, "DOMContentLoaded", { type: "DOMContentLoaded", target: document });
    fire({ _listeners: docListeners }, "readystatechange", { type: "readystatechange", target: document });
    fire({ _listeners: winListeners }, "load", { type: "load", target: win });
    fire({ _listeners: winListeners }, "DOMContentLoaded", { type: "DOMContentLoaded", target: win });
  };
})(NODECAP_PLACEHOLDER);
"##;

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

/// Install the sandboxed mirror DOM ([`DOM_SHIM`]) from a bounded JSON snapshot of
/// the parsed document. The JSON is passed as a JS *string value* (not embedded in
/// the shim source), so no escaping/injection is possible; the shim `JSON.parse`s
/// it and deletes the global. Call this AFTER [`install`] (it delegates canvas
/// creation to the fingerprint-poisoned `document` that `install` set up).
pub fn install_dom(ctx: &mut Context, document_json: &str) -> JsResult<()> {
    ctx.register_global_property(
        js_string!("__CITADEL_DOM_JSON__"),
        js_string!(document_json),
        Attribute::all(),
    )?;
    let shim = DOM_SHIM.replace("NODECAP_PLACEHOLDER", &DOM_MAX_LIVE_NODES.to_string());
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
            .function(
                NativeFunction::from_fn_ptr(noop),
                js_string!("setRequestHeader"),
                2,
            )
            .function(NativeFunction::from_fn_ptr(noop), js_string!("send"), 1)
            .function(NativeFunction::from_fn_ptr(noop), js_string!("abort"), 0)
            .function(
                NativeFunction::from_fn_ptr(noop),
                js_string!("getAllResponseHeaders"),
                0,
            )
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
        .property(
            js_string!("userAgent"),
            js_string!(p.user_agent.as_str()),
            Attribute::all(),
        )
        .property(
            js_string!("appVersion"),
            js_string!(p.app_version.as_str()),
            Attribute::all(),
        )
        .property(
            js_string!("appName"),
            js_string!("Netscape"),
            Attribute::all(),
        )
        .property(
            js_string!("appCodeName"),
            js_string!("Mozilla"),
            Attribute::all(),
        )
        .property(js_string!("product"), js_string!("Gecko"), Attribute::all())
        .property(
            js_string!("platform"),
            js_string!(p.platform.as_str()),
            Attribute::all(),
        )
        .property(
            js_string!("vendor"),
            js_string!(p.vendor.as_str()),
            Attribute::all(),
        )
        .property(
            js_string!("language"),
            js_string!(language),
            Attribute::all(),
        )
        .property(
            js_string!("hardwareConcurrency"),
            JsValue::from(p.hardware_concurrency),
            Attribute::all(),
        )
        .property(
            js_string!("deviceMemory"),
            JsValue::from(p.device_memory),
            Attribute::all(),
        )
        .property(
            js_string!("maxTouchPoints"),
            JsValue::from(p.max_touch_points),
            Attribute::all(),
        )
        // Privacy posture the page is allowed to observe.
        .property(js_string!("doNotTrack"), js_string!("1"), Attribute::all())
        .property(
            js_string!("webdriver"),
            JsValue::from(false),
            Attribute::all(),
        )
        .property(
            js_string!("cookieEnabled"),
            JsValue::from(false),
            Attribute::all(),
        )
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
        .property(
            js_string!("width"),
            JsValue::from(p.screen_width),
            Attribute::all(),
        )
        .property(
            js_string!("height"),
            JsValue::from(p.screen_height),
            Attribute::all(),
        )
        .property(
            js_string!("availWidth"),
            JsValue::from(p.screen_width),
            Attribute::all(),
        )
        .property(
            js_string!("availHeight"),
            JsValue::from(p.screen_height),
            Attribute::all(),
        )
        .property(
            js_string!("colorDepth"),
            JsValue::from(p.color_depth),
            Attribute::all(),
        )
        .property(
            js_string!("pixelDepth"),
            JsValue::from(p.color_depth),
            Attribute::all(),
        )
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
