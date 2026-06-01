//! The privacy binding layer — the product.
//!
//! A bare Boa context exposes no environment to the page. Here we install only
//! the globals we author, each privacy-hardened. This module currently installs
//! the **normalized identity** (navigator/screen): every user presents the *same*
//! identity, so per-user fingerprints collapse. Future milestones add timing
//! clamps, fingerprint-poisoned canvas/WebGL/audio, a network exfil gate, and
//! isolated storage — all through this same gate.

use boa_engine::object::builtins::JsArray;
use boa_engine::object::ObjectInitializer;
use boa_engine::property::Attribute;
use boa_engine::{js_string, Context, JsResult, JsValue};

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
            origin_seed: 0,
        }
    }

    /// The normalized identity plus a per-origin seed (for fingerprint noise).
    pub fn for_origin(origin: &str) -> Self {
        Self {
            origin_seed: fnv1a(origin),
            ..Self::normalized()
        }
    }
}

/// Install the privacy binding layer into a fresh context.
pub fn install(ctx: &mut Context, profile: &PrivacyProfile) -> JsResult<()> {
    install_navigator(ctx, profile)?;
    install_screen(ctx, profile)?;
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
