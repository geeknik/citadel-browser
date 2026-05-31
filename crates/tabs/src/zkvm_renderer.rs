//! ZKVM-isolated renderer for secure tab content processing.
//!
//! This module runs *inside* the ZKVM isolation boundary. Untrusted page bytes
//! enter only through the encrypted [`Channel`]; the renderer parses, sanitizes,
//! and lays them out here, and emits a serializable display list back across the
//! boundary. The host never touches the raw markup — it only paints the sanitized
//! display list. That is the "zero-knowledge tab" property in practice.

use crate::{TabError, TabResult};
use citadel_parser::css::{ColorValue, LengthValue};
use citadel_parser::{
    dom::NodeData, dom::NodeHandle, parse_css, parse_html,
    security::SecurityContext as ParserSecurityContext, CitadelStylesheet,
};
use citadel_zkvm::{Channel, ChannelMessage};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// A request to render a page, sent from the host into the isolation boundary.
///
/// Only the raw, untrusted bytes and a viewport width cross the boundary — the
/// host has not parsed anything yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderRequest {
    /// The page URL (used for context / link resolution only).
    pub url: String,
    /// The raw, untrusted HTML bytes to parse inside the boundary.
    pub html: String,
    /// Viewport width in logical pixels used for block-flow layout.
    pub viewport_width: f32,
}

/// Kind of a rendered primitive, used by the host painter to pick styling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisplayKind {
    /// A heading run (h1–h6).
    Heading,
    /// A block of body text.
    Paragraph,
    /// A hyperlink run.
    Link,
    /// Any other visible text block.
    Generic,
}

/// A single positioned, styled primitive produced by isolated layout.
///
/// This is the *only* representation of page content that leaves the boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayItem {
    /// Semantic kind for host styling.
    pub kind: DisplayKind,
    /// Sanitized, whitespace-collapsed text content.
    pub text: String,
    /// Sanitized link target, if this item is a link.
    pub href: Option<String>,
    /// X position in logical pixels.
    pub x: f32,
    /// Y position in logical pixels.
    pub y: f32,
    /// Laid-out width in logical pixels.
    pub width: f32,
    /// Laid-out height in logical pixels.
    pub height: f32,
    /// Font size in logical pixels.
    pub font_size: f32,
    /// Whether the run should render bold.
    pub bold: bool,
    /// RGB colour for the run.
    pub color: [u8; 3],
}

/// Security metadata describing what the isolation boundary blocked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetadata {
    /// Whether content was sanitized (always true on the success path).
    pub sanitized: bool,
    /// Number of dangerous / non-visual nodes pruned during traversal.
    pub blocked_elements: usize,
    /// Names of the security policies applied at the boundary.
    pub applied_policies: Vec<String>,
}

/// Fully rendered, sanitized content ready for the host to paint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedContent {
    /// Source URL the content was rendered from.
    pub url: String,
    /// Document title extracted inside the boundary.
    pub title: String,
    /// The flat, positioned display list (the render output).
    pub display_list: Vec<DisplayItem>,
    /// Total canvas width in logical pixels (the viewport).
    pub width: f32,
    /// Total content height in logical pixels (for scrolling).
    pub height: f32,
    /// Page background colour resolved from the body's CSS (RGB).
    pub background: [u8; 3],
    /// Width of the centered content column in logical pixels (from body CSS).
    pub content_width: f32,
    /// What the boundary sanitized.
    pub security_metadata: SecurityMetadata,
}

/// CSS resolution context threaded through the DOM walk inside the boundary.
struct StyleCtx<'a> {
    sheet: &'a CitadelStylesheet,
    /// Viewport width / height in px, for resolving vw/vh/percent lengths.
    vw: f32,
    vh: f32,
}

/// Tags that are never visible and must be pruned at the boundary.
/// Pruning `script`/`style`/etc. at the DOM level is the structural form of
/// the engine's "fail closed" sanitization — far stronger than string replace.
const SKIP_TAGS: &[&str] = &[
    "script", "style", "head", "meta", "link", "title", "noscript", "template", "base", "svg",
    "math", "object", "embed", "applet", "iframe",
];

/// Inline tags whose text is merged into the surrounding block run.
const INLINE_TAGS: &[&str] = &[
    "span", "b", "strong", "i", "em", "code", "small", "label", "abbr", "u", "mark", "sub", "sup",
    "q", "cite", "time", "bdi", "bdo", "wbr", "font", "tt", "kbd", "samp", "var", "ins", "del",
    "s",
];

/// ZKVM renderer that processes content in complete isolation.
pub struct ZkVmRenderer {
    /// Channel for receiving rendering requests and returning results.
    channel: Arc<RwLock<Channel>>,
    /// Current rendering state.
    state: Arc<RwLock<RendererState>>,
}

/// Internal renderer state.
#[derive(Debug)]
struct RendererState {
    /// Whether the renderer is active.
    active: bool,
    /// Current tab ID being processed.
    current_tab_id: Option<uuid::Uuid>,
}

impl ZkVmRenderer {
    /// Create a new ZKVM renderer with an isolated communication channel.
    pub fn new(channel: Channel) -> Self {
        Self {
            channel: Arc::new(RwLock::new(channel)),
            state: Arc::new(RwLock::new(RendererState {
                active: true,
                current_tab_id: None,
            })),
        }
    }

    /// Set the current tab being processed.
    pub async fn set_current_tab(&self, tab_id: Option<uuid::Uuid>) -> TabResult<()> {
        let mut state = self.state.write().await;
        state.current_tab_id = tab_id;
        if let Some(id) = tab_id {
            log::debug!("🔒 ZKVM renderer now processing tab: {}", id);
        } else {
            log::debug!("🔒 ZKVM renderer cleared current tab");
        }
        Ok(())
    }

    /// Get the current tab being processed.
    pub async fn get_current_tab(&self) -> Option<uuid::Uuid> {
        let state = self.state.read().await;
        state.current_tab_id
    }

    /// Start the isolated renderer loop.
    pub async fn run(&self) -> TabResult<()> {
        log::info!("🔒 ZKVM renderer starting in isolated environment");

        loop {
            let mut channel = self.channel.write().await;
            match channel.receive().await {
                Ok(message) => {
                    drop(channel);
                    if let Err(e) = self.handle_message(message).await {
                        log::error!("🚨 ZKVM message handling error: {}", e);
                    }
                }
                Err(e) => {
                    // Expected when the host drops its end after a one-shot render.
                    log::debug!("🔒 ZKVM channel closed ({}); renderer exiting cleanly", e);
                    break;
                }
            }

            let active = self.state.read().await.active;
            if !active {
                break;
            }
        }

        log::info!("🔒 ZKVM renderer stopping - isolation boundary maintained");
        Ok(())
    }

    /// Handle incoming messages in the isolated environment.
    async fn handle_message(&self, message: ChannelMessage) -> TabResult<()> {
        match message {
            ChannelMessage::Control { command, params } => match command.as_str() {
                "render_page" => {
                    let request: RenderRequest = serde_json::from_str(&params).map_err(|e| {
                        TabError::InvalidOperation(format!(
                            "ZKVM render request parse failed: {}",
                            e
                        ))
                    })?;
                    log::info!(
                        "🎨 ZKVM: render_page for {} ({} bytes)",
                        request.url,
                        request.html.len()
                    );
                    let rendered = render_in_isolation(&request);
                    log::info!(
                        "✅ ZKVM: produced {} display items, {} elements blocked",
                        rendered.display_list.len(),
                        rendered.security_metadata.blocked_elements
                    );
                    let response = ChannelMessage::Control {
                        command: "rendered_content".to_string(),
                        params: serde_json::to_string(&rendered).map_err(|e| {
                            TabError::InvalidOperation(format!("ZKVM serialize failed: {}", e))
                        })?,
                    };
                    let channel = self.channel.write().await;
                    channel.send(response).await.map_err(|e| {
                        TabError::InvalidOperation(format!("ZKVM boundary send failed: {}", e))
                    })?;
                }
                "shutdown" => {
                    log::info!("🔒 ZKVM: shutdown");
                    self.state.write().await.active = false;
                }
                other => log::warn!("🚨 ZKVM: unknown command: {}", other),
            },
            ChannelMessage::ResourceRequest { url, .. } => {
                log::debug!("🌐 ZKVM: resource request for {} (forwarded to host)", url);
            }
            _ => log::warn!("🚨 ZKVM: unexpected message type"),
        }
        Ok(())
    }
}

/// Parse, sanitize, and lay out untrusted HTML entirely within the boundary.
///
/// This is a pure function of the request: same bytes in, same display list out.
pub fn render_in_isolation(request: &RenderRequest) -> RenderedContent {
    // Parse the untrusted bytes inside the boundary with a bounded-depth context.
    let security_context = Arc::new(ParserSecurityContext::new(15));
    let vw = request.viewport_width.max(120.0);
    let vh = vw * 0.75; // No explicit viewport height crosses the boundary; approximate.
    let mut blocked: usize = 0;

    let dom = match parse_html(&request.html, security_context.clone()) {
        Ok(dom) => dom,
        Err(e) => {
            log::error!("🚨 ZKVM: HTML parse failed (failing closed): {}", e);
            return RenderedContent {
                url: request.url.clone(),
                title: String::new(),
                display_list: Vec::new(),
                width: vw,
                height: 0.0,
                background: [255, 255, 255],
                content_width: vw,
                security_metadata: SecurityMetadata {
                    sanitized: true,
                    blocked_elements: blocked,
                    applied_policies: applied_policies(),
                },
            };
        }
    };

    // Parse the page's own <style> CSS inside the boundary and cascade it.
    let mut css = String::new();
    extract_css(&dom.root(), &mut css);
    let sheet = parse_css(&css, security_context.clone()).unwrap_or_else(|_| CitadelStylesheet {
        rules: Vec::new(),
        security_context,
    });
    let ctx = StyleCtx { sheet: &sheet, vw, vh };

    // Page background + centered content width come from the body's computed style.
    let body = sheet.compute_styles("body", &[], None);
    let background = body
        .background_color
        .as_ref()
        .and_then(color_to_rgb)
        .unwrap_or([255, 255, 255]);
    let content_width = resolve_content_width(&body, vw, vh);

    let mut items = Vec::new();
    collect_blocks(&dom.root(), &mut items, &mut blocked, false, &ctx);
    let (_w, height) = layout_blocks(&mut items, content_width);

    RenderedContent {
        url: request.url.clone(),
        title: dom.get_title(),
        display_list: items,
        width: vw,
        height,
        background,
        content_width,
        security_metadata: SecurityMetadata {
            sanitized: true,
            blocked_elements: blocked,
            applied_policies: applied_policies(),
        },
    }
}

/// The fixed list of security policies applied at the boundary.
fn applied_policies() -> Vec<String> {
    vec![
        "zkvm_isolation".to_string(),
        "dom_level_sanitization".to_string(),
        "script_style_pruning".to_string(),
        "dangerous_scheme_blocking".to_string(),
        "css_cascade_in_boundary".to_string(),
    ]
}

/// Resolve the centered content-column width from the body's width/max-width.
/// Falls back to the full viewport minus margins when the page sets no width.
fn resolve_content_width(body: &citadel_parser::ComputedStyle, vw: f32, vh: f32) -> f32 {
    let from_width = body.width.as_ref().and_then(|l| length_to_px(l, vw, vh));
    let from_max = body.max_width.as_ref().and_then(|l| length_to_px(l, vw, vh));
    let candidate = match (from_width, from_max) {
        (Some(w), Some(m)) => w.min(m),
        (Some(w), None) => w,
        (None, Some(m)) => m.min(vw),
        (None, None) => vw - 48.0,
    };
    candidate.clamp(200.0, vw)
}

/// Collect the text of every `<style>` element into `out` (parsed as page CSS).
fn extract_css(handle: &NodeHandle, out: &mut String) {
    let Ok(node) = handle.read() else { return };
    match &node.data {
        NodeData::Element(el) => {
            if el.local_name().eq_ignore_ascii_case("style") {
                let mut text = String::new();
                collect_raw_text(&node.children, &mut text);
                out.push_str(&text);
                out.push('\n');
                return;
            }
            for child in node.children() {
                extract_css(child, out);
            }
        }
        NodeData::Document => {
            for child in node.children() {
                extract_css(child, out);
            }
        }
        _ => {}
    }
}

/// Concatenate direct text children (used for `<style>` contents).
fn collect_raw_text(children: &[NodeHandle], out: &mut String) {
    for child in children {
        if let Ok(c) = child.read() {
            if let NodeData::Text(t) = &c.data {
                out.push_str(t);
            }
        }
    }
}

/// Convert a CSS colour value to RGB.
fn color_to_rgb(color: &ColorValue) -> Option<[u8; 3]> {
    match color {
        ColorValue::Rgb(r, g, b) => Some([*r, *g, *b]),
        ColorValue::Hex(hex) => parse_hex(hex),
        ColorValue::Named(name) => named_color(name),
    }
}

/// Parse a `#rgb` or `#rrggbb` hex colour.
fn parse_hex(hex: &str) -> Option<[u8; 3]> {
    let hex = hex.trim().trim_start_matches('#');
    match hex.len() {
        6 => {
            let r = u8::from_str_radix(hex.get(0..2)?, 16).ok()?;
            let g = u8::from_str_radix(hex.get(2..4)?, 16).ok()?;
            let b = u8::from_str_radix(hex.get(4..6)?, 16).ok()?;
            Some([r, g, b])
        }
        3 => {
            let r = u8::from_str_radix(hex.get(0..1)?, 16).ok()?.saturating_mul(17);
            let g = u8::from_str_radix(hex.get(1..2)?, 16).ok()?.saturating_mul(17);
            let b = u8::from_str_radix(hex.get(2..3)?, 16).ok()?.saturating_mul(17);
            Some([r, g, b])
        }
        _ => None,
    }
}

/// Resolve a handful of common CSS named colours.
fn named_color(name: &str) -> Option<[u8; 3]> {
    Some(match name.trim().to_ascii_lowercase().as_str() {
        "black" => [0, 0, 0],
        "white" => [255, 255, 255],
        "red" => [255, 0, 0],
        "green" => [0, 128, 0],
        "blue" => [0, 0, 255],
        "gray" | "grey" => [128, 128, 128],
        "silver" => [192, 192, 192],
        "navy" => [0, 0, 128],
        "transparent" => return None,
        _ => return None,
    })
}

/// Resolve a CSS length to pixels, given the viewport for relative units.
fn length_to_px(length: &LengthValue, vw: f32, vh: f32) -> Option<f32> {
    Some(match length {
        LengthValue::Px(px) => *px,
        LengthValue::Em(em) | LengthValue::Rem(em) => em * 16.0,
        LengthValue::Percent(p) => (p / 100.0) * vw,
        LengthValue::Vw(v) => (v / 100.0) * vw,
        LengthValue::Vh(v) => (v / 100.0) * vh,
        LengthValue::Vmin(v) => (v / 100.0) * vw.min(vh),
        LengthValue::Vmax(v) => (v / 100.0) * vw.max(vh),
        LengthValue::Zero => 0.0,
        LengthValue::Auto | LengthValue::Ch(_) | LengthValue::Ex(_) => return None,
    })
}

/// Resolve the visual style for a block element: CSS cascade overrides tag defaults.
fn resolve_block_style(
    ctx: &StyleCtx,
    tag: &str,
    classes: &[String],
    id: Option<&str>,
    inherited_bold: bool,
) -> (f32, bool, [u8; 3], DisplayKind) {
    let (def_size, def_bold, def_color, kind) = style_for(tag, inherited_bold);
    let computed = ctx.sheet.compute_styles(tag, classes, id);

    let font_size = computed
        .font_size
        .as_ref()
        .and_then(|l| length_to_px(l, ctx.vw, ctx.vh))
        .filter(|s| *s > 0.0)
        .unwrap_or(def_size);
    let bold = match computed.font_weight.as_deref() {
        Some("bold" | "bolder" | "600" | "700" | "800" | "900") => true,
        Some("normal" | "lighter" | "100" | "200" | "300" | "400") => false,
        _ => def_bold,
    };
    let color = computed.color.as_ref().and_then(color_to_rgb).unwrap_or(def_color);
    (font_size, bold, color, kind)
}

/// Collapse all runs of ASCII/Unicode whitespace to single spaces and trim.
fn collapse_ws(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Recursively concatenate visible descendant text, pruning non-visual subtrees.
fn collect_text(handle: &NodeHandle, out: &mut String) {
    let Ok(node) = handle.read() else {
        return;
    };
    match &node.data {
        NodeData::Text(t) => out.push_str(t),
        NodeData::Element(el) => {
            let tag = el.local_name().to_ascii_lowercase();
            if SKIP_TAGS.contains(&tag.as_str()) {
                return;
            }
            for child in node.children() {
                collect_text(child, out);
            }
        }
        NodeData::Document => {
            for child in node.children() {
                collect_text(child, out);
            }
        }
        _ => {}
    }
}

/// Block schemes that can exfiltrate or execute. Returns `None` (blocked) for them.
fn sanitize_href(raw: Option<String>, blocked: &mut usize) -> Option<String> {
    let href = raw?;
    let trimmed = href.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    const DANGEROUS: &[&str] = &["javascript:", "data:", "vbscript:", "file:"];
    if DANGEROUS.iter().any(|p| lower.starts_with(p)) {
        *blocked = blocked.saturating_add(1);
        return None;
    }
    Some(trimmed.to_string())
}

/// Style tuple `(font_size, bold, rgb, kind)` derived from a block tag.
fn style_for(tag: &str, inherited_bold: bool) -> (f32, bool, [u8; 3], DisplayKind) {
    match tag {
        "h1" => (32.0, true, [17, 17, 17], DisplayKind::Heading),
        "h2" => (26.0, true, [17, 17, 17], DisplayKind::Heading),
        "h3" => (22.0, true, [17, 17, 17], DisplayKind::Heading),
        "h4" | "h5" | "h6" => (18.0, true, [17, 17, 17], DisplayKind::Heading),
        "pre" | "code" => (14.0, inherited_bold, [34, 34, 34], DisplayKind::Paragraph),
        _ => (16.0, inherited_bold, [34, 34, 34], DisplayKind::Paragraph),
    }
}

/// Flush accumulated inline text as one block-level display item with a resolved
/// (CSS-cascaded) style.
fn flush_inline(
    inline: &mut String,
    out: &mut Vec<DisplayItem>,
    font_size: f32,
    bold: bool,
    color: [u8; 3],
    kind: DisplayKind,
) {
    let text = collapse_ws(inline);
    inline.clear();
    if text.is_empty() {
        return;
    }
    out.push(DisplayItem {
        kind,
        text,
        href: None,
        x: 0.0,
        y: 0.0,
        width: 0.0,
        height: 0.0,
        font_size,
        bold,
        color,
    });
}

/// Read an element node's classes and id for CSS selector matching.
fn element_selectors(handle: &NodeHandle) -> (Vec<String>, Option<String>) {
    match handle.read() {
        Ok(node) => (node.classes().unwrap_or_default(), node.element_id()),
        Err(_) => (Vec::new(), None),
    }
}

/// Push a sanitized link run, styled by the `a` cascade (default link blue).
fn push_link(handle: &NodeHandle, href: Option<String>, out: &mut Vec<DisplayItem>, ctx: &StyleCtx) {
    let mut text = String::new();
    collect_text(handle, &mut text);
    let text = collapse_ws(&text);
    if text.is_empty() {
        return;
    }
    let (classes, id) = element_selectors(handle);
    let computed = ctx.sheet.compute_styles("a", &classes, id.as_deref());
    let color = computed.color.as_ref().and_then(color_to_rgb).unwrap_or([20, 80, 200]);
    let font_size = computed
        .font_size
        .as_ref()
        .and_then(|l| length_to_px(l, ctx.vw, ctx.vh))
        .filter(|s| *s > 0.0)
        .unwrap_or(16.0);
    out.push(DisplayItem {
        kind: DisplayKind::Link,
        text,
        href,
        x: 0.0,
        y: 0.0,
        width: 0.0,
        height: 0.0,
        font_size,
        bold: false,
        color,
    });
}

/// Walk the DOM, emitting block-level display items in document order.
///
/// Non-visual / dangerous subtrees are pruned (counted in `blocked`). Inline text
/// is merged into its parent block; `<a>` elements become their own link runs.
fn collect_blocks(
    handle: &NodeHandle,
    out: &mut Vec<DisplayItem>,
    blocked: &mut usize,
    inherited_bold: bool,
    ctx: &StyleCtx,
) {
    let Ok(node) = handle.read() else {
        *blocked = blocked.saturating_add(1);
        return;
    };

    match &node.data {
        NodeData::Document => {
            for child in node.children() {
                collect_blocks(child, out, blocked, inherited_bold, ctx);
            }
        }
        NodeData::Text(t) => {
            let text = collapse_ws(t);
            if !text.is_empty() {
                let (fs, b, c, k) = resolve_block_style(ctx, "p", &[], None, inherited_bold);
                flush_inline(&mut text.clone(), out, fs, b, c, k);
            }
        }
        NodeData::Element(el) => {
            let tag = el.local_name().to_ascii_lowercase();
            if SKIP_TAGS.contains(&tag.as_str()) {
                *blocked = blocked.saturating_add(1);
                return;
            }

            // A link element becomes a single sanitized link run.
            if tag == "a" {
                let href = sanitize_href(el.get_attribute("href"), blocked);
                push_link(handle, href, out, ctx);
                return;
            }

            // Cascade this element's style once and reuse it for its inline runs.
            let classes = node.classes().unwrap_or_default();
            let id = node.element_id();
            let (font_size, bold, color, kind) =
                resolve_block_style(ctx, &tag, &classes, id.as_deref(), inherited_bold);
            let mut inline = String::new();

            for child in node.children() {
                let Ok(child_node) = child.read() else {
                    *blocked = blocked.saturating_add(1);
                    continue;
                };
                match &child_node.data {
                    NodeData::Text(t) => inline.push_str(t),
                    NodeData::Element(child_el) => {
                        let child_tag = child_el.local_name().to_ascii_lowercase();
                        if SKIP_TAGS.contains(&child_tag.as_str()) {
                            *blocked = blocked.saturating_add(1);
                            continue;
                        }
                        if child_tag == "a" {
                            flush_inline(&mut inline, out, font_size, bold, color, kind);
                            let href = sanitize_href(child_el.get_attribute("href"), blocked);
                            push_link(child, href, out, ctx);
                        } else if INLINE_TAGS.contains(&child_tag.as_str()) {
                            collect_text(child, &mut inline);
                        } else {
                            // Block-level child: flush the current inline run, then recurse.
                            flush_inline(&mut inline, out, font_size, bold, color, kind);
                            drop(child_node);
                            collect_blocks(child, out, blocked, bold, ctx);
                        }
                    }
                    _ => {}
                }
            }
            flush_inline(&mut inline, out, font_size, bold, color, kind);
        }
        _ => {}
    }
}

/// Assign positions/sizes to each item via simple vertical block flow.
///
/// Returns `(content_width, total_height)`.
fn layout_blocks(items: &mut [DisplayItem], content_width: f32) -> (f32, f32) {
    let cw = content_width.max(120.0);
    let pad: f32 = 16.0;
    let mut y = pad;

    for item in items.iter_mut() {
        let line_height = item.font_size * 1.4;
        let avg_char = (item.font_size * 0.52).max(1.0);
        let chars_per_line = ((cw / avg_char).floor() as usize).max(1);
        let n_chars = item.text.chars().count().max(1);
        let lines = n_chars.div_ceil(chars_per_line).max(1);
        let height = (lines as f32) * line_height + item.font_size * 0.4;

        item.x = 0.0;
        item.y = y;
        item.width = cw;
        item.height = height;

        let gap = if item.kind == DisplayKind::Heading {
            item.font_size * 0.5
        } else {
            item.font_size * 0.7
        };
        y += height + gap;
    }

    (cw, y + pad)
}

/// Create and run a ZKVM renderer task with full isolation.
pub async fn spawn_zkvm_renderer(channel: Channel) -> TabResult<()> {
    let renderer = ZkVmRenderer::new(channel);
    renderer.run().await
}
