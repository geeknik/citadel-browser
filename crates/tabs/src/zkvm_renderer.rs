//! ZKVM-isolated renderer for secure tab content processing.
//!
//! This module runs *inside* the ZKVM isolation boundary. Untrusted page bytes
//! enter only through the encrypted [`Channel`]; the renderer parses, sanitizes,
//! and lays them out here, and emits a serializable display list back across the
//! boundary. The host never touches the raw markup — it only paints the sanitized
//! display list. That is the "zero-knowledge tab" property in practice.

use crate::{TabError, TabResult};
use citadel_parser::{
    dom::NodeData, dom::NodeHandle, parse_html, security::SecurityContext as ParserSecurityContext,
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
    /// Total content width in logical pixels.
    pub width: f32,
    /// Total content height in logical pixels (for scrolling).
    pub height: f32,
    /// What the boundary sanitized.
    pub security_metadata: SecurityMetadata,
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
    let mut blocked: usize = 0;

    let (title, mut items) = match parse_html(&request.html, security_context) {
        Ok(dom) => {
            let mut items = Vec::new();
            collect_blocks(&dom.root(), &mut items, &mut blocked, false);
            (dom.get_title(), items)
        }
        Err(e) => {
            log::error!("🚨 ZKVM: HTML parse failed (failing closed): {}", e);
            (String::new(), Vec::new())
        }
    };

    let (width, height) = layout_blocks(&mut items, request.viewport_width);

    RenderedContent {
        url: request.url.clone(),
        title,
        display_list: items,
        width,
        height,
        security_metadata: SecurityMetadata {
            sanitized: true,
            blocked_elements: blocked,
            applied_policies: vec![
                "zkvm_isolation".to_string(),
                "dom_level_sanitization".to_string(),
                "script_style_pruning".to_string(),
                "dangerous_scheme_blocking".to_string(),
            ],
        },
    }
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

/// Flush accumulated inline text as one block-level display item.
fn flush_inline(inline: &mut String, out: &mut Vec<DisplayItem>, tag: &str, bold: bool) {
    let text = collapse_ws(inline);
    inline.clear();
    if text.is_empty() {
        return;
    }
    let (font_size, is_bold, color, kind) = style_for(tag, bold);
    out.push(DisplayItem {
        kind,
        text,
        href: None,
        x: 0.0,
        y: 0.0,
        width: 0.0,
        height: 0.0,
        font_size,
        bold: is_bold,
        color,
    });
}

/// Push a sanitized link run.
fn push_link(handle: &NodeHandle, href: Option<String>, out: &mut Vec<DisplayItem>) {
    let mut text = String::new();
    collect_text(handle, &mut text);
    let text = collapse_ws(&text);
    if text.is_empty() {
        return;
    }
    out.push(DisplayItem {
        kind: DisplayKind::Link,
        text,
        href,
        x: 0.0,
        y: 0.0,
        width: 0.0,
        height: 0.0,
        font_size: 16.0,
        bold: false,
        color: [20, 80, 200],
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
) {
    let Ok(node) = handle.read() else {
        *blocked = blocked.saturating_add(1);
        return;
    };

    match &node.data {
        NodeData::Document => {
            for child in node.children() {
                collect_blocks(child, out, blocked, inherited_bold);
            }
        }
        NodeData::Text(t) => {
            let text = collapse_ws(t);
            if !text.is_empty() {
                flush_inline(&mut text.clone(), out, "p", inherited_bold);
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
                push_link(handle, href, out);
                return;
            }

            let bold = inherited_bold || tag == "b" || tag == "strong";
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
                            flush_inline(&mut inline, out, &tag, bold);
                            let href = sanitize_href(child_el.get_attribute("href"), blocked);
                            push_link(child, href, out);
                        } else if INLINE_TAGS.contains(&child_tag.as_str()) {
                            collect_text(child, &mut inline);
                        } else {
                            // Block-level child: flush the current inline run, then recurse.
                            flush_inline(&mut inline, out, &tag, bold);
                            drop(child_node);
                            collect_blocks(child, out, blocked, bold);
                        }
                    }
                    _ => {}
                }
            }
            flush_inline(&mut inline, out, &tag, bold);
        }
        _ => {}
    }
}

/// Assign positions/sizes to each item via simple vertical block flow.
///
/// Returns `(content_width, total_height)`.
fn layout_blocks(items: &mut [DisplayItem], viewport_width: f32) -> (f32, f32) {
    let margin: f32 = 24.0;
    let content_width = (viewport_width - margin * 2.0).max(120.0);
    let mut y = margin;

    for item in items.iter_mut() {
        let line_height = item.font_size * 1.4;
        let avg_char = (item.font_size * 0.52).max(1.0);
        let chars_per_line = ((content_width / avg_char).floor() as usize).max(1);
        let n_chars = item.text.chars().count().max(1);
        let lines = n_chars.div_ceil(chars_per_line).max(1);
        let height = (lines as f32) * line_height + item.font_size * 0.4;

        item.x = margin;
        item.y = y;
        item.width = content_width;
        item.height = height;

        let gap = if item.kind == DisplayKind::Heading {
            item.font_size * 0.5
        } else {
            item.font_size * 0.7
        };
        y += height + gap;
    }

    (viewport_width.max(content_width), y + margin)
}

/// Create and run a ZKVM renderer task with full isolation.
pub async fn spawn_zkvm_renderer(channel: Channel) -> TabResult<()> {
    let renderer = ZkVmRenderer::new(channel);
    renderer.run().await
}
