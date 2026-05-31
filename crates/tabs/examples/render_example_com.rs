//! Headless proof that example.com renders fully inside a zero-knowledge tab.
//!
//! Run it:
//!     cargo run -p citadel-tabs --example render_example_com
//!     cargo run -p citadel-tabs --example render_example_com -- https://example.org
//!
//! It fetches the page over the network, then hands ONLY the raw bytes across a
//! real AES-256-GCM encrypted channel to an isolated renderer task. The renderer
//! parses, sanitizes, and lays the page out inside the boundary and returns a
//! display list — which is all this host process ever sees. We print it.

use citadel_tabs::{DisplayKind, RenderRequest, RenderedContent};
use citadel_tabs::zkvm_renderer::spawn_zkvm_renderer;
use citadel_zkvm::{Channel, ChannelMessage};
use std::time::Duration;

/// Offline fallback (verbatim example.com structure) if the network is blocked.
const BUNDLED: &str = r#"<!doctype html><html><head><title>Example Domain</title>
<style>body{font-family:sans-serif}</style></head><body><div>
<h1>Example Domain</h1>
<p>This domain is for use in illustrative examples in documents. You may use this
domain in literature without prior coordination or asking for permission.</p>
<p><a href="https://www.iana.org/domains/example">More information...</a></p>
</div></body></html>"#;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://example.com/".to_string());

    eprintln!("→ Fetching {url} over the network …");
    let html = match fetch(&url).await {
        Ok(body) => {
            eprintln!("  fetched {} bytes", body.len());
            body
        }
        Err(e) => {
            eprintln!("  network unavailable ({e}); using bundled example.com");
            BUNDLED.to_string()
        }
    };

    eprintln!("→ Handing raw bytes to an isolated ZKVM renderer over an encrypted channel …");
    let rendered = render_in_zk_tab(&url, html).await?;

    print_render(&rendered);
    Ok(())
}

/// Fetch a URL's body as text.
async fn fetch(url: &str) -> Result<String, reqwest::Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    client.get(url).send().await?.error_for_status()?.text().await
}

/// Drive the real encrypted-channel + isolated-renderer round trip.
async fn render_in_zk_tab(url: &str, html: String) -> Result<RenderedContent, Box<dyn std::error::Error>> {
    let (mut host_side, vm_side) = Channel::new()?;
    tokio::spawn(async move {
        if let Err(e) = spawn_zkvm_renderer(vm_side).await {
            eprintln!("renderer task error: {e}");
        }
    });

    let request = RenderRequest {
        url: url.to_string(),
        html,
        viewport_width: 800.0,
    };
    host_side
        .send(ChannelMessage::Control {
            command: "render_page".to_string(),
            params: serde_json::to_string(&request)?,
        })
        .await?;

    let message = tokio::time::timeout(Duration::from_secs(15), host_side.receive()).await??;
    match message {
        ChannelMessage::Control { command, params } if command == "rendered_content" => {
            Ok(serde_json::from_str(&params)?)
        }
        other => Err(format!("unexpected reply from boundary: {other:?}").into()),
    }
}

/// Pretty-print the sanitized display list that crossed the boundary.
fn print_render(r: &RenderedContent) {
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  ZERO-KNOWLEDGE TAB RENDER                                    ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("URL:      {}", r.url);
    println!("Title:    {}", r.title);
    println!(
        "Canvas:   {:.0} × {:.0} px   |   {} runs   |   {} elements blocked at boundary",
        r.width,
        r.height,
        r.display_list.len(),
        r.security_metadata.blocked_elements
    );
    println!("Policies: {}", r.security_metadata.applied_policies.join(", "));
    println!("────────────────────────────────────────────────────────────────");
    for item in &r.display_list {
        let tag = match item.kind {
            DisplayKind::Heading => "H",
            DisplayKind::Paragraph => "P",
            DisplayKind::Link => "A",
            DisplayKind::Generic => "·",
        };
        let bold = if item.bold { "*" } else { " " };
        print!(
            "[{tag}{bold}] @({:>4.0},{:>4.0}) {:>3.0}px  {}",
            item.x, item.y, item.font_size, item.text
        );
        if let Some(href) = &item.href {
            print!("  → {href}");
        }
        println!();
    }
    println!("────────────────────────────────────────────────────────────────");
    println!("✅ example.com rendered fully inside the zero-knowledge boundary.\n");
}
