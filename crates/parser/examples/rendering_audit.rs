//! Phase 2: Rendering Reality Check
//!
//! Tests the rendering pipeline against 11 locked target sites.
//! Reports what works, what breaks, and categorizes gaps.
//!
//! Run: cargo run -p citadel-parser --example rendering_audit

use citadel_parser::{parse_css, compute_layout, CitadelStylesheet};
use citadel_parser::html::parse_html;
use citadel_parser::security::SecurityContext;
use std::sync::Arc;
use std::time::Instant;

struct SiteResult {
    url: String,
    tier: &'static str,
    fetch_ok: bool,
    fetch_size: usize,
    parse_ok: bool,
    elements_count: usize,
    text_content_len: usize,
    css_rules: usize,
    layout_ok: bool,
    layout_nodes: usize,
    js_scripts_found: usize,
    errors: Vec<String>,
    duration_ms: u128,
}

fn main() {
    println!("=== Citadel Browser Rendering Reality Check ===");
    println!("Testing pipeline: fetch -> parse HTML -> parse CSS -> compute layout\n");

    let sites = vec![
        ("https://example.com", "Tier 1"),
        ("https://motherfuckingwebsite.com", "Tier 1"),
        ("https://lite.cnn.com", "Tier 1"),
        ("https://news.ycombinator.com", "Tier 2"),
        ("https://en.wikipedia.org/wiki/Rust_(programming_language)", "Tier 2"),
        ("https://www.nytimes.com", "Tier 3"),
        ("https://old.reddit.com", "Tier 3"),
        ("https://coveryourtracks.eff.org", "Tier 4"),
        ("https://browserleaks.com", "Tier 4"),
    ];

    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Citadel/0.0.1-alpha")
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .expect("Failed to create HTTP client");

    let mut results: Vec<SiteResult> = Vec::new();

    for (url, tier) in &sites {
        print!("[{}] {} ... ", tier, url);
        let start = Instant::now();
        let result = rt.block_on(test_site(&client, url, tier));
        let duration = start.elapsed().as_millis();

        let mut result = result;
        result.duration_ms = duration;

        if result.parse_ok && result.layout_ok {
            println!("OK ({} elements, {} layout nodes, {}ms)",
                result.elements_count, result.layout_nodes, duration);
        } else if result.fetch_ok && result.parse_ok {
            println!("PARTIAL (parsed {} elements, layout failed, {}ms)",
                result.elements_count, duration);
        } else if result.fetch_ok {
            println!("PARSE FAIL ({}ms)", duration);
        } else {
            println!("FETCH FAIL ({}ms)", duration);
        }

        for err in &result.errors {
            println!("  ERROR: {}", err);
        }
        results.push(result);
    }

    println!("\n{}", "=".repeat(80));
    print_summary(&results);
    print_gap_analysis(&results);
}

async fn test_site(client: &reqwest::Client, url: &str, tier: &'static str) -> SiteResult {
    let mut result = SiteResult {
        url: url.to_string(),
        tier,
        fetch_ok: false,
        fetch_size: 0,
        parse_ok: false,
        elements_count: 0,
        text_content_len: 0,
        css_rules: 0,
        layout_ok: false,
        layout_nodes: 0,
        js_scripts_found: 0,
        errors: Vec::new(),
        duration_ms: 0,
    };

    // Step 1: Fetch
    let html = match client.get(url).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                result.errors.push(format!("HTTP {}", response.status()));
                return result;
            }
            match response.text().await {
                Ok(text) => {
                    result.fetch_ok = true;
                    result.fetch_size = text.len();
                    text
                }
                Err(e) => {
                    result.errors.push(format!("Body read error: {}", e));
                    return result;
                }
            }
        }
        Err(e) => {
            result.errors.push(format!("Fetch error: {}", e));
            return result;
        }
    };

    // Step 2: Parse HTML
    let security_context = Arc::new(SecurityContext::new(10));
    let dom = match parse_html(&html, security_context.clone()) {
        Ok(dom) => {
            result.parse_ok = true;
            result.text_content_len = dom.get_text_content().len();

            // Count elements
            let all_elements = dom.get_elements_by_tag_name("*");
            result.elements_count = all_elements.len();

            // Count script tags
            let scripts = dom.get_elements_by_tag_name("script");
            result.js_scripts_found = scripts.len();

            dom
        }
        Err(e) => {
            result.errors.push(format!("Parse error: {}", e));
            return result;
        }
    };

    // Step 3: Extract and parse inline CSS
    let mut combined_css = String::new();
    let style_elements = dom.get_elements_by_tag_name("style");
    for style_handle in &style_elements {
        if let Ok(node) = style_handle.read() {
            combined_css.push_str(&node.text_content());
            combined_css.push('\n');
        }
    }

    let stylesheet = if !combined_css.is_empty() {
        match parse_css(&combined_css, security_context.clone()) {
            Ok(ss) => {
                result.css_rules = ss.rules.len();
                ss
            }
            Err(e) => {
                result.errors.push(format!("CSS parse error: {}", e));
                CitadelStylesheet::new(security_context.clone())
            }
        }
    } else {
        CitadelStylesheet::new(security_context.clone())
    };

    // Step 4: Compute layout
    match compute_layout(&dom, &stylesheet, 1280.0, 800.0) {
        Ok(layout) => {
            result.layout_ok = true;
            result.layout_nodes = layout.node_layouts.len();
        }
        Err(e) => {
            result.errors.push(format!("Layout error: {}", e));
        }
    }

    result
}

fn print_summary(results: &[SiteResult]) {
    println!("\nSUMMARY");
    println!("{}", "-".repeat(80));
    println!("{:<45} {:>6} {:>6} {:>6} {:>6} {:>6}",
        "URL", "Fetch", "Parse", "CSS", "Layout", "Time");
    println!("{}", "-".repeat(80));

    let mut pass_count = 0;
    for r in results {
        let fetch = if r.fetch_ok { "OK" } else { "FAIL" };
        let parse = if r.parse_ok { format!("{}", r.elements_count) } else { "FAIL".to_string() };
        let css = format!("{}", r.css_rules);
        let layout = if r.layout_ok { format!("{}", r.layout_nodes) } else { "FAIL".to_string() };

        let short_url = if r.url.len() > 43 { format!("{}...", &r.url[..40]) } else { r.url.clone() };
        println!("{:<45} {:>6} {:>6} {:>6} {:>6} {:>4}ms",
            short_url, fetch, parse, css, layout, r.duration_ms);

        if r.parse_ok && r.layout_ok && r.text_content_len > 0 {
            pass_count += 1;
        }
    }

    println!("{}", "-".repeat(80));
    println!("\nRendering pipeline success: {}/{} sites", pass_count, results.len());
    println!("Success criterion: 3/{} sites render recognizably (2 from Tier 1/2)", results.len());

    if pass_count >= 3 {
        println!("STATUS: CRITERION MET");
    } else {
        println!("STATUS: CRITERION NOT MET (need {} more)", 3 - pass_count);
    }
}

fn print_gap_analysis(results: &[SiteResult]) {
    println!("\nGAP ANALYSIS");
    println!("{}", "-".repeat(80));

    // Collect all errors by category
    let mut layout_gaps = Vec::new();
    let mut css_gaps = Vec::new();
    let mut fetch_gaps = Vec::new();
    let mut js_heavy_sites = Vec::new();

    for r in results {
        if !r.fetch_ok {
            fetch_gaps.push(format!("{}: {}", r.url, r.errors.first().map(|s| s.as_str()).unwrap_or("unknown")));
        }
        if r.fetch_ok && !r.layout_ok {
            layout_gaps.push(format!("{}: {}", r.url, r.errors.iter().find(|e| e.contains("Layout")).map(|s| s.as_str()).unwrap_or("unknown layout error")));
        }
        if r.css_rules == 0 && r.fetch_ok {
            css_gaps.push(format!("{}: No inline CSS parsed (external stylesheets not loaded)", r.url));
        }
        if r.js_scripts_found > 10 {
            js_heavy_sites.push(format!("{}: {} script tags (JS-heavy, may render blank without execution)", r.url, r.js_scripts_found));
        }
    }

    if !fetch_gaps.is_empty() {
        println!("\nNetwork gaps:");
        for g in &fetch_gaps { println!("  - {}", g); }
    }
    if !layout_gaps.is_empty() {
        println!("\nLayout gaps:");
        for g in &layout_gaps { println!("  - {}", g); }
    }
    if !css_gaps.is_empty() {
        println!("\nCSS gaps:");
        for g in &css_gaps { println!("  - {}", g); }
    }
    if !js_heavy_sites.is_empty() {
        println!("\nJS-heavy sites (content may require JS execution):");
        for g in &js_heavy_sites { println!("  - {}", g); }
    }

    // Summary stats
    let total_elements: usize = results.iter().map(|r| r.elements_count).sum();
    let total_text: usize = results.iter().map(|r| r.text_content_len).sum();
    let total_scripts: usize = results.iter().map(|r| r.js_scripts_found).sum();
    println!("\nAggregate stats:");
    println!("  Total elements parsed: {}", total_elements);
    println!("  Total text content: {} chars", total_text);
    println!("  Total script tags found: {}", total_scripts);
}
