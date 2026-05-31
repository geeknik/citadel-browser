//! Live integration test for the in-house HTTPS client (Tier-2 dep cut).
//!
//! Hits the network. The deterministic parsing logic is covered by unit tests in
//! `http.rs`; this proves the real TCP + rustls 0.23 + HTTP/1.1 path end-to-end.

use citadel_networking::https_fetch;
use url::Url;

#[tokio::test]
async fn fetches_example_com_over_https() {
    let url = Url::parse("https://example.com/").expect("url");
    let resp = https_fetch(
        &url,
        &[("User-Agent".to_string(), "Citadel/0.0.1-alpha".to_string())],
    )
    .await
    .expect("fetch example.com");

    assert_eq!(resp.status, 200, "expected 200, got {}", resp.status);
    let body = resp.body_text();
    assert!(
        body.contains("Example Domain"),
        "body should contain 'Example Domain'"
    );
    // The TLS + redirect-aware client records where it ended up.
    assert!(resp.final_url.starts_with("https://"));
}

#[tokio::test]
async fn rejects_plain_http() {
    let url = Url::parse("http://example.com/").expect("url");
    let err = https_fetch(&url, &[]).await;
    assert!(err.is_err(), "plain http must be rejected (HTTPS-only)");
}
