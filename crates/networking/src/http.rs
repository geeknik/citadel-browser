//! Minimal in-house HTTPS/1.1 client over rustls.
//!
//! Replaces reqwest/hyper for page fetches (dependency-budget Tier-2). It is
//! deliberately small and HTTPS-only:
//! - TLS is rustls 0.23 with bundled Mozilla roots — we never hand-roll crypto.
//! - `Connection: close` (no keep-alive pool) keeps the state machine tiny.
//! - Response size is bounded (DoS) and redirects are capped.
//! - Hostnames resolve via the std resolver (`TcpStream::connect`), so the DNS
//!   library is no longer on the page-fetch hot path.
//!
//! **Request-shape uniformity.** Every Citadel user emits the *same* browser-like
//! request — identical header set, order, casing, and values — so the HTTP-layer
//! fingerprint identifies "Citadel", not the individual (an anonymity-set goal,
//! same doctrine as the normalized JS identity). We do NOT randomize per request:
//! jitter would make each user *more* unique, not less.
//!
//! Known residual tells, tracked on the roadmap (defense-in-depth, secondary to
//! the JS/API binding cage and to network-level anonymity i.e. the IP itself):
//! - `Connection: close` (browsers keep-alive) — our client is genuinely one-shot.
//! - HTTP/1.1 only (browsers negotiate HTTP/2).
//! - TLS ClientHello / JA3 is rustls's, not Chrome's (rustls resists impersonation).
//! - SNI and DNS are still plaintext — ECH + DoH/DoT is the fix (needs DNS work).

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use url::Url;

use crate::error::NetworkError;

/// Maximum response body we will buffer (DoS bound). Also caps *decompressed*
/// output so a small gzip body cannot expand into a memory-exhaustion bomb.
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
/// Per-request network timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum redirects to follow.
const MAX_REDIRECTS: u8 = 5;

// ---------------------------------------------------------------------------
// Canonical Citadel wire identity — uniform for every user.
//
// INVARIANT: `USER_AGENT` MUST stay byte-identical to
// `PrivacyProfile::normalized().user_agent` in crates/parser/src/js/bindings.rs.
// A mismatch between the wire `User-Agent` and the JS `navigator.userAgent` is
// itself a high-entropy fingerprint. (Roadmap: hoist this into one shared const
// so the two layers cannot drift.)
// ---------------------------------------------------------------------------

/// Chrome 120 on Windows — matches the JS navigator identity exactly.
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
/// Chrome's default top-level navigation `Accept`.
const ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
/// Matches the normalized `navigator.languages` (en-US, en).
const ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";
/// Only what we can actually decode. (Roadmap: add br/zstd to byte-match Chrome's
/// `gzip, deflate, br, zstd` — needs brotli/zstd decoders.)
const ACCEPT_ENCODING: &str = "gzip, deflate";
/// Client-hint brand list for Chrome 120.
const SEC_CH_UA: &str = "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"";

/// Headers we author and own: a caller may not override them (that would break
/// the uniform shape) — they are dropped from `extra_headers`, case-insensitively.
const MANAGED_HEADERS: &[&str] = &[
    "host",
    "connection",
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
    "upgrade-insecure-requests",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
];

/// A parsed HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The URL the response was ultimately served from (after redirects).
    pub final_url: String,
}

impl HttpResponse {
    /// Case-insensitive header lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The body decoded as UTF-8 (lossily).
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Fetch a URL over HTTPS, following up to `MAX_REDIRECTS` redirects.
///
/// `extra_headers` are appended to the request (Host/Connection are managed here;
/// CRLF-bearing entries are dropped to prevent header injection).
pub async fn fetch(
    url: &Url,
    extra_headers: &[(String, String)],
) -> Result<HttpResponse, NetworkError> {
    let mut current = url.clone();
    for _ in 0..=MAX_REDIRECTS {
        let resp = request_once(&current, extra_headers).await?;
        if (300..400).contains(&resp.status) && resp.status != 304 {
            if let Some(location) = resp.header("location") {
                let next = current
                    .join(location)
                    .map_err(NetworkError::UrlError)?;
                if next.scheme() != "https" {
                    return Err(NetworkError::HttpsEnforcementError(format!(
                        "redirect to non-HTTPS URL: {next}"
                    )));
                }
                current = next;
                continue;
            }
        }
        return Ok(resp);
    }
    Err(NetworkError::ConnectionError("too many redirects".into()))
}

/// Build the uniform, browser-like request line + header block.
///
/// The header set, order, casing, and values are fixed and identical for every
/// user (uniformity, not randomization). `extra_headers` may add only headers we
/// do not manage (e.g. conditional-request validators); managed headers and any
/// CRLF-bearing entries are dropped, so a caller cannot perturb the shape or
/// smuggle headers via injection.
fn build_request(target: &str, host: &str, extra_headers: &[(String, String)]) -> String {
    // Chrome's HTTP/1.1 navigation header order.
    let mut request = String::with_capacity(512);
    request.push_str("GET ");
    request.push_str(target);
    request.push_str(" HTTP/1.1\r\n");
    request.push_str("Host: ");
    request.push_str(host);
    request.push_str("\r\n");
    request.push_str("Connection: close\r\n");
    request.push_str("sec-ch-ua: ");
    request.push_str(SEC_CH_UA);
    request.push_str("\r\n");
    request.push_str("sec-ch-ua-mobile: ?0\r\n");
    request.push_str("sec-ch-ua-platform: \"Windows\"\r\n");
    request.push_str("Upgrade-Insecure-Requests: 1\r\n");
    request.push_str("User-Agent: ");
    request.push_str(USER_AGENT);
    request.push_str("\r\n");
    request.push_str("Accept: ");
    request.push_str(ACCEPT);
    request.push_str("\r\n");
    request.push_str("Sec-Fetch-Site: none\r\n");
    request.push_str("Sec-Fetch-Mode: navigate\r\n");
    request.push_str("Sec-Fetch-User: ?1\r\n");
    request.push_str("Sec-Fetch-Dest: document\r\n");
    request.push_str("Accept-Encoding: ");
    request.push_str(ACCEPT_ENCODING);
    request.push_str("\r\n");
    request.push_str("Accept-Language: ");
    request.push_str(ACCEPT_LANGUAGE);
    request.push_str("\r\n");

    for (k, v) in extra_headers {
        if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
            continue; // header-injection guard
        }
        if MANAGED_HEADERS.iter().any(|m| k.eq_ignore_ascii_case(m)) {
            continue; // callers cannot override the uniform identity headers
        }
        request.push_str(k);
        request.push_str(": ");
        request.push_str(v);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request
}

/// Perform a single HTTPS GET (no redirect following).
async fn request_once(
    url: &Url,
    extra_headers: &[(String, String)],
) -> Result<HttpResponse, NetworkError> {
    if url.scheme() != "https" {
        return Err(NetworkError::HttpsEnforcementError(format!(
            "non-HTTPS URL: {url}"
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| NetworkError::ConnectionError("missing host".into()))?;
    let port = url.port().unwrap_or(443);

    // Request target = path + query (default "/").
    let mut target = String::from(url.path());
    if target.is_empty() {
        target.push('/');
    }
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }

    let request = build_request(&target, host, extra_headers);

    let raw = tokio::time::timeout(REQUEST_TIMEOUT, async {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| NetworkError::TlsError(format!("invalid server name '{host}': {e}")))?;

        let tcp = TcpStream::connect((host, port)).await?;
        let mut tls = connector.connect(server_name, tcp).await?;
        tls.write_all(request.as_bytes()).await?;
        tls.flush().await?;

        let mut buf = Vec::new();
        tls.take(MAX_RESPONSE_BYTES).read_to_end(&mut buf).await?;
        Ok::<Vec<u8>, NetworkError>(buf)
    })
    .await
    .map_err(|_| NetworkError::TimeoutError(REQUEST_TIMEOUT))??;

    parse_response(&raw, url.as_str())
}

/// Parse a raw HTTP/1.1 response into status, headers, and (de-chunked) body.
fn parse_response(raw: &[u8], final_url: &str) -> Result<HttpResponse, NetworkError> {
    let sep = find_subslice(raw, b"\r\n\r\n")
        .ok_or_else(|| NetworkError::ResourceError("malformed response (no header end)".into()))?;
    let head = String::from_utf8_lossy(raw.get(..sep).unwrap_or(&[]));
    let body_start = sep.saturating_add(4);

    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| NetworkError::ResourceError("empty response".into()))?;
    let status = parse_status(status_line)?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let raw_body = raw.get(body_start..).unwrap_or(&[]);
    let is_chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    });
    // Transport framing (chunked) first, then payload encoding (gzip/deflate).
    let framed = if is_chunked {
        dechunk(raw_body)?
    } else {
        raw_body.to_vec()
    };
    let content_encoding = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
        .map(|(_, v)| v.trim().to_ascii_lowercase());
    let body = match content_encoding.as_deref() {
        Some("gzip") | Some("x-gzip") => decompress_gzip(&framed)?,
        Some("deflate") => decompress_deflate(&framed)?,
        // identity, empty, or an encoding we never advertised: pass through.
        _ => framed,
    };

    Ok(HttpResponse {
        status,
        headers,
        body,
        final_url: final_url.to_string(),
    })
}

/// Parse the numeric status code out of a status line like `HTTP/1.1 200 OK`.
fn parse_status(line: &str) -> Result<u16, NetworkError> {
    line.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| NetworkError::ResourceError(format!("bad status line: {line}")))
}

/// Decode a chunked transfer-encoded body.
fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, NetworkError> {
    let mut out = Vec::new();
    loop {
        let nl = find_subslice(data, b"\r\n")
            .ok_or_else(|| NetworkError::ResourceError("malformed chunk header".into()))?;
        let size_field = std::str::from_utf8(data.get(..nl).unwrap_or(&[]))
            .map_err(|_| NetworkError::ResourceError("non-utf8 chunk size".into()))?;
        // A chunk size may carry extensions after ';'.
        let size_hex = size_field.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| NetworkError::ResourceError("bad chunk size".into()))?;
        data = data.get(nl.saturating_add(2)..).unwrap_or(&[]);
        if size == 0 {
            break;
        }
        let chunk = data
            .get(..size)
            .ok_or_else(|| NetworkError::ResourceError("truncated chunk".into()))?;
        out.extend_from_slice(chunk);
        // Skip the chunk's trailing CRLF.
        data = data.get(size.saturating_add(2)..).unwrap_or(&[]);
        if out.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(NetworkError::ResourceError("response too large".into()));
        }
    }
    Ok(out)
}

/// Inflate a gzip body, bounding output to `MAX_RESPONSE_BYTES` (bomb guard).
fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, NetworkError> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut out)
        .map_err(|e| NetworkError::ResourceError(format!("gzip decode failed: {e}")))?;
    Ok(out)
}

/// Inflate a `deflate` body. HTTP "deflate" is usually zlib-wrapped, but some
/// servers send raw DEFLATE; try zlib first, then fall back. Bomb-bounded.
fn decompress_deflate(data: &[u8]) -> Result<Vec<u8>, NetworkError> {
    let mut out = Vec::new();
    if flate2::read::ZlibDecoder::new(data)
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut out)
        .is_ok()
    {
        return Ok(out);
    }
    out.clear();
    flate2::read::DeflateDecoder::new(data)
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut out)
        .map_err(|e| NetworkError::ResourceError(format!("deflate decode failed: {e}")))?;
    Ok(out)
}

/// Index of the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_and_headers_and_chunked_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
        let r = parse_response(raw, "https://x.example/").unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-type"), Some("text/html"));
        assert_eq!(r.body_text(), "Hello World");
    }

    #[test]
    fn parses_identity_body() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nabc";
        let r = parse_response(raw, "https://x.example/").unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(r.body, b"abc");
    }

    #[test]
    fn rejects_response_without_header_terminator() {
        assert!(parse_response(b"HTTP/1.1 200 OK", "https://x/").is_err());
    }

    #[test]
    fn request_is_a_uniform_browser_shape() {
        let req = build_request("/", "example.com", &[]);
        assert!(req.starts_with("GET / HTTP/1.1\r\nHost: example.com\r\n"));
        assert!(req.contains(&format!("\r\nUser-Agent: {USER_AGENT}\r\n")));
        assert!(req.contains("\r\nAccept: text/html,"));
        assert!(req.contains("\r\nAccept-Encoding: gzip, deflate\r\n"));
        assert!(req.contains("\r\nAccept-Language: en-US,en;q=0.9\r\n"));
        assert!(req.contains("\r\nSec-Fetch-Mode: navigate\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
        // The scripted-client tell is gone.
        assert!(!req.contains("identity"));
    }

    #[test]
    fn wire_user_agent_matches_js_navigator_identity() {
        // INVARIANT: the wire UA must equal the JS navigator.userAgent. A drift
        // here is a fingerprint. (citadel-parser is not a dep, so assert the
        // exact literal both layers are pinned to.)
        assert_eq!(
            USER_AGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        );
    }

    #[test]
    fn caller_cannot_break_uniformity_or_inject() {
        let extra = vec![
            ("User-Agent".to_string(), "EvilBot/1.0".to_string()),
            ("X-Test".to_string(), "ok".to_string()),
            ("X-Inject".to_string(), "a\r\nEvil: 1".to_string()),
        ];
        let req = build_request("/", "h", &extra);
        // Managed identity headers are not overridable.
        assert!(!req.contains("EvilBot"));
        assert_eq!(req.matches("\r\nUser-Agent:").count(), 1);
        // Benign, unmanaged extras are allowed through.
        assert!(req.contains("\r\nX-Test: ok\r\n"));
        // CRLF injection is dropped wholesale.
        assert!(!req.contains("Evil: 1"));
    }

    #[test]
    fn decompresses_gzip_response() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"Hello World").unwrap();
        let gz = enc.finish().unwrap();

        let mut raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: ".to_vec();
        raw.extend_from_slice(gz.len().to_string().as_bytes());
        raw.extend_from_slice(b"\r\n\r\n");
        raw.extend_from_slice(&gz);

        let r = parse_response(&raw, "https://x/").unwrap();
        assert_eq!(r.body_text(), "Hello World");
    }
}
