//! Minimal in-house HTTPS/1.1 client over rustls.
//!
//! Replaces reqwest/hyper for page fetches (dependency-budget Tier-2). It is
//! deliberately small and HTTPS-only:
//! - TLS is rustls 0.23 with bundled Mozilla roots — we never hand-roll crypto.
//! - `Connection: close` (no keep-alive pool) keeps the state machine tiny.
//! - Response size is bounded (DoS) and redirects are capped.
//! - Hostnames resolve via the std resolver (`TcpStream::connect`), so the DNS
//!   library is no longer on the page-fetch hot path.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use url::Url;

use crate::error::NetworkError;

/// Maximum response body we will buffer (DoS bound).
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
/// Per-request network timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum redirects to follow.
const MAX_REDIRECTS: u8 = 5;

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

    let mut request = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept-Encoding: identity\r\n"
    );
    for (k, v) in extra_headers {
        // Header-injection guard + don't let callers override managed headers.
        if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
            continue;
        }
        if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("connection") {
            continue;
        }
        request.push_str(k);
        request.push_str(": ");
        request.push_str(v);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

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
    let body = if is_chunked {
        dechunk(raw_body)?
    } else {
        raw_body.to_vec()
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
}
