use std::sync::Arc;

use bytes::Bytes;

use crate::dns::CitadelDnsResolver;
use crate::error::NetworkError;
use crate::request::{Method, Request};
use crate::response::Response;
use crate::NetworkConfig;

/// Resource types that can be fetched
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    /// HTML document
    Html,
    /// CSS stylesheet
    Css,
    /// JavaScript file
    Script,
    /// Image
    Image,
    /// Font
    Font,
    /// JSON data
    Json,
    /// XML data
    Xml,
    /// Plain text
    Text,
    /// Binary data
    Binary,
    /// Other/unknown type
    Other,
}

/// Resource fetching client with privacy protections
pub struct Resource {
    /// DNS resolver
    dns_resolver: Arc<CitadelDnsResolver>,

    /// Network configuration
    config: NetworkConfig,
}

impl Resource {
    /// Create a new resource fetcher with the specified configuration
    pub async fn new(config: NetworkConfig) -> Result<Self, NetworkError> {
        let dns_resolver = Arc::new(CitadelDnsResolver::with_mode(config.dns_mode.clone()).await?);
        Ok(Self {
            dns_resolver,
            config,
        })
    }

    /// Fetch a resource with the provided request, via the in-house HTTPS client.
    pub async fn fetch(&self, request: Request) -> Result<Response, NetworkError> {
        // Apply privacy enhancements based on current settings.
        let prepared_request = if self.config.privacy_level == request.privacy_level() {
            request.prepare()
        } else {
            request
        };

        // The in-house client is GET-only over HTTPS.
        if !matches!(prepared_request.method(), Method::GET) {
            return Err(NetworkError::ConnectionError(
                "only GET is supported by the in-house HTTPS client".to_string(),
            ));
        }

        let final_url = prepared_request.url().clone();
        let method = prepared_request.method().clone();
        let headers: Vec<(String, String)> = prepared_request
            .headers()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let http_response = crate::http::fetch(&final_url, &headers).await?;

        let header_map = http_response.headers.into_iter().collect();
        let mut response = Response::new(
            http_response.status,
            header_map,
            Bytes::from(http_response.body),
            final_url,
            method,
        );

        // Flag any tracking attempts based on the response URL.
        self.detect_tracking_attempts(&mut response);
        Ok(response)
    }

    /// Detect potential tracking attempts in the response
    fn detect_tracking_attempts(&self, response: &mut Response) {
        // Simple detection based on URL patterns
        let tracking_patterns = [
            "google-analytics.com",
            "doubleclick.net",
            "facebook.com/tr",
            "connect.facebook.net",
            "googletagmanager.com",
            "analytics.",
            "tracker.",
            "tracking.",
            "metric.",
            "matomo.",
            "piwik.",
        ];

        // Copy the URL first to avoid borrowing issues
        let url = response.url().as_str().to_string();

        for pattern in tracking_patterns.iter() {
            if url.contains(pattern) {
                response
                    .add_blocked_tracking(format!("Potential tracking URL detected: {}", pattern));
            }
        }

        // More sophisticated detection could look at response body content
        // for known tracking scripts, but that's beyond this simple example
    }

    /// Determine the resource type from a response
    pub fn determine_resource_type(response: &Response) -> ResourceType {
        let content_type = match response.content_type() {
            Some(ct) => ct.to_lowercase(),
            None => return ResourceType::Other,
        };

        if content_type.contains("text/html") {
            ResourceType::Html
        } else if content_type.contains("text/css") {
            ResourceType::Css
        } else if content_type.contains("javascript") || content_type.contains("application/js") {
            ResourceType::Script
        } else if content_type.contains("image/") {
            ResourceType::Image
        } else if content_type.contains("font/") || content_type.contains("application/font") {
            ResourceType::Font
        } else if content_type.contains("application/json") {
            ResourceType::Json
        } else if content_type.contains("application/xml") || content_type.contains("text/xml") {
            ResourceType::Xml
        } else if content_type.contains("text/plain") {
            ResourceType::Text
        } else if content_type.contains("application/octet-stream") {
            ResourceType::Binary
        } else {
            ResourceType::Other
        }
    }

    /// Get the DNS resolver
    pub fn dns_resolver(&self) -> &CitadelDnsResolver {
        &self.dns_resolver
    }

    /// Get the current network configuration
    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }

    /// Set a new network configuration
    pub async fn set_config(&mut self, config: NetworkConfig) -> Result<(), NetworkError> {
        // Update DNS mode if it changed.
        if self.config.dns_mode != config.dns_mode {
            self.dns_resolver =
                Arc::new(CitadelDnsResolver::with_mode(config.dns_mode.clone()).await?);
        }

        // Update the configuration
        self.config = config;

        Ok(())
    }

    /// Helper method to fetch an HTML document
    pub async fn fetch_html(&self, url: &str) -> Result<Response, NetworkError> {
        let request = Request::new(Method::GET, url)?
            .with_header("Accept", "text/html,application/xhtml+xml")
            .prepare();

        self.fetch(request).await
    }

    /// Helper method to fetch JSON data
    pub async fn fetch_json(&self, url: &str) -> Result<Response, NetworkError> {
        let request = Request::new(Method::GET, url)?
            .with_header("Accept", "application/json")
            .prepare();

        self.fetch(request).await
    }

    /// Helper method to fetch a CSS stylesheet
    pub async fn fetch_css(&self, url: &str) -> Result<Response, NetworkError> {
        let request = Request::new(Method::GET, url)?
            .with_header("Accept", "text/css")
            .prepare();

        self.fetch(request).await
    }

    /// Helper method to fetch a JavaScript file
    pub async fn fetch_script(&self, url: &str) -> Result<Response, NetworkError> {
        let request = Request::new(Method::GET, url)?
            .with_header("Accept", "application/javascript,text/javascript")
            .prepare();

        self.fetch(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resource_creation() {
        let config = NetworkConfig::default();
        let resource = Resource::new(config).await;
        assert!(resource.is_ok());
    }
}
