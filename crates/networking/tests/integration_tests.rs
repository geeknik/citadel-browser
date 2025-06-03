use citadel_networking::{NetworkConfig, PrivacyLevel, Resource, Request};
use citadel_networking::request::Method;
use std::time::Duration;

#[tokio::test]
async fn test_basic_fetch() {
    // Create a default config
    let config = NetworkConfig::default();
    
    // Create a resource fetcher
    let _resource = Resource::new(config).await.expect("Failed to create resource fetcher");
    
    // Fetch a test URL
    let response = _resource.fetch_html("https://example.com")
        .await
        .expect("Failed to fetch HTML");
        
    // Verify the response
    assert!(response.is_success());
    assert!(response.is_html());
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn test_privacy_levels() {
    // Test different privacy levels
    for privacy_level in [
        PrivacyLevel::Maximum,
        PrivacyLevel::High,
        PrivacyLevel::Balanced
    ].iter() {
        // Create config with specific privacy level
        let mut config = NetworkConfig::default();
        config.privacy_level = *privacy_level;
        
        // Create a resource fetcher
        let _resource = Resource::new(config).await.expect("Failed to create resource fetcher");
        
        // Make a request
        let request = Request::new(Method::GET, "https://example.com")
            .expect("Failed to create request")
            .with_privacy_level(*privacy_level)
            .with_timeout(Duration::from_secs(10))
            .prepare();
            
        // Fetch with that privacy level
        let response = _resource.fetch(request)
            .await
            .expect("Failed to fetch with privacy level");
            
        // Basic verification
        assert!(response.is_success());
    }
}

#[tokio::test]
async fn test_https_enforcement() {
    // Create a default config
    let config = NetworkConfig::default();
    
    // Create a resource fetcher
    let _resource = Resource::new(config).await.expect("Failed to create resource fetcher");
    
    // Try to fetch an insecure URL, which should fail
    let result = Request::new(Method::GET, "http://example.com");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_tracking_param_removal() {
    // Create a default config
    let config = NetworkConfig::default();
    
    // Create a resource fetcher
    let _resource = Resource::new(config).await.expect("Failed to create resource fetcher");
    
    // Create a request with tracking parameters
    let request = Request::new(
        Method::GET, 
        "https://example.com/?id=123&utm_source=test&valid=true&fbclid=abc123"
    ).expect("Failed to create request")
    .prepare();
    
    // The URL should have tracking parameters removed
    let url = request.url();
    let query = url.query().unwrap_or("");
    
    assert!(query.contains("id=123"));
    assert!(query.contains("valid=true"));
    assert!(!query.contains("utm_source"));
    assert!(!query.contains("fbclid"));
} 