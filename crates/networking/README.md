# Citadel Networking Layer

A privacy-first networking layer for the Citadel browser engine. This crate provides comprehensive networking capabilities with a focus on privacy, security, and user sovereignty.

## Key Components

### ResourceManager

The `ResourceManager` is the highest-level API for resource fetching, providing:

- **Resource Policy Enforcement**: Control what types of resources can be loaded
- **Cache Management**: Intelligent caching with privacy considerations
- **Origin Classification**: Distinguish between first-party, third-party, and tracking resources
- **Tracker Blocking**: Built-in detection and blocking of common tracking services
- **Resource Statistics**: Track network activity and blocked content

```rust
// Create a ResourceManager with default privacy-enhancing settings
let manager = ResourceManager::new().await?;

// Load a main document
let response = manager.fetch_html("https://example.com").await?;

// Fetch resources with appropriate content types
let css = manager.fetch("https://example.com/styles.css", Some(ResourceType::Css)).await?;
let script = manager.fetch("https://example.com/script.js", Some(ResourceType::Script)).await?;

// Get resource statistics
let stats = manager.get_stats().await;
println!("Requests: {}, Blocked trackers: {}", 
         stats.total_requests, stats.blocked.keys().len());
```

### CitadelDnsResolver

The `CitadelDnsResolver` provides privacy-preserving DNS resolution:

- **Local Caching**: Minimizes network requests that could be tracked
- **No Third-Party DNS**: Never uses third-party DNS services by default
- **Optional Secure DNS**: Support for DNS-over-HTTPS and DNS-over-TLS as user options
- **TTL Normalization**: Prevents timing-based tracking via DNS TTLs

### Connection Management

The `Connection` class handles secure connection establishment:

- **TLS Configuration**: Multiple security levels from maximum to balanced
- **HTTPS Enforcement**: All connections use HTTPS by default
- **Privacy-Enhancing Parameters**: TCP and TLS parameters optimized for privacy

### Request/Response Handling

- **Privacy Headers**: Automatically applies privacy-preserving headers
- **Tracking Parameter Removal**: Strips known tracking parameters from URLs
- **User Agent Management**: Randomization and normalization to prevent fingerprinting
- **Content Type Detection**: Intelligent content type handling

## Privacy Policies

The ResourceManager supports multiple privacy policies:

- **AllowAll**: Allow loading all resources (basic browsing)
- **BlockScripts**: Block script resources (enhanced privacy)
- **BlockThirdParty**: Block all third-party resources (strict privacy)
- **BlockTracking**: Block known tracking resources (balanced approach)
- **Custom**: User-defined policies

## Caching Policies

The caching system supports various policies:

- **Normal**: Standard HTTP caching rules
- **PreferCache**: Prefer cached resources even when expired
- **AlwaysValidate**: Always validate with the server
- **NeverCache**: Never cache resources (private browsing mode)

## Examples

### Blocking Trackers

```rust
let config = ResourceManagerConfig {
    resource_policy: ResourcePolicy::BlockTracking,
    ..ResourceManagerConfig::default()
};

let manager = ResourceManager::with_config(config).await?;

// This will succeed (not a tracker)
let response = manager.fetch("https://example.com/image.png", None).await?;

// This will fail (known analytics service)
let result = manager.fetch("https://google-analytics.com/analytics.js", None).await;
assert!(result.is_err());
```

### Custom DNS Mode

```rust
let mut config = NetworkConfig::default();
config.dns_mode = DnsMode::DoT("1.1.1.1".to_string());

let resource = Resource::new(config).await?;
```
