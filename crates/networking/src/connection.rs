use std::sync::Arc;
use std::time::Duration;
use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use hyper_rustls::HttpsConnector;
use hyper::client::connect::HttpConnector;
use rustls::{ClientConfig, RootCertStore, Certificate};
use tokio::time::timeout;
use tokio::sync::Mutex;

use crate::dns::CitadelDnsResolver;
use crate::error::NetworkError;

/// Connection security level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Maximum security: only support modern, secure cipher suites and protocols
    Maximum,
    /// High security: support secure cipher suites with good compatibility
    High,
    /// Balanced: reasonable security with wide compatibility
    Balanced,
    /// Custom security settings
    Custom,
}

/// Connection metrics for monitoring
#[derive(Debug, Default)]
pub struct ConnectionMetrics {
    /// Total number of requests made
    requests: AtomicUsize,
    /// Number of successful requests
    successes: AtomicUsize,
    /// Number of failed requests
    failures: AtomicUsize,
    /// Number of timeouts
    timeouts: AtomicUsize,
}

impl ConnectionMetrics {
    pub fn increment_requests(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_successes(&self) {
        self.successes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_failures(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_timeouts(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }
}

/// Connection pool entry
struct PoolEntry {
    client: HyperClient,
    last_used: std::time::Instant,
}

/// TLS versions to support for connections
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.2
    Tls12,
    /// TLS 1.3
    Tls13,
}

/// Type alias for our Hyper client
pub type HyperClient = hyper::Client<HttpsConnector<HttpConnector>>;

/// Secure connection manager for privacy-preserving HTTP(S) connections
pub struct Connection {
    /// HTTPS connector configured for privacy and security
    connector: HttpsConnector<HttpConnector>,
    
    /// Current security level
    security_level: SecurityLevel,
    
    /// DNS resolver for hostname resolution
    dns_resolver: Arc<CitadelDnsResolver>,
    
    /// Connection timeout duration
    timeout: Duration,

    /// Connection pool
    pool: Arc<Mutex<HashMap<String, PoolEntry>>>,

    /// Connection metrics
    metrics: Arc<ConnectionMetrics>,

    /// Maximum pool size per host
    max_pool_size: usize,

    /// Connection idle timeout
    idle_timeout: Duration,
}

impl Connection {
    /// Create a new connection manager with the specified DNS resolver and security level
    pub fn new(
        dns_resolver: Arc<CitadelDnsResolver>,
        security_level: SecurityLevel,
    ) -> Result<Self, NetworkError> {
        let connector = Self::build_connector(security_level)?;
        
        Ok(Self {
            connector,
            security_level,
            dns_resolver,
            timeout: Duration::from_secs(30),
            pool: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(ConnectionMetrics::default()),
            max_pool_size: 10,
            idle_timeout: Duration::from_secs(60),
        })
    }
    
    /// Build an HTTPS connector with the specified security level
    fn build_connector(
        security_level: SecurityLevel,
    ) -> Result<HttpsConnector<HttpConnector>, NetworkError> {
        // Create a TLS configuration based on the security level
        let tls_config = match security_level {
            SecurityLevel::Maximum => Self::maximum_security_config()?,
            SecurityLevel::High => Self::high_security_config()?,
            SecurityLevel::Balanced => Self::balanced_security_config()?,
            SecurityLevel::Custom => Self::custom_security_config()?,
        };
        
        // Create an HTTP connector with privacy-enhancing settings
        let mut http = HttpConnector::new();
        http.enforce_http(false);  // Allow HTTPS
        http.set_nodelay(true);    // Optimize for responsiveness
        http.set_connect_timeout(Some(Duration::from_secs(30)));
        
        // Create the HTTPS connector with our TLS configuration
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_only() // Enforce HTTPS for privacy
            .enable_http1()
            .enable_http2() // Enable HTTP/2 support
            .wrap_connector(http);
            
        Ok(https)
    }
    
    /// Configure maximum security TLS settings
    fn maximum_security_config() -> Result<ClientConfig, NetworkError> {
        let mut root_store = RootCertStore::empty();
        
        // Add Mozilla's root certificates
        for cert in rustls_native_certs::load_native_certs().map_err(|e| {
            NetworkError::TlsError(format!("Failed to load system certificates: {}", e))
        })? {
            let rustls_cert = Certificate(cert.0);
            root_store.add(&rustls_cert).map_err(|e| {
                NetworkError::TlsError(format!("Failed to add certificate to store: {}", e))
            })?;
        }
        
        // Configure with maximum security settings
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
            
        Ok(config)
    }
    
    /// Configure high security TLS settings with good compatibility
    fn high_security_config() -> Result<ClientConfig, NetworkError> {
        // For high security, we use the same approach as maximum but might allow
        // slightly more cipher suites for compatibility
        Self::maximum_security_config()
    }
    
    /// Configure balanced security TLS settings with wide compatibility
    fn balanced_security_config() -> Result<ClientConfig, NetworkError> {
        // For balanced security, we use mostly the same approach but
        // might allow a few more protocols for compatibility
        Self::high_security_config()
    }
    
    /// Configure custom security TLS settings
    fn custom_security_config() -> Result<ClientConfig, NetworkError> {
        // For custom security, we start with balanced settings
        // In a real implementation, this would be configurable
        Self::balanced_security_config()
    }
    
    /// Get the HTTPS connector for making requests
    pub fn connector(&self) -> &HttpsConnector<HttpConnector> {
        &self.connector
    }
    
    /// Get the current security level
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }
    
    /// Set the connection timeout
    pub fn set_timeout(&mut self, timeout_duration: Duration) {
        self.timeout = timeout_duration;
    }
    
    /// Get the connection timeout
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
    
    /// Perform a connection check to a host with timeout
    pub async fn check_connection(&self, host: &str, port: u16) -> Result<bool, NetworkError> {
        // First resolve the hostname using our privacy-preserving DNS resolver
        let addresses = self.dns_resolver.resolve(host).await?;
        
        if addresses.is_empty() {
            return Err(NetworkError::ConnectionError(
                format!("Could not resolve hostname: {}", host)
            ));
        }
        
        // Try to connect to the first resolved address
        let addr = addresses[0];
        let socket_addr = SocketAddr::new(addr, port);
        
        // Attempt connection with timeout
        match timeout(
            self.timeout,
            tokio::net::TcpStream::connect(socket_addr)
        ).await {
            Ok(Ok(_)) => Ok(true),
            Ok(Err(e)) => Err(NetworkError::ConnectionError(
                format!("Failed to connect to {}: {}", socket_addr, e)
            )),
            Err(_) => Err(NetworkError::TimeoutError(self.timeout)),
        }
    }

    /// Get or create a client from the connection pool
    pub async fn get_client(&self, host: &str) -> Result<HyperClient, NetworkError> {
        let mut pool = self.pool.lock().await;
        
        // Clean up old connections
        self.cleanup_pool(&mut pool).await;
        
        // Check if we have a pooled connection
        if let Some(entry) = pool.get_mut(host) {
            entry.last_used = std::time::Instant::now();
            return Ok(entry.client.clone());
        }
        
        // Create new client if pool isn't full
        if pool.len() < self.max_pool_size {
            let client = hyper::Client::builder()
                .pool_idle_timeout(self.idle_timeout)
                .build(self.connector.clone());
                
            pool.insert(host.to_string(), PoolEntry {
                client: client.clone(),
                last_used: std::time::Instant::now(),
            });
            
            Ok(client)
        } else {
            Err(NetworkError::ConnectionError("Connection pool full".to_string()))
        }
    }

    /// Clean up old connections from the pool
    async fn cleanup_pool(&self, pool: &mut HashMap<String, PoolEntry>) {
        let now = std::time::Instant::now();
        pool.retain(|_, entry| {
            now.duration_since(entry.last_used) < self.idle_timeout
        });
    }

    /// Get connection metrics
    pub fn metrics(&self) -> Arc<ConnectionMetrics> {
        self.metrics.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_connection_creation() {
        let dns_resolver = Arc::new(CitadelDnsResolver::new().await.unwrap());
        let connection = Connection::new(dns_resolver, SecurityLevel::High).unwrap();
        
        assert_eq!(connection.security_level(), SecurityLevel::High);
    }

    #[tokio::test]
    async fn test_connection_pool() {
        let dns_resolver = Arc::new(CitadelDnsResolver::new().await.unwrap());
        let connection = Connection::new(dns_resolver, SecurityLevel::High).unwrap();
        
        // Get client from pool
        let client1 = connection.get_client("example.com").await.unwrap();
        let client2 = connection.get_client("example.com").await.unwrap();
        
        // Since we can't directly compare the Arc pointers (they're cloned),
        // we'll just check that we can get multiple clients for the same domain
        // Both clients should be successfully created
        
        // Check that the connection pool has an entry for example.com
        let pool = connection.pool.lock().await;
        assert!(pool.contains_key("example.com"));
    }
    
    #[tokio::test]
    async fn test_metrics() {
        let dns_resolver = Arc::new(CitadelDnsResolver::new().await.unwrap());
        let connection = Connection::new(dns_resolver, SecurityLevel::High).unwrap();
        
        let metrics = connection.metrics();
        metrics.increment_requests();
        metrics.increment_successes();
        
        assert_eq!(metrics.requests.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.successes.load(Ordering::Relaxed), 1);
    }
} 