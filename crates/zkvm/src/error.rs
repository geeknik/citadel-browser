use thiserror::Error;

/// Errors that can occur during ZKVM operations
#[derive(Error, Debug)]
pub enum ZkVmError {
    #[error("Memory allocation failed: {0}")]
    MemoryError(String),
    
    #[error("Encryption operation failed: {0}")]
    CryptoError(String),
    
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    
    #[error("Communication channel error: {0}")]
    ChannelError(String),
} 