//! Error types for the time-travel debugger.

use ethrex_levm::errors::VMError;

#[derive(Debug, thiserror::Error)]
pub enum DebuggerError {
    #[error("VM error: {0}")]
    Vm(#[from] VMError),

    #[error("Step {index} out of range (max {max})")]
    StepOutOfRange { index: usize, max: usize },

    #[cfg(feature = "cli")]
    #[error("CLI error: {0}")]
    Cli(String),

    #[cfg(feature = "cli")]
    #[error("Invalid bytecode: {0}")]
    InvalidBytecode(String),

    #[cfg(feature = "autopsy")]
    #[error("{0}")]
    Rpc(RpcError),

    #[cfg(feature = "autopsy")]
    #[error("Report error: {0}")]
    Report(String),
}

/// Structured RPC error types for programmatic handling.
#[cfg(feature = "autopsy")]
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("Connection to {url} failed: {cause}")]
    ConnectionFailed { url: String, cause: String },

    #[error("{method} timed out after {elapsed_ms}ms")]
    Timeout { method: String, elapsed_ms: u64 },

    #[error("{method} HTTP {status}: {body}")]
    HttpError {
        method: String,
        status: u16,
        body: String,
    },

    #[error("{method} JSON-RPC error {code}: {message}")]
    JsonRpcError {
        method: String,
        code: i64,
        message: String,
    },

    #[error("{method} response parse error in {field}: {cause}")]
    ParseError {
        method: String,
        field: String,
        cause: String,
    },

    #[error("{method} failed after {attempts} attempt(s): {last_error}")]
    RetryExhausted {
        method: String,
        attempts: u32,
        last_error: Box<RpcError>,
    },
}

#[cfg(feature = "autopsy")]
impl RpcError {
    /// Whether this error is likely transient and retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            RpcError::ConnectionFailed { .. } => true,
            RpcError::Timeout { .. } => true,
            RpcError::HttpError { status, .. } => {
                // 429 = rate limited, 502/503/504 = server issues
                matches!(*status, 429 | 502 | 503 | 504)
            }
            RpcError::JsonRpcError { .. } => false,
            RpcError::ParseError { .. } => false,
            RpcError::RetryExhausted { .. } => false,
        }
    }

    /// For HTTP 429, extract Retry-After header value (if available).
    pub fn retry_after_secs(&self) -> Option<u64> {
        // Retry-After is captured in the body field as a hint
        if let RpcError::HttpError {
            status: 429, body, ..
        } = self
        {
            body.strip_prefix("retry-after:")
                .and_then(|s| s.trim().parse().ok())
        } else {
            None
        }
    }

    /// Create a simple RPC string error (backward compat convenience).
    pub fn simple(msg: impl Into<String>) -> Self {
        let msg = msg.into();
        RpcError::ParseError {
            method: String::new(),
            field: String::new(),
            cause: msg,
        }
    }
}

/// Convenience: allow constructing DebuggerError::Rpc from a string for backward compat.
#[cfg(feature = "autopsy")]
impl From<RpcError> for DebuggerError {
    fn from(e: RpcError) -> Self {
        DebuggerError::Rpc(e)
    }
}
