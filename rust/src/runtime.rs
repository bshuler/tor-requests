use std::sync::Arc;

use tokio::runtime::Runtime as TokioRuntime;

use crate::error::{Result, TorError};

/// Manages a tokio runtime in a background thread for bridging async→sync.
pub struct TorRuntime {
    rt: Arc<TokioRuntime>,
}

impl TorRuntime {
    /// Create a new tokio multi-thread runtime.
    pub fn new() -> Result<Self> {
        let rt = TokioRuntime::new()
            .map_err(|e| TorError::Bootstrap(format!("Failed to create tokio runtime: {}", e)))?;
        Ok(TorRuntime { rt: Arc::new(rt) })
    }

    /// Execute an async operation synchronously by blocking on the runtime.
    pub fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        self.rt.block_on(future)
    }

    /// Get a handle to the runtime for spawning tasks.
    pub fn handle(&self) -> tokio::runtime::Handle {
        self.rt.handle().clone()
    }
}
