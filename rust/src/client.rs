use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use arti_client::TorClient;
use pyo3::prelude::*;
use tor_rtcompat::PreferredRuntime;

use crate::config::TorConfig;
use crate::error::{Result, TorError};
use crate::runtime::TorRuntime;
use crate::stream::TorStream;

/// A Tor tunnel wrapping arti-client's TorClient.
#[pyclass]
pub struct TorTunnel {
    client: Arc<TorClient<PreferredRuntime>>,
    runtime: Arc<TorRuntime>,
    alive: Arc<AtomicBool>,

    #[pyo3(get)]
    _isolation: bool,
}

#[pymethods]
impl TorTunnel {
    #[new]
    fn new(py: Python<'_>, config: &TorConfig) -> PyResult<Self> {
        let isolation = config.isolation;

        Ok(py.allow_threads(|| -> Result<TorTunnel> {
            let rt = TorRuntime::new()?;

            let arti_config = config.to_arti_config()?;

            let client = rt.block_on(async {
                TorClient::create_bootstrapped(arti_config)
                    .await
                    .map_err(|e| TorError::Bootstrap(format!("Failed to bootstrap Tor: {}", e)))
            })?;

            Ok(TorTunnel {
                client: Arc::new(client),
                runtime: Arc::new(rt),
                alive: Arc::new(AtomicBool::new(true)),
                _isolation: isolation,
            })
        })?)
    }

    /// Create a new Tor stream to the given host and port.
    fn create_stream(&self, py: Python<'_>, host: &str, port: u16) -> PyResult<TorStream> {
        if !self.alive.load(Ordering::SeqCst) {
            return Err(TorError::TunnelClosed)?;
        }

        let client = self.client.clone();
        let target = format!("{}:{}", host, port);
        let handle = self.runtime.handle();

        let stream = py.allow_threads(|| -> Result<TorStream> {
            let data_stream = self.runtime.block_on(async {
                client
                    .connect(target.as_str())
                    .await
                    .map_err(|e| TorError::Connection(format!("Failed to connect: {}", e)))
            })?;

            Ok(TorStream::new(data_stream, handle))
        })?;

        Ok(stream)
    }

    /// Create an isolated Tor stream (uses a separate circuit).
    fn create_isolated_stream(&self, py: Python<'_>, host: &str, port: u16) -> PyResult<TorStream> {
        if !self.alive.load(Ordering::SeqCst) {
            return Err(TorError::TunnelClosed)?;
        }

        let client = self.client.clone();
        let target = format!("{}:{}", host, port);
        let handle = self.runtime.handle();

        let stream = py.allow_threads(|| -> Result<TorStream> {
            let isolated = client.isolated_client();
            let data_stream = self.runtime.block_on(async {
                isolated.connect(target.as_str()).await.map_err(|e| {
                    TorError::Connection(format!("Failed to connect (isolated): {}", e))
                })
            })?;

            Ok(TorStream::new(data_stream, handle))
        })?;

        Ok(stream)
    }

    /// Close the tunnel.
    fn close(&self) {
        self.alive.store(false, Ordering::SeqCst);
    }

    /// Check if the tunnel is still alive.
    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}
