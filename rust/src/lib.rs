//! tor-requests native extension module.
//!
//! This crate provides the Rust core for the `tor-requests` Python package.
//! It uses arti-client (the Tor Project's pure-Rust Tor implementation) to
//! create transparent Tor routing accessible from Python.

// pyo3 #[pymethods] macro generates code that triggers this false positive
#![allow(clippy::useless_conversion)]

mod client;
mod config;
mod error;
mod runtime;
mod stream;

use client::TorTunnel;
use config::TorConfig;
use pyo3::prelude::*;
use stream::TorStream;

/// Native extension module for tor-requests.
///
/// This module is not meant to be used directly. Use the `tor_requests`
/// Python package instead, which provides a high-level socket-compatible API.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Initialize tracing (respects RUST_LOG env var).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    m.add_class::<TorTunnel>()?;
    m.add_class::<TorStream>()?;
    m.add_class::<TorConfig>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
