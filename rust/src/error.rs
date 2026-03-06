use pyo3::exceptions::{
    PyConnectionError, PyOSError, PyRuntimeError, PyTimeoutError, PyValueError,
};
use pyo3::PyErr;
use thiserror::Error;

/// All errors that can occur in the tor-requests library.
#[derive(Error, Debug)]
pub enum TorError {
    #[error("Bootstrap error: {0}")]
    Bootstrap(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Stream closed")]
    StreamClosed,

    #[error("Connection timed out")]
    Timeout,

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Tunnel is closed")]
    TunnelClosed,

    #[error("Channel error: {0}")]
    Channel(String),
}

impl From<TorError> for PyErr {
    fn from(err: TorError) -> PyErr {
        match &err {
            TorError::Bootstrap(_) => PyRuntimeError::new_err(err.to_string()),
            TorError::Connection(_) => PyConnectionError::new_err(err.to_string()),
            TorError::Io(_) => PyOSError::new_err(err.to_string()),
            TorError::StreamClosed | TorError::TunnelClosed => {
                PyConnectionError::new_err(err.to_string())
            }
            TorError::Timeout => PyTimeoutError::new_err(err.to_string()),
            TorError::Config(_) => PyValueError::new_err(err.to_string()),
            TorError::Channel(_) => PyRuntimeError::new_err(err.to_string()),
        }
    }
}

impl<T> From<crossbeam_channel::SendError<T>> for TorError {
    fn from(err: crossbeam_channel::SendError<T>) -> Self {
        TorError::Channel(format!("Send error: {}", err))
    }
}

impl From<crossbeam_channel::RecvError> for TorError {
    fn from(err: crossbeam_channel::RecvError) -> Self {
        TorError::Channel(format!("Recv error: {}", err))
    }
}

impl From<crossbeam_channel::RecvTimeoutError> for TorError {
    fn from(err: crossbeam_channel::RecvTimeoutError) -> Self {
        match err {
            crossbeam_channel::RecvTimeoutError::Timeout => TorError::Timeout,
            crossbeam_channel::RecvTimeoutError::Disconnected => {
                TorError::Channel("Channel disconnected".into())
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, TorError>;
