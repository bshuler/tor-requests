use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::{bounded, Receiver, Sender};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{Result, TorError};

/// Messages from Python to the async write task.
enum WriteMsg {
    Data(Vec<u8>),
    Close,
}

/// A Tor stream bridging async arti DataStream to synchronous Python calls.
#[pyclass]
pub struct TorStream {
    /// Channel for sending data to the async writer.
    write_tx: Sender<WriteMsg>,
    /// Channel for receiving data from the async reader.
    read_rx: Receiver<std::result::Result<Vec<u8>, String>>,
    /// Whether the stream is still connected.
    connected: Arc<AtomicBool>,
}

impl TorStream {
    /// Create a new TorStream from an arti DataStream.
    ///
    /// Spawns two background tokio tasks:
    /// - Reader: reads from DataStream, sends chunks to Python via channel
    /// - Writer: receives data from Python via channel, writes to DataStream
    pub fn new(stream: arti_client::DataStream, handle: tokio::runtime::Handle) -> Self {
        let connected = Arc::new(AtomicBool::new(true));

        // Channels for the write path (Python → async)
        let (write_tx, write_rx) = bounded::<WriteMsg>(64);

        // Channels for the read path (async → Python)
        let (read_tx, read_rx) = bounded::<std::result::Result<Vec<u8>, String>>(64);

        let (reader, writer) = tokio::io::split(stream);

        // Spawn reader task
        let read_connected = connected.clone();
        handle.spawn(async move {
            let mut reader = reader;
            loop {
                let mut buf = vec![0u8; 16384];
                match reader.read(&mut buf).await {
                    Ok(0) => {
                        read_connected.store(false, Ordering::SeqCst);
                        let _ = read_tx.send(Ok(vec![]));
                        break;
                    }
                    Ok(n) => {
                        buf.truncate(n);
                        if read_tx.send(Ok(buf)).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        read_connected.store(false, Ordering::SeqCst);
                        let _ = read_tx.send(Err(e.to_string()));
                        break;
                    }
                }
            }
        });

        // Spawn writer task
        let write_connected = connected.clone();
        handle.spawn(async move {
            let mut writer = writer;
            loop {
                match write_rx.recv() {
                    Ok(WriteMsg::Data(data)) => {
                        if let Err(_e) = writer.write_all(&data).await {
                            write_connected.store(false, Ordering::SeqCst);
                            break;
                        }
                        if let Err(_e) = writer.flush().await {
                            write_connected.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                    Ok(WriteMsg::Close) | Err(_) => {
                        let _ = writer.shutdown().await;
                        break;
                    }
                }
            }
        });

        TorStream {
            write_tx,
            read_rx,
            connected,
        }
    }
}

#[pymethods]
impl TorStream {
    /// Send data through the Tor stream.
    fn send(&self, py: Python<'_>, data: &[u8]) -> PyResult<usize> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err(TorError::StreamClosed)?;
        }

        let len = data.len();
        py.allow_threads(|| {
            self.write_tx
                .send(WriteMsg::Data(data.to_vec()))
                .map_err(|_| TorError::StreamClosed)?;
            Ok(len)
        })
    }

    /// Receive data from the Tor stream.
    #[pyo3(signature = (max_bytes, timeout_ms=None))]
    fn recv<'py>(
        &self,
        py: Python<'py>,
        max_bytes: usize,
        timeout_ms: Option<u64>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let result = py.allow_threads(|| -> Result<Vec<u8>> {
            let data = match timeout_ms {
                Some(ms) => self
                    .read_rx
                    .recv_timeout(Duration::from_millis(ms))
                    .map_err(|e| match e {
                        crossbeam_channel::RecvTimeoutError::Timeout => TorError::Timeout,
                        crossbeam_channel::RecvTimeoutError::Disconnected => TorError::StreamClosed,
                    })?,
                None => self.read_rx.recv().map_err(|_| TorError::StreamClosed)?,
            };

            match data {
                Ok(bytes) => {
                    if bytes.len() > max_bytes {
                        Ok(bytes[..max_bytes].to_vec())
                    } else {
                        Ok(bytes)
                    }
                }
                Err(e) => Err(TorError::Connection(e)),
            }
        })?;

        Ok(PyBytes::new_bound(py, &result))
    }

    /// Close the stream.
    fn close(&self) {
        self.connected.store(false, Ordering::SeqCst);
        let _ = self.write_tx.send(WriteMsg::Close);
    }

    /// Check if the stream is still connected.
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }
}
