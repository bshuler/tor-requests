use pyo3::prelude::*;

/// Configuration for the Tor tunnel.
#[pyclass]
#[derive(Clone, Debug)]
pub struct TorConfig {
    /// Directory for arti state/cache. None uses arti default.
    #[pyo3(get, set)]
    pub data_dir: Option<String>,

    /// Bridge relay lines for censored networks.
    #[pyo3(get, set)]
    pub bridges: Vec<String>,

    /// Per-stream circuit isolation.
    #[pyo3(get, set)]
    pub isolation: bool,
}

#[pymethods]
impl TorConfig {
    #[new]
    #[pyo3(signature = (data_dir=None, bridges=vec![], isolation=false))]
    fn new(data_dir: Option<String>, bridges: Vec<String>, isolation: bool) -> Self {
        TorConfig {
            data_dir,
            bridges,
            isolation,
        }
    }
}

impl TorConfig {
    /// Build an arti-client TorClientConfig from our config.
    pub fn to_arti_config(
        &self,
    ) -> std::result::Result<arti_client::TorClientConfig, crate::error::TorError> {
        use arti_client::config::TorClientConfigBuilder;
        use std::path::PathBuf;

        let builder = if let Some(dir) = &self.data_dir {
            let path = PathBuf::from(dir);
            TorClientConfigBuilder::from_directories(path.clone(), path)
        } else {
            TorClientConfigBuilder::default()
        };

        builder
            .build()
            .map_err(|e| crate::error::TorError::Config(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TorConfig::new(None, vec![], false);
        assert!(config.data_dir.is_none());
        assert!(config.bridges.is_empty());
        assert!(!config.isolation);
    }

    #[test]
    fn test_custom_config() {
        let config = TorConfig::new(
            Some("/tmp/arti".to_string()),
            vec!["bridge1".to_string()],
            true,
        );
        assert_eq!(config.data_dir, Some("/tmp/arti".to_string()));
        assert_eq!(config.bridges.len(), 1);
        assert!(config.isolation);
    }
}
