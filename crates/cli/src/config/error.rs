use std::path::PathBuf;

use smplx_build::error::{DependencyValidationError, TomlEditError};

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error(transparent)]
    TomlEdit(#[from] TomlEditError),

    #[error(transparent)]
    Dependency(#[from] DependencyValidationError),

    #[error("Network name should be `SequentiaTestnet`, got: {0}")]
    BadNetworkName(String),

    #[error(
        "{0} is not a Sequentia network. This build of Simplex speaks Sequentia's transaction encoding only; \
         use upstream Simplex for Liquid and Elements"
    )]
    UnsupportedNetwork(String),

    #[error("Unable to deserialize config: {0}")]
    UnableToDeserialize(toml::de::Error),

    #[error("Unable to get env variable: {0}")]
    UnableToGetEnv(#[from] std::env::VarError),

    #[error("Path doesn't a file: '{0}'")]
    PathIsNotFile(PathBuf),

    #[error("Path doesn't exist: '{0}'")]
    PathNotExists(PathBuf),
}
