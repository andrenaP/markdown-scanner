use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("YAML parse error: {0}")]
    Yaml(#[from] yaml_rust::ScanError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Scanner error: {0}")]
    Scanner(String),
}

pub type Result<T> = std::result::Result<T, AppError>;
