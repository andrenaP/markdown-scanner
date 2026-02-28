use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::path::PathBuf;

/// Represents the raw file input to be scanned
#[derive(Debug, Clone)]
pub struct FileContext {
    pub path: PathBuf,
    pub relative_path: String,
    pub content: String,
    pub base_dir: String,
    pub time: u64,
    pub vidlinks: Vec<(String, String)>,
}

/// A uniform result returned by any scanner
#[derive(Debug, Clone)]
pub enum ScanResult {
    Metadata(JsonValue), // From Frontmatter
    Tag(String),         // From Inline or Frontmatter
    Backlink(String),    // Raw backlink text (e.g., "My Note")
    CreatedAt(u64),      // Time
    YoutubeVideo { url: String, title: String },
}

/// The aggregated result of all scanners, ready for DB insertion
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AggregatedData {
    pub metadata: JsonValue,
    pub tags: Vec<String>,
    pub backlinks: Vec<String>,
}
