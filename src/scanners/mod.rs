pub mod backlinks;
pub mod filetime;
pub mod frontmatter;
pub mod tags;
pub mod youtubescanner;

use crate::error::Result;
use crate::models::{AggregatedData, FileContext, ScanResult};

use async_trait::async_trait;
use log::debug;

use serde_json::json;

/// Trait that all individual scanners must implement
#[async_trait]
pub trait Scanner: Send + Sync {
    /// The main scan logic. Pure function: Input -> Data. No DB access here.
    async fn scan(&self, ctx: &FileContext) -> Result<Vec<ScanResult>>;
}

/// Orchestrator to hold and run scanners
pub struct ScannerManager {
    scanners: Vec<Box<dyn Scanner>>,
}

impl ScannerManager {
    pub fn new() -> Self {
        Self {
            scanners: Vec::new(),
        }
    }

    pub fn register<S: Scanner + 'static>(&mut self, scanner: S) {
        self.scanners.push(Box::new(scanner));
    }

    /// Runs all registered scanners concurrently and aggregates results
    pub async fn process_file(&self, ctx: &FileContext) -> Result<AggregatedData> {
        let mut aggregated = AggregatedData {
            metadata: serde_json::json!({}),
            tags: Vec::new(),
            backlinks: Vec::new(),
        };

        // Run scanners concurrently
        let mut futures = Vec::new();
        for scanner in &self.scanners {
            futures.push(scanner.scan(ctx));
        }

        let results_list = futures::future::join_all(futures).await;

        for res in results_list {
            match res {
                Ok(items) => {
                    for item in items {
                        match item {
                            ScanResult::Metadata(m) => {
                                // Merge metadata objects
                                if let serde_json::Value::Object(mut map) =
                                    aggregated.metadata.clone()
                                {
                                    if let serde_json::Value::Object(new_map) = m {
                                        for (k, v) in new_map {
                                            map.insert(k, v);
                                        }
                                    }
                                    aggregated.metadata = serde_json::Value::Object(map);
                                }
                            }
                            ScanResult::Tag(t) => {
                                if !aggregated.tags.contains(&t) {
                                    aggregated.tags.push(t);
                                }
                            }
                            ScanResult::Backlink(b) => {
                                if !aggregated.backlinks.contains(&b) {
                                    aggregated.backlinks.push(b);
                                }
                            }
                            ScanResult::CreatedAt(ts) => {
                                if let serde_json::Value::Object(ref mut map) = aggregated.metadata
                                {
                                    map.insert("created_at".to_string(), json!(ts));
                                }
                            }
                            ScanResult::YoutubeVideo { url, title } => {
                                if let serde_json::Value::Object(ref mut map) = aggregated.metadata
                                {
                                    // Find the "ytVideos" array, or create it if it doesn't exist yet
                                    let entry = map.entry("ytVideos").or_insert_with(|| json!([]));

                                    // Push the new video object into the array
                                    if let Some(array) = entry.as_array_mut() {
                                        array.push(json!({
                                            "url": url,
                                            "title": title
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Scanner error: {}", e);
                    // Decide if you want to fail hard or log and continue
                    return Err(e);
                }
            }
        }

        Ok(aggregated)
    }
}
