use crate::error::Result;
use crate::models::{FileContext, ScanResult};
use crate::scanners::Scanner;
use crate::utils::sanitize_backlink;
use async_trait::async_trait;
use regex::Regex;
use std::path::Path; // Added to extract the file stem

pub struct BacklinkScanner;

#[async_trait]
impl Scanner for BacklinkScanner {
    async fn scan(&self, ctx: &FileContext) -> Result<Vec<ScanResult>> {
        let mut results = Vec::new();

        let backlink_re = Regex::new(r"(@)?\[\[([^\]\[]+?)\]\]").unwrap();
        let mut in_code_block = false;

        let file_prefix = Path::new(&ctx.path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        for line in ctx.content.lines() {
            if line.trim().starts_with("```") {
                in_code_block = !in_code_block;
                continue;
            }

            if !in_code_block {
                for cap in backlink_re.captures_iter(line) {
                    let is_local = cap.get(1).is_some();
                    let raw_link = &cap[2];

                    let processed_link = if is_local && !file_prefix.is_empty() {
                        format!("{} - {}", file_prefix, raw_link)
                    } else {
                        raw_link.to_string()
                    };

                    if let Some(sanitized) = sanitize_backlink(&processed_link) {
                        results.push(ScanResult::Backlink(sanitized));
                    }
                }
            }
        }

        Ok(results)
    }
}
