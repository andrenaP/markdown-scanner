use crate::error::Result;
use crate::models::{FileContext, ScanResult};
use crate::scanners::Scanner;
use crate::utils::sanitize_backlink;
use async_trait::async_trait;
use regex::Regex;

pub struct BacklinkScanner;

#[async_trait]
impl Scanner for BacklinkScanner {
    async fn scan(&self, ctx: &FileContext) -> Result<Vec<ScanResult>> {
        let mut results = Vec::new();
        let backlink_re = Regex::new(r"\[\[([^\]\[]+?)\]\]").unwrap();
        let mut in_code_block = false;

        for line in ctx.content.lines() {
            if line.trim().starts_with("```") {
                in_code_block = !in_code_block;
                continue;
            }

            if !in_code_block {
                for cap in backlink_re.captures_iter(line) {
                    let raw = &cap[1];
                    if let Some(sanitized) = sanitize_backlink(raw) {
                        results.push(ScanResult::Backlink(sanitized));
                    }
                }
            }
        }

        Ok(results)
    }
}
