use crate::error::Result;
use crate::models::{FileContext, ScanResult};
use crate::scanners::Scanner;
use crate::utils::clean_text_for_parsing;
use async_trait::async_trait;
use regex::Regex;

pub struct TagScanner;

#[async_trait]
impl Scanner for TagScanner {
    async fn scan(&self, ctx: &FileContext) -> Result<Vec<ScanResult>> {
        let mut results = Vec::new();
        // Regex for #tag
        let tag_re = Regex::new(r"#[\p{L}\p{N}_-]+").unwrap();

        let mut in_code_block = false;

        for line in ctx.content.lines() {
            if line.trim().starts_with("```") {
                in_code_block = !in_code_block;
                continue;
            }

            if !in_code_block {
                let cleaned = clean_text_for_parsing(line);
                for cap in tag_re.captures_iter(&cleaned) {
                    let tag = &cap[0][1..]; // Remove '#'
                    results.push(ScanResult::Tag(tag.to_string()));
                }
            }
        }

        Ok(results)
    }
}
