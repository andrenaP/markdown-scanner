use crate::error::Result;
use crate::models::{FileContext, ScanResult};
use crate::scanners::Scanner;
use crate::usafecode::get_linux_btime;
use async_trait::async_trait;
use chrono::{NaiveDate, NaiveDateTime};
use regex::Regex;
use std::fs;
use std::time::UNIX_EPOCH;

pub struct TimeScanner;

#[async_trait]
impl Scanner for TimeScanner {
    async fn scan(&self, ctx: &FileContext) -> Result<Vec<ScanResult>> {
        let mut results = Vec::new();

        if ctx.time > 0 {
            results.push(ScanResult::CreatedAt(ctx.time));
            return Ok(results);
        }

        let date_re = Regex::new(r"(?m)^(?:date|created):\s*['\x22]?(\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?)['\x22]?").unwrap();

        let limit = 2048.min(ctx.content.len());
        let mut end = limit;
        while end > 0 && !ctx.content.is_char_boundary(end) {
            end -= 1;
        }
        let scan_chunk = &ctx.content[..end];

        if let Some(cap) = date_re.captures(scan_chunk) {
            let date_str = &cap[1];
            if let Some(ts) = parse_date_string(date_str) {
                results.push(ScanResult::CreatedAt(ts.unsigned_abs() as u64)); // assuming positive timestamps
                return Ok(results); // ← early return if we trust content date
            }
        }

        // 2. Filesystem metadata

        if let Some(btime_secs) = get_linux_btime(&ctx.path) {
            results.push(ScanResult::CreatedAt(btime_secs));
        }
        // 2. Fallback to modification time
        else {
            match fs::metadata(&ctx.path) {
                Ok(metadata) => {
                    // Real birth/creation time if available (ext4/btrfs/xfs/... + modern kernel)
                    if let Ok(created) = metadata.created() {
                        if let Ok(dur) = created.duration_since(UNIX_EPOCH) {
                            results.push(ScanResult::CreatedAt(dur.as_secs()));
                            return Ok(results);
                        }
                    }
                    // Fallback: modification time
                    else if let Ok(modified) = metadata.modified() {
                        if let Ok(dur) = modified.duration_since(UNIX_EPOCH) {
                            results.push(ScanResult::CreatedAt(dur.as_secs()));
                        }
                    }
                    // if let Ok(modified) = metadata.modified() { ... ScanResult::ModifiedAt(...) }
                }
                Err(e) => {
                    // Log or handle – but don't push fake time
                    eprintln!("Cannot read metadata for {}: {}", ctx.path.display(), e);
                }
            }
        }
        // Do NOT push current time here!
        Ok(results)
    }
}

fn parse_date_string(date_str: &str) -> Option<i64> {
    // With seconds
    if let Ok(dt) = NaiveDateTime::parse_from_str(date_str, "%Y-%m-%d %H:%M:%S") {
        return Some(dt.and_utc().timestamp());
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(date_str, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt.and_utc().timestamp());
    }
    // Date only → midnight UTC
    if let Ok(date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
        if let Some(dt) = date.and_hms_opt(0, 0, 0) {
            return Some(dt.and_utc().timestamp());
        }
    }
    None
}
