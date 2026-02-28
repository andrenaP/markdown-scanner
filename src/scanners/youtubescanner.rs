use crate::error::Result;
use crate::models::{FileContext, ScanResult};
use crate::scanners::Scanner;
use async_trait::async_trait;
use regex::Regex;
use tokio::process::Command;

pub struct YoutubeScanner;

#[async_trait]
impl Scanner for YoutubeScanner {
    async fn scan(&self, ctx: &FileContext) -> Result<Vec<ScanResult>> {
        let mut results = Vec::new();

        // Forgiving regex that handles \n, \r\n, and weird spacing
        let vid_re = Regex::new(r"```vid\s+(https?://[^\s]+)\s+```").unwrap();

        for cap in vid_re.captures_iter(&ctx.content) {
            let url = &cap[1];
            println!("[DEBUG] 1. Regex matched URL: {}", url);

            // 1. Check if the URL already exists in our cached vidlinks
            let cached_title = ctx
                .vidlinks
                .iter()
                .find(|(cached_url, _)| cached_url == url)
                .map(|(_, title)| title.clone()); // Clone the string so we own it for ScanResult

            // 2. Decide whether to use the cache or fetch a new one
            if let Some(title) = cached_title {
                println!(
                    "[DEBUG] Found URL in cache. Skipping wget. Title: {}",
                    title
                );
                results.push(ScanResult::YoutubeVideo {
                    url: url.to_string(),
                    title,
                });
            } else {
                println!("[DEBUG] URL not found in cache. Fetching...");
                match fetch_youtube_title_wget(url).await {
                    Some(title) => {
                        println!("[DEBUG] Success! Title extracted: {}", title);

                        // Push the new variant
                        results.push(ScanResult::YoutubeVideo {
                            url: url.to_string(),
                            title,
                        });
                    }
                    None => {
                        println!("[DEBUG] Failure: Could not extract title for {}", url);
                    }
                }
            }
        }

        if results.is_empty() {
            println!("[DEBUG] Scanner finished, but 0 results were added.");
        }

        Ok(results)
    }
}

fn extract_between<'a>(s: &'a str, start_str: &str, end_str: &str) -> Option<&'a str> {
    let start_pos = s.find(start_str)? + start_str.len();
    let remainder = &s[start_pos..];
    let end_pos = remainder.find(end_str)?;
    Some(&remainder[..end_pos])
}

async fn fetch_youtube_title_wget(url: &str) -> Option<String> {
    println!("[DEBUG] 2. Spawning wget for: {}", url);

    // Call wget using tokio::process
    let output = Command::new("wget")
        .arg("-qO-")
        // CRITICAL: We spoof the User-Agent. YouTube will often block default wget requests.
        .arg("--header=User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .arg(url)
        .output()
        .await;

    let output = match output {
        Ok(out) => out,
        Err(e) => {
            println!("[DEBUG] 3. Wget command failed to execute entirely: {}", e);
            return None;
        }
    };

    if !output.status.success() {
        println!(
            "[DEBUG] 3. Wget returned an error status code: {}",
            output.status
        );
        return None;
    }

    let html = String::from_utf8_lossy(&output.stdout);

    if html.trim().is_empty() {
        println!("[DEBUG] 3. Wget succeeded, but the downloaded HTML is empty.");
        return None;
    }

    println!("[DEBUG] 3. HTML downloaded successfully. Attempting to parse...");

    // Try Lua exact logic first
    let start_str = r#"hNextResults":{"results":{"results":{"contents":[{"videoPrimaryInfoRenderer":{"title":{"runs":[{"text":""#;
    let end_str = r#""}]},"viewCount""#;

    if let Some(title) = extract_between(&html, start_str, end_str) {
        return Some(title.to_string());
    }

    // Fallback: Just grab the <title> tag. This is usually much safer!
    if let Some(title) = extract_between(&html, "<title>", "</title>") {
        return Some(title.replace(" - YouTube", "").to_string());
    }

    // If it fails, print the first 200 chars of HTML so we know what YouTube sent us
    println!(
        "[DEBUG] 3. Parse failed! Could not find markers. First 200 chars of HTML: {:.200}",
        html
    );
    None
}
