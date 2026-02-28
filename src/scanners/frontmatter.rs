use crate::error::{AppError, Result};
use crate::models::{FileContext, ScanResult};
use crate::scanners::Scanner;
use async_trait::async_trait;
use serde_json::Value as JsonValue;
use yaml_rust::{Yaml, YamlLoader};

pub struct FrontmatterScanner;

#[async_trait]
impl Scanner for FrontmatterScanner {
    async fn scan(&self, ctx: &FileContext) -> Result<Vec<ScanResult>> {
        let mut results = Vec::new();
        let mut yaml_str = String::new();

        let mut lines = ctx.content.lines();

        // Check if the VERY FIRST line is "---"
        // If the file doesn't start with ---, it doesn't have frontmatter.
        if let Some(first_line) = lines.next() {
            if first_line.trim() != "---" {
                return Ok(results);
            }
        } else {
            // Empty file
            return Ok(results);
        }

        // Read lines until the closing "---"
        let mut found_closing = false;
        for line in lines {
            if line.trim() == "---" {
                found_closing = true;
                break;
            }
            yaml_str.push_str(line);
            yaml_str.push('\n');
        }

        // Only parse if we found the closing tag and content is not empty
        if found_closing && !yaml_str.trim().is_empty() {
            let docs = YamlLoader::load_from_str(&yaml_str)?;
            if let Some(doc) = docs.get(0) {
                // Convert YAML to JSON for storage
                let json = yaml_to_json(doc)?;

                // Extract tags specifically from YAML if present
                if let Some(tags) = json.get("tags").and_then(|t| t.as_array()) {
                    for tag in tags {
                        if let Some(t_str) = tag.as_str() {
                            results.push(ScanResult::Tag(t_str.to_string()));
                        }
                    }
                }

                results.push(ScanResult::Metadata(json));
            }
        }

        Ok(results)
    }
}

// Helper to convert yaml_rust::Yaml to serde_json::Value
fn yaml_to_json(yaml: &Yaml) -> Result<JsonValue> {
    match yaml {
        Yaml::String(s) => Ok(JsonValue::String(s.clone())),
        Yaml::Integer(i) => Ok(JsonValue::Number((*i).into())),
        Yaml::Real(s) => {
            // Use AppError::Scanner to avoid constructing private yaml_rust types
            let f = s
                .parse::<f64>()
                .map_err(|_| AppError::Scanner(format!("Invalid float value in YAML: {}", s)))?;
            Ok(JsonValue::Number(serde_json::Number::from_f64(f).unwrap()))
        }
        Yaml::Boolean(b) => Ok(JsonValue::Bool(*b)),
        Yaml::Array(arr) => {
            let v: Result<Vec<_>> = arr.iter().map(yaml_to_json).collect();
            Ok(JsonValue::Array(v?))
        }
        Yaml::Hash(h) => {
            let mut map = serde_json::Map::new();
            for (k, v) in h {
                if let Yaml::String(key) = k {
                    map.insert(key.clone(), yaml_to_json(v)?);
                }
            }
            Ok(JsonValue::Object(map))
        }
        _ => Ok(JsonValue::Null),
    }
}
