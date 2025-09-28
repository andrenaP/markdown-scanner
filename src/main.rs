use clap::{Arg, Command};
use jwalk::WalkDir;
use log::{debug, info};
use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{self, Value as JsonValue};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use thiserror::Error;
use yaml_rust::{Yaml, YamlLoader};

#[derive(Error, Debug)]
enum AppError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("YAML parse error: {0}")]
    Yaml(#[from] yaml_rust::ScanError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, AppError>;

fn main() -> Result<()> {
    env_logger::init();
    let matches = Command::new("markdown-scanner")
        .version("0.1.0")
        .about("Scans Markdown files for tags and backlinks")
        .arg(
            Arg::new("file")
                .help("Path to markdown file")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("base_dir")
                .help("Base directory for relative paths")
                .required(true)
                .index(2),
        )
        .arg(
            Arg::new("database")
                .help("Path to SQLite database")
                .long("database")
                .short('d')
                .default_value("markdown_data.db"),
        )
        .arg(
            Arg::new("json-only")
                .help("Output JSON only without modifying the database")
                .long("json-only")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let file_path = matches.get_one::<String>("file").unwrap();
    let base_dir = matches.get_one::<String>("base_dir").unwrap();
    let db_path = matches.get_one::<String>("database").unwrap();
    let json_only = matches.get_flag("json-only");

    info!(
        "Starting scan: file={}, base_dir={}, db_path={}, json_only={}",
        file_path, base_dir, db_path, json_only
    );

    if json_only {
        let result = process_file_json_only(file_path, base_dir)?;
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let conn = Connection::open(db_path)?;
        setup_database(&conn)?;
        process_file(&conn, file_path, base_dir)?;
        info!("Scan completed successfully");
    }

    Ok(())
}

fn setup_database(conn: &Connection) -> Result<()> {
    debug!("Setting up database tables");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS folders (
            id INTEGER PRIMARY KEY,
            path TEXT UNIQUE
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            path TEXT UNIQUE,
            file_name TEXT,
            folder_id INTEGER,
            metadata TEXT DEFAULT '{}',
            FOREIGN KEY(folder_id) REFERENCES folders(id)
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY,
            tag TEXT UNIQUE
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS file_tags (
            file_id INTEGER,
            tag_id INTEGER,
            FOREIGN KEY(file_id) REFERENCES files(id),
            FOREIGN KEY(tag_id) REFERENCES tags(id),
            UNIQUE(file_id, tag_id)
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS backlinks (
            id INTEGER PRIMARY KEY,
            backlink TEXT,
            backlink_id INTEGER,
            file_id INTEGER,
            FOREIGN KEY(file_id) REFERENCES files(id),
            FOREIGN KEY(backlink_id) REFERENCES files(id),
            UNIQUE(backlink_id, file_id, backlink)
        )",
        [],
    )?;

    // Check if metadata column exists and add it if missing
    let mut stmt = conn.prepare("PRAGMA table_info(files)")?;
    let columns: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.contains(&"metadata".to_string()) {
        debug!("Adding metadata column to files table");
        conn.execute(
            "ALTER TABLE files ADD COLUMN metadata TEXT DEFAULT '{}'",
            [],
        )?;
    }

    debug!("Database tables set up successfully");
    Ok(())
}

fn process_file(conn: &Connection, file_path: &str, base_dir: &str) -> Result<()> {
    debug!("Processing file: {}", file_path);
    // Canonicalize file path
    let canonical_path = Path::new(file_path).canonicalize()?;
    let file_name = canonical_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            AppError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid file name",
            ))
        })?;
    let relative_path = remove_string(&canonical_path.to_string_lossy(), base_dir);
    debug!(
        "Canonical path: {}, Relative path: {}, File name: {}",
        canonical_path.display(),
        relative_path,
        file_name
    );

    // Get folder path and make it relative
    let folder_path = canonical_path
        .parent()
        .map(|p| {
            if p == Path::new(base_dir) {
                "".to_string() // Root directory
            } else {
                remove_string(&p.to_string_lossy(), base_dir)
            }
        })
        .unwrap_or_default();
    debug!("Folder path (relative): {}", folder_path);

    // Get or insert folder ID
    let folder_id = insert_folder(conn, &folder_path)?;
    debug!("Folder ID: {}", folder_id);

    // Get or update file ID
    let file_id = get_or_update_file_id(conn, &relative_path, file_name, folder_id)?;
    debug!("File ID: {}", file_id);

    // Clear existing tags and backlinks
    debug!(
        "Clearing existing tags and backlinks for file_id={}",
        file_id
    );
    conn.execute("DELETE FROM file_tags WHERE file_id = ?1", params![file_id])?;
    conn.execute("DELETE FROM backlinks WHERE file_id = ?1", params![file_id])?;
    debug!("Existing tags and backlinks cleared");

    // Read file and process YAML and tags
    let file = File::open(&canonical_path)?;
    let reader = BufReader::new(file);
    let mut in_yaml = false;
    let mut yaml_content = String::new();
    let mut in_tags = false;
    let mut yaml_tags = Vec::new();
    let mut in_code_block = false;
    let mut lines = Vec::new();

    // First pass: collect YAML content and tags
    debug!("Reading file for YAML and lines");
    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        lines.push(line.clone());
        debug!("Line {}: {}", line_num + 1, line);

        if line.trim() == "```" {
            in_code_block = !in_code_block;
            debug!(
                "Line {}: Code block {}",
                line_num + 1,
                if in_code_block { "started" } else { "ended" }
            );
            continue;
        }

        if !in_code_block {
            if line.trim() == "---" {
                if in_yaml {
                    // End of YAML frontmatter
                    in_yaml = false;
                    // Parse the collected YAML content
                    if !yaml_content.trim().is_empty() {
                        let parsed_yaml = parse_yaml_frontmatter(&yaml_content, &mut yaml_tags);
                        if let Some(metadata_json) = parsed_yaml {
                            // Update files table with metadata
                            if let Err(e) = conn.execute(
                                "UPDATE files SET metadata = ?1 WHERE id = ?2",
                                params![metadata_json, file_id],
                            ) {
                                debug!("Failed to update metadata for file_id={}: {}", file_id, e);
                            } else {
                                debug!("Stored metadata for file_id={}", file_id);
                            }
                        }
                    }
                    yaml_content.clear();
                    in_tags = false;
                } else {
                    // Start of YAML frontmatter
                    in_yaml = true;
                    yaml_content.clear();
                }
                debug!(
                    "Line {}: YAML frontmatter {}",
                    line_num + 1,
                    if in_yaml { "started" } else { "ended" }
                );
            } else if in_yaml {
                yaml_content.push_str(&line);
                yaml_content.push('\n');
                if line.starts_with("tags:") {
                    in_tags = true;
                    debug!("Line {}: Found 'tags:' section", line_num + 1);
                } else if in_tags && line.trim().starts_with("-") {
                    if let Some(tag) = line.trim().strip_prefix("-").map(|s| s.trim()) {
                        debug!("Line {}: Found YAML tag: {}", line_num + 1, tag);
                        yaml_tags.push(tag.to_string());
                    } else {
                        debug!("Line {}: Invalid YAML tag format: {}", line_num + 1, line);
                    }
                } else if in_tags && !line.trim().starts_with("-") {
                    in_tags = false;
                    debug!("Line {}: End of tags section", line_num + 1);
                }
            }
        }
    }

    // Handle case where YAML is at the end of file without closing ---
    if in_yaml && !yaml_content.trim().is_empty() {
        debug!("File ends with open YAML frontmatter, parsing...");
        let parsed_yaml = parse_yaml_frontmatter(&yaml_content, &mut yaml_tags);
        if let Some(metadata_json) = parsed_yaml {
            // Update files table with metadata
            if let Err(e) = conn.execute(
                "UPDATE files SET metadata = ?1 WHERE id = ?2",
                params![metadata_json, file_id],
            ) {
                debug!("Failed to update metadata for file_id={}: {}", file_id, e);
            } else {
                debug!("Stored metadata for file_id={}", file_id);
            }
        }
    }

    debug!("YAML tags found: {:?}", yaml_tags);

    // Process YAML tags
    debug!("Processing {} YAML tags", yaml_tags.len());
    for tag in yaml_tags {
        debug!("Processing YAML tag: {}", tag);
        match insert_tag(conn, &tag) {
            Ok(tag_id) => {
                debug!("Inserted/Retrieved tag: {} (tag_id={})", tag, tag_id);
                if let Err(e) = insert_file_tag(conn, file_id, tag_id) {
                    debug!(
                        "Failed to insert file_tag for file_id={}, tag_id={}: {}",
                        file_id, tag_id, e
                    );
                } else {
                    debug!(
                        "Inserted file_tag for file_id={}, tag_id={}",
                        file_id, tag_id
                    );
                }
            }
            Err(e) => debug!("Failed to insert tag {}: {}", tag, e),
        }
    }

    // Second pass: process inline tags
    debug!("Processing inline tags");
    in_code_block = false;
    let tag_re = Regex::new(r"#[\p{L}\p{N}_-]+").unwrap();
    for (line_num, line) in lines.iter().enumerate() {
        if line.trim() == "```" {
            in_code_block = !in_code_block;
            debug!(
                "Line {}: Code block {}",
                line_num + 1,
                if in_code_block { "started" } else { "ended" }
            );
            continue;
        }
        if !in_code_block {
            let cleaned = clearfromtrashtags(line);
            debug!(
                "Line {}: Cleaned line for inline tags: {}",
                line_num + 1,
                cleaned
            );
            for cap in tag_re.captures_iter(&cleaned) {
                let tag = &cap[0][1..]; // Remove '#'
                debug!("Line {}: Found inline tag: {}", line_num + 1, tag);
                match insert_tag(conn, tag) {
                    Ok(tag_id) => {
                        debug!("Inserted/Retrieved inline tag: {} (tag_id={})", tag, tag_id);
                        if let Err(e) = insert_file_tag(conn, file_id, tag_id) {
                            debug!(
                                "Failed to insert file_tag for file_id={}, tag_id={}: {}",
                                file_id, tag_id, e
                            );
                        } else {
                            debug!(
                                "Inserted file_tag for file_id={}, tag_id={}",
                                file_id, tag_id
                            );
                        }
                    }
                    Err(e) => debug!("Failed to insert inline tag {}: {}", tag, e),
                }
            }
        }
    }

    // Process backlinks
    debug!("Processing backlinks");
    let content = clearfromusless(fs::read_to_string(&canonical_path)?);
    let backlink_re = Regex::new(r"\[\[([^\]\[]+?)\]\]").unwrap();
    for cap in backlink_re.captures_iter(&content) {
        let backlink = &cap[1];
        debug!("Found backlink: {}", backlink);
        let sanitized = sanitize_backlink(backlink);
        if let Some(sanitized_backlink) = sanitized {
            debug!("Sanitized backlink: {}", sanitized_backlink);
            let (backlink_id, _backlink_path) =
                find_backlink_file(conn, &sanitized_backlink, base_dir, file_name, folder_id)?;
            if let Some(backlink_id) = backlink_id {
                debug!(
                    "Inserting backlink: backlink={}, backlink_id={}, file_id={}",
                    backlink, backlink_id, file_id
                );
                conn.execute(
                    "INSERT OR IGNORE INTO backlinks (backlink, backlink_id, file_id) VALUES (?1, ?2, ?3)",
                    params![backlink, backlink_id, file_id],
                )?;
            } else {
                debug!(
                    "No matching file found for backlink: {}",
                    sanitized_backlink
                );
                conn.execute(
                    "INSERT OR IGNORE INTO backlinks (backlink, file_id) VALUES (?1, ?2)",
                    params![backlink, file_id],
                )?;
            }
        } else {
            debug!("Skipped backlink due to invalid sanitization: {}", backlink);
        }
    }

    // Debug: Dump tags for this file
    debug!("Dumping tags for file_id={}", file_id);
    let mut stmt = conn.prepare(
        "SELECT t.tag FROM tags t JOIN file_tags ft ON t.id = ft.tag_id WHERE ft.file_id = ?",
    )?;
    let tags = stmt.query_map([file_id], |row| row.get::<_, String>(0))?;
    debug!(
        "Tags for file_id={}: {:?}",
        file_id,
        tags.collect::<rusqlite::Result<Vec<_>>>()?
    );

    debug!("Finished processing file: {}", file_path);
    Ok(())
}

fn process_file_json_only(file_path: &str, base_dir: &str) -> Result<JsonValue> {
    debug!("Processing file in JSON-only mode: {}", file_path);
    // Canonicalize file path
    let canonical_path = Path::new(file_path).canonicalize()?;
    let file_name = canonical_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            AppError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid file name",
            ))
        })?;
    let relative_path = remove_string(&canonical_path.to_string_lossy(), base_dir);
    debug!(
        "Canonical path: {}, Relative path: {}, File name: {}",
        canonical_path.display(),
        relative_path,
        file_name
    );

    // Get folder path and make it relative
    let folder_path = canonical_path
        .parent()
        .map(|p| {
            if p == Path::new(base_dir) {
                "".to_string() // Root directory
            } else {
                remove_string(&p.to_string_lossy(), base_dir)
            }
        })
        .unwrap_or_default();
    debug!("Folder path (relative): {}", folder_path);

    // Read file and process YAML and tags
    let file = File::open(&canonical_path)?;
    let reader = BufReader::new(file);
    let mut in_yaml = false;
    let mut yaml_content = String::new();
    let mut in_tags = false;
    let mut tags = Vec::new();
    let mut in_code_block = false;
    let mut lines = Vec::new();

    // First pass: collect YAML content and tags
    debug!("Reading file for YAML and lines");
    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        lines.push(line.clone());
        debug!("Line {}: {}", line_num + 1, line);

        if line.trim() == "```" {
            in_code_block = !in_code_block;
            debug!(
                "Line {}: Code block {}",
                line_num + 1,
                if in_code_block { "started" } else { "ended" }
            );
            continue;
        }

        if !in_code_block {
            if line.trim() == "---" {
                if in_yaml {
                    in_yaml = false;
                    if !yaml_content.trim().is_empty() {
                        parse_yaml_frontmatter(&yaml_content, &mut tags);
                    }
                    yaml_content.clear();
                    in_tags = false;
                } else {
                    in_yaml = true;
                    yaml_content.clear();
                }
                debug!(
                    "Line {}: YAML frontmatter {}",
                    line_num + 1,
                    if in_yaml { "started" } else { "ended" }
                );
            } else if in_yaml {
                yaml_content.push_str(&line);
                yaml_content.push('\n');
                if line.starts_with("tags:") {
                    in_tags = true;
                    debug!("Line {}: Found 'tags:' section", line_num + 1);
                } else if in_tags && line.trim().starts_with("-") {
                    if let Some(tag) = line.trim().strip_prefix("-").map(|s| s.trim()) {
                        debug!("Line {}: Found YAML tag: {}", line_num + 1, tag);
                        tags.push(tag.to_string());
                    } else {
                        debug!("Line {}: Invalid YAML tag format: {}", line_num + 1, line);
                    }
                } else if in_tags && !line.trim().starts_with("-") {
                    in_tags = false;
                    debug!("Line {}: End of tags section", line_num + 1);
                }
            }
        }
    }

    // Handle case where YAML is at the end of file without closing ---
    if in_yaml && !yaml_content.trim().is_empty() {
        debug!("File ends with open YAML frontmatter, parsing...");
        parse_yaml_frontmatter(&yaml_content, &mut tags);
    }

    debug!("YAML tags found: {:?}", tags);

    // Second pass: process inline tags
    debug!("Processing inline tags");
    in_code_block = false;
    let tag_re = Regex::new(r"#[\p{L}\p{N}_-]+").unwrap();
    for (line_num, line) in lines.iter().enumerate() {
        if line.trim() == "```" {
            in_code_block = !in_code_block;
            debug!(
                "Line {}: Code block {}",
                line_num + 1,
                if in_code_block { "started" } else { "ended" }
            );
            continue;
        }
        if !in_code_block {
            let cleaned = clearfromtrashtags(line);
            debug!(
                "Line {}: Cleaned line for inline tags: {}",
                line_num + 1,
                cleaned
            );
            for cap in tag_re.captures_iter(&cleaned) {
                let tag = &cap[0][1..]; // Remove '#'
                debug!("Line {}: Found inline tag: {}", line_num + 1, tag);
                if !tags.contains(&tag.to_string()) {
                    tags.push(tag.to_string());
                }
            }
        }
    }

    // Process backlinks
    debug!("Processing backlinks");
    let content = clearfromusless(fs::read_to_string(&canonical_path)?);
    let backlink_re = Regex::new(r"\[\[([^\]\[]+?)\]\]").unwrap();
    let mut backlinks = Vec::new();
    for cap in backlink_re.captures_iter(&content) {
        let backlink = &cap[1];
        debug!("Found backlink: {}", backlink);
        let sanitized = sanitize_backlink(backlink);
        if let Some(sanitized_backlink) = sanitized {
            debug!("Sanitized backlink: {}", sanitized_backlink);
            backlinks.push(sanitized_backlink);
        } else {
            debug!("Skipped backlink due to invalid sanitization: {}", backlink);
        }
    }

    // Build JSON output
    let metadata = if !yaml_content.trim().is_empty() {
        parse_yaml_frontmatter(&yaml_content, &mut Vec::new())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(JsonValue::Object(serde_json::Map::new()))
    } else {
        JsonValue::Object(serde_json::Map::new())
    };

    let json_output = serde_json::json!({
        "file": {
            "path": relative_path,
            "file_name": file_name,
            "folder_path": folder_path
        },
        "metadata": metadata,
        "tags": tags,
        "backlinks": backlinks
    });

    debug!("JSON output generated: {:?}", json_output);
    Ok(json_output)
}

// Helper function to parse YAML frontmatter and extract tags
fn parse_yaml_frontmatter(yaml_str: &str, yaml_tags: &mut Vec<String>) -> Option<String> {
    if yaml_str.trim().is_empty() {
        return None;
    }

    // Clear any existing tags from this YAML block
    let mut block_tags = Vec::new();
    let mut in_tags = false;
    let lines: Vec<&str> = yaml_str.lines().collect();

    // First, extract tags from this YAML block
    for line in &lines {
        let line = line.trim();
        if line.starts_with("tags:") {
            in_tags = true;
        } else if in_tags && line.starts_with("-") {
            if let Some(tag) = line.strip_prefix("-").map(|s| s.trim()) {
                block_tags.push(tag.to_string());
            }
        } else if in_tags && !line.starts_with("-") && !line.is_empty() {
            in_tags = false;
        }
    }

    // Add block tags to the overall list (avoid duplicates)
    for tag in block_tags {
        if !yaml_tags.contains(&tag) {
            yaml_tags.push(tag);
        }
    }

    // Now try to parse the YAML
    match YamlLoader::load_from_str(yaml_str) {
        Ok(yaml_docs) => {
            if let Some(yaml) = yaml_docs.get(0) {
                match yaml_to_json(yaml) {
                    Ok(json_value) => match serde_json::to_string(&json_value) {
                        Ok(metadata_json) => {
                            debug!(
                                "Successfully parsed YAML frontmatter to JSON: {}",
                                metadata_json
                            );
                            Some(metadata_json)
                        }
                        Err(e) => {
                            debug!("Failed to serialize YAML to JSON: {}", e);
                            None
                        }
                    },
                    Err(e) => {
                        debug!("Failed to convert YAML to JSON: {}", e);
                        None
                    }
                }
            } else {
                debug!("No YAML document found in frontmatter");
                None
            }
        }
        Err(e) => {
            debug!(
                "Failed to parse YAML frontmatter: {} at {:?}",
                e,
                e.marker()
            );
            // Log the problematic YAML content for debugging
            debug!("Problematic YAML content: {}", yaml_str);
            None
        }
    }
}

// Helper function to convert YAML to JSON
fn yaml_to_json(yaml: &Yaml) -> Result<serde_json::Value> {
    match yaml {
        Yaml::String(s) => Ok(serde_json::Value::String(s.clone())),
        Yaml::Integer(i) => Ok(serde_json::Value::Number((*i).into())),
        Yaml::Real(s) => {
            let f = s.parse::<f64>().map_err(|e| {
                AppError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid float: {}", e),
                ))
            })?;
            Ok(serde_json::Value::Number(
                serde_json::Number::from_f64(f).ok_or_else(|| {
                    AppError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid float conversion",
                    ))
                })?,
            ))
        }
        Yaml::Boolean(b) => Ok(serde_json::Value::Bool(*b)),
        Yaml::Array(vec) => {
            let mut arr = Vec::new();
            for item in vec {
                arr.push(yaml_to_json(item)?);
            }
            Ok(serde_json::Value::Array(arr))
        }
        Yaml::Hash(hash) => {
            let mut map = serde_json::Map::new();
            for (key, value) in hash {
                if let Yaml::String(key_str) = key {
                    map.insert(key_str.clone(), yaml_to_json(value)?);
                }
            }
            Ok(serde_json::Value::Object(map))
        }
        _ => Ok(serde_json::Value::Null),
    }
}

fn insert_folder(conn: &Connection, relative_path: &str) -> Result<i64> {
    let path = if relative_path.is_empty() {
        "/"
    } else {
        relative_path
    };
    debug!("Inserting folder: {}", path);
    conn.execute(
        "INSERT OR IGNORE INTO folders (path) VALUES (?1)",
        params![path],
    )?;
    let id: i64 = conn.query_row(
        "SELECT id FROM folders WHERE path = ?1",
        params![path],
        |row| row.get(0),
    )?;
    debug!("Folder inserted/retrieved: path={}, id={}", path, id);
    Ok(id)
}

fn get_or_update_file_id(
    conn: &Connection,
    path: &str,
    file_name: &str,
    folder_id: i64,
) -> Result<i64> {
    debug!(
        "Getting or updating file_id for path={}, file_name={}, folder_id={}",
        path, file_name, folder_id
    );
    let existing_id: Option<i64> = conn
        .query_row(
            "SELECT id FROM files WHERE path = ?1",
            params![path],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(id) = existing_id {
        debug!("Found existing file_id: {}", id);
        // Update folder_id, file_name, and ensure metadata is set
        conn.execute(
            "UPDATE files SET folder_id = ?1, file_name = ?2, metadata = COALESCE(metadata, '{}') WHERE id = ?3",
            params![folder_id, file_name, id],
        )?;
        debug!(
            "Updated file: id={}, path={}, folder_id={}",
            id, path, folder_id
        );
        Ok(id)
    } else {
        debug!("No existing file found, inserting new file");
        insert_file(conn, path, file_name, folder_id)
    }
}

fn insert_file(conn: &Connection, path: &str, file_name: &str, folder_id: i64) -> Result<i64> {
    debug!(
        "Inserting file: path={}, file_name={}, folder_id={}",
        path, file_name, folder_id
    );
    conn.execute(
        "INSERT OR IGNORE INTO files (path, file_name, folder_id, metadata) VALUES (?1, ?2, ?3, ?4)",
        params![path, file_name, folder_id, "{}"],
    )?;
    let id: i64 = conn.query_row(
        "SELECT id FROM files WHERE path = ?1",
        params![path],
        |row| row.get(0),
    )?;
    debug!("File inserted: id={}, path={}", id, path);
    Ok(id)
}

fn remove_string(full_path: &str, part_to_remove: &str) -> String {
    let escaped_part = regex::escape(part_to_remove);
    let result = Regex::new(&escaped_part)
        .unwrap()
        .replace_all(full_path, "")
        .trim_start_matches('/')
        .to_string();
    debug!(
        "Removed base_dir from path: full_path={}, part_to_remove={}, result={}",
        full_path, part_to_remove, result
    );
    result
}

fn clearfromtrashtags(input: &str) -> String {
    let re_brackets = Regex::new(r"\[.*?\]").unwrap();
    let re_parens = Regex::new(r"\(.*?\)").unwrap();
    let re_code = Regex::new(r"`.*?`").unwrap();
    let re_urls = Regex::new(r"https?://[\w\.\-\_/\%#]+").unwrap();
    let re_angles = Regex::new(r"<.*?>").unwrap();

    let result = re_angles
        .replace_all(
            &re_urls.replace_all(
                &re_code.replace_all(
                    &re_parens.replace_all(&re_brackets.replace_all(input, ""), ""),
                    "",
                ),
                " ",
            ),
            "",
        )
        .to_string();
    debug!("Cleaned line for tags: input={}, result={}", input, result);
    result
}

fn clearfromusless(input: String) -> String {
    let re_code = Regex::new(r"`.*?`").unwrap();
    let re_urls = Regex::new(r"https?://[\w\.\-\_/\%#]+").unwrap();
    let re_angles = Regex::new(r"<.*?>").unwrap();

    let result = re_angles
        .replace_all(
            &re_urls.replace_all(&re_code.replace_all(&input, ""), " "),
            "",
        )
        .to_string();
    debug!("Cleaned content for backlinks: result={}", result);
    result
}

fn sanitize_backlink(backlink: &str) -> Option<String> {
    if backlink.is_empty() {
        debug!("Backlink is empty, skipping");
        return None;
    }

    let mut result = backlink.to_string();
    if let Some(idx) = result.find('#') {
        debug!(
            "Removing fragment from backlink: {} -> {}",
            result,
            &result[..idx]
        );
        result = result[..idx].to_string();
    }
    if let Some(idx) = result.find('|') {
        debug!(
            "Removing alias from backlink: {} -> {}",
            result,
            &result[..idx]
        );
        result = result[..idx].to_string();
    }

    let sanitized_filename = result.replace("\'", "\'\'");
    let final_result = if !sanitized_filename.contains('.') {
        format!("{}.md", sanitized_filename)
    } else {
        sanitized_filename
    };

    debug!(
        "Sanitized backlink: input={}, output={}",
        backlink, final_result
    );
    Some(final_result)
}

fn insert_tag(conn: &Connection, tag: &str) -> Result<i64> {
    debug!("Inserting tag: {}", tag);
    conn.execute("INSERT OR IGNORE INTO tags (tag) VALUES (?1)", params![tag])?;
    let id: i64 = conn.query_row("SELECT id FROM tags WHERE tag = ?1", params![tag], |row| {
        row.get(0)
    })?;
    debug!("Tag inserted/retrieved: tag={}, id={}", tag, id);
    Ok(id)
}

fn insert_file_tag(conn: &Connection, file_id: i64, tag_id: i64) -> Result<()> {
    debug!("Inserting file_tag: file_id={}, tag_id={}", file_id, tag_id);
    conn.execute(
        "INSERT OR IGNORE INTO file_tags (file_id, tag_id) VALUES (?1, ?2)",
        params![file_id, tag_id],
    )?;
    debug!("File_tag inserted: file_id={}, tag_id={}", file_id, tag_id);
    Ok(())
}

fn find_backlink_file(
    conn: &Connection,
    backlink: &str,
    base_dir: &str,
    _file_name: &str,
    folder_id: i64,
) -> Result<(Option<i64>, Option<String>)> {
    let filename = Path::new(backlink)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(backlink);
    debug!(
        "Finding backlink file: backlink={}, filename={}",
        backlink, filename
    );

    // Search all files in the database with matching file_name
    let query = "SELECT f.id, f.path, f.folder_id, fo.path AS folder_path
                 FROM files f
                 JOIN folders fo ON f.folder_id = fo.id
                 WHERE f.file_name = ?1";
    debug!("Executing query: {} with file_name={}", query, filename);
    let mut stmt = conn.prepare(query)?;
    let mut rows = stmt.query(params![filename])?;

    let mut valid_matches = Vec::new();
    let mut invalid_matches = Vec::new();
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let path: String = row.get(1)?;
        let file_folder_id: i64 = row.get(2)?;
        let folder_path: String = row.get(3)?;
        let full_path = Path::new(base_dir).join(&path);
        debug!(
            "Checking database match: id={}, path={}, folder_id={}, folder_path={}",
            id, path, file_folder_id, folder_path
        );
        if full_path.exists() {
            debug!("File exists at: {}", full_path.display());
            valid_matches.push((id, path, file_folder_id));
        } else {
            debug!("File does not exist at: {}", full_path.display());
            invalid_matches.push((id, path, file_folder_id));
        }
    }

    // Handle valid matches
    if valid_matches.len() == 1 {
        let (id, path, _) = valid_matches.into_iter().next().unwrap();
        debug!("Found single valid match: id={}, path={}", id, path);
        return Ok((Some(id), Some(path)));
    } else if valid_matches.len() > 1 {
        // Prefer match in the same folder, if available
        if let Some(&(id, ref path, _)) =
            valid_matches.iter().find(|&&(_, _, fid)| fid == folder_id)
        {
            debug!(
                "Multiple matches found, selecting match in same folder: id={}, path={}",
                id, path
            );
            // Clean up other valid matches to avoid duplicates
            for (other_id, _, _) in valid_matches.iter().filter(|&&(_id, _, _)| _id != id) {
                debug!("Removing duplicate file entry: id={}", other_id);
                conn.execute(
                    "DELETE FROM backlinks WHERE file_id = ?1 OR backlink_id = ?1",
                    params![other_id],
                )?;
                conn.execute(
                    "DELETE FROM file_tags WHERE file_id = ?1",
                    params![other_id],
                )?;
                conn.execute("DELETE FROM files WHERE id = ?1", params![other_id])?;
            }
            return Ok((Some(id), Some(path.clone())));
        }
        // Otherwise, select the shortest path
        let &(id, ref path, _) = valid_matches
            .iter()
            .min_by_key(|&(_, ref path, _)| path.len())
            .unwrap();
        debug!(
            "Multiple matches found, selecting shortest path: id={}, path={}",
            id, path
        );
        // Clean up other valid matches to avoid duplicates
        for (other_id, _, _) in valid_matches.iter().filter(|&&(_id, _, _)| _id != id) {
            debug!("Removing duplicate file entry: id={}", other_id);
            conn.execute(
                "DELETE FROM backlinks WHERE file_id = ?1 OR backlink_id = ?1",
                params![other_id],
            )?;
            conn.execute(
                "DELETE FROM file_tags WHERE file_id = ?1",
                params![other_id],
            )?;
            conn.execute("DELETE FROM files WHERE id = ?1", params![other_id])?;
        }
        return Ok((Some(id), Some(path.clone())));
    }

    // Clean up invalid matches
    if !invalid_matches.is_empty() {
        debug!(
            "Found {} invalid database entries for file_name={}",
            invalid_matches.len(),
            filename
        );
        for (id, path, _) in invalid_matches {
            debug!("Removing invalid file entry: id={}, path={}", id, path);
            conn.execute(
                "DELETE FROM backlinks WHERE file_id = ?1 OR backlink_id = ?1",
                params![id],
            )?;
            conn.execute("DELETE FROM file_tags WHERE file_id = ?1", params![id])?;
            conn.execute("DELETE FROM files WHERE id = ?1", params![id])?;
        }
    }

    // Fallback: search base_dir filesystem
    debug!("Searching filesystem for backlink file: {}", filename);
    let mut matches: Vec<PathBuf> = WalkDir::new(base_dir)
        .parallelism(jwalk::Parallelism::RayonNewPool(0))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().file_name().and_then(|s| s.to_str()) == Some(filename))
        .map(|e| e.path().to_path_buf())
        .collect();

    for path in &matches {
        debug!("Found file in filesystem: {}", path.display());
    }

    matches.sort_by(|a, b| a.to_string_lossy().len().cmp(&b.to_string_lossy().len()));

    if let Some(matching_file) = matches.first() {
        let folder_path = matching_file
            .parent()
            .map(|p| {
                if p == Path::new(base_dir) {
                    "".to_string() // Root directory
                } else {
                    remove_string(&p.to_string_lossy(), base_dir)
                }
            })
            .unwrap_or_default();
        let relative_path = remove_string(&matching_file.to_string_lossy(), base_dir);
        debug!(
            "Found file in filesystem: path={}, folder_path={}",
            relative_path, folder_path
        );
        let new_folder_id = insert_folder(conn, &folder_path)?;

        // Check if an existing entry needs to be updated
        let existing_id: Option<i64> = conn
            .query_row(
                "SELECT id FROM files WHERE file_name = ?1",
                params![filename],
                |row| row.get(0),
            )
            .optional()?;

        let backlink_id = if let Some(id) = existing_id {
            debug!(
                "Updating existing file entry: id={}, path={}, folder_id={}",
                id, relative_path, new_folder_id
            );
            conn.execute(
                "UPDATE files SET path = ?1, folder_id = ?2, metadata = COALESCE(metadata, '{}') WHERE id = ?3",
                params![relative_path, new_folder_id, id],
            )?;
            id
        } else {
            debug!(
                "Inserting new file: path={}, file_name={}, folder_id={}",
                relative_path, filename, new_folder_id
            );
            insert_file(conn, &relative_path, filename, new_folder_id)?
        };

        debug!(
            "Inserted/Updated backlink file: id={}, path={}",
            backlink_id, relative_path
        );
        Ok((Some(backlink_id), Some(relative_path)))
    } else {
        debug!(
            "No file found for backlink: {}. Skipping backlink insertion.",
            filename
        );
        Ok((None, None))
    }
}