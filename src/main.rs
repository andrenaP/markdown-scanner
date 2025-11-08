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
        .version("0.1.4")
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
        .arg(
            Arg::new("delete")
                .help("Remove file from db")
                .short('d')
                .long("delete")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let file_path = matches.get_one::<String>("file").unwrap();
    let base_dir = matches.get_one::<String>("base_dir").unwrap();
    let db_path = matches.get_one::<String>("database").unwrap();
    let json_only = matches.get_flag("json-only");
    let delete = matches.get_flag("delete");
    info!(
        "Starting scan: file={}, base_dir={}, db_path={}, json_only={}",
        file_path, base_dir, db_path, json_only
    );

    if json_only {
        let result = process_file_json_only(file_path, base_dir)?;
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if delete {
        let conn = Connection::open(db_path)?;
        remove_file_from_db(&conn, file_path, base_dir)?;
        println!("Ok")
    } else {
        let conn = Connection::open(db_path)?;
        setup_database(&conn)?;
        process_file(&conn, file_path, base_dir)?;
        info!("Scan completed successfully");
    }

    Ok(())
}

fn setup_database(conn: &Connection) -> Result<()> {
    debug!("Foreign keys enabled");
    conn.execute("PRAGMA foreign_keys = ON", [])?;

    debug!("Setting up database tables");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS folders (
                id INTEGER PRIMARY KEY,
                path TEXT UNIQUE
            )",
        [],
    )?;

    // Files table (add CASCADE for folder_id if desired; here it's optional)
    conn.execute(
            "CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                path TEXT UNIQUE,
                file_name TEXT,
                folder_id INTEGER,
                metadata TEXT DEFAULT '{}',
                FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE CASCADE  -- Optional: cascades if deleting folders
            )",
            [],
        )?;

    // Tags table (no changes)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY,
                tag TEXT UNIQUE
            )",
        [],
    )?;

    // File_tags table (cascade on file_id, but not on tag_id)
    conn.execute(
            "CREATE TABLE IF NOT EXISTS file_tags (
                file_id INTEGER,
                tag_id INTEGER,
                FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,  -- Auto-delete tags for this file
                FOREIGN KEY(tag_id) REFERENCES tags(id),                      -- No cascade: keep tags
                UNIQUE(file_id, tag_id)
            )",
            [],
        )?;

    // Backlinks table (cascade on both file_id and backlink_id for bidirectional cleanup)
    conn.execute(
            "CREATE TABLE IF NOT EXISTS backlinks (
                id INTEGER PRIMARY KEY,
                backlink TEXT,
                backlink_id INTEGER,
                file_id INTEGER,
                FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,             -- Auto-delete if target file deleted
                FOREIGN KEY(backlink_id) REFERENCES files(id) ON DELETE CASCADE,         -- Auto-delete if source file deleted
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

    let folder_path = canonical_path
        .parent()
        .map(|p| {
            if p == Path::new(base_dir) {
                "".to_string()
            } else {
                remove_string(&p.to_string_lossy(), base_dir)
            }
        })
        .unwrap_or_default();
    debug!("Folder path (relative): {}", folder_path);

    let file = File::open(&canonical_path)?;
    let reader = BufReader::new(file);
    let mut in_yaml = false;
    let mut yaml_content = String::new();
    let mut tags = Vec::new();
    let mut in_code_block = false;
    let mut lines = Vec::new();
    let mut metadata = JsonValue::Object(serde_json::Map::new());

    debug!("Reading file for YAML and lines");
    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        lines.push(line.clone());
        debug!("Line {}: {}", line_num + 1, &line);

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
                        debug!("Parsing YAML: {}", yaml_content);
                        if let Some(json_str) = parse_yaml_frontmatter(&yaml_content, &mut tags) {
                            metadata = serde_json::from_str(&json_str).map_err(|e| {
                                AppError::Io(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!("Failed to parse YAML JSON: {}", e),
                                ))
                            })?;
                        }
                    }
                    yaml_content.clear();
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
            }
        }
    }

    if in_yaml && !yaml_content.trim().is_empty() {
        debug!("Parsing unclosed YAML: {}", yaml_content);
        if let Some(json_str) = parse_yaml_frontmatter(&yaml_content, &mut tags) {
            metadata = serde_json::from_str(&json_str).map_err(|e| {
                AppError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse YAML JSON: {}", e),
                ))
            })?;
        }
    }

    debug!("YAML tags found: {:?}", tags);

    in_code_block = false;
    let tag_re = Regex::new(r"#[\p{L}\p{N}_-]+").unwrap();
    for (line_num, line) in lines.iter().enumerate() {
        if line.trim() == "```" {
            in_code_block = !in_code_block;
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
                let tag = &cap[0][1..];
                debug!("Line {}: Found inline tag: {}", line_num + 1, tag);
                if !tags.contains(&tag.to_string()) {
                    tags.push(tag.to_string());
                }
            }
        }
    }

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
        }
    }

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

fn remove_file_from_db(conn: &Connection, file_path: &str, base_dir: &str) -> Result<()> {
    let file_name = Path::new(file_path)
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            AppError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid file name",
            ))
        })?;
    let relative_path = remove_string(file_path, base_dir);
    debug!(
        "File path: {}, Relative path: {}, File name: {}",
        file_path, relative_path, file_name
    );

    // Delete the file—cascades handle file_tags and backlinks
    let files_deleted =
        conn.execute("DELETE FROM files WHERE path = ?1", params![relative_path])?;

    debug!(
        "Deleted {} file(s) (cascades cleaned related data)",
        files_deleted
    );

    if files_deleted == 0 {
        return Err(AppError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File not found in DB",
        )));
    }

    Ok(())
}
// Helper function to parse YAML frontmatter and extract tags
fn parse_yaml_frontmatter(yaml_str: &str, yaml_tags: &mut Vec<String>) -> Option<String> {
    if yaml_str.trim().is_empty() {
        return None;
    }

    let mut block_tags = Vec::new();
    let mut in_tags = false;
    let lines: Vec<&str> = yaml_str.lines().collect();

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

    for tag in block_tags {
        if !yaml_tags.contains(&tag) {
            yaml_tags.push(tag);
        }
    }

    match YamlLoader::load_from_str(yaml_str) {
        Ok(yaml_docs) => {
            if let Some(yaml) = yaml_docs.get(0) {
                match yaml_to_json(yaml) {
                    Ok(json_value) => match serde_json::to_string(&json_value) {
                        Ok(metadata_json) => {
                            debug!("Parsed YAML to JSON: {}", metadata_json);
                            Some(metadata_json)
                        }
                        Err(e) => {
                            debug!("Failed to serialize YAML to JSON: {}", e);
                            None
                        }
                    },
                    Err(e) => {
                        debug!("Failed to convert YAML to JSON: {:?}", e);
                        None
                    }
                }
            } else {
                debug!("No YAML document found in frontmatter");
                None
            }
        }
        Err(e) => {
            debug!("Failed to parse YAML: {} at {:?}", e, e.marker());
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
    let re_angles = Regex::new(r"<[^>]+>[^<]*</[^>]+>").unwrap(); // Match tag and content

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
    let re_angles = Regex::new(r"<[^>]+>[^<]*</[^>]+>").unwrap();
    let re_spaces = Regex::new(r"\s+").unwrap();

    let result = re_spaces
        .replace_all(
            &re_angles.replace_all(
                &re_urls.replace_all(&re_code.replace_all(&input, ""), " "),
                "",
            ),
            " ",
        )
        .trim()
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
    // let sanitized_filename = result.replace("\'", "\'\'"); REMEMBER NOT DO TO THAT. THIS IS NOT LUA.
    // Do not escape single quotes here; handle escaping in SQL queries directly
    let final_result = if !result.contains('.') {
        format!("{}.md", result)
    } else {
        result
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
        debug!(
            "Checking database match: id={}, path={}, folder_id={}, folder_path={}",
            id, path, file_folder_id, folder_path
        );

        // __dangling__ entries as always valid
        if folder_path == "/" {
            debug!("Dangling link found, treating as valid: {}", path);
            valid_matches.push((id, path, file_folder_id));
            continue; // Skip the full_path.exists() check
        }

        let full_path = Path::new(base_dir).join(&path);
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

        // Delete all invalid matches, as they are orphans
        for (invalid_id, invalid_path, _) in invalid_matches {
            debug!(
                "Removing invalid (orphan) file entry: id={}, path={}",
                invalid_id, invalid_path
            );
            // Delete from files table, cascades will handle file_tags and backlinks
            conn.execute("DELETE FROM files WHERE id = ?1", params![invalid_id])?;
        }

        return Ok((Some(id), Some(path)));
    } else if valid_matches.len() > 1 {
        // Prefer match in the same folder, if available
        let (id, path) = if let Some(&(id, ref path, _)) =
            valid_matches.iter().find(|&&(_, _, fid)| fid == folder_id)
        {
            debug!(
                "Multiple matches found, selecting match in same folder: id={}, path={}",
                id, path
            );
            (id, path.clone())
        } else {
            // Otherwise, select the shortest path
            let &(id, ref path, _) = valid_matches
                .iter()
                .min_by_key(|&(_, ref path, _)| path.len())
                .unwrap();
            debug!(
                "Multiple matches found, selecting shortest path: id={}, path={}",
                id, path
            );
            (id, path.clone())
        };

        // Clean up other valid matches (duplicates)
        for (other_id, other_path, _) in valid_matches.iter().filter(|&&(_id, _, _)| _id != id) {
            debug!(
                "Removing duplicate valid file entry: id={}, path={}",
                other_id, other_path
            );
            conn.execute("DELETE FROM files WHERE id = ?1", params![other_id])?;
        }

        // Delete all invalid matches
        for (invalid_id, invalid_path, _) in invalid_matches {
            debug!(
                "Removing invalid (orphan) file entry: id={}, path={}",
                invalid_id, invalid_path
            );
            conn.execute("DELETE FROM files WHERE id = ?1", params![invalid_id])?;
        }

        return Ok((Some(id), Some(path)));
    }

    // No valid matches found, clean up all invalid matches
    if !invalid_matches.is_empty() {
        debug!(
            "Found {} invalid database entries for file_name={}",
            invalid_matches.len(),
            filename
        );
        for (id, path, _) in invalid_matches {
            debug!("Removing invalid file entry: id={}, path={}", id, path);
            // Deleting from 'files' will cascade to file_tags and backlinks
            conn.execute("DELETE FROM files WHERE id = ?1", params![id])?;
        }
    }

    // Fallback: search base_dir filesystem
    debug!("Searching filesystem for backlink file: {}", filename);
    let mut matches: Vec<(PathBuf, String, String)> = WalkDir::new(base_dir)
        .parallelism(jwalk::Parallelism::RayonNewPool(0))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().file_name().and_then(|s| s.to_str()) == Some(filename))
        .map(|e| {
            let path = e.path().to_path_buf();
            let relative_path = remove_string(&path.to_string_lossy(), base_dir);
            let folder_path = path
                .parent()
                .map(|p| {
                    if p == Path::new(base_dir) {
                        "".to_string()
                    } else {
                        remove_string(&p.to_string_lossy(), base_dir)
                    }
                })
                .unwrap_or_default();
            (path, relative_path, folder_path)
        })
        .collect();

    for (path, relative_path, folder_path) in &matches {
        debug!(
            "Found file in filesystem: path={}, relative_path={}, folder_path={}",
            path.display(),
            relative_path,
            folder_path
        );
    }

    matches.sort_by(|a, b| a.1.len().cmp(&b.1.len()));

    if let Some((_matching_file, relative_path, folder_path)) = matches.first() {
        let new_folder_id = insert_folder(conn, &folder_path)?;

        let existing_id: Option<i64> = conn
            .query_row(
                "SELECT id FROM files WHERE file_name = ?1",
                params![filename],
                |row| row.get(0),
            )
            .optional()?;

        let backlink_id = if let Some(id) = existing_id {
            debug!(
                "Updating existing file entry (found via FS search): id={}, path={}, folder_id={}",
                id, relative_path, new_folder_id
            );
            conn.execute(
                "UPDATE files SET path = ?1, folder_id = ?2, metadata = COALESCE(metadata, '{}') WHERE id = ?3",
                params![relative_path, new_folder_id, id],
            )?;
            id
        } else {
            debug!(
                "Inserting new file (found via FS search): path={}, file_name={}, folder_id={}",
                relative_path, filename, new_folder_id
            );
            insert_file(conn, &relative_path, filename, new_folder_id)?
        };

        debug!(
            "Inserted/Updated backlink file: id={}, path={}",
            backlink_id, relative_path
        );
        Ok((Some(backlink_id), Some(relative_path.clone())))
    } else {
        debug!(
            "No file found for backlink: {}. Creating placeholder.",
            backlink
        );

        // Use a special path: e.g., "__dangling__/file.md"
        let placeholder_path = format!("{}.md", backlink.trim_end_matches(".md"));
        let placeholder_folder_path = "";

        let placeholder_folder_id = insert_folder(conn, placeholder_folder_path)?;
        let placeholder_file_id =
            insert_file(conn, &placeholder_path, filename, placeholder_folder_id)?;

        debug!(
            "Created placeholder file: id={}, path={}",
            placeholder_file_id, placeholder_path
        );

        return Ok((Some(placeholder_file_id), Some(placeholder_path)));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    fn setup_test_db() -> Result<Connection> {
        let conn = Connection::open_in_memory()?;
        setup_database(&conn)?;
        Ok(conn)
    }

    fn create_temp_md_file(dir: &TempDir, content: &str, file_name: &str) -> Result<String> {
        let file_path = dir.path().join(file_name);
        let mut file = File::create(&file_path)?;
        write!(file, "{}", content)?;
        Ok(file_path.to_string_lossy().into_owned())
    }

    fn get_table_count(conn: &Connection, table: &str) -> Result<i64> {
        let count: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {}", table), [], |row| {
            row.get(0)
        })?;
        Ok(count)
    }

    #[test]
    fn test_setup_database() {
        let conn = setup_test_db().unwrap();
        let tables = ["folders", "files", "tags", "file_tags", "backlinks"];
        for table in &tables {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "Table {} should exist", table);
        }
        let mut stmt = conn.prepare("PRAGMA table_info(files)").unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(columns.contains(&"metadata".to_string()));
    }

    #[test]
    fn test_insert_folder() {
        let conn = setup_test_db().unwrap();
        let folder_id = insert_folder(&conn, "/test/folder").unwrap();
        assert!(folder_id > 0);
        let count = get_table_count(&conn, "folders").unwrap();
        assert_eq!(count, 1);
        let path: String = conn
            .query_row(
                "SELECT path FROM folders WHERE id = ?",
                params![folder_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(path, "/test/folder");
    }

    #[test]
    fn test_insert_file() {
        let conn = setup_test_db().unwrap();
        let folder_id = insert_folder(&conn, "/test").unwrap();
        let file_id = insert_file(&conn, "test.md", "test.md", folder_id).unwrap();
        let count = get_table_count(&conn, "files").unwrap();
        assert_eq!(count, 1);
        let (path, fname, fid): (String, String, i64) = conn
            .query_row(
                "SELECT path, file_name, folder_id FROM files WHERE id = ?",
                params![file_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(path, "test.md");
        assert_eq!(fname, "test.md");
        assert_eq!(fid, folder_id);
    }

    #[test]
    fn test_insert_tag_and_file_tag() {
        let conn = setup_test_db().unwrap();
        let folder_id = insert_folder(&conn, "/test").unwrap();
        let file_id = insert_file(&conn, "test.md", "test.md", folder_id).unwrap();
        let tag_id = insert_tag(&conn, "mytag").unwrap();
        insert_file_tag(&conn, file_id, tag_id).unwrap();
        let count = get_table_count(&conn, "tags").unwrap();
        assert_eq!(count, 1);
        let count = get_table_count(&conn, "file_tags").unwrap();
        assert_eq!(count, 1);
        let tag: String = conn
            .query_row(
                "SELECT tag FROM tags WHERE id = ?",
                params![tag_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tag, "mytag");
        let ft: (i64, i64) = conn
            .query_row(
                "SELECT file_id, tag_id FROM file_tags WHERE file_id = ? AND tag_id = ?",
                params![file_id, tag_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(ft, (file_id, tag_id));
    }

    #[test]
    fn test_remove_file_from_db() {
        let conn = setup_test_db().unwrap();
        let folder_id = insert_folder(&conn, "/test").unwrap();
        let file_id = insert_file(&conn, "test.md", "test.md", folder_id).unwrap();
        let tag_id = insert_tag(&conn, "mytag").unwrap();
        insert_file_tag(&conn, file_id, tag_id).unwrap();
        let backlink_file_id = insert_file(&conn, "other.md", "other.md", folder_id).unwrap();
        conn.execute(
            "INSERT INTO backlinks (backlink, backlink_id, file_id) VALUES (?, ?, ?)",
            params!["other.md", backlink_file_id, file_id],
        )
        .unwrap();
        assert_eq!(get_table_count(&conn, "files").unwrap(), 2);
        assert_eq!(get_table_count(&conn, "file_tags").unwrap(), 1);
        assert_eq!(get_table_count(&conn, "backlinks").unwrap(), 1);
        remove_file_from_db(&conn, "test.md", "/test").unwrap();
        assert_eq!(get_table_count(&conn, "files").unwrap(), 1);
        assert_eq!(get_table_count(&conn, "file_tags").unwrap(), 0);
        assert_eq!(get_table_count(&conn, "backlinks").unwrap(), 0);
        assert_eq!(get_table_count(&conn, "tags").unwrap(), 1);
        assert_eq!(get_table_count(&conn, "folders").unwrap(), 1);
    }

    #[test]
    fn test_remove_file_from_db_not_found() {
        let conn = setup_test_db().unwrap();
        let result = remove_file_from_db(&conn, "nonexistent.md", "/test");
        assert!(matches!(
            result,
            Err(AppError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound
        ));
    }
    #[test]
    fn test_process_file_yaml_and_tags() {
        let conn = setup_test_db().unwrap();
        let dir = TempDir::new().unwrap();
        let file_path = create_temp_md_file(
            &dir,
            r#"
---
title: Test Doc
tags:
  - tag1
  - tag2
---
# Hello
This is a #testtag.
"#,
            "test.md",
        )
        .unwrap();
        let base_dir = dir.path().to_string_lossy().into_owned();
        process_file(&conn, &file_path, &base_dir).unwrap();
        let file_id: i64 = conn
            .query_row(
                "SELECT id FROM files WHERE path = ?",
                params!["test.md"],
                |row| row.get(0),
            )
            .unwrap();
        let metadata: String = conn
            .query_row(
                "SELECT metadata FROM files WHERE id = ?",
                params![file_id],
                |row| row.get(0),
            )
            .unwrap();
        let json: serde_json::Value = serde_json::from_str(&metadata).unwrap();
        assert_eq!(json["title"], "Test Doc");
        assert_eq!(json["tags"], serde_json::json!(["tag1", "tag2"]));
        let tags: Vec<String> = conn
            .query_row(
                "SELECT GROUP_CONCAT(tag) FROM tags JOIN file_tags ON tags.id = file_tags.tag_id WHERE file_tags.file_id = ?",
                params![file_id],
                |row| row.get(0),
            )
            .map(|s: String| {
                let mut v: Vec<String> = s.split(',').map(String::from).collect();
                v.sort();
                v
            })
            .unwrap();
        assert_eq!(tags.len(), 3);
        assert_eq!(tags, vec!["tag1", "tag2", "testtag"]);
    }

    #[test]
    fn test_process_file_backlinks() {
        let conn = setup_test_db().unwrap();
        let dir = TempDir::new().unwrap();
        let file_path = create_temp_md_file(
            &dir,
            r#"
---
title: Test Doc
---
Link to [[other.md]].
"#,
            "test.md",
        )
        .unwrap();
        let base_dir = dir.path().to_string_lossy().into_owned();
        let folder_id = insert_folder(&conn, "").unwrap();
        // Create the backlink file on disk
        create_temp_md_file(&dir, "This is other.md", "other.md").unwrap();
        // Insert the backlink file into the DB *before* processing
        let backlink_id = insert_file(&conn, "other.md", "other.md", folder_id).unwrap();

        process_file(&conn, &file_path, &base_dir).unwrap();
        let file_id: i64 = conn
            .query_row(
                "SELECT id FROM files WHERE path = ?",
                params!["test.md"],
                |row| row.get(0),
            )
            .unwrap();
        let backlink: (String, i64) = conn
            .query_row(
                "SELECT backlink, backlink_id FROM backlinks WHERE file_id = ?",
                params![file_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(backlink.0, "other.md");
        assert_eq!(backlink.1, backlink_id);
    }

    #[test]
    fn test_process_file_json_only() {
        let dir = TempDir::new().unwrap();
        let file_path = create_temp_md_file(
            &dir,
            r#"
---
title: Test Doc
tags:
  - tag1
  - tag2
---
# Hello
This is a #testtag.
Link to [[other.md]].
"#,
            "test.md",
        )
        .unwrap();
        let base_dir = dir.path().to_string_lossy().into_owned();
        let result = process_file_json_only(&file_path, &base_dir).unwrap();
        assert_eq!(result["file"]["path"], "test.md");
        assert_eq!(result["file"]["file_name"], "test.md");
        assert_eq!(result["metadata"]["title"], "Test Doc");
        assert_eq!(
            result["tags"],
            serde_json::json!(["tag1", "tag2", "testtag"])
        );
        assert_eq!(result["backlinks"], serde_json::json!(["other.md"]));
    }

    #[test]
    fn test_remove_string() {
        let result = remove_string("/base/test/file.md", "/base");
        assert_eq!(result, "test/file.md");
        let result = remove_string("/base/file.md", "/base");
        assert_eq!(result, "file.md");
        let result = remove_string("/base/file.md", "/other");
        assert_eq!(result, "base/file.md");
    }

    #[test]
    fn test_clearfromtrashtags() {
        let input ="Text [link]<a href=\"http://example.com\" target=\"_blank\" rel=\"noopener noreferrer nofollow\"></a> `code` #tag1 <b>bold</b>";
        let result = clearfromtrashtags(input);
        assert_eq!(result, "Text   #tag1 ");
        let input = "#tag1 in code `use #tag2`";
        let result = clearfromtrashtags(input);
        assert_eq!(result, "#tag1 in code ");
    }

    #[test]
    fn test_clearfromusless() {
        let input = "Text `code` http://example.com <b>bold</b>";
        let result = clearfromusless(input.to_string());
        assert_eq!(result, "Text"); // Expect no trailing space
    }

    #[test]
    fn test_sanitize_backlink() {
        assert_eq!(sanitize_backlink("file").unwrap(), "file.md");
        assert_eq!(sanitize_backlink("file.md").unwrap(), "file.md");
        assert_eq!(sanitize_backlink("file#section").unwrap(), "file.md");
        assert_eq!(sanitize_backlink("file|alias").unwrap(), "file.md");
        assert_eq!(sanitize_backlink("file's").unwrap(), "file's.md"); //yes no doubling down
        assert_eq!(sanitize_backlink(""), None);
    }

    #[test]
    fn test_yaml_to_json() {
        let yaml = YamlLoader::load_from_str(
            r#"
title: Test Doc
tags:
  - tag1
  - tag2
number: 42
"#,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
        let json = yaml_to_json(&yaml).unwrap();
        assert_eq!(json["title"], "Test Doc");
        assert_eq!(json["tags"], serde_json::json!(["tag1", "tag2"]));
        assert_eq!(json["number"], 42);
    }

    #[test]
    fn test_find_backlink_file_filesystem_search() {
        let conn = setup_test_db().unwrap();
        let dir = TempDir::new().unwrap();
        let base_dir = dir.path().to_string_lossy().into_owned();
        let folder_id = insert_folder(&conn, "").unwrap();
        // Create the backlink file on disk
        create_temp_md_file(&dir, "This is other.md", "other.md").unwrap();
        // Do NOT insert it into the DB
        let (backlink_id, backlink_path) =
            find_backlink_file(&conn, "other.md", &base_dir, "test.md", folder_id).unwrap();
        assert!(backlink_id.is_some());
        let new_id = backlink_id.unwrap();
        assert_eq!(backlink_path, Some("other.md".to_string()));
        let (path, fname): (String, String) = conn
            .query_row(
                "SELECT path, file_name FROM files WHERE id = ?",
                params![new_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(path, "other.md");
        assert_eq!(fname, "other.md");
    }

    #[test]
    fn test_parse_yaml_frontmatter() {
        let mut tags = Vec::new();
        let yaml = r#"
title: Test Doc
tags:
  - tag1
  - tag2
"#;
        let result = parse_yaml_frontmatter(yaml, &mut tags).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["title"], "Test Doc");
        assert_eq!(tags, vec!["tag1", "tag2"]);
    }

    #[test]
    fn test_process_file_with_single_quote_in_name() {
        let conn = setup_test_db().unwrap();
        let dir = TempDir::new().unwrap();
        // Create a file with a single quote in its name
        let file_path = create_temp_md_file(
            &dir,
            r#"
---
title: Test Doc
tags:
  - tag1
  - tag2
---
# Hello
This is a #testtag.
Link to [[other.md]].
"#,
            "O'Reilly.md",
        )
        .unwrap();
        let base_dir = dir.path().to_string_lossy().into_owned();

        // Create a referenced backlink file
        create_temp_md_file(&dir, "Other file", "other.md").unwrap();

        // Process the file
        process_file(&conn, &file_path, &base_dir).unwrap();

        // Verify file entry in the database
        let file_id: i64 = conn
            .query_row(
                "SELECT id FROM files WHERE path = ?",
                params!["O'Reilly.md"],
                |row| row.get(0),
            )
            .unwrap();
        assert!(file_id > 0, "File should be inserted with a valid ID");

        // Verify file metadata
        let metadata: String = conn
            .query_row(
                "SELECT metadata FROM files WHERE id = ?",
                params![file_id],
                |row| row.get(0),
            )
            .unwrap();
        let json: serde_json::Value = serde_json::from_str(&metadata).unwrap();
        assert_eq!(json["title"], "Test Doc", "Metadata title should match");
        assert_eq!(
            json["tags"],
            serde_json::json!(["tag1", "tag2"]),
            "Metadata tags should match"
        );

        // Verify tags
        let tags: Vec<String> = conn
            .query_row(
                "SELECT GROUP_CONCAT(tag) FROM tags JOIN file_tags ON tags.id = file_tags.tag_id WHERE file_tags.file_id = ?",
                params![file_id],
                |row| row.get(0),
            )
            .map(|s: String| {
                let mut v: Vec<String> = s.split(',').map(String::from).collect();
                v.sort();
                v
            })
            .unwrap();
        assert_eq!(tags.len(), 3, "Should have three tags");
        assert_eq!(tags, vec!["tag1", "tag2", "testtag"]);

        // Verify folder
        let folder_id: i64 = conn
            .query_row(
                "SELECT folder_id FROM files WHERE id = ?",
                params![file_id],
                |row| row.get(0),
            )
            .unwrap();
        let folder_path: String = conn
            .query_row(
                "SELECT path FROM folders WHERE id = ?",
                params![folder_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(folder_path, "/", "Folder path should be root");

        // Verify backlink
        let backlink_id: i64 = conn
            .query_row(
                "SELECT id FROM files WHERE path = ?",
                params!["other.md"],
                |row| row.get(0),
            )
            .unwrap();
        let backlink: (String, i64) = conn
            .query_row(
                "SELECT backlink, backlink_id FROM backlinks WHERE file_id = ?",
                params![file_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(backlink.0, "other.md", "Backlink name should match");
        assert_eq!(
            backlink.1, backlink_id,
            "Backlink ID should match the linked file"
        );

        // Test JSON-only mode
        let json_result = process_file_json_only(&file_path, &base_dir).unwrap();
        assert_eq!(
            json_result["file"]["path"], "O'Reilly.md",
            "JSON path should match"
        );
        assert_eq!(
            json_result["file"]["file_name"], "O'Reilly.md",
            "JSON file name should match"
        );
        assert_eq!(
            json_result["metadata"]["title"], "Test Doc",
            "JSON metadata title should match"
        );
        assert_eq!(
            json_result["tags"],
            serde_json::json!(["tag1", "tag2", "testtag"]),
            "JSON tags should match"
        );
        assert_eq!(
            json_result["backlinks"],
            serde_json::json!(["other.md"]),
            "JSON backlinks should match"
        );

        // Test removing file from database
        remove_file_from_db(&conn, &file_path, &base_dir).unwrap();
        let file_count = get_table_count(&conn, "files").unwrap();
        assert_eq!(
            file_count, 1,
            "Only the backlink file (other.md) should remain"
        );
        let file_tags_count = get_table_count(&conn, "file_tags").unwrap();
        assert_eq!(file_tags_count, 0, "File tags should be removed");
        let backlinks_count = get_table_count(&conn, "backlinks").unwrap();
        assert_eq!(backlinks_count, 0, "Backlinks should be removed");
    }

    #[test]
    fn test_backlink_to_nonexistent_file() {
        let conn = setup_test_db().unwrap();
        let dir = TempDir::new().unwrap();
        let base_dir = dir.path().to_string_lossy().into_owned();

        let file_path =
            create_temp_md_file(&dir, "Link to [[nonexistentfile.md]].", "test.md").unwrap();

        process_file(&conn, &file_path, &base_dir).unwrap();

        let file_id: i64 = conn
            .query_row(
                "SELECT id FROM files WHERE path = ?",
                params!["test.md"],
                |row| row.get(0),
            )
            .unwrap();
        assert!(file_id > 0);

        // The logic creates a path from the backlink name
        let placeholder_path = "nonexistentfile.md";
        let placeholder_id: i64 = conn
            .query_row(
                "SELECT id FROM files WHERE path = ?",
                params![placeholder_path],
                |row| row.get(0),
            )
            .unwrap();
        assert!(placeholder_id > 0);

        let backlink: (String, i64) = conn
            .query_row(
                "SELECT backlink, backlink_id FROM backlinks WHERE file_id = ?",
                params![file_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert_eq!(backlink.0, "nonexistentfile.md");
        assert_eq!(
            backlink.1, placeholder_id,
            "Backlink should point to the placeholder ID"
        );

        assert_eq!(get_table_count(&conn, "files").unwrap(), 2);
    }
}
