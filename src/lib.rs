pub mod db;
pub mod error;
pub mod models;
pub mod scanners;
pub mod usafecode;
pub mod utils;

use log::info;
use std::fs;
use std::path::Path;

use crate::db::repo::DatabaseRepo;
use crate::models::FileContext;
use crate::scanners::youtubescanner::YoutubeScanner;
use crate::scanners::{
    backlinks::BacklinkScanner, filetime::TimeScanner, frontmatter::FrontmatterScanner,
    tags::TagScanner, ScannerManager,
};
use crate::utils::remove_base_dir;

/// Deletes a file from the database.
pub fn delete_markdown_file(
    file_path: &str,
    base_dir: &str,
    db_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let canonical_path = Path::new(file_path).canonicalize()?;
    let relative_path = remove_base_dir(&canonical_path, base_dir);

    let mut conn = db::init_connection(db_path)?;
    let mut repo = DatabaseRepo::new(&mut conn);
    repo.delete_file(&relative_path)?;
    info!("File deleted from DB");

    Ok(())
}

/// Scans a file and saves it to the database (or returns the JSON string if requested).
pub async fn scan_markdown_file(
    file_path: &str,
    base_dir: &str,
    db_path: &str,
    json_only: bool,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let canonical_path = Path::new(file_path).canonicalize()?;
    let relative_path = remove_base_dir(&canonical_path, base_dir);

    let mut conn = db::init_connection(db_path)?;
    let repo = DatabaseRepo::new(&mut conn);

    let content = fs::read_to_string(&canonical_path)?;
    let existing_time = repo.get_created_at(&relative_path)?.unwrap_or(0);
    let thelistoflinks = repo.get_vid_links(&relative_path).unwrap();

    let ctx = FileContext {
        path: canonical_path,
        relative_path,
        content,
        base_dir: base_dir.to_string(),
        time: existing_time,
        vidlinks: thelistoflinks,
    };

    let mut manager = ScannerManager::new();
    manager.register(FrontmatterScanner);
    manager.register(TagScanner);
    manager.register(BacklinkScanner);
    manager.register(TimeScanner);
    manager.register(YoutubeScanner);

    let data = manager.process_file(&ctx).await?;

    if json_only {
        return Ok(Some(serde_json::to_string_pretty(&data)?));
    } else {
        let mut conn = db::init_connection(db_path)?;
        let mut repo = DatabaseRepo::new(&mut conn);
        repo.save_file_results(&ctx, &data)?;
        info!("Successfully scanned and saved: {}", ctx.relative_path);
        return Ok(None);
    }
}

/// Adds a non-markdown file (like an image) directly to the folders/files tables.
pub fn register_asset_file(
    file_path: &str,
    base_dir: &str,
    db_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let canonical_path = Path::new(file_path).canonicalize()?;
    let relative_path_str = remove_base_dir(&canonical_path, base_dir);
    let relative_path = Path::new(&relative_path_str);

    let file_name = relative_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    let folder_path_raw = relative_path
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or("");

    // Handle root directory edge case and standardize slashes for the DB
    let folder_path = if folder_path_raw == "." || folder_path_raw.is_empty() {
        "".to_string()
    } else {
        folder_path_raw.replace("\\", "/")
    };

    let conn = db::init_connection(db_path)?;

    // 1. Insert Folder
    conn.execute(
        "INSERT OR IGNORE INTO folders (path) VALUES (?1)",
        [&folder_path],
    )?;

    // 2. Insert File
    conn.execute(
        "INSERT OR IGNORE INTO files (file_name, folder_id) VALUES (?1, (SELECT id FROM folders WHERE path = ?2))",
        [&file_name, folder_path.as_str()],
    )?;

    info!("Asset file registered: {}/{}", folder_path, file_name);

    Ok(())
}

/// Deletes a non-markdown file from the files table
pub fn delete_asset_file(
    file_path: &str,
    base_dir: &str,
    db_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let canonical_path = Path::new(file_path).canonicalize()?;
    let relative_path_str = remove_base_dir(&canonical_path, base_dir);
    let relative_path = Path::new(&relative_path_str);

    let file_name = relative_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    let folder_path_raw = relative_path
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or("");

    let folder_path = if folder_path_raw == "." || folder_path_raw.is_empty() {
        "".to_string()
    } else {
        folder_path_raw.replace("\\", "/")
    };

    let conn = db::init_connection(db_path)?;

    conn.execute(
        "DELETE FROM files WHERE file_name = ?1 AND folder_id = (SELECT id FROM folders WHERE path = ?2)",
        [&file_name, folder_path.as_str()],
    )?;

    info!("Asset file deleted: {}/{}", folder_path, file_name);

    Ok(())
}

pub fn clean_orphaned_files(
    base_dir: &str,
    db_path: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut conn = db::init_connection(db_path)?;
    let mut repo = DatabaseRepo::new(&mut conn);

    let deleted = repo.cleanup_orphaned_files(base_dir)?;
    info!(
        "Cleaned up {} orphaned files/placeholders from the database.",
        deleted
    );

    Ok(deleted)
}
