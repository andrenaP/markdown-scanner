use crate::error::Result;
use crate::models::{AggregatedData, FileContext};
use crate::utils::remove_base_dir;
use jwalk::WalkDir;
use log::debug;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub struct DatabaseRepo<'a> {
    conn: &'a mut Connection,
}

impl<'a> DatabaseRepo<'a> {
    pub fn new(conn: &'a mut Connection) -> Self {
        Self { conn }
    }

    /// Primary function: Writes all scan results in a single transaction
    pub fn save_file_results(&mut self, ctx: &FileContext, data: &AggregatedData) -> Result<()> {
        let tx = self.conn.transaction()?;

        // Folder
        let folder_relative = get_parent_relative(&ctx.path, &ctx.base_dir);
        let folder_id = insert_folder(&tx, &folder_relative)?;

        // File
        let file_name = ctx.path.file_name().unwrap().to_str().unwrap();

        // Check if exists to get ID
        let existing_id: Option<i64> = tx
            .query_row(
                "SELECT id FROM files WHERE path = ?1",
                params![ctx.relative_path],
                |r| r.get(0),
            )
            .optional()?;

        let file_id = if let Some(id) = existing_id {
            let meta_str = serde_json::to_string(&data.metadata)?;
            tx.execute(
                "UPDATE files SET folder_id = ?1, file_name = ?2, metadata = ?3 WHERE id = ?4",
                params![folder_id, file_name, meta_str, id],
            )?;
            id
        } else {
            let meta_str = serde_json::to_string(&data.metadata)?;
            tx.execute(
                "INSERT INTO files (path, file_name, folder_id, metadata) VALUES (?1, ?2, ?3, ?4)",
                params![ctx.relative_path, file_name, folder_id, meta_str],
            )?;
            tx.last_insert_rowid()
        };

        // Clear old associations
        tx.execute("DELETE FROM file_tags WHERE file_id = ?", params![file_id])?;
        tx.execute("DELETE FROM backlinks WHERE file_id = ?", params![file_id])?;

        // Tags
        for tag in &data.tags {
            tx.execute("INSERT OR IGNORE INTO tags (tag) VALUES (?)", params![tag])?;
            let tag_id: i64 =
                tx.query_row("SELECT id FROM tags WHERE tag = ?", params![tag], |r| {
                    r.get(0)
                })?;
            tx.execute(
                "INSERT INTO file_tags (file_id, tag_id) VALUES (?, ?)",
                params![file_id, tag_id],
            )?;
        }

        // Backlinks (Resolve Logic with Placeholders)
        for link in &data.backlinks {
            // pass the transaction so lookups/inserts happen in same context
            let (target_id, _) = find_backlink_target(&tx, link, &ctx.base_dir, folder_id)?;

            if let Some(tid) = target_id {
                tx.execute(
                    "INSERT INTO backlinks (backlink, backlink_id, file_id) VALUES (?1, ?2, ?3)",
                    params![link, tid, file_id],
                )?;
            }
        }

        tx.commit()?;
        Ok(())
    }

    pub fn delete_file(&mut self, relative_path: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM files WHERE path = ?1", params![relative_path])?;
        Ok(())
    }

    pub fn get_created_at(&self, relative_path: &str) -> Result<Option<u64>> {
        let mut stmt = self
            .conn
            .prepare("SELECT json_extract(metadata, '$.created_at') FROM files WHERE path = ?1")?;

        // 1. row.get::<_, Option<i64>>(0) handles a SQL NULL inside the column.
        // 2. .optional()? handles the case where the row itself doesn't exist.
        // This results in an Option<Option<i64>>.
        let result: Option<Option<i64>> = stmt
            .query_row(params![relative_path], |row| row.get::<_, Option<i64>>(0))
            .optional()?;

        // .flatten() turns Option<Option<i64>> into Option<i64>, dropping the Nones.
        Ok(result.flatten().map(|t| t as u64))
    }
    pub fn get_vid_links(&self, relative_path: &str) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT json_extract(metadata, '$.ytVideos') FROM files WHERE path = ?1")?;

        // 1. Extract the JSON array as a String.
        let result: Option<Option<String>> = stmt
            .query_row(params![relative_path], |row| {
                row.get::<_, Option<String>>(0)
            })
            .optional()?;

        let mut videos = Vec::new();

        // .flatten() drops Nones. If we have a JSON string, parse it.
        if let Some(json_string) = result.flatten() {
            // Parse the string back into a serde_json Value array
            if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str(&json_string) {
                // Iterate and extract the url and title strings
                for item in arr {
                    if let (Some(url), Some(title)) = (
                        item.get("url").and_then(|v| v.as_str()),
                        item.get("title").and_then(|v| v.as_str()),
                    ) {
                        videos.push((url.to_string(), title.to_string()));
                    }
                }
            }
        }

        Ok(videos)
    }
}

// --- Helper Functions ---

fn insert_folder(conn: &Connection, path: &str) -> Result<i64> {
    conn.execute(
        "INSERT OR IGNORE INTO folders (path) VALUES (?1)",
        params![path],
    )?;
    let id: i64 = conn.query_row(
        "SELECT id FROM folders WHERE path = ?1",
        params![path],
        |row| row.get(0),
    )?;
    Ok(id)
}

fn insert_file(conn: &Connection, path: &str, file_name: &str, folder_id: i64) -> Result<i64> {
    conn.execute(
        "INSERT OR IGNORE INTO files (path, file_name, folder_id, metadata) VALUES (?1, ?2, ?3, '{}')",
        params![path, file_name, folder_id],
    )?;
    let id: i64 = conn.query_row(
        "SELECT id FROM files WHERE path = ?1",
        params![path],
        |row| row.get(0),
    )?;
    Ok(id)
}

fn get_parent_relative(path: &Path, base_dir: &str) -> String {
    path.parent()
        .map(|p| remove_base_dir(p, base_dir))
        .unwrap_or_default()
}

/// Robust backlink resolution: Checks DB -> Checks FS -> Creates Placeholder
fn find_backlink_target(
    conn: &Connection,
    backlink: &str,
    base_dir: &str,
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

    // Search DB
    let mut stmt = conn.prepare(
        "SELECT f.id, f.path, f.folder_id, fo.path AS folder_path
         FROM files f
         JOIN folders fo ON f.folder_id = fo.id
         WHERE f.file_name = ?1",
    )?;

    let rows = stmt.query_map(params![filename], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;

    let mut valid_matches = Vec::new();
    let mut invalid_matches = Vec::new();

    for r in rows {
        let (id, path, file_folder_id, folder_path) = r?;

        // If folder path is empty (root), treat as valid placeholder (dangling link)
        if folder_path.is_empty() || folder_path == "/" {
            debug!("Dangling link found in DB, treating as valid: {}", path);
            valid_matches.push((id, path, file_folder_id));
            continue;
        }

        let full_path = Path::new(base_dir).join(&path);
        if full_path.exists() {
            valid_matches.push((id, path, file_folder_id));
        } else {
            debug!(
                "File DB entry exists but file missing on disk: {}",
                full_path.display()
            );
            invalid_matches.push((id, path, file_folder_id));
        }
    }

    // Resolve Conflicts / Cleanup
    if !valid_matches.is_empty() {
        let (selected_id, selected_path) = if valid_matches.len() == 1 {
            let (id, path, _) = &valid_matches[0];
            (*id, path.clone())
        } else {
            // Prefer same folder
            if let Some((id, path, _)) = valid_matches.iter().find(|(_, _, fid)| *fid == folder_id)
            {
                (*id, path.clone())
            } else {
                // Else shortest path
                let (id, path, _) = valid_matches
                    .iter()
                    .min_by_key(|(_, p, _)| p.len())
                    .unwrap();
                (*id, path.clone())
            }
        };

        // Clean up duplicates (other valid matches that we didn't pick)
        for (vid, _, _) in &valid_matches {
            if *vid != selected_id {
                conn.execute("DELETE FROM files WHERE id = ?", params![vid])?;
            }
        }

        // Clean up orphans (invalid matches)
        for (iid, _, _) in invalid_matches {
            conn.execute("DELETE FROM files WHERE id = ?", params![iid])?;
        }

        return Ok((Some(selected_id), Some(selected_path)));
    }

    // Clean up orphans if no valid matches found
    for (iid, _, _) in invalid_matches {
        conn.execute("DELETE FROM files WHERE id = ?", params![iid])?;
    }

    // Fallback: Search Filesystem
    debug!("Searching filesystem for: {}", filename);

    // Scan efficiently using jwalk
    let found = WalkDir::new(base_dir)
        .parallelism(jwalk::Parallelism::RayonNewPool(0))
        .into_iter()
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy() == filename);

    if let Some(entry) = found {
        let path = entry.path();
        let relative_path = remove_base_dir(&path, base_dir);
        let parent = path.parent().unwrap_or(Path::new(""));
        let parent_relative = remove_base_dir(parent, base_dir);

        debug!("Found on FS: {}", relative_path);

        let new_folder_id = insert_folder(conn, &parent_relative)?;

        // Upsert logic
        let existing_id: Option<i64> = conn
            .query_row(
                "SELECT id FROM files WHERE file_name = ?1",
                params![filename],
                |row| row.get(0),
            )
            .optional()?;

        let file_id = if let Some(id) = existing_id {
            conn.execute(
                "UPDATE files SET path = ?1, folder_id = ?2 WHERE id = ?3",
                params![relative_path, new_folder_id, id],
            )?;
            id
        } else {
            insert_file(conn, &relative_path, filename, new_folder_id)?
        };

        return Ok((Some(file_id), Some(relative_path)));
    }

    // Create Placeholder (Dangling Link)
    debug!("Creating placeholder for: {}", backlink);
    let placeholder_path = format!("{}.md", backlink.trim_end_matches(".md"));
    // Placeholders go in root folder (empty string path)
    let placeholder_folder_id = insert_folder(conn, "")?;
    let placeholder_id = insert_file(conn, &placeholder_path, filename, placeholder_folder_id)?;

    Ok((Some(placeholder_id), Some(placeholder_path)))
}
