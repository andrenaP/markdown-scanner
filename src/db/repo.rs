use crate::error::Result;
use crate::models::{AggregatedData, FileContext};
use crate::utils::remove_base_dir;
use jwalk::WalkDir;
use log::debug;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::path::PathBuf;

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
        debug!(
            "DEBUG: folder_relative string being passed to DB: '{}'",
            folder_relative
        );
        let folder_id = insert_folder(&tx, &folder_relative)?;

        // File
        let file_name = ctx.path.file_name().unwrap().to_str().unwrap();

        // Check if exists to get ID
        let existing_id: Option<i64> = tx
            .query_row(
                "SELECT id FROM vw_files_with_paths WHERE path = ?1",
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
            // REMOVED path and ctx.relative_path
            tx.execute(
                "INSERT INTO files (file_name, folder_id, metadata) VALUES (?1, ?2, ?3)",
                params![file_name, folder_id, meta_str],
            )?;
            tx.last_insert_rowid()
        };

        // Clear old associations
        tx.execute("DELETE FROM file_tags WHERE file_id = ?", params![file_id])?;
        tx.execute("DELETE FROM backlinks WHERE file_id = ?", params![file_id])?;

        // Tags
        for (order_idx, tag) in data.tags.iter().enumerate() {
            tx.execute("INSERT OR IGNORE INTO tags (tag) VALUES (?)", params![tag])?;
            let tag_id: i64 =
                tx.query_row("SELECT id FROM tags WHERE tag = ?", params![tag], |r| {
                    r.get(0)
                })?;
            tx.execute(
                "INSERT INTO file_tags (file_id, tag_id, order_index) VALUES (?1, ?2, ?3)",
                params![file_id, tag_id, order_idx as i64],
            )?;
        }

        // Backlinks
        // Use .enumerate() to get a 0-based index for the order
        for (order_idx, link) in data.backlinks.iter().enumerate() {
            // pass the transaction so lookups/inserts happen in same context
            let (target_id, _) = find_backlink_target(&tx, link, &ctx.base_dir, folder_id)?;

            if let Some(tid) = target_id {
                tx.execute(
                            "INSERT INTO backlinks (backlink, backlink_id, file_id, order_index) VALUES (?1, ?2, ?3, ?4)",
                            params![link, tid, file_id, order_idx as i64],
                        )?;
            }
        }

        tx.commit()?;
        Ok(())
    }

    pub fn delete_file(&mut self, relative_path: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM files WHERE id IN (SELECT id FROM vw_files_with_paths WHERE path = ?1)",
            params![relative_path],
        )?;
        Ok(())
    }

    pub fn get_created_at(&self, relative_path: &str) -> Result<Option<u64>> {
        let mut stmt = self
            .conn
            .prepare("SELECT json_extract(metadata, '$.created_at') FROM vw_files_with_paths WHERE path = ?1")?;

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
        let mut stmt = self.conn.prepare(
            "SELECT json_extract(metadata, '$.ytVideos') FROM vw_files_with_paths WHERE path = ?1",
        )?;

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

    pub fn cleanup_orphaned_files(&mut self, base_dir: &str) -> Result<usize> {
        // 1 & 2. Query and Check FS inside an isolated block
        // This ensures the immutable borrow on self.conn is dropped immediately after.
        let missing_on_disk = {
            let mut stmt = self
                .conn
                .prepare("SELECT id, path FROM vw_files_with_paths")?;

            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;

            let mut missing = Vec::new();
            for r in rows {
                let (id, path) = r?;
                let full_path = Path::new(base_dir).join(&path);

                if !full_path.exists() {
                    missing.push(id);
                }
            }
            missing
        }; // <--- `stmt` is dropped here, releasing the immutable borrow

        if missing_on_disk.is_empty() {
            return Ok(0);
        }

        let mut deleted_count = 0;

        // 3. Delete from the database (Mutable borrow now allowed!)
        let tx = self.conn.transaction()?;
        {
            let mut del_stmt = tx.prepare(
                "DELETE FROM files
                     WHERE id = ?1
                     AND id NOT IN (
                         SELECT backlink_id
                         FROM backlinks
                         WHERE backlink_id IS NOT NULL
                     )",
            )?;

            for id in missing_on_disk {
                deleted_count += del_stmt.execute(params![id])?;
            }
        }

        // 4. (Bonus) Clean up orphaned folders that no longer have any files associated
        tx.execute(
            "DELETE FROM folders WHERE id NOT IN (SELECT DISTINCT folder_id FROM files)",
            [],
        )?;

        tx.commit()?;

        Ok(deleted_count)
    }
}

// --- Helper Functions ---

fn insert_folder(conn: &Connection, path: &str) -> Result<i64> {
    // Treat empty string as the root/no-folder
    let cleaned = path.trim_matches(|c| c == '/' || c == '\\');

    conn.execute(
        "INSERT OR IGNORE INTO folders (path) VALUES (?1)",
        params![cleaned],
    )?;

    let id: i64 = conn.query_row(
        "SELECT id FROM folders WHERE path = ?1",
        params![cleaned],
        |row| row.get(0),
    )?;
    Ok(id)
}

fn insert_file(conn: &Connection, file_name: &str, folder_id: i64) -> Result<i64> {
    conn.execute(
        "INSERT OR IGNORE INTO files (file_name, folder_id, metadata) VALUES (?1, ?2, '{}')",
        params![file_name, folder_id],
    )?;

    // We now look up the ID using the combination of file_name and folder_id
    let id: i64 = conn.query_row(
        "SELECT id FROM files WHERE file_name = ?1 AND folder_id = ?2",
        params![file_name, folder_id],
        |row| row.get(0),
    )?;
    Ok(id)
}

fn get_parent_relative(path: &Path, base_dir: &str) -> String {
    // 1. Get the parent directory of the file
    let parent = path.parent().unwrap_or(Path::new(""));

    // 2. Canonicalize the base_dir and parent to ensure they are comparable
    // (This handles different slash formats and absolute vs relative path issues)
    let base_path = Path::new(base_dir)
        .canonicalize()
        .unwrap_or(PathBuf::from(base_dir));
    let parent_path = parent.canonicalize().unwrap_or(parent.to_path_buf());

    // 3. Use strip_prefix - this is the "correct" way to remove a base dir
    match parent_path.strip_prefix(&base_path) {
        Ok(relative) => {
            let s = relative.to_string_lossy();
            // If the relative path is "." (same as base), return empty
            if s == "." || s.is_empty() {
                "".to_string()
            } else {
                s.to_string()
            }
        }
        Err(_) => {
            // Fallback: If stripping fails, the file is likely outside the base_dir
            // Return empty to default it to root
            "".to_string()
        }
    }
}

/// Robust backlink resolution: Checks DB -> Checks FS -> Creates Placeholder
/// Robust backlink resolution: Checks DB -> Checks FS -> Creates/Updates Placeholder
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
        "SELECT v.id, v.path, v.folder_id, fo.path AS folder_path
             FROM vw_files_with_paths v
             JOIN folders fo ON v.folder_id = fo.id
             WHERE v.file_name = ?1",
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
    let mut placeholders = Vec::new(); // Track dangling links separately

    for r in rows {
        let (id, path, file_folder_id, folder_path) = r?;
        let full_path = Path::new(base_dir).join(&path);

        if full_path.exists() {
            valid_matches.push((id, path, file_folder_id));
        } else {
            // File missing on disk. Is it a placeholder?
            if folder_path.is_empty() || folder_path == "/" {
                debug!("Dangling link placeholder found in DB: {}", path);
                placeholders.push((id, path, file_folder_id));
            } else {
                debug!(
                    "File DB entry exists but file missing on disk: {}",
                    full_path.display()
                );
                invalid_matches.push((id, path, file_folder_id));
            }
        }
    }

    // Resolve Conflicts / Cleanup for Real Matches
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

        // Clean up duplicates
        for (vid, _, _) in &valid_matches {
            if *vid != selected_id {
                conn.execute("DELETE FROM files WHERE id = ?", params![vid])?;
            }
        }
        // Clean up orphans
        for (iid, _, _) in &invalid_matches {
            conn.execute("DELETE FROM files WHERE id = ?", params![iid])?;
        }
        // Clean up placeholders since we found a real file
        for (pid, _, _) in &placeholders {
            conn.execute("DELETE FROM files WHERE id = ?", params![pid])?;
        }

        return Ok((Some(selected_id), Some(selected_path)));
    }

    // Clean up non-placeholder orphans before we run the heavy filesystem search
    for (iid, _, _) in invalid_matches {
        conn.execute("DELETE FROM files WHERE id = ?", params![iid])?;
    }

    // Fallback: Search Filesystem
    debug!("Searching filesystem for: {}", filename);
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

        // Upsert logic: It's crucial we update an existing record if one exists
        // so that foreign keys in the `backlinks` table don't break.
        let existing_id: Option<i64> = conn
            .query_row(
                "SELECT id FROM files WHERE file_name = ?1",
                params![filename],
                |row| row.get(0),
            )
            .optional()?;

        let file_id = if let Some(id) = existing_id {
            // This organically upgrades our placeholder!
            // We ONLY need to update the folder_id now.
            conn.execute(
                "UPDATE files SET folder_id = ?1 WHERE id = ?2",
                params![new_folder_id, id],
            )?;
            id
        } else {
            // Notice we removed `&relative_path` here (see the helper update below)
            insert_file(conn, filename, new_folder_id)?
        };

        // Clean up any extraneous placeholders for this file
        for (pid, _, _) in placeholders {
            if Some(pid) != existing_id {
                conn.execute("DELETE FROM files WHERE id = ?", params![pid])?;
            }
        }

        return Ok((Some(file_id), Some(relative_path)));
    }

    // If we reach here, the file truly doesn't exist on disk.
    // If we already have a placeholder in the DB, reuse it to avoid ID churn.
    if let Some((pid, ppath, _)) = placeholders.into_iter().next() {
        debug!("Re-using existing placeholder: {}", ppath);
        return Ok((Some(pid), Some(ppath)));
    }

    // Create Placeholder (Dangling Link)
    debug!("Creating placeholder for: {}", backlink);
    let placeholder_folder_id = insert_folder(conn, "")?;

    // Removed `&placeholder_path` from the arguments
    let placeholder_id = insert_file(conn, filename, placeholder_folder_id)?;

    Ok((Some(placeholder_id), None))
}
