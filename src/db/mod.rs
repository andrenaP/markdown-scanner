use crate::error::Result;
use log::debug;
use rusqlite::Connection;

pub mod repo;

pub fn init_connection(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    setup_schema(&conn)?;
    Ok(conn)
}

pub fn setup_schema(conn: &Connection) -> Result<()> {
    // Always enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON", [])?;

    let current_version: i32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

    // Define all database states sequentially
    let migrations = [
        // --- Version 1: Initial Schema ---
        "
        CREATE TABLE IF NOT EXISTS folders (
            id INTEGER PRIMARY KEY,
            path TEXT UNIQUE
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            path TEXT UNIQUE,
            file_name TEXT,
            folder_id INTEGER,
            FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY,
            tag TEXT UNIQUE
        );
        CREATE TABLE IF NOT EXISTS file_tags (
            file_id INTEGER,
            tag_id INTEGER,
            FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY(tag_id) REFERENCES tags(id),
            UNIQUE(file_id, tag_id)
        );
        CREATE TABLE IF NOT EXISTS backlinks (
            id INTEGER PRIMARY KEY,
            backlink TEXT,
            backlink_id INTEGER,
            file_id INTEGER,
            FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY(backlink_id) REFERENCES files(id) ON DELETE SET NULL,
            UNIQUE(backlink_id, file_id, backlink)
        );
        ",
        // --- Version 2: Add metadata to files ---
        "ALTER TABLE files ADD COLUMN metadata TEXT DEFAULT '{}';",
        // --- Version 3: Add order indexes ---
        "
        ALTER TABLE file_tags ADD COLUMN order_index INTEGER;
        ALTER TABLE backlinks ADD COLUMN order_index INTEGER;
        ",
    ];

    // Automatically apply any missing migrations
    for (i, migration) in migrations.iter().enumerate() {
        let target_version = (i + 1) as i32;

        if current_version < target_version {
            debug!(
                "Updating DB to version {} from {}",
                target_version, current_version
            );

            // execute_batch runs multiple statements separated by semicolons
            conn.execute_batch(migration)?;

            // Safely update the PRAGMA version
            conn.pragma_update(None, "user_version", target_version)?;
        }
    }

    Ok(())
}
