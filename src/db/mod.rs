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
        // --- Version 4: Optimize file_tags with WITHOUT ROWID ---
        "
        CREATE TABLE file_tags_new (
            file_id INTEGER,
            tag_id INTEGER,
            order_index INTEGER,
            PRIMARY KEY(file_id, tag_id),
            FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY(tag_id) REFERENCES tags(id)
        ) WITHOUT ROWID;

        INSERT INTO file_tags_new (file_id, tag_id, order_index)
        SELECT file_id, tag_id, order_index FROM file_tags;

        DROP TABLE file_tags;

        ALTER TABLE file_tags_new RENAME TO file_tags;
        ",

        // --- Version 5: Remove redundant path column from files ---
        "
        -- 1. Turn off foreign keys to prevent CASCADE DELETE from wiping out file_tags and backlinks
        PRAGMA foreign_keys = OFF;

        -- 2. Create the new optimized table without the path column
        CREATE TABLE files_new (
            id INTEGER PRIMARY KEY,
            file_name TEXT,
            folder_id INTEGER,
            metadata TEXT DEFAULT '{}',
            FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE CASCADE
        );

        -- 3. Copy over all existing data (skipping the path column)
        INSERT INTO files_new (id, file_name, folder_id, metadata)
        SELECT id, file_name, folder_id, metadata FROM files;

        -- 4. Drop the old table
        DROP TABLE files;

        -- 5. Rename the new table to take its place
        ALTER TABLE files_new RENAME TO files;

        -- 6. Turn foreign keys back on
        PRAGMA foreign_keys = ON;

        -- 7. (Optional but recommended) Recreate the view we talked about so your app doesn't break
        CREATE VIEW vw_files_with_paths AS
        SELECT
            files.id,
            files.file_name,
            files.folder_id,
            files.metadata,
            folders.path || '/' || files.file_name AS path
        FROM files
        JOIN folders ON files.folder_id = folders.id;
        ",
        // --- Version 6: Fix leading slash in root files ---
        "
        DROP VIEW IF EXISTS vw_files_with_paths;

        CREATE VIEW vw_files_with_paths AS
        SELECT
            files.id,
            files.file_name,
            files.folder_id,
            files.metadata,
            CASE
                WHEN folders.path = '' THEN files.file_name
                ELSE folders.path || '/' || files.file_name
            END AS path
        FROM files
        JOIN folders ON files.folder_id = folders.id;
        ",
        // --- Version 7: Enforce unique file names per folder ---
        "
        -- 1. Turn off foreign keys temporarily
        PRAGMA foreign_keys = OFF;

        -- 2. Drop the view BEFORE we mess with the tables it relies on
        DROP VIEW IF EXISTS vw_files_with_paths;

        -- 3. Create the new table with the UNIQUE constraint
        CREATE TABLE files_new (
            id INTEGER PRIMARY KEY,
            file_name TEXT,
            folder_id INTEGER,
            metadata TEXT DEFAULT '{}',
            FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE CASCADE,
            UNIQUE(file_name, folder_id)
        );

        -- 4. Copy the data over (using INSERT OR IGNORE to cleanly discard any existing duplicates)
        INSERT OR IGNORE INTO files_new (id, file_name, folder_id, metadata)
        SELECT id, file_name, folder_id, metadata FROM files;

        -- 5. Drop the old table
        DROP TABLE files;

        -- 6. Rename the new table
        ALTER TABLE files_new RENAME TO files;

        -- 7. Recreate the view now that the 'files' table is safely in place
        CREATE VIEW vw_files_with_paths AS
        SELECT
            files.id,
            files.file_name,
            files.folder_id,
            files.metadata,
            CASE
                WHEN folders.path = '' THEN files.file_name
                ELSE folders.path || '/' || files.file_name
            END AS path
        FROM files
        JOIN folders ON files.folder_id = folders.id;

        -- 8. Turn foreign keys back on
        PRAGMA foreign_keys = ON;
        "
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
