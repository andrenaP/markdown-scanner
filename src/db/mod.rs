use crate::error::Result;
use rusqlite::Connection;

pub mod repo;

pub fn init_connection(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    setup_schema(&conn)?;
    Ok(conn)
}

fn setup_schema(conn: &Connection) -> Result<()> {
    conn.execute("PRAGMA foreign_keys = ON", [])?;

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
            FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE CASCADE
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
            FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
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
            FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY(backlink_id) REFERENCES files(id) ON DELETE SET NULL,
            UNIQUE(backlink_id, file_id, backlink)
        )",
        [],
    )?;

    Ok(())
}
