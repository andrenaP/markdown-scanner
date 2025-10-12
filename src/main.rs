use axum::{
    body::Bytes,
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand};
use jwalk::WalkDir;
use log::{debug, error, info};
use regex::Regex;
use reqwest::Client;
use rusqlite::{params, types::ValueRef, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{self, Value as JsonValue};
use std::fs;
use std::io::{ErrorKind, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use yaml_rust::{Yaml, YamlLoader};

//-////////////////////////////////////////////////////////////////////////////
//  ERROR HANDLING & SHARED TYPES
//-////////////////////////////////////////////////////////////////////////////

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
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Server error: {0}")]
    Server(String),
}

type Result<T> = std::result::Result<T, AppError>;

#[derive(Serialize, Deserialize, Debug)]
struct ScanPayload {
    relative_path: String,
    content: String,
    client_validated_backlinks: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct DeletePayload {
    relative_path: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct SqlQueryPayload {
    query: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct SqlQueryResult {
    columns: Vec<String>,
    rows: Vec<Vec<JsonValue>>,
    error: Option<String>,
    rows_affected: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct ServerResponse {
    success: bool,
    message: String,
}

//-////////////////////////////////////////////////////////////////////////////
//  COMMAND-LINE INTERFACE DEFINITION (CLAP)
//-////////////////////////////////////////////////////////////////////////////

#[derive(Parser, Debug)]
#[command(
    name = "markdown-scanner",
    version = "1.2.0",
    about = "Scans Markdown files locally or via a server."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run in server mode, listening for client requests.
    Serve(ServeArgs),
    /// Scan a file and send the data to a server.
    Scan(ScanArgs),
    /// Request the server to delete a file's data.
    Delete(DeleteArgs),
    /// Process a file locally and output JSON (no server/db interaction).
    JsonOnly(JsonOnlyArgs),
    /// Run a complete local scan without a server.
    Local(LocalArgs),
    /// Execute a raw SQL query on the server's database.
    Sql(SqlArgs),
    /// Download the entire database file from the server.
    DownloadDb(DownloadDbArgs),
}

#[derive(Parser, Debug)]
struct ServeArgs {
    #[arg(long, short, default_value = "markdown_data.db")]
    database: String,
    #[arg(long, short, default_value = "127.0.0.1:3000")]
    bind: SocketAddr,
}

#[derive(Parser, Debug)]
struct ClientArgs {
    #[arg(long, short, default_value = "http://127.0.0.1:3000")]
    server_url: String,
    #[arg(index = 1)]
    file: String,
    #[arg(index = 2)]
    base_dir: String,
}

#[derive(Parser, Debug)]
struct ScanArgs {
    #[clap(flatten)]
    client: ClientArgs,
}

#[derive(Parser, Debug)]
struct DeleteArgs {
    #[clap(flatten)]
    client: ClientArgs,
}

#[derive(Parser, Debug)]
struct JsonOnlyArgs {
    #[arg(index = 1)]
    file: String,
    #[arg(index = 2)]
    base_dir: String,
}

#[derive(Parser, Debug)]
struct LocalArgs {
    #[arg(index = 1)]
    file: String,
    #[arg(index = 2)]
    base_dir: String,
    #[arg(long, short, default_value = "markdown_data.db")]
    database: String,
}

#[derive(Parser, Debug)]
struct SqlArgs {
    #[arg(long, short, default_value = "http://127.0.0.1:3000")]
    server_url: String,
    #[arg(index = 1)]
    query: String,
}

#[derive(Parser, Debug)]
struct DownloadDbArgs {
    #[arg(long, short, default_value = "http://127.0.0.1:3000")]
    server_url: String,
    #[arg(index = 1)]
    output_file: String,
}

//-////////////////////////////////////////////////////////////////////////////
//  MAIN APPLICATION LOGIC
//-////////////////////////////////////////////////////////////////////////////

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve(args) => run_server(args).await,
        Commands::Scan(args) => run_scan_client(args).await,
        Commands::Delete(args) => run_delete_client(args).await,
        Commands::JsonOnly(args) => run_json_only(args),
        Commands::Local(args) => run_local_scan(args),
        Commands::Sql(args) => run_sql_client(args).await,
        Commands::DownloadDb(args) => run_download_db_client(args).await,
    }
}

//-////////////////////////////////////////////////////////////////////////////
//  CLIENT IMPLEMENTATION
//-////////////////////////////////////////////////////////////////////////////

async fn run_scan_client(args: ScanArgs) -> Result<()> {
    info!(
        "Scanning file {} to send to server {}",
        args.client.file, args.client.server_url
    );
    let content = fs::read_to_string(&args.client.file)?;
    let relative_path = remove_string(
        &Path::new(&args.client.file)
            .canonicalize()?
            .to_string_lossy(),
        &args.client.base_dir,
    );

    // Pre-validate backlinks on the client side
    let mut client_validated_backlinks = Vec::new();
    let backlink_re = Regex::new(r"\[\[([^\]\[]+?)\]\]").unwrap();
    let base_path = Path::new(&args.client.base_dir);

    for cap in backlink_re.captures_iter(&content) {
        if let Some(sanitized) = sanitize_backlink(&cap[1]) {
            let backlink_path = base_path.join(&sanitized);
            if backlink_path.exists() {
                client_validated_backlinks.push(sanitized);
            }
        }
    }
    debug!(
        "Client validated backlinks: {:?}",
        client_validated_backlinks
    );

    let payload = ScanPayload {
        relative_path,
        content,
        client_validated_backlinks,
    };

    let client = Client::new();
    let res = client
        .post(format!("{}/scan", args.client.server_url))
        .json(&payload)
        .send()
        .await?;

    if res.status().is_success() {
        info!(
            "Server response: {}",
            res.json::<ServerResponse>().await?.message
        );
        Ok(())
    } else {
        Err(AppError::Server(format!(
            "Failed with status: {}",
            res.status()
        )))
    }
}

async fn run_delete_client(args: DeleteArgs) -> Result<()> {
    info!(
        "Requesting deletion of {} from server {}",
        args.client.file, args.client.server_url
    );
    let relative_path = remove_string(
        &Path::new(&args.client.file)
            .canonicalize()?
            .to_string_lossy(),
        &args.client.base_dir,
    );
    let payload = DeletePayload { relative_path };
    let client = Client::new();
    let res = client
        .post(format!("{}/delete", args.client.server_url))
        .json(&payload)
        .send()
        .await?;

    if res.status().is_success() {
        info!(
            "Server response: {}",
            res.json::<ServerResponse>().await?.message
        );
        Ok(())
    } else {
        Err(AppError::Server(format!(
            "Failed with status: {}",
            res.status()
        )))
    }
}

async fn run_sql_client(args: SqlArgs) -> Result<()> {
    info!("Sending SQL query to server: {}", args.query);
    let payload = SqlQueryPayload { query: args.query };
    let client = Client::new();
    let res = client
        .post(format!("{}/sql", args.server_url))
        .json(&payload)
        .send()
        .await?;

    if res.status().is_success() {
        let result: SqlQueryResult = res.json().await?;
        if let Some(err) = result.error {
            error!("Server returned a query error: {}", err);
        } else {
            let json_output = serde_json::to_string_pretty(&result)?;
            println!("{}", json_output);
        }
        Ok(())
    } else {
        Err(AppError::Server(format!(
            "Failed with status: {}",
            res.status()
        )))
    }
}

async fn run_download_db_client(args: DownloadDbArgs) -> Result<()> {
    info!(
        "Requesting database from server, saving to {}",
        args.output_file
    );
    let client = Client::new();
    let res = client.get(format!("{}/db", args.server_url)).send().await?;

    if res.status().is_success() {
        let mut file = fs::File::create(args.output_file)?;
        let bytes = res.bytes().await?;
        file.write_all(&bytes)?;
        info!("Database downloaded successfully.");
        Ok(())
    } else {
        Err(AppError::Server(format!(
            "Failed with status: {}",
            res.status()
        )))
    }
}

//-////////////////////////////////////////////////////////////////////////////
//  LOCAL & JSON-ONLY IMPLEMENTATION
//-////////////////////////////////////////////////////////////////////////////

fn run_json_only(args: JsonOnlyArgs) -> Result<()> {
    // This function is the same as before
    let canonical_path = Path::new(&args.file).canonicalize()?;
    let content = fs::read_to_string(&canonical_path)?;
    let relative_path = remove_string(&canonical_path.to_string_lossy(), &args.base_dir);

    let path_obj = Path::new(&relative_path);
    let file_name = path_obj.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let folder_path = path_obj.parent().and_then(|p| p.to_str()).unwrap_or("");

    let mut tags = Vec::new();
    let (metadata_json_str, lines) = parse_content(&content, &mut tags)?;

    let metadata: JsonValue = metadata_json_str
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(JsonValue::Object(Default::default()));

    let mut in_code_block = false;
    let tag_re = Regex::new(r"#[\p{L}\p{N}_-]+").unwrap();
    for line in lines.iter() {
        if line.trim() == "```" {
            in_code_block = !in_code_block;
            continue;
        }
        if !in_code_block {
            let cleaned = clearfromtrashtags(line);
            for cap in tag_re.captures_iter(&cleaned) {
                let tag = &cap[0][1..];
                if !tags.contains(&tag.to_string()) {
                    tags.push(tag.to_string());
                }
            }
        }
    }

    let content_for_backlinks = clearfromusless(content.clone());
    let backlink_re = Regex::new(r"\[\[([^\]\[]+?)\]\]").unwrap();
    let backlinks: Vec<String> = backlink_re
        .captures_iter(&content_for_backlinks)
        .filter_map(|cap| sanitize_backlink(&cap[1]))
        .collect();

    let json_output = serde_json::json!({
        "file": { "path": relative_path, "file_name": file_name, "folder_path": folder_path },
        "metadata": metadata,
        "tags": tags,
        "backlinks": backlinks
    });

    println!("{}", serde_json::to_string_pretty(&json_output)?);
    Ok(())
}

fn run_local_scan(args: LocalArgs) -> Result<()> {
    info!("Starting local scan for file: {}", args.file);
    let conn = Connection::open(&args.database)?;
    setup_database(&conn)?;
    process_file_local(&conn, &args.file, &args.base_dir)?;
    info!("Local scan completed successfully.");
    Ok(())
}

fn process_file_local(conn: &Connection, file_path: &str, base_dir: &str) -> Result<()> {
    let canonical_path = Path::new(file_path).canonicalize()?;
    let relative_path = remove_string(&canonical_path.to_string_lossy(), base_dir);
    let path_obj = Path::new(&relative_path);
    let file_name = path_obj.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let folder_path_str = path_obj.parent().and_then(|p| p.to_str()).unwrap_or("");

    let folder_id = insert_folder(conn, folder_path_str)?;
    let file_id = get_or_update_file_id(conn, &relative_path, file_name, folder_id)?;

    conn.execute("DELETE FROM file_tags WHERE file_id = ?1", params![file_id])?;
    conn.execute("DELETE FROM backlinks WHERE file_id = ?1", params![file_id])?;

    let content = fs::read_to_string(&canonical_path)?;
    let mut yaml_tags = Vec::new();
    let (metadata_json, lines) = parse_content(&content, &mut yaml_tags)?;

    if let Some(json_str) = metadata_json {
        conn.execute(
            "UPDATE files SET metadata = ?1 WHERE id = ?2",
            params![json_str, file_id],
        )?;
    }

    for tag in yaml_tags {
        let tag_id = insert_tag(conn, &tag)?;
        insert_file_tag(conn, file_id, tag_id)?;
    }

    let mut in_code_block = false;
    let tag_re = Regex::new(r"#[\p{L}\p{N}_-]+").unwrap();
    for line in lines.iter() {
        if line.trim() == "```" {
            in_code_block = !in_code_block;
            continue;
        }
        if !in_code_block {
            let cleaned = clearfromtrashtags(line);
            for cap in tag_re.captures_iter(&cleaned) {
                let tag = &cap[0][1..];
                let tag_id = insert_tag(conn, tag)?;
                insert_file_tag(conn, file_id, tag_id)?;
            }
        }
    }

    let content_for_backlinks = clearfromusless(content);
    let backlink_re = Regex::new(r"\[\[([^\]\[]+?)\]\]").unwrap();
    for cap in backlink_re.captures_iter(&content_for_backlinks) {
        let backlink_text = &cap[1];
        if let Some(sanitized) = sanitize_backlink(backlink_text) {
            if let (Some(backlink_id), _) =
                find_backlink_file_local(conn, &sanitized, base_dir, folder_id)?
            {
                conn.execute("INSERT OR IGNORE INTO backlinks (backlink, backlink_id, file_id) VALUES (?1, ?2, ?3)", params![backlink_text, backlink_id, file_id])?;
            } else {
                conn.execute(
                    "INSERT OR IGNORE INTO backlinks (backlink, file_id) VALUES (?1, ?2)",
                    params![backlink_text, file_id],
                )?;
            }
        }
    }
    Ok(())
}

fn find_backlink_file_local(
    conn: &Connection,
    backlink: &str,
    base_dir: &str,
    current_folder_id: i64,
) -> Result<(Option<i64>, Option<String>)> {
    let filename = Path::new(backlink)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(backlink);

    let mut stmt = conn.prepare("SELECT id, path, folder_id FROM files WHERE file_name = ?1")?;
    let mut rows = stmt.query(params![filename])?;
    let mut db_matches = Vec::new();
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let path: String = row.get(1)?;
        let folder_id: i64 = row.get(2)?;
        if Path::new(base_dir).join(&path).exists() {
            db_matches.push((id, path, folder_id));
        }
    }

    if !db_matches.is_empty() {
        if db_matches.len() == 1 {
            return Ok((Some(db_matches[0].0), Some(db_matches[0].1.clone())));
        }
        if let Some(m) = db_matches
            .iter()
            .find(|(_, _, fid)| *fid == current_folder_id)
        {
            return Ok((Some(m.0), Some(m.1.clone())));
        }
        db_matches.sort_by(|a, b| a.1.len().cmp(&b.1.len()));
        return Ok((Some(db_matches[0].0), Some(db_matches[0].1.clone())));
    }

    let mut fs_matches: Vec<String> = WalkDir::new(base_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy() == filename)
        .map(|e| remove_string(&e.path().to_string_lossy(), base_dir))
        .collect();

    if fs_matches.is_empty() {
        return Ok((None, None));
    }

    fs_matches.sort_by_key(|p| p.len());
    let best_match_path = fs_matches.remove(0);

    let path_obj = Path::new(&best_match_path);
    let fname = path_obj.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let folder_path = path_obj.parent().and_then(|p| p.to_str()).unwrap_or("");
    let new_folder_id = insert_folder(conn, folder_path)?;
    let new_file_id = get_or_update_file_id(conn, &best_match_path, fname, new_folder_id)?;

    Ok((Some(new_file_id), Some(best_match_path)))
}

//-////////////////////////////////////////////////////////////////////////////
//  SERVER IMPLEMENTATION
//-////////////////////////////////////////////////////////////////////////////

struct AppState {
    db: Arc<Mutex<Connection>>,
    db_path: String,
}

async fn run_server(args: ServeArgs) -> Result<()> {
    info!("Starting server at {}", args.bind);
    info!("Using database: {}", args.database);
    let db_conn = Connection::open(&args.database)?;
    setup_database(&db_conn)?;
    let shared_state = Arc::new(AppState {
        db: Arc::new(Mutex::new(db_conn)),
        db_path: args.database,
    });

    let app = Router::new()
        .route("/scan", post(handle_scan))
        .route("/delete", post(handle_delete))
        .route("/sql", post(handle_sql))
        .route("/db", get(handle_db_download))
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_scan(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ScanPayload>,
) -> impl IntoResponse {
    info!("Received scan request for: {}", payload.relative_path);
    let conn_guard = state.db.lock().unwrap();
    match process_payload(&conn_guard, payload) {
        Ok(_) => (
            StatusCode::OK,
            Json(ServerResponse {
                success: true,
                message: "File processed".into(),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ServerResponse {
                success: false,
                message: e.to_string(),
            }),
        ),
    }
}

async fn handle_delete(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DeletePayload>,
) -> impl IntoResponse {
    info!("Received delete request for: {}", payload.relative_path);
    let conn_guard = state.db.lock().unwrap();
    match remove_file_from_db(&conn_guard, &payload.relative_path) {
        Ok(_) => (
            StatusCode::OK,
            Json(ServerResponse {
                success: true,
                message: "File removed".into(),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ServerResponse {
                success: false,
                message: e.to_string(),
            }),
        ),
    }
}

async fn handle_db_download(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match fs::read(&state.db_path) {
        Ok(data) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/vnd.sqlite3"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"markdown_data.db\"",
                ),
            ],
            Bytes::from(data),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to read db file for download: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not read database file",
            )
                .into_response()
        }
    }
}

fn sql_value_to_json(v: ValueRef) -> JsonValue {
    match v {
        ValueRef::Null => JsonValue::Null,
        ValueRef::Integer(i) => JsonValue::Number(i.into()),
        ValueRef::Real(f) => JsonValue::Number(
            serde_json::Number::from_f64(f).unwrap_or(serde_json::Number::from(0)),
        ),
        ValueRef::Text(s) => JsonValue::String(String::from_utf8_lossy(s).into_owned()),
        ValueRef::Blob(b) => JsonValue::String(String::from_utf8_lossy(b).into_owned()),
    }
}

async fn handle_sql(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SqlQueryPayload>,
) -> Json<SqlQueryResult> {
    info!("Received SQL query: {}", payload.query);
    let conn = state.db.lock().unwrap();
    let query_trim = payload.query.trim().to_lowercase();

    if query_trim.starts_with("select") || query_trim.starts_with("pragma") {
        match conn.prepare(&payload.query) {
            Ok(mut stmt) => {
                let columns: Vec<String> =
                    stmt.column_names().iter().map(|s| s.to_string()).collect();
                let col_count = stmt.column_count();

                let result = stmt.query_map([], |row| {
                    let mut values = Vec::with_capacity(col_count);
                    for i in 0..col_count {
                        values.push(sql_value_to_json(row.get_ref_unwrap(i)));
                    }
                    Ok(values)
                });

                match result {
                    Ok(rows) => match rows.collect::<std::result::Result<Vec<_>, _>>() {
                        Ok(r) => Json(SqlQueryResult {
                            columns,
                            rows: r,
                            error: None,
                            rows_affected: 0,
                        }),
                        Err(e) => Json(SqlQueryResult {
                            columns: vec![],
                            rows: vec![],
                            error: Some(e.to_string()),
                            rows_affected: 0,
                        }),
                    },
                    Err(e) => Json(SqlQueryResult {
                        columns: vec![],
                        rows: vec![],
                        error: Some(e.to_string()),
                        rows_affected: 0,
                    }),
                }
            }
            Err(e) => Json(SqlQueryResult {
                columns: vec![],
                rows: vec![],
                error: Some(e.to_string()),
                rows_affected: 0,
            }),
        }
    } else {
        match conn.execute(&payload.query, []) {
            Ok(count) => Json(SqlQueryResult {
                columns: vec![],
                rows: vec![],
                error: None,
                rows_affected: count as u64,
            }),
            Err(e) => Json(SqlQueryResult {
                columns: vec![],
                rows: vec![],
                error: Some(e.to_string()),
                rows_affected: 0,
            }),
        }
    }
}

//-////////////////////////////////////////////////////////////////////////////
//  CORE PROCESSING LOGIC (Server-side)
//-////////////////////////////////////////////////////////////////////////////

fn process_payload(conn: &Connection, payload: ScanPayload) -> Result<()> {
    let path = Path::new(&payload.relative_path);
    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let folder_path_str = path.parent().and_then(|p| p.to_str()).unwrap_or("");

    let folder_id = insert_folder(conn, folder_path_str)?;
    let file_id = get_or_update_file_id(conn, &payload.relative_path, file_name, folder_id)?;

    conn.execute("DELETE FROM file_tags WHERE file_id = ?1", params![file_id])?;
    conn.execute("DELETE FROM backlinks WHERE file_id = ?1", params![file_id])?;

    let mut yaml_tags = Vec::new();
    let (metadata_json, lines) = parse_content(&payload.content, &mut yaml_tags)?;

    if let Some(json_str) = metadata_json {
        conn.execute(
            "UPDATE files SET metadata = ?1 WHERE id = ?2",
            params![json_str, file_id],
        )?;
    }

    for tag in yaml_tags {
        let tag_id = insert_tag(conn, &tag)?;
        insert_file_tag(conn, file_id, tag_id)?;
    }

    let mut in_code_block = false;
    let tag_re = Regex::new(r"#[\p{L}\p{N}_-]+").unwrap();
    for line in lines.iter() {
        if line.trim() == "```" {
            in_code_block = !in_code_block;
            continue;
        }
        if !in_code_block {
            let cleaned = clearfromtrashtags(line);
            for cap in tag_re.captures_iter(&cleaned) {
                let tag = &cap[0][1..];
                let tag_id = insert_tag(conn, tag)?;
                insert_file_tag(conn, file_id, tag_id)?;
            }
        }
    }

    let content_for_backlinks = clearfromusless(payload.content.clone());
    let backlink_re = Regex::new(r"\[\[([^\]\[]+?)\]\]").unwrap();
    for cap in backlink_re.captures_iter(&content_for_backlinks) {
        let backlink_text = &cap[1];
        if let Some(sanitized) = sanitize_backlink(backlink_text) {
            if payload.client_validated_backlinks.contains(&sanitized) {
                let b_path = Path::new(&sanitized);
                let b_fname = b_path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                let b_folder = b_path.parent().and_then(|p| p.to_str()).unwrap_or("");
                let b_folder_id = insert_folder(conn, b_folder)?;
                let backlink_id = get_or_update_file_id(conn, &sanitized, b_fname, b_folder_id)?;
                conn.execute("INSERT OR IGNORE INTO backlinks (backlink, backlink_id, file_id) VALUES (?1, ?2, ?3)", params![backlink_text, backlink_id, file_id])?;
            } else {
                conn.execute(
                    "INSERT OR IGNORE INTO backlinks (backlink, file_id) VALUES (?1, ?2)",
                    params![backlink_text, file_id],
                )?;
            }
        }
    }
    Ok(())
}

//-////////////////////////////////////////////////////////////////////////////
//  DATABASE HELPERS & UTILITIES (SHARED)
//-////////////////////////////////////////////////////////////////////////////

fn setup_database(conn: &Connection) -> Result<()> {
    // Unchanged from previous version
    conn.execute("PRAGMA foreign_keys = ON", [])?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS folders (id INTEGER PRIMARY KEY, path TEXT UNIQUE)",
        [],
    )?;
    conn.execute("CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, path TEXT UNIQUE, file_name TEXT, folder_id INTEGER, metadata TEXT DEFAULT '{}', FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE CASCADE)",[])?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS tags (id INTEGER PRIMARY KEY, tag TEXT UNIQUE)",
        [],
    )?;
    conn.execute("CREATE TABLE IF NOT EXISTS file_tags (file_id INTEGER, tag_id INTEGER, FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE, FOREIGN KEY(tag_id) REFERENCES tags(id), UNIQUE(file_id, tag_id))",[])?;
    conn.execute("CREATE TABLE IF NOT EXISTS backlinks (id INTEGER PRIMARY KEY, backlink TEXT, backlink_id INTEGER, file_id INTEGER, FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE, FOREIGN KEY(backlink_id) REFERENCES files(id) ON DELETE CASCADE, UNIQUE(backlink_id, file_id, backlink))",[])?;
    Ok(())
}

fn remove_file_from_db(conn: &Connection, relative_path: &str) -> Result<()> {
    let files_deleted =
        conn.execute("DELETE FROM files WHERE path = ?1", params![relative_path])?;
    if files_deleted == 0 {
        return Err(AppError::Io(std::io::Error::new(
            ErrorKind::NotFound,
            "File not found in DB",
        )));
    }
    Ok(())
}

fn insert_folder(conn: &Connection, path: &str) -> Result<i64> {
    let p = if path.is_empty() { "/" } else { path };
    conn.execute(
        "INSERT OR IGNORE INTO folders (path) VALUES (?1)",
        params![p],
    )?;
    conn.query_row("SELECT id FROM folders WHERE path = ?1", params![p], |r| {
        r.get(0)
    })
    .map_err(AppError::from)
}

fn get_or_update_file_id(
    conn: &Connection,
    path: &str,
    file_name: &str,
    folder_id: i64,
) -> Result<i64> {
    if let Some(id) = conn
        .query_row("SELECT id FROM files WHERE path = ?1", params![path], |r| {
            r.get(0)
        })
        .optional()?
    {
        conn.execute(
            "UPDATE files SET folder_id = ?1, file_name = ?2 WHERE id = ?3",
            params![folder_id, file_name, id],
        )?;
        Ok(id)
    } else {
        insert_file(conn, path, file_name, folder_id)
    }
}

fn insert_file(conn: &Connection, path: &str, file_name: &str, folder_id: i64) -> Result<i64> {
    conn.execute(
        "INSERT INTO files (path, file_name, folder_id) VALUES (?1, ?2, ?3)",
        params![path, file_name, folder_id],
    )?;
    Ok(conn.last_insert_rowid())
}

fn insert_tag(conn: &Connection, tag: &str) -> Result<i64> {
    conn.execute("INSERT OR IGNORE INTO tags (tag) VALUES (?1)", params![tag])?;
    conn.query_row("SELECT id FROM tags WHERE tag = ?1", params![tag], |r| {
        r.get(0)
    })
    .map_err(AppError::from)
}

fn insert_file_tag(conn: &Connection, file_id: i64, tag_id: i64) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO file_tags (file_id, tag_id) VALUES (?1, ?2)",
        params![file_id, tag_id],
    )?;
    Ok(())
}

fn parse_content(
    content: &str,
    yaml_tags: &mut Vec<String>,
) -> Result<(Option<String>, Vec<String>)> {
    let mut in_yaml = false;
    let mut yaml_content = String::new();
    let lines: Vec<String> = content.lines().map(String::from).collect();
    let mut metadata_json: Option<String> = None;

    for line in &lines {
        if line.trim() == "---" {
            if in_yaml {
                if !yaml_content.is_empty() {
                    metadata_json = parse_yaml_frontmatter(&yaml_content, yaml_tags);
                }
                break;
            } else {
                in_yaml = true;
            }
        } else if in_yaml {
            yaml_content.push_str(line);
            yaml_content.push('\n');
        }
    }
    Ok((metadata_json, lines))
}

fn parse_yaml_frontmatter(yaml_str: &str, yaml_tags: &mut Vec<String>) -> Option<String> {
    YamlLoader::load_from_str(yaml_str).ok().and_then(|docs| {
        docs.get(0).and_then(|doc| {
            if let Some(tags_array) = doc["tags"].as_vec() {
                for tag_yaml in tags_array {
                    if let Some(tag_str) = tag_yaml.as_str() {
                        if !yaml_tags.contains(&tag_str.to_string()) {
                            yaml_tags.push(tag_str.to_string());
                        }
                    }
                }
            }
            yaml_to_json(doc)
                .ok()
                .and_then(|j| serde_json::to_string(&j).ok())
        })
    })
}

fn yaml_to_json(yaml: &Yaml) -> Result<JsonValue> {
    // Unchanged from previous version
    match yaml {
        Yaml::String(s) => Ok(JsonValue::String(s.clone())),
        Yaml::Integer(i) => Ok(JsonValue::Number((*i).into())),
        Yaml::Real(s) => s
            .parse::<f64>()
            .map_err(|_| AppError::Io(std::io::Error::new(ErrorKind::InvalidData, "Invalid float")))
            .and_then(|f| {
                serde_json::Number::from_f64(f)
                    .ok_or_else(|| {
                        AppError::Io(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "Invalid float conversion",
                        ))
                    })
                    .map(JsonValue::Number)
            }),
        Yaml::Boolean(b) => Ok(JsonValue::Bool(*b)),
        Yaml::Array(v) => v
            .iter()
            .map(yaml_to_json)
            .collect::<Result<Vec<_>>>()
            .map(JsonValue::Array),
        Yaml::Hash(h) => {
            let mut map = serde_json::Map::new();
            for (k, v) in h {
                if let Yaml::String(key_str) = k {
                    map.insert(key_str.clone(), yaml_to_json(v)?);
                }
            }
            Ok(JsonValue::Object(map))
        }
        _ => Ok(JsonValue::Null),
    }
}

fn remove_string(full_path: &str, part_to_remove: &str) -> String {
    let Ok(canonical_part) = Path::new(part_to_remove).canonicalize() else {
        return full_path.to_string();
    };
    let Ok(canonical_full) = Path::new(full_path).canonicalize() else {
        return full_path.to_string();
    };
    if let Ok(stripped) = canonical_full.strip_prefix(canonical_part) {
        return stripped
            .to_string_lossy()
            .trim_start_matches(['/', '\\'])
            .to_string();
    }
    full_path.to_string()
}

fn clearfromtrashtags(input: &str) -> String {
    let re_code = Regex::new(r"`.*?`").unwrap();
    let intermediate = re_code.replace_all(input, "");
    let re_link = Regex::new(r"\[(.*?)\]\(.*?\)").unwrap();
    re_link.replace_all(&intermediate, "$1").to_string()
}

fn clearfromusless(input: String) -> String {
    let re_code_blocks = Regex::new(r"(?s)```.*?```").unwrap();
    re_code_blocks.replace_all(&input, "").to_string()
}

fn sanitize_backlink(backlink: &str) -> Option<String> {
    if backlink.is_empty() {
        return None;
    }
    let part = backlink.splitn(2, '|').next().unwrap_or("").trim();
    let part = part.splitn(2, '#').next().unwrap_or("").trim();
    if part.is_empty() {
        return None;
    }
    Some(if !part.contains('.') {
        format!("{}.md", part)
    } else {
        part.to_string()
    })
}
