mod db;
mod error;
mod models;
mod scanners;
mod usafecode;
mod utils;

use clap::{Arg, Command};
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let matches = Command::new("markdown-scanner")
        .version("1.1.0")
        .arg(Arg::new("file").required(true))
        .arg(Arg::new("base_dir").required(true))
        .arg(
            Arg::new("database")
                .long("database")
                .short('d')
                .default_value("markdown_data.db"),
        )
        .arg(
            Arg::new("json-only")
                .long("json-only")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("delete")
                .long("delete")
                .short('x')
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let file_path = matches.get_one::<String>("file").unwrap();
    let base_dir = matches.get_one::<String>("base_dir").unwrap();
    let db_path = matches.get_one::<String>("database").unwrap();
    let json_only = matches.get_flag("json-only");
    let delete_flag = matches.get_flag("delete");

    // Setup Context
    let canonical_path = Path::new(file_path).canonicalize()?;
    let relative_path = remove_base_dir(&canonical_path, base_dir);

    if delete_flag {
        let mut conn = db::init_connection(db_path)?;
        let mut repo = DatabaseRepo::new(&mut conn);
        repo.delete_file(&relative_path)?;
        info!("File deleted from DB");
        return Ok(());
    }

    // Initialize DB Connection
    let mut conn = db::init_connection(db_path)?;
    let repo = DatabaseRepo::new(&mut conn);

    // Read Content
    let content = fs::read_to_string(&canonical_path)?;

    // Fetch existing time BEFORE building context
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

    // Initialize Manager and Register Scanners
    let mut manager = ScannerManager::new();
    manager.register(FrontmatterScanner);
    manager.register(TagScanner);
    manager.register(BacklinkScanner);
    manager.register(TimeScanner);
    manager.register(YoutubeScanner);
    // Process Async
    let data = manager.process_file(&ctx).await?;

    if json_only {
        println!("{}", serde_json::to_string_pretty(&data)?);
    } else {
        // Batch Write to DB
        let mut conn = db::init_connection(db_path)?;
        let mut repo = DatabaseRepo::new(&mut conn);
        repo.save_file_results(&ctx, &data)?;
        info!("Successfully scanned and saved: {}", ctx.relative_path);
    }

    Ok(())
}
