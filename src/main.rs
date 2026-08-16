use clap::{Arg, Command};
use markdown_scanner::{
    clean_orphaned_files, delete_asset_file, delete_markdown_file, register_asset_file,
    scan_markdown_file,
};
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let matches = Command::new("markdown-scanner")
        .version("1.3.0")
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
        .arg(
            Arg::new("clean")
                .long("clean")
                .short('c')
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let file_path = matches.get_one::<String>("file").unwrap();
    let base_dir = matches.get_one::<String>("base_dir").unwrap();
    let db_path = matches.get_one::<String>("database").unwrap();
    let json_only = matches.get_flag("json-only");
    let delete_flag = matches.get_flag("delete");
    let clean_flag = matches.get_flag("clean");
    if clean_flag {
        clean_orphaned_files(base_dir, db_path)?;
    }

    let is_markdown = Path::new(file_path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.eq_ignore_ascii_case("md"))
        .unwrap_or(false);

    if delete_flag {
        if is_markdown {
            delete_markdown_file(file_path, base_dir, db_path)?;
        } else {
            delete_asset_file(file_path, base_dir, db_path)?;
        }
    } else {
        if is_markdown {
            if let Some(json) = scan_markdown_file(file_path, base_dir, db_path, json_only).await? {
                println!("{}", json);
            }
        } else {
            // It's an image or another asset, register it in the folders/files tables
            register_asset_file(file_path, base_dir, db_path)?;
        }
    }
    Ok(())
}
