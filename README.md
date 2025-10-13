# Markdown Scanner

## Overview
`markdown-scanner` is a Rust-based command-line tool designed to scan Markdown files within a specified directory (e.g., an Obsidian vault) and extract metadata such as tags and backlinks. It stores this information in a SQLite database for efficient querying and organization. The tool is invoked via a Bash script (`markdown-processor-all-rust.bash`) that processes all `.md` files in a directory, making it suitable for integration with text editors like Neovim or workflows involving Markdown-based note-taking systems like Obsidian.

## Features
- **Tag Extraction**: Extracts both YAML frontmatter tags and inline `#tags` from Markdown files, ignoring tags within code blocks.
- **Backlink Detection**: Identifies `[[backlink]]` references in Markdown files and links them to corresponding files in the database.
- **SQLite Database**: Stores file metadata, folder structure, tags, and backlinks in a relational SQLite database for easy querying.
- **File System Integration**: Resolves file paths relative to a base directory and handles file system changes, ensuring accurate metadata.
- **Error Handling**: Robust error handling with custom error types and detailed logging for debugging.
- **Editor Integration**: Designed to be triggered on file save in editors like Neovim or used in batch processing for Markdown vaults.

## Usage
The tool is typically executed via the provided Bash script or directly as a command-line utility.

### Progect that use markdown-scanner
[nvim-minimal](https://github.com/andrenaP/nvim-minimal) 
[midetor](https://github.com/andrenaP/midetor)

### Bash Script
The `markdown-processor-all-rust.bash` script processes all `.md` files in a specified directory (e.g., an Obsidian vault):

```bash
#!/bin/bash
DB="markdown_data.db"
find "$Obsidian_valt_main_path" -name "*.md" | while read -r file; do
    echo "Processing file: $file"
    markdown-scanner "$file" "$Obsidian_valt_main_path" -d "$DB"
    echo "Data inserted for file: $file"
done
```

- **Environment Variable**: Set `Obsidian_valt_main_path` to the root directory of your Markdown files.
- **Database**: Specify the SQLite database file (defaults to `markdown_data.db`).
- **Execution**: Run the script to process all `.md` files in the specified directory.

### Command-Line Usage
The Rust binary can be invoked directly:

```bash
markdown-scanner <file_path> <base_dir> -d <database_path>
```

- `<file_path>`: Path to the Markdown file to process.
- `<base_dir>`: Base directory for resolving relative paths.
- `-d <database_path>`: Path to the SQLite database (default: `markdown_data.db`).

Example:
```bash
markdown-scanner /path/to/note.md /path/to/vault/dir/ -d markdown_data.db
```

### Integration with Neovim
Well I was using it in neovim for a long time. I think I will make it in one plugin when I rip the code form my enormous init.lua.

## Database Schema
The SQLite database (`markdown_data.db`) contains the following tables:

- **folders**: Stores unique folder paths with their IDs.
  - `id`: Primary key.
  - `path`: Relative folder path (unique).
- **files**: Stores file metadata.
  - `id`: Primary key.
  - `path`: Relative file path (unique).
  - `file_name`: Name of the file.
  - `folder_id`: References `folders(id)`.
  - `metadata` : yaml data.
- **tags**: Stores unique tags.
  - `id`: Primary key.
  - `tag`: Tag name (unique).
- **file_tags**: Maps files to tags.
  - `file_id`: References `files(id)`.
  - `tag_id`: References `tags(id)`.
  - Unique constraint on `(file_id, tag_id)`.
- **backlinks**: Stores backlink relationships.
  - `id`: Primary key.
  - `backlink`: Backlink text (e.g., `Note Title`).
  - `backlink_id`: References `files(id)` (nullable).
  - `file_id`: References `files(id)`.
  - Unique constraint on `(backlink_id, file_id, backlink)`.

## Installation
1. **Prerequisites**:
   - Rust (stable) and Cargo for building the Rust binary.
   - SQLite library for database operations (optioinal but recommended).
   - Bash for running the script.
2. **Build**:
   ```bash
   cargo build --release
   ```
   Or use [this if you are using linux](cheat sheet.md)

3. **Set Up Script**:
   - Copy `markdown-processor-all-rust.bash` to a vault.
   - Ensure it’s executable: `chmod +x markdown-processor-all-rust.bash`.
   - Set the `Obsidian_valt_main_path` environment variable or hardcode the path in the script.

## How It Works
1. **Initialization**:
   - The tool initializes a SQLite database with the required schema if it doesn’t exist.
   - It uses `clap` for command-line argument parsing and `env_logger` for detailed logging.
2. **File Processing**:
   - Reads the specified Markdown file.
   - Extracts YAML frontmatter tags and inline `#tags`.
   - Identifies `[[backlink]]` references, resolving them to existing files in the database or filesystem.
   - Cleans content by removing code blocks, URLs, and other irrelevant text before processing tags and backlinks.
3. **Database Operations**:
   - Inserts or updates folder and file metadata.
   - Stores tags and associates them with files.
   - Records backlinks, linking to other files when possible.
   - Handles duplicate files by preferring matches in the same folder or the shortest path.
4. **Filesystem Traversal**:
   - Uses `jwalk` for efficient filesystem traversal when resolving backlinks.
   - Canonicalizes paths to ensure consistency across systems.

## Limitations
- **Obsidian Vault**: While designed for Obsidian, the tool assumes a flat or hierarchical Markdown file structure and may not handle all Obsidian-specific features.
- **Backlink Resolution**: Backlinks are resolved based on file names, which may lead to ambiguities if multiple files have the same name in different folders.
- **No Real-Time Updates**: The tool processes files on-demand (e.g., on save or via the script) and does not monitor the filesystem for changes (But easy to fix...).

## Contributing
Contributions are welcome!


## TODO / Future Improvements

* [x] Make full yaml extraction in json. Like in `datopian/markdowndb`
* [ ] Add `--watch` To monitor files for changes and update the database accordingly


## Why I Built This
I started using Obsidian for note-taking, but I ran into a major issue that drove me up the wall: it took 20–30 seconds to start Obsidian on my Android phone, and its search functionality was painfully slow. Searching for a specific file required remembering the full path or relying on a content-based search that didn’t prioritize file names. Using a terminal with `nano` on my Android was significantly faster, which pushed me to find a better solution.

I explored alternatives like Logseq, but they felt restrictive, forcing me to organize notes according to their rigid rules. Then I discovered Neovim’s powerful plugin system, which works seamlessly in a TTY environment, allowing me to edit files directly on my system without the overhead of GUI-based tools. This was a game-changer for my workflow.

My first attempt was a quick Bash script paired with a basic Lua configuration for Neovim. It worked, but it was clunky. I then tried rewriting the tool entirely in Lua, thinking I could leverage Neovim’s `init.lua` to manage dependencies. Big mistake. Termux, my Android terminal environment, didn’t support Lua libraries well, and the setup broke completely when a package link for Lua libraries changed unexpectedly. The frustration of dealing with broken dependencies pushed me to my limit.

Eventually, I turned to Rust to create a static binary that wouldn’t rely on fickle dependencies or slow plugins. I briefly experimented with `epwalsh/obsidian.nvim`, which was promising but took an excruciating 14 seconds to follow a backlink on my low-powered device—slower than my `rg` (ripgrep) searches! While `obsidian.nvim` is a great tool for more powerful systems, it wasn’t suitable for my "potato calculator." So, I built `markdown-scanner` to create a lightweight, fast, and reliable solution that integrates with Neovim, processes Markdown files efficiently, and stores metadata in a SQLite database for quick access.

## License
This project is licensed under the GNU General Public License v3.0.
