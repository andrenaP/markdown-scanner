#!/bin/bash
DB="markdown_data.db"
find "$Obsidian_valt_main_path" -name "*.md" | while read -r file; do
    echo "Processing file: $file"
    markdown-scanner "$file" "$Obsidian_valt_main_path" -d "$DB"
    echo "Data inserted for file: $file"
done