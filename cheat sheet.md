## To build just.
### Linux
```bash
cargo install --target=x86_64-unknown-linux-musl  --path .
```
### aarch
```bash
docker run --rm -v $(pwd):/usr/src/app -w /usr/src/app messense/rust-musl-cross:aarch64-musl cargo build --release --target aarch64-unknown-linux-musl
```
### windows
```bash
cargo build --target x86_64-pc-windows-gnu
```



```bash
ObsidianReadTags() {
    sqlite3 markdown_data.db ".mode box" "
SELECT f.file_name as file,
       GROUP_CONCAT(t.tag) as tags,
       SUBSTR(json_extract(f.metadata, '$.date'), 1, 10) as Date,
       json_extract(f.metadata, '$.chapters') as chapters,
       IIF(json_extract(f.metadata, '$.Finished')=1, '✅', '❌') as Done
FROM files f
JOIN file_tags ft ON f.id = ft.file_id
JOIN tags t ON ft.tag_id = t.id
GROUP BY f.id
HAVING tags NOT LIKE '%dead%'
ORDER BY Date;
" | less
}
```
