use regex::Regex;
use std::path::Path;

pub fn remove_base_dir(full_path: &Path, base_dir: &str) -> String {
    let path_str = full_path.to_string_lossy();
    let escaped_part = regex::escape(base_dir);
    let re = Regex::new(&escaped_part).unwrap();
    re.replace(&path_str, "")
        .trim_start_matches('/')
        .trim_start_matches('\\')
        .to_string()
}

/// Cleans text to make tag extraction accurate (removes code blocks, urls, etc)
pub fn clean_text_for_parsing(input: &str) -> String {
    let re_brackets = Regex::new(r"\[.*?\]").unwrap();
    let re_parens = Regex::new(r"\(.*?\)").unwrap();
    let re_code = Regex::new(r"`.*?`").unwrap();
    let re_urls = Regex::new(r"https?://[\w\.\-\_/\%#]+").unwrap();
    let re_angles = Regex::new(r"<[^>]+>[^<]*</[^>]+>").unwrap();

    let step1 = re_brackets.replace_all(input, "");
    let step2 = re_parens.replace_all(&step1, "");
    let step3 = re_code.replace_all(&step2, "");
    let step4 = re_urls.replace_all(&step3, " ");
    let step5 = re_angles.replace_all(&step4, "");

    step5.to_string()
}

pub fn sanitize_backlink(backlink: &str) -> Option<String> {
    if backlink.trim().is_empty() {
        return None;
    }
    let mut result = backlink.to_string();

    // Remove aliases | and fragments #
    if let Some(idx) = result.find('|') {
        result.truncate(idx);
    }
    if let Some(idx) = result.find('#') {
        result.truncate(idx);
    }

    let result = result.trim().to_string();
    if result.is_empty() {
        return None;
    }

    if !result.contains('.') {
        Some(format!("{}.md", result))
    } else {
        Some(result)
    }
}
