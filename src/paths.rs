use std::path::{Component, Path};

pub fn is_slug(value: &str) -> bool {
    let mut parts = value.split('-');
    let Some(first) = parts.next() else {
        return false;
    };
    if !slug_part(first, true) {
        return false;
    }
    parts.all(|part| slug_part(part, false))
}

pub fn repo_path(root: &Path, value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 256 {
        return None;
    }
    if value.contains('\\') || value.contains('\0') || value.starts_with('/') || value.starts_with('~') {
        return None;
    }
    let mut absolute = root.to_path_buf();
    for segment in value.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return None;
        }
        absolute.push(segment);
    }
    if !absolute.starts_with(root) {
        return None;
    }
    Some(value.to_string())
}

pub fn check_path_pattern(pattern: &str) -> Result<(), String> {
    let body = pattern.strip_suffix('/').unwrap_or(pattern);
    if body.is_empty()
        || pattern.len() > 256
        || pattern.starts_with('/')
        || pattern.starts_with('!')
        || pattern.contains('\\')
        || pattern.contains('\0')
        || drive_prefix(pattern)
        || body.split('/').any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(format!("path pattern is invalid: {pattern}"));
    }
    Ok(())
}

pub fn check_path_patterns(patterns: &[String]) -> Result<Vec<String>, String> {
    for pattern in patterns {
        check_path_pattern(pattern)?;
    }
    Ok(patterns.to_vec())
}

pub fn paths_match(pattern: &str, path: &str) -> bool {
    if pattern.ends_with('/') {
        return path.starts_with(pattern);
    }
    let pattern_segments: Vec<&str> = pattern.split('/').collect();
    let path_segments: Vec<&str> = path.split('/').collect();
    match_segments(&pattern_segments, &path_segments)
}

pub fn any_path_matches(patterns: &[String], paths: &[String]) -> bool {
    patterns.iter().any(|pattern| paths.iter().any(|path| paths_match(pattern, path)))
}

pub fn to_posix(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn drive_prefix(pattern: &str) -> bool {
    let mut chars = pattern.chars();
    matches!((chars.next(), chars.next()), (Some(letter), Some(':')) if letter.is_ascii_alphabetic())
}

fn match_segments(pattern: &[&str], path: &[&str]) -> bool {
    let mut pattern_index = 0;
    let mut path_index = 0;
    let mut star_pattern = None;
    let mut star_path = 0;
    while path_index < path.len() {
        if pattern_index < pattern.len() && pattern[pattern_index] == "**" {
            star_pattern = Some(pattern_index);
            star_path = path_index;
            pattern_index += 1;
            continue;
        }
        if pattern_index < pattern.len() && segment_match(pattern[pattern_index], path[path_index]) {
            pattern_index += 1;
            path_index += 1;
            continue;
        }
        let Some(saved) = star_pattern else {
            return false;
        };
        star_path += 1;
        if star_path > path.len() {
            return false;
        }
        path_index = star_path;
        pattern_index = saved + 1;
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == "**" {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn segment_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let mut pattern_index = 0;
    let mut text_index = 0;
    let mut star = None;
    let mut star_text = 0;
    while text_index < text.len() {
        if pattern_index < pattern.len() && (pattern[pattern_index] == '?' || pattern[pattern_index] == text[text_index]) {
            pattern_index += 1;
            text_index += 1;
            continue;
        }
        if pattern_index < pattern.len() && pattern[pattern_index] == '*' {
            star = Some(pattern_index);
            star_text = text_index;
            pattern_index += 1;
            continue;
        }
        let Some(saved) = star else {
            return false;
        };
        star_text += 1;
        text_index = star_text;
        pattern_index = saved + 1;
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == '*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn slug_part(part: &str, first: bool) -> bool {
    let mut chars = part.chars();
    let Some(lead) = chars.next() else {
        return false;
    };
    let lead_ok = if first {
        lead.is_ascii_lowercase()
    } else {
        lead.is_ascii_lowercase() || lead.is_ascii_digit()
    };
    lead_ok && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn accepts_a_repository_relative_path() {
        let root = Path::new("/repo");
        assert_eq!(
            repo_path(root, ".agents/closeout/testing.yaml").as_deref(),
            Some(".agents/closeout/testing.yaml")
        );
    }

    #[test]
    fn rejects_paths_that_leave_the_repository() {
        let root = Path::new("/repo");
        assert!(repo_path(root, "../secret.yaml").is_none());
        assert!(repo_path(root, "/etc/passwd").is_none());
        assert!(repo_path(root, "~/.agents/closeout.yaml").is_none());
        assert!(repo_path(root, "a\\b").is_none());
        assert!(repo_path(root, "a//b").is_none());
        assert!(repo_path(root, "").is_none());
    }

    #[test]
    fn globs_stay_in_a_segment_and_double_star_crosses() {
        assert!(paths_match("apps/engine/**", "apps/engine/main.ts"));
        assert!(paths_match("apps/engine/**", "apps/engine/src/main.ts"));
        assert!(paths_match("apps/engine/**", "apps/engine"));
        assert!(!paths_match("apps/engine/**", "apps/frontend/main.ts"));
        assert!(!paths_match("apps/engine/**", "apps/engine-extra/main.ts"));
        assert!(paths_match("apps/engine/", "apps/engine/main.ts"));
        assert!(!paths_match("apps/engine/", "apps/engine"));
        assert!(!paths_match("apps/engine/", "apps/engine-extra/main.ts"));
        assert!(paths_match("*.ts", "main.ts"));
        assert!(!paths_match("*.ts", "src/main.ts"));
        assert!(paths_match("**/*.ts", "src/main.ts"));
        assert!(paths_match("**/*.ts", "main.ts"));
        assert!(paths_match("a?c", "abc"));
        assert!(!paths_match("a?c", "ac"));
        assert!(!paths_match("*", "a/b"));
        assert!(paths_match("a/**/b", "a/b"));
        assert!(paths_match("a/**/b", "a/x/y/b"));
    }

    #[test]
    fn path_patterns_stay_inside_the_repository() {
        assert!(check_path_pattern("src/**").is_ok());
        assert!(check_path_pattern("apps/engine/").is_ok());
        assert!(check_path_pattern("*.md").is_ok());
        assert!(check_path_pattern("../secret").is_err());
        assert!(check_path_pattern("/etc/passwd").is_err());
        assert!(check_path_pattern("!secret").is_err());
        assert!(check_path_pattern("a\\b").is_err());
        assert!(check_path_pattern("C:/windows").is_err());
        assert!(check_path_pattern("a/../b").is_err());
        assert!(check_path_pattern("a//b").is_err());
        assert!(check_path_pattern(".").is_err());
        assert!(check_path_pattern("foo/").is_ok());
    }
}
