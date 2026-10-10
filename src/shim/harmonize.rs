//! Agent daemon and detach harmonizer.
//!
//! Normalizes command-line arguments across AI coding agent CLIs to ensure
//! foreground execution and prevent background detach failures in private PID namespaces.

/// Normalizes a binary path or name to its lowercase file stem.
fn normalize_bin_stem(binary_name: &str) -> String {
    let norm = binary_name.replace('\\', "/");
    let stem = std::path::Path::new(&norm)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(binary_name);
    stem.to_ascii_lowercase()
}

/// Normalizes and prepares agent arguments before invocation.
///
/// Injects vendor-specific foreground execution flags if not already provided:
/// - `codex` / `codex-cli`: `--no-daemon`
/// - `goose` / `goose-ai`: `--foreground`
/// - `openhands` / `all-hands`: `--no-daemon`
/// - `cline` / `cline-cli`: `--no-daemon`
/// - `cursor-server`: `--foreground`
pub fn harmonize_agent_args(binary_name: &str, raw_args: &[String]) -> Vec<String> {
    let mut args = raw_args.to_vec();
    let stem = normalize_bin_stem(binary_name);

    let required_flag = match stem.as_str() {
        "codex" | "codex-cli" => Some("--no-daemon"),
        "goose" | "goose-ai" => Some("--foreground"),
        "openhands" | "all-hands" => Some("--no-daemon"),
        "cline" | "cline-cli" => Some("--no-daemon"),
        "cursor-server" => Some("--foreground"),
        _ => None,
    };

    if let Some(flag) = required_flag {
        if !args.iter().any(|a| a == flag) {
            args.push(flag.to_string());
        }
    }

    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harmonize_codex() {
        let args = vec!["exec".to_string(), "run".to_string()];
        let harmonized = harmonize_agent_args("codex", &args);
        assert_eq!(harmonized, vec!["exec", "run", "--no-daemon"]);

        // If already present, don't duplicate
        let already = vec!["--no-daemon".to_string(), "exec".to_string()];
        assert_eq!(harmonize_agent_args("codex-cli", &already), already);
    }

    #[test]
    fn test_harmonize_goose() {
        let args = vec!["session".to_string()];
        let harmonized = harmonize_agent_args("goose", &args);
        assert_eq!(harmonized, vec!["session", "--foreground"]);

        let path = "/usr/local/bin/goose-ai";
        let harmonized = harmonize_agent_args(path, &args);
        assert_eq!(harmonized, vec!["session", "--foreground"]);
    }

    #[test]
    fn test_harmonize_openhands() {
        let args = vec![];
        let harmonized = harmonize_agent_args("openhands", &args);
        assert_eq!(harmonized, vec!["--no-daemon"]);
    }

    #[test]
    fn test_harmonize_cline() {
        let args = vec!["task".to_string()];
        let harmonized = harmonize_agent_args("cline", &args);
        assert_eq!(harmonized, vec!["task", "--no-daemon"]);
    }

    #[test]
    fn test_harmonize_cursor_server() {
        let args = vec![];
        let harmonized = harmonize_agent_args("cursor-server", &args);
        assert_eq!(harmonized, vec!["--foreground"]);
    }

    #[test]
    fn test_harmonize_unaffected() {
        let args = vec!["prompt".to_string()];
        let harmonized = harmonize_agent_args("claude", &args);
        assert_eq!(harmonized, vec!["prompt"]);
    }
}
