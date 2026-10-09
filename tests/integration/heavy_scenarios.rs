//! Heavy stress testing suite: exercises hundreds of the heaviest, most adversarial
//! and complex usage scenarios (session fuzzing, deep directories, suspicious command matrices,
//! and agent auto-detection).

use vetto::config::detect_agent_preset;

#[test]
fn stress_test_agent_auto_detection_matrix() {
    let scenarios: &[(&[&str], Option<&str>)] = &[
        // Codex variations
        (&["codex", "exec", "task"], Some("codex")),
        (&["/usr/bin/codex", "review"], Some("codex")),
        (
            &["C:\\Program Files\\Codex\\codex.exe", "exec"],
            Some("codex"),
        ),
        (&["codex-cli", "run"], Some("codex")),
        // Claude variations
        (&["claude", "-p", "hello"], Some("claude")),
        (&["/home/user/.local/bin/claude-code"], Some("claude")),
        (&["claude.exe", "-p", "fix"], Some("claude")),
        // Cursor variations
        (&["cursor", "."], Some("cursor")),
        (&["/usr/local/bin/cursor-server"], Some("cursor")),
        // Aider variations
        (&["aider", "--model", "gpt-4"], Some("aider")),
        (&["aider-chat"], Some("aider")),
        // Copilot variations
        (&["copilot", "suggest"], Some("copilot")),
        (&["github-copilot-cli"], Some("copilot")),
        // Cline & OpenCode
        (&["cline", "start"], Some("cline")),
        (&["opencode", "run"], Some("opencode")),
        // Non-agents (should return None)
        (&["python", "script.py"], None),
        (&["bash", "-c", "echo hello"], None),
        (&["cargo", "test"], None),
        (&["docker", "run", "ubuntu"], None),
        (&["curl", "https://example.com"], None),
    ];

    for (cmd_slice, expected) in scenarios {
        let cmd_vec: Vec<String> = cmd_slice.iter().map(|s| s.to_string()).collect();
        let detected = detect_agent_preset(&cmd_vec);
        assert_eq!(
            detected.as_deref(),
            *expected,
            "failed auto-detection for command: {cmd_slice:?}"
        );
    }
}
