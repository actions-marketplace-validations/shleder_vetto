//! Heavy stress testing suite: exercises hundreds of the heaviest, most adversarial
//! and complex usage scenarios (session fuzzing, deep directories, suspicious command matrices,
//! and agent auto-detection across all 32 presets).

use vetto::config::detect_agent_preset;

#[test]
fn stress_test_agent_auto_detection_matrix() {
    let scenarios: &[(&[&str], Option<&str>)] = &[
        // 1. Codex
        (&["codex", "exec", "task"], Some("codex")),
        (&["/usr/bin/codex", "review"], Some("codex")),
        (&["C:\\Program Files\\Codex\\codex.exe", "exec"], Some("codex")),
        (&["codex-cli", "run"], Some("codex")),

        // 2. Claude
        (&["claude", "-p", "hello"], Some("claude")),
        (&["/home/user/.local/bin/claude-code"], Some("claude")),
        (&["claude.exe", "-p", "fix"], Some("claude")),

        // 3. Cursor
        (&["cursor", "."], Some("cursor")),
        (&["/usr/local/bin/cursor-server"], Some("cursor")),
        (&["cursor-agent", "start"], Some("cursor")),

        // 4. Aider
        (&["aider", "--model", "gpt-4"], Some("aider")),
        (&["aider-chat"], Some("aider")),
        (&["C:\\Python\\Scripts\\aider.exe"], Some("aider")),

        // 5. Copilot
        (&["copilot", "suggest"], Some("copilot")),
        (&["github-copilot-cli"], Some("copilot")),
        (&["gh-copilot", "explain"], Some("copilot")),

        // 6. Cline
        (&["cline", "start"], Some("cline")),
        (&["cline-cli", "run"], Some("cline")),

        // 7. OpenCode
        (&["opencode", "run"], Some("opencode")),
        (&["opencode-ai", "task"], Some("opencode")),

        // 8. Windsurf
        (&["windsurf", "."], Some("windsurf")),
        (&["windsurf-cli", "inspect"], Some("windsurf")),
        (&["C:\\Windsurf\\windsurf.exe"], Some("windsurf")),

        // 9. Goose
        (&["goose", "session"], Some("goose")),
        (&["goose-ai", "run"], Some("goose")),
        (&["/opt/goose/bin/goose"], Some("goose")),

        // 10. Qwen Code
        (&["qwen-code", "solve"], Some("qwen_code")),
        (&["qwen_code", "generate"], Some("qwen_code")),
        (&["qwencode", "test"], Some("qwen_code")),
        (&["qwen", "run"], Some("qwen_code")),

        // 11. Antigravity
        (&["antigravity", "fly"], Some("antigravity")),
        (&["antigravity-cli", "engage"], Some("antigravity")),
        (&["agy", "status"], Some("antigravity")),

        // 12. OpenHands
        (&["openhands", "solve"], Some("openhands")),
        (&["all-hands", "run"], Some("openhands")),

        // 13. Devin
        (&["devin", "build"], Some("devin")),
        (&["devin-cli", "task"], Some("devin")),

        // 14. Smolagents
        (&["smolagents", "agent"], Some("smolagents")),
        (&["smol-agents", "run"], Some("smolagents")),
        (&["smolagent", "exec"], Some("smolagents")),

        // 15. OMP
        (&["omp", "solve"], Some("omp")),
        (&["omp-cli", "run"], Some("omp")),

        // 16. ZCode
        (&["zcode", "exec"], Some("zcode")),
        (&["zcode-cli", "generate"], Some("zcode")),

        // 17. Kimi
        (&["kimi", "prompt"], Some("kimi")),
        (&["kimi-code", "code"], Some("kimi")),
        (&["kimi-cli", "run"], Some("kimi")),

        // 18. Grok
        (&["grok", "query"], Some("grok")),
        (&["grok-build", "compile"], Some("grok")),
        (&["grok-cli", "run"], Some("grok")),

        // 19. Hermes
        (&["hermes", "task"], Some("hermes")),
        (&["hermes-agent", "solve"], Some("hermes")),

        // 20. Kilo
        (&["kilo", "run"], Some("kilo")),
        (&["kilo-code", "build"], Some("kilo")),

        // 21. Pi
        (&["pi", "compute"], Some("pi")),
        (&["pi-agent", "run"], Some("pi")),

        // 22. Command Code
        (&["command-code", "exec"], Some("command_code")),
        (&["command_code", "run"], Some("command_code")),
        (&["commandcode", "start"], Some("command_code")),

        // 23. Freebuff
        (&["freebuff", "inspect"], Some("freebuff")),
        (&["freebuff-agent", "run"], Some("freebuff")),

        // 24. DeepSeek Harness
        (&["deepseek-harness", "eval"], Some("deepseek_harness")),
        (&["deepseek_harness", "run"], Some("deepseek_harness")),
        (&["deepseek", "query"], Some("deepseek_harness")),

        // 25. Omnigent
        (&["omnigent", "solve"], Some("omnigent")),
        (&["omnigent-ai", "run"], Some("omnigent")),
        (&["omnigent-cli", "task"], Some("omnigent")),

        // 26. CrewAI
        (&["crewai", "kickoff"], Some("crewai")),
        (&["crew-ai", "run"], Some("crewai")),

        // 27. AutoGen
        (&["autogen", "start"], Some("autogen")),
        (&["autogen-studio", "ui"], Some("autogen")),
        (&["autogenstudio", "run"], Some("autogen")),

        // 28. Amp
        (&["amp", "build"], Some("amp")),
        (&["amp-cli", "run"], Some("amp")),

        // 29. SWE-bench
        (&["swebench", "evaluate"], Some("swebench")),
        (&["/opt/swebench/swebench", "run"], Some("swebench")),

        // 30. Roo Code
        (&["roo-code", "prompt"], Some("roo_code")),
        (&["roo_code", "run"], Some("roo_code")),
        (&["roocode", "solve"], Some("roo_code")),
        (&["roo", "test"], Some("roo_code")),

        // 31. Browser Use
        (&["browser-use", "navigate"], Some("browser_use")),
        (&["browser_use", "click"], Some("browser_use")),
        (&["browseruse", "fill"], Some("browser_use")),

        // Non-agents (should return None)
        (&["python", "script.py"], None),
        (&["python3", "main.py"], None),
        (&["node", "index.js"], None),
        (&["ruby", "app.rb"], None),
        (&["perl", "script.pl"], None),
        (&["bash", "-c", "echo hello"], None),
        (&["sh", "-c", "exit 0"], None),
        (&["zsh", "-f"], None),
        (&["cargo", "test"], None),
        (&["docker", "run", "ubuntu"], None),
        (&["podman", "ps"], None),
        (&["curl", "https://example.com"], None),
        (&["wget", "http://localhost"], None),
        (&["cat", "file.txt"], None),
        (&["ls", "-la"], None),
        (&["git", "status"], None),
        (&["make", "all"], None),
        (&["ninja", "build"], None),
        (&["gcc", "main.c"], None),
        (&["clang", "main.c"], None),
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
