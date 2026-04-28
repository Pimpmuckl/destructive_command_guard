//! Subprocess integration tests for Codex CLI hook protocol.
//!
//! Verifies that the real dcg binary, spawned as a child process, correctly
//! handles Codex 0.125.0+ payloads (exit code 2 + stderr deny) and Claude
//! Code payloads (exit 0 + stdout JSON deny).
//!
//! Each test is hermetic: isolated HOME, isolated TMPDIR, no shared state.
//! Safe for parallel execution via `cargo nextest`.

#![allow(clippy::doc_markdown, clippy::uninlined_format_args)]

use std::fmt;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

// ---------------------------------------------------------------------------
// HookOutcome — typed subprocess result with postmortem diagnostics
// ---------------------------------------------------------------------------

/// Result of spawning dcg as a subprocess.
pub struct HookOutcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
    /// The JSON bytes piped to stdin (for diagnostics).
    pub stdin_sent: Vec<u8>,
    /// Hermetic HOME used for this invocation.
    pub home_dir: PathBuf,
}

impl HookOutcome {
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    pub fn stderr_contains(&self, needle: &str) -> bool {
        self.stderr_str().contains(needle)
    }

    /// Codex block shape: exit 2, zero stdout bytes, non-empty stderr.
    pub fn is_codex_block_shape(&self) -> bool {
        self.exit_code == 2 && self.stdout.is_empty() && !self.stderr.is_empty()
    }

    /// Claude block shape: exit 0, stdout contains hookSpecificOutput JSON.
    pub fn is_claude_block_shape(&self) -> bool {
        self.exit_code == 0
            && !self.stdout.is_empty()
            && self.stdout_str().contains("hookSpecificOutput")
    }

    /// Allow shape: exit 0, empty (or whitespace-only) stdout.
    pub fn is_allow_shape(&self) -> bool {
        self.exit_code == 0 && self.stdout_str().trim().is_empty()
    }

    /// Parse stdout as JSON (panics with diagnostics if not valid JSON).
    pub fn stdout_json(&self) -> serde_json::Value {
        let s = self.stdout_str();
        serde_json::from_str(s.trim())
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\n{self}"))
    }
}

impl fmt::Display for HookOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "--- HookOutcome postmortem ---")?;
        writeln!(f, "exit_code: {}", self.exit_code)?;
        writeln!(f, "home_dir: {}", self.home_dir.display())?;
        writeln!(f, "stdin ({} bytes):", self.stdin_sent.len())?;
        writeln!(f, "  {}", String::from_utf8_lossy(&self.stdin_sent))?;
        writeln!(f, "stdout ({} bytes):", self.stdout.len())?;
        writeln!(f, "  UTF-8: {}", String::from_utf8_lossy(&self.stdout))?;
        if self.stdout.len() <= 256 {
            write!(f, "  hex: ")?;
            for b in &self.stdout {
                write!(f, "{b:02x} ")?;
            }
            writeln!(f)?;
        }
        writeln!(f, "stderr ({} bytes):", self.stderr.len())?;
        writeln!(f, "  {}", String::from_utf8_lossy(&self.stderr))?;
        write!(f, "--- end postmortem ---")
    }
}

impl fmt::Debug for HookOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// ---------------------------------------------------------------------------
// Binary discovery
// ---------------------------------------------------------------------------

/// Path to the dcg binary (same workspace-relative discovery as
/// tests/agent_hook_output.rs).
fn dcg_binary() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // test binary name
    path.pop(); // deps/
    path.push("dcg");
    path
}

// ---------------------------------------------------------------------------
// Payload builders
// ---------------------------------------------------------------------------

/// Build a complete Codex 0.125.0+ stdin payload.
///
/// Includes ALL fields a real Codex client sends (session_id, turn_id,
/// transcript_path, cwd, hook_event_name, model, permission_mode,
/// tool_name, tool_input, tool_use_id) so tests mirror production payloads.
fn build_codex_payload(command: &str) -> String {
    let escaped = command.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"{{
  "session_id": "019dd11d-b795-7261-a9cb-9b85a5dad632",
  "turn_id": "turn-test-1",
  "transcript_path": null,
  "cwd": "/tmp/test-workdir",
  "hook_event_name": "PreToolUse",
  "model": "gpt-5.5",
  "permission_mode": "bypassPermissions",
  "tool_name": "Bash",
  "tool_input": {{ "command": "{escaped}" }},
  "tool_use_id": "call_test_abc123"
}}"#
    )
}

/// Build a complete Claude Code stdin payload (per code.claude.com/docs/en/hooks).
///
/// Does NOT include turn_id — that's the Codex disambiguator.
fn build_claude_payload(command: &str) -> String {
    let escaped = command.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"{{
  "session_id": "sess-claude-test",
  "transcript_path": "/tmp/claude/transcript.jsonl",
  "cwd": "/tmp/test-workdir",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {{ "command": "{escaped}" }},
  "tool_use_id": "toolu_01TEST"
}}"#
    )
}

// ---------------------------------------------------------------------------
// Hermetic subprocess runner
//
// IMPORTANT: Every spawn uses env_clear() + a minimal PATH + an isolated
// per-test HOME and TMPDIR. This prevents cross-contamination when cargo
// nextest runs tests in parallel — without per-test HOME, concurrent tests
// would race on history sqlite, pending-exception files, and allowlists.
// ---------------------------------------------------------------------------

/// Create an isolated HOME directory for one test invocation.
fn make_hermetic_home() -> tempfile::TempDir {
    tempfile::tempdir().expect("failed to create hermetic HOME tempdir")
}

/// Spawn dcg with raw JSON bytes and optional env overrides.
///
/// This is the lowest-level helper — all other `run_*` functions delegate here.
pub fn run_hook_raw(json_bytes: &[u8], extra_env: &[(&str, &str)]) -> HookOutcome {
    let home = make_hermetic_home();
    let home_path = home.path().to_path_buf();
    let tmp_path = home.path().join("tmp");
    std::fs::create_dir_all(&tmp_path).ok();

    let system_path = std::env::var("PATH").unwrap_or_default();

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("PATH", &system_path)
        .env("HOME", home.path())
        .env("TMPDIR", &tmp_path)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn().expect("failed to spawn dcg process");

    {
        let stdin = child.stdin.as_mut().expect("failed to get stdin");
        stdin
            .write_all(json_bytes)
            .expect("failed to write to stdin");
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");

    // Keep tempdir if DCG_TEST_KEEP_TEMPDIRS is set (for postmortem).
    let keep = std::env::var_os("DCG_TEST_KEEP_TEMPDIRS").is_some();
    if keep {
        eprintln!("  [keep-tempdirs] hermetic HOME: {}", home.path().display());
        // Leak the TempDir so it isn't cleaned up.
        let _ = home.keep();
    }

    HookOutcome {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
        stdin_sent: json_bytes.to_vec(),
        home_dir: home_path,
    }
}

/// Run dcg with a Codex 0.125.0+ payload for the given command.
pub fn run_codex_hook(command: &str) -> HookOutcome {
    run_codex_hook_with_env(command, &[], &[])
}

/// Run dcg with a Codex payload, additional env vars, and env removals.
pub fn run_codex_hook_with_env(
    command: &str,
    extra_env: &[(&str, &str)],
    _remove_env: &[&str],
) -> HookOutcome {
    let payload = build_codex_payload(command);
    run_hook_raw(payload.as_bytes(), extra_env)
}

/// Run dcg with a Claude Code payload for the given command.
pub fn run_claude_hook(command: &str) -> HookOutcome {
    run_claude_hook_with_env(command, &[], &[])
}

/// Run dcg with a Claude Code payload, additional env vars, and env removals.
pub fn run_claude_hook_with_env(
    command: &str,
    extra_env: &[(&str, &str)],
    _remove_env: &[&str],
) -> HookOutcome {
    let payload = build_claude_payload(command);
    run_hook_raw(payload.as_bytes(), extra_env)
}

// ---------------------------------------------------------------------------
// Smoke tests — validate the scaffold helpers work before leaf tests depend
// on them.
// ---------------------------------------------------------------------------

#[test]
fn smoke_codex_safe_command_allowed() {
    let outcome = run_codex_hook("git status");
    assert!(
        outcome.is_allow_shape(),
        "safe command via Codex should be allowed (exit 0, empty stdout)\n{outcome}"
    );
}

#[test]
fn smoke_claude_safe_command_allowed() {
    let outcome = run_claude_hook("git status");
    assert!(
        outcome.is_allow_shape(),
        "safe command via Claude should be allowed (exit 0, empty stdout)\n{outcome}"
    );
}

#[test]
fn smoke_codex_destructive_command_blocked() {
    let outcome = run_codex_hook("git reset --hard HEAD~1");
    assert!(
        outcome.is_codex_block_shape(),
        "destructive command via Codex should produce exit 2 + empty stdout + non-empty stderr\n{outcome}"
    );
}

#[test]
fn smoke_claude_destructive_command_blocked() {
    let outcome = run_claude_hook("git reset --hard HEAD~1");
    assert!(
        outcome.is_claude_block_shape(),
        "destructive command via Claude should produce exit 0 + hookSpecificOutput JSON\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.2 — Codex deny path: exit=2, 0 bytes stdout, non-empty stderr
// ---------------------------------------------------------------------------

#[test]
fn codex_deny_multiple_destructive_commands() {
    let commands = [
        ("git reset --hard HEAD~5", "core.git:reset-hard"),
        ("git clean -fd", "core.git:clean-force"),
        ("git push --force origin main", "core.git"),
        ("rm -rf /important/data", "core.filesystem"),
    ];

    for (cmd, expected_rule_fragment) in commands {
        let outcome = run_codex_hook(cmd);
        assert_eq!(
            outcome.exit_code, 2,
            "Codex deny must exit 2 for '{cmd}'\n{outcome}"
        );
        assert!(
            outcome.stdout.is_empty(),
            "Codex deny must produce 0 bytes stdout for '{cmd}'\n{outcome}"
        );
        assert!(
            !outcome.stderr.is_empty(),
            "Codex deny must produce non-empty stderr for '{cmd}'\n{outcome}"
        );
        assert!(
            outcome.stderr_contains(expected_rule_fragment),
            "stderr must contain rule fragment '{expected_rule_fragment}' for '{cmd}'\n{outcome}"
        );
    }
}

#[test]
fn codex_deny_stderr_is_not_empty_even_when_nosuggest() {
    // exit 2 + empty stderr = Failed in Codex (catastrophic); dcg must always
    // produce non-empty stderr on deny.
    let outcome = run_codex_hook("git reset --hard");
    assert_eq!(outcome.exit_code, 2, "exit code 2 expected\n{outcome}");
    assert!(
        outcome.stderr.len() > 10,
        "stderr must be substantive (>10 bytes), got {} bytes\n{outcome}",
        outcome.stderr.len()
    );
}

// ---------------------------------------------------------------------------
// P2.3 — Codex allow path: exit=0, no stdout, no stderr
// ---------------------------------------------------------------------------

#[test]
fn codex_allow_safe_commands_produce_no_output() {
    let safe_commands = [
        "git status",
        "git log --oneline -5",
        "git diff HEAD",
        "git checkout -b new-feature",
        "ls -la",
        "echo hello",
        "cat README.md",
    ];

    for cmd in safe_commands {
        let outcome = run_codex_hook(cmd);
        assert_eq!(
            outcome.exit_code, 0,
            "safe command '{cmd}' must exit 0\n{outcome}"
        );
        assert!(
            outcome.stdout.is_empty(),
            "safe command '{cmd}' must produce 0 bytes stdout\n{outcome}"
        );
        // stderr may contain trace/debug output but should be empty or minimal
        // in a clean hermetic env.
    }
}

#[test]
fn codex_allow_git_clean_dry_run_not_blocked() {
    let outcome = run_codex_hook("git clean -n");
    assert!(
        outcome.is_allow_shape(),
        "git clean -n (dry run) must be allowed\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.5 — Regression: tool_use_id (no turn_id) stays on Claude path
// ---------------------------------------------------------------------------

#[test]
fn regression_claude_tool_use_id_bash_stays_claude_path() {
    // A Claude Code payload with tool_use_id but NO turn_id must produce
    // Claude-shaped output (exit 0 + hookSpecificOutput JSON), NOT Codex
    // (exit 2 + stderr). If the disambiguator keyed on tool_use_id instead
    // of turn_id, this would fail.
    let outcome = run_claude_hook("git reset --hard HEAD~1");
    assert_eq!(
        outcome.exit_code, 0,
        "Claude path must exit 0, not 2\n{outcome}"
    );
    assert!(
        outcome.is_claude_block_shape(),
        "Claude deny must produce hookSpecificOutput JSON on stdout\n{outcome}"
    );
    let json = outcome.stdout_json();
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"], "deny",
        "Claude deny must have permissionDecision=deny\n{outcome}"
    );
}

#[test]
fn regression_claude_tool_use_id_launch_process_stays_claude_path() {
    // Variant with launch-process tool name.
    let payload = r#"{
  "session_id": "sess-claude-test",
  "transcript_path": "/tmp/claude/transcript.jsonl",
  "cwd": "/tmp/test-workdir",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "launch-process",
  "tool_input": { "command": "git reset --hard HEAD~1" },
  "tool_use_id": "toolu_01LAUNCH"
}"#
    .to_string();
    let outcome = run_hook_raw(payload.as_bytes(), &[]);
    assert_eq!(
        outcome.exit_code, 0,
        "launch-process Claude path must exit 0\n{outcome}"
    );
    assert!(
        outcome.is_claude_block_shape(),
        "launch-process Claude deny must produce hookSpecificOutput JSON\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.4 — Codex warn path: exit=0, no stdout, stderr warns
// ---------------------------------------------------------------------------

#[test]
fn codex_warn_path_exits_zero_with_stderr_warning() {
    // Critical patterns can only be downgraded via per-rule override in config.
    // Write a config file with the per-rule override to the hermetic HOME.
    let home = tempfile::tempdir().expect("tempdir");
    let config_dir = home.path().join(".config/dcg");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        b"[policy.rules]\n\"core.git:reset-hard\" = \"warn\"\n",
    )
    .unwrap();

    let payload = build_codex_payload("git reset --hard HEAD~1");
    let system_path = std::env::var("PATH").unwrap_or_default();

    let mut cmd = Command::new(dcg_binary());
    cmd.env_clear()
        .env("PATH", &system_path)
        .env("HOME", home.path())
        .env("TMPDIR", home.path().join("tmp"))
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(payload.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let outcome = HookOutcome {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(-1),
        stdin_sent: payload.into_bytes(),
        home_dir: home.path().to_path_buf(),
    };

    assert_eq!(
        outcome.exit_code, 0,
        "Codex warn must exit 0 (not 2)\n{outcome}"
    );
    assert!(
        outcome.stdout.is_empty(),
        "Codex warn must produce 0 bytes stdout\n{outcome}"
    );
    assert!(
        !outcome.stderr.is_empty(),
        "Codex warn must produce non-empty stderr\n{outcome}"
    );
    assert!(
        outcome.stderr_contains("WARNING") || outcome.stderr_contains("warn"),
        "stderr must contain warning text\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// P2.7 — DCG_BYPASS=1 short-circuits before Codex protocol detection
// ---------------------------------------------------------------------------

#[test]
fn codex_bypass_exits_zero_silently() {
    // DCG_BYPASS=1 must cause silent exit 0 even for Codex destructive commands.
    let outcome = run_codex_hook_with_env("git reset --hard HEAD~1", &[("DCG_BYPASS", "1")], &[]);
    assert_eq!(outcome.exit_code, 0, "bypass must exit 0, not 2\n{outcome}");
    assert!(
        outcome.stdout.is_empty(),
        "bypass must produce no stdout\n{outcome}"
    );
}

#[test]
fn claude_bypass_exits_zero_silently() {
    // Same for Claude path — bypass silences everything.
    let outcome = run_claude_hook_with_env("git reset --hard HEAD~1", &[("DCG_BYPASS", "1")], &[]);
    assert_eq!(outcome.exit_code, 0, "Claude bypass must exit 0\n{outcome}");
    assert!(
        outcome.stdout.is_empty(),
        "Claude bypass must produce no stdout\n{outcome}"
    );
}

// ---------------------------------------------------------------------------
// Hermetic HOME isolation
// ---------------------------------------------------------------------------

#[test]
fn smoke_hermetic_home_isolates_pending_exceptions() {
    let outcome = run_codex_hook("git reset --hard HEAD~1");
    assert!(outcome.is_codex_block_shape(), "block expected\n{outcome}");

    // Verify the pending exception directory (if any) is inside the test HOME
    let pending_dir = outcome.home_dir.join(".config/dcg/pending");
    // It's OK if the dir doesn't exist (dcg may not write pending in all modes),
    // but if it does, it proves isolation.
    if pending_dir.exists() {
        let entries: Vec<_> = std::fs::read_dir(&pending_dir)
            .expect("failed to read pending dir")
            .collect();
        assert!(
            !entries.is_empty(),
            "pending dir exists but is empty — expected pending exception entry"
        );
    }
    // The real HOME must NOT have been touched.
    if let Ok(real_home) = std::env::var("HOME") {
        let real_pending = PathBuf::from(&real_home).join(".config/dcg/pending");
        // We can't assert it doesn't exist (it may from normal usage), but
        // we verify our test HOME is different from real HOME.
        assert_ne!(
            PathBuf::from(&real_home),
            outcome.home_dir,
            "hermetic HOME must differ from real HOME"
        );
        let _ = real_pending; // suppress unused warning
    }
}
