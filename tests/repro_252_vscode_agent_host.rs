//! Regression tests for issue #252: the VS Code "Agent Host" batched
//! `toolCalls` envelope.
//!
//! The newer Copilot Agent Host (and the Agents window built on it) sends
//! `{"sessionId": "...", "cwd": "...", "toolCalls": [{"name": "powershell",
//! "args": "{\"command\":\"...\"}"}]}` — an *array* under plural `toolCalls`,
//! with each entry's `args` JSON-encoded as a string. Before the fix the
//! envelope deserialized without any recognized command and the hook silently
//! failed open.

use destructive_command_guard::hook::{
    HookInput, HookProtocol, detect_protocol, extract_command_with_context,
};
use destructive_command_guard::normalize::ShellDialect;

fn parse(json: &str) -> HookInput {
    serde_json::from_str(json).expect("hook input must deserialize")
}

/// The documented envelope from issue #252, verbatim: stringified `args`
/// carrying a destructive PowerShell command.
const DOCUMENTED_ENVELOPE: &str = r#"{"sessionId":"s","cwd":"C:\\ws","toolCalls":[{"name":"powershell","args":"{\"command\":\"Remove-Item -Recurse -Force C:\\\\src\"}"}]}"#;

#[test]
fn documented_envelope_detects_claude_compatible() {
    let input = parse(DOCUMENTED_ENVELOPE);
    assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
}

#[test]
fn documented_envelope_extracts_inner_command_and_dialect() {
    let input = parse(DOCUMENTED_ENVELOPE);
    let extracted =
        extract_command_with_context(&input).expect("batched shell call must extract a command");
    assert_eq!(extracted.command, r"Remove-Item -Recurse -Force C:\src");
    assert_eq!(extracted.protocol, HookProtocol::ClaudeCompatible);
    assert_eq!(extracted.dialect, ShellDialect::PowerShell);
}

#[test]
fn stringified_and_object_args_both_extract() {
    let stringified = parse(
        r#"{"sessionId":"s","toolCalls":[{"name":"bash","args":"{\"command\":\"echo hi\"}"}]}"#,
    );
    let object =
        parse(r#"{"sessionId":"s","toolCalls":[{"name":"bash","args":{"command":"echo hi"}}]}"#);

    for input in [stringified, object] {
        let extracted = extract_command_with_context(&input)
            .expect("both args encodings must extract the command");
        assert_eq!(extracted.command, "echo hi");
        assert_eq!(extracted.dialect, ShellDialect::Posix);
    }
}

#[test]
fn batch_extracts_every_shell_call_joined_by_newline() {
    // A non-shell tool call in the batch is skipped; both bash calls are
    // evaluated (a single destructive entry must deny the whole batch, so
    // both commands must be visible to the evaluator).
    let input = parse(
        r#"{"sessionId":"s","cwd":"/w","toolCalls":[
            {"name":"readFile","args":{"path":"/w/a.txt"}},
            {"name":"bash","args":"{\"command\":\"echo one\"}"},
            {"name":"bash","args":{"command":"echo two"}}
        ]}"#,
    );
    let extracted =
        extract_command_with_context(&input).expect("batched bash calls must extract commands");
    assert_eq!(extracted.command, "echo one\necho two");
    assert_eq!(extracted.dialect, ShellDialect::Posix);
    assert_eq!(extracted.protocol, HookProtocol::ClaudeCompatible);
}

#[test]
fn mixed_shell_batch_falls_back_to_unknown_dialect() {
    let input = parse(
        r#"{"sessionId":"s","toolCalls":[
            {"name":"bash","args":{"command":"echo posix"}},
            {"name":"powershell","args":{"command":"Write-Output ps"}}
        ]}"#,
    );
    let extracted =
        extract_command_with_context(&input).expect("mixed batch must still extract commands");
    assert_eq!(extracted.command, "echo posix\nWrite-Output ps");
    assert_eq!(
        extracted.dialect,
        ShellDialect::Unknown,
        "mixed shells must keep the conservative all-dialect view"
    );
}

#[test]
fn empty_tool_calls_array_extracts_nothing_and_detection_falls_through() {
    // An empty batch alone: nothing to extract.
    let bare = parse(r#"{"sessionId":"s","toolCalls":[]}"#);
    assert_eq!(extract_command_with_context(&bare), None);

    // Detection must fall through to the pre-#252 logic: with Gemini's
    // markers alongside an empty `toolCalls`, the Gemini classification wins.
    let gemini_shaped = parse(
        r#"{"toolCalls":[],"session_id":"g","cwd":"/w","hook_event_name":"BeforeTool",
            "tool_name":"run_shell_command","tool_input":{"command":"echo hi"}}"#,
    );
    assert_eq!(detect_protocol(&gemini_shaped), HookProtocol::Gemini);
    let extracted = extract_command_with_context(&gemini_shaped)
        .expect("the old tool_input path must still extract");
    assert_eq!(extracted.command, "echo hi");
    assert_eq!(extracted.protocol, HookProtocol::Gemini);
}

#[test]
fn batch_without_shell_calls_extracts_nothing() {
    let input = parse(
        r#"{"sessionId":"s","toolCalls":[
            {"name":"readFile","args":{"path":"/w/a.txt"}},
            {"name":"editFile","args":"{\"path\":\"/w/b.txt\"}"}
        ]}"#,
    );
    // The plural-toolCalls envelope still identifies the Agent Host…
    assert_eq!(detect_protocol(&input), HookProtocol::ClaudeCompatible);
    // …but a batch with no shell tool is not a shell hook candidate.
    assert_eq!(extract_command_with_context(&input), None);
}

#[test]
fn singular_tool_call_envelope_still_detects_antigravity() {
    // The Antigravity CLI (`agy`) envelope uses singular `toolCall`; the new
    // plural `toolCalls` handling must not shadow it.
    let input = parse(
        r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"git status","Cwd":"/w",
            "WaitMsBeforeAsync":500}},"conversationId":"c0","stepIdx":4}"#,
    );
    assert_eq!(detect_protocol(&input), HookProtocol::Antigravity);
    let extracted = extract_command_with_context(&input).expect("agy envelope must still extract");
    assert_eq!(extracted.command, "git status");
    assert_eq!(extracted.protocol, HookProtocol::Antigravity);
}

// ---------------------------------------------------------------------------
// Binary-level coverage: the real dcg hook denies a destructive batch
// ---------------------------------------------------------------------------

/// Path to the dcg binary (same workspace-relative discovery as
/// tests/codex_hook_protocol.rs).
fn dcg_binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // test binary name
    path.pop(); // deps/
    path.push(format!("dcg{}", std::env::consts::EXE_SUFFIX));
    path
}

#[test]
fn destructive_bash_batch_is_denied_on_stdout_with_exit_zero() {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let payload = r#"{"sessionId":"s","cwd":"/w","toolCalls":[
        {"name":"bash","args":"{\"command\":\"git status\"}"},
        {"name":"bash","args":"{\"command\":\"rm -rf /\"}"}
    ]}"#;

    // Hermetic spawn: isolated HOME/TMPDIR so parallel tests never share
    // history or pending-exception state (mirrors codex_hook_protocol.rs).
    let home = tempfile::tempdir().expect("failed to create hermetic HOME");
    let tmp = home.path().join("tmp");
    std::fs::create_dir_all(&tmp).expect("failed to create hermetic TMPDIR");
    let system_path = std::env::var("PATH").unwrap_or_default();

    let mut child = Command::new(dcg_binary())
        .env_clear()
        .env("PATH", &system_path)
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("TMPDIR", &tmp)
        .env("TEMP", &tmp)
        .env("TMP", &tmp)
        .env("NO_COLOR", "1")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_HEREDOC_TIMEOUT_MS", "5000")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn dcg");

    child
        .stdin
        .as_mut()
        .expect("stdin must be piped")
        .write_all(payload.as_bytes())
        .expect("failed to write hook payload");
    let output = child.wait_with_output().expect("failed to wait for dcg");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "Agent Host consumes Claude-shaped output; deny must use exit 0.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("\"permissionDecision\""),
        "deny must be a Claude-compatible stdout JSON payload.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("\"deny\""),
        "the destructive batch entry must deny the whole batch.\nstdout: {stdout}\nstderr: {stderr}"
    );
}
