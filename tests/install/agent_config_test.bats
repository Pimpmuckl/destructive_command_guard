#!/usr/bin/env bats
# Unit tests for agent configuration functions in install.sh
#
# Tests:
# - Claude Code configuration (configure_claude_code)
# - Gemini CLI configuration (configure_gemini)
# - Configuration idempotency
# - Existing settings preservation

load test_helper

setup() {
    setup_isolated_home
    setup_test_log "$BATS_TEST_NAME"
    extract_install_functions
    extract_uninstall_functions

    # Set default DEST for configuration
    DEST="$TEST_TMPDIR/bin"
    mkdir -p "$DEST"

    # Create mock dcg binary for path references
    cat > "$DEST/dcg" << 'MOCKEOF'
#!/bin/bash
echo "dcg 1.0.0"
MOCKEOF
    chmod +x "$DEST/dcg"
}

teardown() {
    log_test "=== Test completed: $BATS_TEST_NAME (status: $status) ==="
    teardown_isolated_home
}

# ============================================================================
# Claude Code Configuration Tests
# ============================================================================

@test "configure_claude_code: creates settings.json when directory missing" {
    log_test "Testing Claude Code configuration with missing directory..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"

    # Directory doesn't exist yet
    [ ! -d "$HOME/.claude" ]

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "Settings file exists: $([ -f "$CLAUDE_SETTINGS" ] && echo yes || echo no)"
    log_test "Settings content: $(cat "$CLAUDE_SETTINGS" 2>/dev/null || echo 'N/A')"

    [ -f "$CLAUDE_SETTINGS" ]
    grep -q "dcg" "$CLAUDE_SETTINGS"
}

@test "configure_claude_code: creates settings.json with correct hook structure" {
    log_test "Testing Claude Code hook structure..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "Settings content: $(cat "$CLAUDE_SETTINGS")"

    # Check for required structure
    grep -q "PreToolUse" "$CLAUDE_SETTINGS"
    grep -q "Bash" "$CLAUDE_SETTINGS"
    grep -q "dcg" "$CLAUDE_SETTINGS"
}

@test "configure_claude_code: preserves existing settings" {
    log_test "Testing Claude Code existing settings preservation..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    # Create existing settings with other content
    cat > "$CLAUDE_SETTINGS" << 'EOF'
{
  "theme": "dark",
  "fontSize": 14,
  "someOtherSetting": true
}
EOF

    log_test "Initial settings: $(cat "$CLAUDE_SETTINGS")"

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "Final settings: $(cat "$CLAUDE_SETTINGS")"

    # Should have dcg hook
    grep -q "dcg" "$CLAUDE_SETTINGS"

    # Should preserve existing settings (python3 merge should keep them)
    # Note: This depends on python3 being available for merge
    if command -v python3 &>/dev/null; then
        grep -q "theme" "$CLAUDE_SETTINGS"
        grep -q "dark" "$CLAUDE_SETTINGS"
    fi
}

@test "configure_claude_code: is idempotent" {
    log_test "Testing Claude Code config idempotency..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    # Create settings with dcg hook already present
    cat > "$CLAUDE_SETTINGS" << EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "$DEST/dcg"}
        ]
      }
    ]
  }
}
EOF

    local before
    before=$(cat "$CLAUDE_SETTINGS")
    log_test "Before: $before"

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    local after
    after=$(cat "$CLAUDE_SETTINGS")
    log_test "After: $after"

    # CLAUDE_STATUS should be "already"
    [ "$CLAUDE_STATUS" = "already" ]
}

@test "configure_claude_code: does not duplicate hooks" {
    log_test "Testing Claude Code no duplicate hooks..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"
    echo '{}' > "$CLAUDE_SETTINGS"

    # Configure twice
    configure_claude_code "$CLAUDE_SETTINGS" "0"
    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "Final settings: $(cat "$CLAUDE_SETTINGS")"

    # Count dcg occurrences in command fields
    local dcg_count
    dcg_count=$(grep -o '"command".*dcg' "$CLAUDE_SETTINGS" | wc -l)
    log_test "dcg command count: $dcg_count"

    # Second call should detect already configured
    [ "$dcg_count" -le 1 ]
}

@test "configure_claude_code: does not treat dcg substring commands as installed" {
    log_test "Testing Claude Code exact dcg command detection..."

    command -v python3 &>/dev/null || skip "python3 not available"

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    cat > "$CLAUDE_SETTINGS" << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/opt/dcgrep/bin/scan"}
        ]
      }
    ]
  }
}
EOF

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS"
    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    [ "$CLAUDE_STATUS" = "merged" ]
    python3 - "$CLAUDE_SETTINGS" "$DEST/dcg" <<'PY'
import json
import sys

settings_file, dcg_path = sys.argv[1:3]
with open(settings_file, "r") as f:
    settings = json.load(f)

commands = []
for entry in settings["hooks"]["PreToolUse"]:
    if entry.get("matcher") == "Bash":
        for hook in entry.get("hooks", []):
            commands.append(hook.get("command"))

assert dcg_path in commands, commands
assert "/opt/dcgrep/bin/scan" in commands, commands
assert commands.count(dcg_path) == 1, commands
PY
}

@test "configure_claude_code: no-python fallback ignores dcg substrings" {
    log_test "Testing Claude Code no-python fallback exact detection..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    cat > "$CLAUDE_SETTINGS" << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/opt/dcgrep/bin/scan"}
        ]
      }
    ]
  }
}
EOF

    local no_python_path="$TEST_TMPDIR/no-python-bin"
    mkdir -p "$no_python_path"
    local tool
    for tool in dirname mkdir cp date grep sed rm mv cat; do
        ln -s "$(command -v "$tool")" "$no_python_path/$tool"
    done

    local old_path="$PATH"
    PATH="$no_python_path"
    configure_claude_code "$CLAUDE_SETTINGS" "0"
    local rc=$?
    PATH="$old_path"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS rc=$rc"
    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    [ "$rc" -eq 1 ]
    [ "$CLAUDE_STATUS" = "failed" ]
    grep -qF '/opt/dcgrep/bin/scan' "$CLAUDE_SETTINGS"
    ! grep -qF "$DEST/dcg" "$CLAUDE_SETTINGS"
}

@test "configure_claude_code: no-python fallback recognizes exact dcg hook" {
    log_test "Testing Claude Code no-python fallback exact already-configured state..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    cat > "$CLAUDE_SETTINGS" << EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "$DEST/dcg"}
        ]
      }
    ]
  }
}
EOF

    local no_python_path="$TEST_TMPDIR/no-python-bin"
    mkdir -p "$no_python_path"
    local tool
    for tool in dirname mkdir cp date grep sed rm mv cat; do
        ln -s "$(command -v "$tool")" "$no_python_path/$tool"
    done

    local old_path="$PATH"
    PATH="$no_python_path"
    configure_claude_code "$CLAUDE_SETTINGS" "0"
    local rc=$?
    PATH="$old_path"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS rc=$rc"

    [ "$rc" -eq 0 ]
    [ "$CLAUDE_STATUS" = "already" ]
}

@test "configure_claude_code: no-python fallback recognizes minified dcg hook" {
    log_test "Testing Claude Code no-python fallback with minified JSON..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"
    printf '{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"%s"}]}]}}\n' "$DEST/dcg" > "$CLAUDE_SETTINGS"

    local no_python_path="$TEST_TMPDIR/no-python-bin"
    mkdir -p "$no_python_path"
    local tool
    for tool in dirname mkdir cp date grep sed rm mv cat; do
        ln -s "$(command -v "$tool")" "$no_python_path/$tool"
    done

    local old_path="$PATH"
    PATH="$no_python_path"
    configure_claude_code "$CLAUDE_SETTINGS" "0"
    local rc=$?
    PATH="$old_path"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS rc=$rc"

    [ "$rc" -eq 0 ]
    [ "$CLAUDE_STATUS" = "already" ]
}

# ============================================================================
# Gemini CLI Configuration Tests
# ============================================================================

@test "configure_gemini: skips when not installed" {
    log_test "Testing Gemini CLI skips when not installed..."

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"

    # Gemini not installed (no directory, no command)
    configure_gemini "$GEMINI_SETTINGS"

    log_test "GEMINI_STATUS: $GEMINI_STATUS"

    [ "$GEMINI_STATUS" = "skipped" ]
}

@test "configure_gemini: creates settings.json when directory exists" {
    log_test "Testing Gemini CLI configuration..."

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"
    setup_mock_gemini
    rm -f "$GEMINI_SETTINGS"  # Remove the mock settings

    configure_gemini "$GEMINI_SETTINGS"

    log_test "Settings file exists: $([ -f "$GEMINI_SETTINGS" ] && echo yes || echo no)"
    log_test "Settings content: $(cat "$GEMINI_SETTINGS" 2>/dev/null || echo 'N/A')"

    [ -f "$GEMINI_SETTINGS" ]
    grep -q "dcg" "$GEMINI_SETTINGS"
}

@test "configure_gemini: uses BeforeTool hook type" {
    log_test "Testing Gemini CLI uses BeforeTool..."

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"
    setup_mock_gemini
    rm -f "$GEMINI_SETTINGS"

    configure_gemini "$GEMINI_SETTINGS"

    log_test "Settings content: $(cat "$GEMINI_SETTINGS")"

    # Gemini uses BeforeTool instead of PreToolUse
    grep -q "BeforeTool" "$GEMINI_SETTINGS"
    grep -q "run_shell_command" "$GEMINI_SETTINGS"
}

@test "configure_gemini: is idempotent" {
    log_test "Testing Gemini CLI config idempotency..."

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"
    setup_mock_gemini

    # Create settings with dcg hook already present
    cat > "$GEMINI_SETTINGS" << EOF
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {"name": "dcg", "type": "command", "command": "$DEST/dcg", "timeout": 5000}
        ]
      }
    ]
  }
}
EOF

    configure_gemini "$GEMINI_SETTINGS"

    log_test "GEMINI_STATUS: $GEMINI_STATUS"

    [ "$GEMINI_STATUS" = "already" ]
}

@test "configure_gemini: does not treat dcg substring commands as installed" {
    log_test "Testing Gemini exact dcg command detection..."
    command -v python3 &>/dev/null || skip "python3 not available"

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"
    setup_mock_gemini

    cat > "$GEMINI_SETTINGS" <<'EOF'
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {"name": "not-dcg", "type": "command", "command": "/opt/not-dcg-wrapper/bin/hook", "timeout": 5000}
        ]
      }
    ]
  }
}
EOF

    configure_gemini "$GEMINI_SETTINGS"

    log_test "GEMINI_STATUS: $GEMINI_STATUS"
    log_test "Settings content: $(cat "$GEMINI_SETTINGS")"

    [ "$GEMINI_STATUS" = "merged" ]
    grep -q "\"command\": \"$DEST/dcg\"" "$GEMINI_SETTINGS"
    grep -q "/opt/not-dcg-wrapper/bin/hook" "$GEMINI_SETTINGS"
}

@test "configure_gemini: invalid settings.json is preserved and reports failed" {
    log_test "Testing Gemini invalid settings.json preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    GEMINI_SETTINGS="$HOME/.gemini/settings.json"
    setup_mock_gemini
    printf '%s\n' '{"hooks":{"BeforeTool":[' > "$GEMINI_SETTINGS"
    local before
    before=$(cat "$GEMINI_SETTINGS")

    configure_gemini "$GEMINI_SETTINGS"
    local rc=$?

    log_test "GEMINI_STATUS: $GEMINI_STATUS"
    log_test "GEMINI_FAILURE_REASON: ${GEMINI_FAILURE_REASON:-}"
    log_test "Settings content: $(cat "$GEMINI_SETTINGS")"

    [ "$rc" -eq 0 ]
    [ "$GEMINI_STATUS" = "failed" ]
    [[ "$GEMINI_FAILURE_REASON" == *"invalid"* ]]
    [ "$(cat "$GEMINI_SETTINGS")" = "$before" ]
    [ -z "$GEMINI_BACKUP" ]
}

# ============================================================================
# Predecessor Migration Tests
# ============================================================================

@test "configure_claude_code: removes predecessor hook when requested" {
    log_test "Testing predecessor removal..."

    # Skip if python3 not available (needed for JSON manipulation)
    command -v python3 &>/dev/null || skip "python3 not available"

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    # Create settings with predecessor hook
    cat > "$CLAUDE_SETTINGS" << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/path/to/git_safety_guard.py"}
        ]
      }
    ]
  }
}
EOF

    log_test "Before: $(cat "$CLAUDE_SETTINGS")"

    # Configure with cleanup_predecessor=1
    configure_claude_code "$CLAUDE_SETTINGS" "1"

    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    # Should have dcg
    grep -q "dcg" "$CLAUDE_SETTINGS"

    # Should NOT have git_safety_guard
    ! grep -q "git_safety_guard" "$CLAUDE_SETTINGS"
}

@test "configure_claude_code: keeps predecessor when not requested" {
    log_test "Testing predecessor preservation..."

    # Skip if python3 not available
    command -v python3 &>/dev/null || skip "python3 not available"

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    # Create settings with predecessor hook
    cat > "$CLAUDE_SETTINGS" << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/path/to/git_safety_guard.py"}
        ]
      }
    ]
  }
}
EOF

    log_test "Before: $(cat "$CLAUDE_SETTINGS")"

    # Configure with cleanup_predecessor=0
    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    # Should have dcg
    grep -q "dcg" "$CLAUDE_SETTINGS"

    # Should still have git_safety_guard
    grep -q "git_safety_guard" "$CLAUDE_SETTINGS"
}

# ============================================================================
# Edge Cases
# ============================================================================

@test "configure_claude_code: handles malformed JSON gracefully" {
    log_test "Testing malformed JSON handling..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    # Create malformed JSON
    echo "not valid json {{{" > "$CLAUDE_SETTINGS"

    log_test "Malformed content: $(cat "$CLAUDE_SETTINGS")"

    # This might fail or succeed depending on implementation
    # The key is it shouldn't crash
    configure_claude_code "$CLAUDE_SETTINGS" "0" || true

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS"
    log_test "After: $(cat "$CLAUDE_SETTINGS" 2>/dev/null || echo 'N/A')"

    # Either status should be set
    [ -n "$CLAUDE_STATUS" ]
}

@test "configure_claude_code: handles empty settings file" {
    log_test "Testing empty settings file..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    # Create empty file
    touch "$CLAUDE_SETTINGS"

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS"
    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    # Should have added dcg hook
    grep -q "dcg" "$CLAUDE_SETTINGS"
}

@test "configure_claude_code: handles settings with empty hooks array" {
    log_test "Testing empty hooks array..."

    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    cat > "$CLAUDE_SETTINGS" << 'EOF'
{
  "hooks": {}
}
EOF

    configure_claude_code "$CLAUDE_SETTINGS" "0"

    log_test "CLAUDE_STATUS: $CLAUDE_STATUS"
    log_test "After: $(cat "$CLAUDE_SETTINGS")"

    # Should have added dcg hook
    grep -q "dcg" "$CLAUDE_SETTINGS"
}

# ============================================================================
# Aider Configuration Tests
# ============================================================================

@test "configure_aider: skips when not installed" {
    log_test "Testing Aider skips when not installed..."

    AIDER_SETTINGS="$HOME/.aider.conf.yml"

    # Aider not installed (no command in our isolated PATH)
    configure_aider "$AIDER_SETTINGS"

    log_test "AIDER_STATUS: $AIDER_STATUS"

    [ "$AIDER_STATUS" = "skipped" ]
}

@test "configure_aider: creates config file when installed" {
    log_test "Testing Aider configuration creation..."

    setup_mock_aider
    AIDER_SETTINGS="$HOME/.aider.conf.yml"

    # No existing config
    [ ! -f "$AIDER_SETTINGS" ]

    configure_aider "$AIDER_SETTINGS"

    log_test "AIDER_STATUS: $AIDER_STATUS"
    log_test "Config content: $(cat "$AIDER_SETTINGS" 2>/dev/null || echo 'N/A')"

    [ -f "$AIDER_SETTINGS" ]
    [ "$AIDER_STATUS" = "created" ]
    grep -q "git-commit-verify: true" "$AIDER_SETTINGS"
}

@test "configure_aider: sets git-commit-verify to true" {
    log_test "Testing Aider git-commit-verify setting..."

    setup_mock_aider
    AIDER_SETTINGS="$HOME/.aider.conf.yml"

    configure_aider "$AIDER_SETTINGS"

    log_test "Config content: $(cat "$AIDER_SETTINGS")"

    # Must have git-commit-verify: true
    grep -qE "git-commit-verify:\s*true" "$AIDER_SETTINGS"
}

@test "configure_aider: updates false to true" {
    log_test "Testing Aider updates git-commit-verify from false to true..."

    setup_mock_aider
    AIDER_SETTINGS="$HOME/.aider.conf.yml"

    # Create config with git-commit-verify: false
    cat > "$AIDER_SETTINGS" << 'EOF'
# Aider config
model: gpt-4
git-commit-verify: false
auto-commits: true
EOF

    log_test "Before: $(cat "$AIDER_SETTINGS")"

    configure_aider "$AIDER_SETTINGS"

    log_test "AIDER_STATUS: $AIDER_STATUS"
    log_test "After: $(cat "$AIDER_SETTINGS")"

    # Should now be true
    grep -qE "git-commit-verify:\s*true" "$AIDER_SETTINGS"
    [ "$AIDER_STATUS" = "merged" ]
}

@test "configure_aider: appends setting to existing config" {
    log_test "Testing Aider appends to existing config..."

    setup_mock_aider
    AIDER_SETTINGS="$HOME/.aider.conf.yml"

    # Create config without git-commit-verify
    cat > "$AIDER_SETTINGS" << 'EOF'
# Aider config
model: gpt-4
auto-commits: true
EOF

    log_test "Before: $(cat "$AIDER_SETTINGS")"

    configure_aider "$AIDER_SETTINGS"

    log_test "AIDER_STATUS: $AIDER_STATUS"
    log_test "After: $(cat "$AIDER_SETTINGS")"

    # Should have the setting added
    grep -qE "git-commit-verify:\s*true" "$AIDER_SETTINGS"
    # Should preserve existing settings
    grep -q "model: gpt-4" "$AIDER_SETTINGS"
    [ "$AIDER_STATUS" = "merged" ]
}

@test "configure_aider: is idempotent" {
    log_test "Testing Aider config idempotency..."

    setup_mock_aider
    AIDER_SETTINGS="$HOME/.aider.conf.yml"

    # Create config with git-commit-verify already true
    cat > "$AIDER_SETTINGS" << 'EOF'
# Aider config
git-commit-verify: true
model: gpt-4
EOF

    configure_aider "$AIDER_SETTINGS"

    log_test "AIDER_STATUS: $AIDER_STATUS"

    [ "$AIDER_STATUS" = "already" ]
}

@test "configure_aider: creates backup when modifying" {
    log_test "Testing Aider creates backup..."

    setup_mock_aider
    AIDER_SETTINGS="$HOME/.aider.conf.yml"

    # Create config with git-commit-verify: false
    cat > "$AIDER_SETTINGS" << 'EOF'
model: gpt-4
git-commit-verify: false
EOF

    configure_aider "$AIDER_SETTINGS"

    log_test "AIDER_BACKUP: $AIDER_BACKUP"

    # Should have created backup
    [ -n "$AIDER_BACKUP" ]
    [ -f "$AIDER_BACKUP" ]
}

# ============================================================================
# Continue Configuration Tests
# ============================================================================

@test "configure_continue: skips when not installed" {
    log_test "Testing Continue skips when not installed..."

    # Continue not installed (no directory, no command)
    configure_continue

    log_test "CONTINUE_STATUS: $CONTINUE_STATUS"

    [ "$CONTINUE_STATUS" = "skipped" ]
}

@test "configure_continue: detects via ~/.continue directory" {
    log_test "Testing Continue detection via directory..."

    setup_mock_continue

    configure_continue

    log_test "CONTINUE_STATUS: $CONTINUE_STATUS"

    # Should be unsupported (detected but no hooks available)
    [ "$CONTINUE_STATUS" = "unsupported" ]
}

@test "configure_continue: detects via cn command" {
    log_test "Testing Continue detection via cn command..."

    # Create mock cn binary
    mkdir -p "$TEST_TMPDIR/bin"
    cat > "$TEST_TMPDIR/bin/cn" << 'EOF'
#!/bin/bash
echo "Continue CLI v1.0.0"
EOF
    chmod +x "$TEST_TMPDIR/bin/cn"
    export PATH="$TEST_TMPDIR/bin:$PATH"

    configure_continue

    log_test "CONTINUE_STATUS: $CONTINUE_STATUS"

    # Should be unsupported (detected but no hooks available)
    [ "$CONTINUE_STATUS" = "unsupported" ]
}

@test "configure_continue: reports unsupported (no shell command hooks)" {
    log_test "Testing Continue reports unsupported status..."

    setup_mock_continue

    configure_continue

    log_test "CONTINUE_STATUS: $CONTINUE_STATUS"

    # Continue does not have shell command hooks like Claude Code or Gemini
    # Status should be "unsupported" to indicate detection but no auto-config
    [ "$CONTINUE_STATUS" = "unsupported" ]
}

# ============================================================================
# Codex CLI Detection Tests
# ============================================================================

assert_codex_hooks_has_current_dcg() {
    [ -f "$CODEX_SETTINGS" ]
    grep -q '"PreToolUse"' "$CODEX_SETTINGS"
    grep -q '"matcher": "Bash"' "$CODEX_SETTINGS"
    grep -q "\"command\": \"$DEST/dcg\"" "$CODEX_SETTINGS"
}

assert_codex_first_bash_hook_command() {
    command -v python3 &>/dev/null || skip "python3 not available"

    python3 - "$CODEX_SETTINGS" "$1" <<'PYEOF'
import json
import sys

hooks_file = sys.argv[1]
expected = sys.argv[2]

with open(hooks_file, "r") as f:
    config = json.load(f)

for entry in config["hooks"]["PreToolUse"]:
    if entry.get("matcher") == "Bash":
        actual = entry["hooks"][0]["command"]
        if actual != expected:
            raise SystemExit(f"first Bash hook was {actual!r}, expected {expected!r}")
        raise SystemExit(0)

raise SystemExit("no Bash PreToolUse matcher found")
PYEOF
}

assert_codex_dcg_hook_count() {
    command -v python3 &>/dev/null || skip "python3 not available"

    python3 - "$CODEX_SETTINGS" "$1" <<'PYEOF'
import json
import os
import shlex
import sys

hooks_file = sys.argv[1]
expected = int(sys.argv[2])

with open(hooks_file, "r") as f:
    config = json.load(f)

count = 0
for entry in config.get("hooks", {}).get("PreToolUse", []):
    if not isinstance(entry, dict):
        continue
    for hook in entry.get("hooks", []):
        if not isinstance(hook, dict):
            continue
        command = hook.get("command")
        if not isinstance(command, str):
            continue
        try:
            parts = shlex.split(command)
        except ValueError:
            continue
        if parts:
            name = os.path.basename(parts[0])
            if name.endswith(".exe"):
                name = name[:-4]
            if name == "dcg":
                count += 1

if count != expected:
    raise SystemExit(f"dcg hook count was {count}, expected {expected}")
PYEOF
}

create_no_python_path() {
    local no_python_path="$TEST_TMPDIR/no-python-path"
    mkdir -p "$no_python_path"

    local tool
    for tool in dirname cp mv rm mkdir date grep; do
        ln -s "$(command -v "$tool")" "$no_python_path/$tool"
    done

    echo "$no_python_path"
}

log_codex_hooks_transition() {
    log_test "Codex hooks after: $(cat "$CODEX_SETTINGS" 2>/dev/null || echo 'missing')"
}

codex_post_tool_use_json() {
    command -v python3 &>/dev/null || skip "python3 not available"

    python3 - "$CODEX_SETTINGS" <<'PYEOF'
import json
import sys

with open(sys.argv[1], "r") as f:
    config = json.load(f)

post_tool_use = config.get("hooks", {}).get("PostToolUse")
print(json.dumps(post_tool_use, sort_keys=True, separators=(",", ":")))
PYEOF
}

@test "configure_codex: skips when not installed" {
    log_test "Testing Codex detection when not installed..."

    # Make sure .codex doesn't exist
    rm -rf "$HOME/.codex"

    configure_codex

    log_test "CODEX_STATUS: $CODEX_STATUS"

    # Should be skipped when not installed
    [ "$CODEX_STATUS" = "skipped" ]
}

@test "configure_codex: detects via .codex directory" {
    log_test "Testing Codex detection via .codex directory..."

    setup_mock_codex

    configure_codex

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "hooks.json: $(cat "$CODEX_SETTINGS" 2>/dev/null || echo 'missing')"

    [ "$CODEX_STATUS" = "created" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"
}

@test "configure_codex: detects via codex command" {
    log_test "Testing Codex detection via codex command..."

    # Create mock codex binary
    mkdir -p "$TEST_TMPDIR/bin"
    cat > "$TEST_TMPDIR/bin/codex" << 'EOF'
#!/bin/bash
echo "Codex CLI v1.0.0"
EOF
    chmod +x "$TEST_TMPDIR/bin/codex"
    export PATH="$TEST_TMPDIR/bin:$PATH"

    configure_codex

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "hooks.json: $(cat "$CODEX_SETTINGS" 2>/dev/null || echo 'missing')"

    [ "$CODEX_STATUS" = "created" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"
}

@test "configure_codex: is idempotent when current hook already exists" {
    log_test "Testing Codex idempotent already status..."

    setup_mock_codex

    configure_codex

    log_test "First CODEX_STATUS: $CODEX_STATUS"
    log_test "First hooks.json: $(cat "$CODEX_SETTINGS" 2>/dev/null || echo 'missing')"

    [ "$CODEX_STATUS" = "created" ]

    configure_codex

    log_test "Second CODEX_STATUS: $CODEX_STATUS"
    log_test "Second hooks.json: $(cat "$CODEX_SETTINGS" 2>/dev/null || echo 'missing')"

    [ "$CODEX_STATUS" = "already" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_dcg_hook_count 1
}

@test "configure_codex: merges existing hooks and keeps dcg first" {
    log_test "Testing Codex merge with existing hooks..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    cat > "$CODEX_SETTINGS" <<'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "atuin history start"}
        ]
      },
      {
        "matcher": "Read",
        "hooks": [
          {"type": "command", "command": "echo read-hook"}
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "echo post-hook"}
        ]
      }
    ]
  },
  "theme": "dark"
}
EOF

    log_test "Before hooks.json: $(cat "$CODEX_SETTINGS")"

    configure_codex

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "After hooks.json: $(cat "$CODEX_SETTINGS")"

    [ "$CODEX_STATUS" = "merged" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"
    grep -q "atuin history start" "$CODEX_SETTINGS"
    grep -q "echo read-hook" "$CODEX_SETTINGS"
    grep -q "echo post-hook" "$CODEX_SETTINGS"
    grep -q '"theme": "dark"' "$CODEX_SETTINGS"
}

@test "configure_codex: updates stale dcg hook path" {
    log_test "Testing Codex stale dcg path update..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    cat > "$CODEX_SETTINGS" <<'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/old/bin/dcg"}
        ]
      }
    ]
  }
}
EOF

    log_test "Before hooks.json: $(cat "$CODEX_SETTINGS")"

    configure_codex

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "After hooks.json: $(cat "$CODEX_SETTINGS")"

    [ "$CODEX_STATUS" = "merged" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"
    if grep -q "/old/bin/dcg" "$CODEX_SETTINGS"; then
        return 1
    fi
    assert_codex_dcg_hook_count 1
}

@test "configure_codex: collapses duplicate and stale dcg hooks" {
    log_test "Testing Codex duplicate dcg hook cleanup..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    cat > "$CODEX_SETTINGS" <<EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "$DEST/dcg"},
          {"type": "command", "command": "/old/bin/dcg"},
          {"type": "command", "command": "atuin history start"}
        ]
      }
    ]
  }
}
EOF

    log_test "Before hooks.json: $(cat "$CODEX_SETTINGS")"

    configure_codex

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "After hooks.json: $(cat "$CODEX_SETTINGS")"

    [ "$CODEX_STATUS" = "merged" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"
    assert_codex_dcg_hook_count 1
    grep -q "atuin history start" "$CODEX_SETTINGS"
    if grep -q "/old/bin/dcg" "$CODEX_SETTINGS"; then
        return 1
    fi
}

@test "configure_codex: repairs malformed Bash hooks shape" {
    log_test "Testing Codex malformed Bash hooks repair..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    cat > "$CODEX_SETTINGS" <<'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": {"bad": "shape"}
      },
      {
        "matcher": "Read",
        "hooks": [
          {"type": "command", "command": "echo read-hook"}
        ]
      }
    ]
  }
}
EOF

    configure_codex

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "After hooks.json: $(cat "$CODEX_SETTINGS")"

    [ "$CODEX_STATUS" = "merged" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"
    assert_codex_dcg_hook_count 1
    grep -q "echo read-hook" "$CODEX_SETTINGS"
}

@test "configure_codex: invalid hooks.json is preserved and reports failed" {
    log_test "Testing Codex invalid hooks.json preservation..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    printf '%s\n' '{"hooks":{"PreToolUse":[' > "$CODEX_SETTINGS"
    save_codex_hooks_snapshot

    configure_codex
    local rc=$?

    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "CODEX_FAILURE_REASON: ${CODEX_FAILURE_REASON:-}"
    log_codex_hooks_transition

    [ "$rc" -eq 0 ]
    [ "$CODEX_STATUS" = "failed" ]
    [[ "$CODEX_FAILURE_REASON" == *"invalid"* ]]
    [ -z "$CODEX_BACKUP" ]
    assert_codex_hooks_unchanged
}

@test "configure_codex: fails without python3 and preserves existing hooks.json" {
    log_test "Testing Codex merge failure when python3 is unavailable..."

    setup_mock_codex
    cat > "$CODEX_SETTINGS" <<'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "atuin history start"}
        ]
      }
    ]
  }
}
EOF

    local before
    before=$(cat "$CODEX_SETTINGS")
    log_test "Before hooks.json: $before"

    # shellcheck disable=SC2031 # Bats runs each test in an isolated subshell.
    local saved_path="$PATH"
    PATH="$(create_no_python_path)"

    configure_codex
    local rc=$?

    PATH="$saved_path"

    local after
    after=$(cat "$CODEX_SETTINGS")
    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_test "Return code: $rc"
    log_test "After hooks.json: $after"

    [ "$rc" -eq 0 ]
    [ "$CODEX_STATUS" = "failed" ]
    [[ "$CODEX_FAILURE_REASON" == *"python3"* ]]
    [ "$after" = "$before" ]
    [ -z "$CODEX_BACKUP" ]
    if grep -q "$DEST/dcg" "$CODEX_SETTINGS"; then
        return 1
    fi
}

@test "configure_codex + unconfigure_codex: clean setup round-trips idempotently" {
    log_test "Testing Codex clean install/uninstall repeated round trip..."

    setup_mock_codex

    configure_codex
    log_test "First CODEX_STATUS: $CODEX_STATUS"
    log_codex_hooks_transition

    [ "$CODEX_STATUS" = "created" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"

    run unconfigure_codex
    log_test "First unconfigure status: $status"
    log_test "First unconfigure output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [[ "$output" == *"removed"* ]]
    assert_codex_hooks_deleted

    configure_codex
    log_test "Second CODEX_STATUS: $CODEX_STATUS"
    log_codex_hooks_transition

    [ "$CODEX_STATUS" = "created" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"

    configure_codex
    log_test "Third CODEX_STATUS: $CODEX_STATUS"
    log_codex_hooks_transition

    [ "$CODEX_STATUS" = "already" ]
    assert_codex_hooks_has_current_dcg

    local dcg_count
    dcg_count=$(grep -oF "$DEST/dcg" "$CODEX_SETTINGS" | wc -l)
    [ "$dcg_count" -eq 1 ]

    run unconfigure_codex
    log_test "Second unconfigure status: $status"
    log_test "Second unconfigure output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [[ "$output" == *"removed"* ]]
    assert_codex_hooks_deleted

    run unconfigure_codex
    log_test "Extra unconfigure status: $status"
    log_test "Extra unconfigure output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    assert_codex_hooks_deleted
}

@test "configure_codex + unconfigure_codex: preserves atuin PostToolUse" {
    log_test "Testing Codex install/uninstall preserves atuin PostToolUse..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    cat > "$CODEX_SETTINGS" <<'EOF'
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "atuin history end"}
        ]
      }
    ]
  }
}
EOF

    local before_post
    before_post="$(codex_post_tool_use_json)"
    log_test "Before PostToolUse: $before_post"

    configure_codex
    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_codex_hooks_transition

    [ "$CODEX_STATUS" = "merged" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"

    local after_install_post
    after_install_post="$(codex_post_tool_use_json)"
    log_test "After install PostToolUse: $after_install_post"
    [ "$after_install_post" = "$before_post" ]

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [[ "$output" == *"removed"* ]]
    assert_codex_hooks_not_contains "$DEST/dcg"
    assert_codex_hooks_contains "PostToolUse"
    assert_codex_hooks_contains "atuin history end"

    local after_uninstall_post
    after_uninstall_post="$(codex_post_tool_use_json)"
    log_test "After uninstall PostToolUse: $after_uninstall_post"
    [ "$after_uninstall_post" = "$before_post" ]
}

@test "configure_codex + unconfigure_codex: replaces stale dcg path then removes it" {
    log_test "Testing Codex stale path update followed by uninstall..."
    command -v python3 &>/dev/null || skip "python3 not available"

    setup_mock_codex
    cat > "$CODEX_SETTINGS" <<'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/old/bin/dcg"}
        ]
      }
    ]
  }
}
EOF

    configure_codex
    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_codex_hooks_transition

    [ "$CODEX_STATUS" = "merged" ]
    assert_codex_hooks_has_current_dcg
    assert_codex_first_bash_hook_command "$DEST/dcg"
    assert_codex_hooks_not_contains "/old/bin/dcg"

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [[ "$output" == *"removed"* ]]
    assert_codex_hooks_deleted
}

@test "configure_codex + unconfigure_codex: malformed installed hooks do not panic" {
    log_test "Testing Codex uninstall after installed hooks become malformed..."

    setup_mock_codex

    configure_codex
    log_test "CODEX_STATUS: $CODEX_STATUS"
    log_codex_hooks_transition

    [ "$CODEX_STATUS" = "created" ]
    assert_codex_hooks_has_current_dcg

    printf '%s\n' '{"command": "dcg",' > "$CODEX_SETTINGS"
    save_codex_hooks_snapshot

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    [[ "$output" != *"Traceback"* ]]
    assert_codex_hooks_unchanged
}

@test "unconfigure_codex: deletes hooks.json when only dcg is present" {
    log_test "Testing Codex uninstall deletes dcg-only hooks.json..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/dcg"}
        ]
      }
    ]
  }
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [[ "$output" == *"removed"* ]]
    assert_codex_hooks_deleted
}

@test "unconfigure_codex: preserves coexisting atuin hook in same Bash matcher" {
    log_test "Testing Codex uninstall preserves same-matcher non-dcg hook..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/dcg"},
          {"type": "command", "command": "atuin history start"}
        ]
      }
    ]
  }
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    assert_codex_hooks_contains "atuin history start"
    assert_codex_hooks_not_contains "/usr/local/bin/dcg"
}

@test "unconfigure_codex: preserves separate matcher block for atuin" {
    log_test "Testing Codex uninstall preserves separate matcher block..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/dcg"}
        ]
      },
      {
        "matcher": "^Bash$",
        "hooks": [
          {"type": "command", "command": "atuin history start"}
        ]
      }
    ]
  }
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    assert_codex_hooks_contains '"matcher": "^Bash$"'
    assert_codex_hooks_contains "atuin history start"
    assert_codex_hooks_not_contains "/usr/local/bin/dcg"
}

@test "unconfigure_codex: preserves PostToolUse when only PreToolUse had dcg" {
    log_test "Testing Codex uninstall preserves PostToolUse hooks..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/dcg"}
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "atuin history end"}
        ]
      }
    ]
  }
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    assert_codex_hooks_contains "PostToolUse"
    assert_codex_hooks_contains "atuin history end"
    assert_codex_hooks_not_contains "/usr/local/bin/dcg"
}

@test "unconfigure_codex: no-op when file has no dcg entries" {
    log_test "Testing Codex uninstall no-op without dcg entries..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "atuin history start"}
        ]
      }
    ]
  }
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    assert_codex_hooks_unchanged
}

@test "unconfigure_codex: no-op when file does not exist" {
    log_test "Testing Codex uninstall no-op without hooks.json..."

    mkdir -p "$HOME/.codex"
    [ ! -e "$CODEX_SETTINGS" ]

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    assert_codex_hooks_unchanged
}

@test "unconfigure_codex: malformed JSON leaves hooks.json unchanged" {
    log_test "Testing Codex uninstall leaves malformed JSON unchanged..."
    command -v python3 &>/dev/null || skip "python3 not available"

    mkdir -p "$HOME/.codex"
    printf '%s\n' '{"command": "dcg",' > "$CODEX_SETTINGS"
    save_codex_hooks_snapshot

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    assert_codex_hooks_unchanged
}

@test "unconfigure_codex: PreToolUse is not a list leaves hooks.json unchanged" {
    log_test "Testing Codex uninstall leaves non-list PreToolUse unchanged..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": {
      "matcher": "Bash",
      "hooks": [
        {"type": "command", "command": "/usr/local/bin/dcg"}
      ]
    }
  }
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    assert_codex_hooks_unchanged
}

@test "unconfigure_codex: hooks key is not a dict leaves hooks.json unchanged" {
    log_test "Testing Codex uninstall leaves non-dict hooks unchanged..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": [
    {"type": "command", "command": "/usr/local/bin/dcg"}
  ]
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    [ -z "$output" ]
    assert_codex_hooks_unchanged
}

@test "unconfigure_codex: python3 unavailable returns 1 and preserves hooks.json" {
    log_test "Testing Codex uninstall failure without python3..."

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/dcg"}
        ]
      }
    ]
  }
}'

    local saved_path="$PATH"
    PATH="$(create_no_python_path)"

    run unconfigure_codex

    PATH="$saved_path"

    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 1 ]
    [[ "$output" == *"python3 not available"* ]]
    assert_codex_hooks_unchanged
}

@test "unconfigure_codex: read-only directory returns 1 and preserves hooks.json" {
    log_test "Testing Codex uninstall failure with read-only hooks directory..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/dcg"}
        ]
      }
    ]
  }
}'

    chmod 500 "$HOME/.codex"
    run unconfigure_codex
    chmod 700 "$HOME/.codex"

    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 1 ]
    [[ "$output" == *"failed to update"* ]]
    assert_codex_hooks_unchanged
}

@test "unconfigure_codex: preserves dcg-helper while removing dcg" {
    log_test "Testing Codex uninstall preserves commands whose basename is not dcg..."
    command -v python3 &>/dev/null || skip "python3 not available"

    seed_codex_hooks_json '{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/dcg"},
          {"type": "command", "command": "/usr/local/bin/dcg-helper"}
        ]
      }
    ]
  }
}'

    run unconfigure_codex
    log_test "unconfigure_codex status: $status"
    log_test "unconfigure_codex output: $output"
    log_codex_hooks_transition

    [ "$status" -eq 0 ]
    assert_codex_hooks_contains "dcg-helper"
    assert_codex_hooks_not_contains "/usr/local/bin/dcg\""
}
