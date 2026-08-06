//! Regression tests for issue #222: `windows.filesystem` must block the .NET
//! recursive directory delete that PowerShell can call with no external tool:
//! `[System.IO.Directory]::Delete($path, $true)`.
//!
//! Root cause of the original false negative: PowerShell tokenization treats
//! `(` and `)` as separators, so the generic segment splitter cut
//! `[System.IO.Directory]::Delete($path, $true)` into the fragments
//! `[System.IO.Directory]::Delete` and `$path, $true`. The pack's expression
//! matchers are anchored to a word start *and* require the opening `(`, so no
//! fragment could ever satisfy them and the rule never fired end to end. The
//! fix scans real PowerShell statements (split only on newline, `;`, and
//! pipeline operators) so a call expression is never separated from its
//! argument list.
//!
//! Both directions are asserted: the dangerous forms deny, and benign
//! lookalikes (read-only .NET APIs, quoted data, non-recursive member calls)
//! stay allowed.

use destructive_command_guard::evaluator::{
    EvaluationResult, evaluate_command_with_pack_order_at_path_in_dialect,
};
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{config::Config, load_default_allowlists};
use std::collections::HashSet;

/// Evaluate `command` with `windows.filesystem` enabled in `dialect`.
///
/// The Windows packs are default-ON only under `cfg(windows)`, so the test
/// enables the pack explicitly; that mirrors a native-Windows install.
fn evaluate(command: &str, dialect: ShellDialect) -> EvaluationResult {
    let mut config = Config::default();
    config.packs.enabled.push("windows.filesystem".to_string());

    let enabled: HashSet<String> = config.enabled_pack_ids();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled);
    let ordered = REGISTRY.expand_enabled_ordered(&enabled);
    let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered);
    let overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    let heredoc_settings = config.heredoc_settings();

    evaluate_command_with_pack_order_at_path_in_dialect(
        command,
        &keywords,
        &ordered,
        keyword_index.as_ref(),
        &overrides,
        &allowlists,
        &heredoc_settings,
        None,
        dialect,
    )
}

/// Dialects a native-Windows caller can present. `Posix` is excluded on
/// purpose: a caller that proved a POSIX shell is not running PowerShell.
const WINDOWS_DIALECTS: [ShellDialect; 2] = [ShellDialect::PowerShell, ShellDialect::Unknown];

fn denied(command: &str, expected_rule: &str) {
    for dialect in WINDOWS_DIALECTS {
        let result = evaluate(command, dialect);
        assert!(
            result.is_denied(),
            "expected DENY for {command:?} in {dialect:?}, got {:?}",
            result.decision
        );
        let rule = result
            .pattern_info
            .as_ref()
            .and_then(|info| info.pattern_name.as_deref())
            .unwrap_or("(unnamed)");
        assert_eq!(
            rule, expected_rule,
            "{command:?} in {dialect:?} denied by {rule:?}, expected {expected_rule:?}"
        );
    }
}

fn allowed_in(command: &str, dialect: ShellDialect) {
    let result = evaluate(command, dialect);
    assert!(
        result.is_allowed(),
        "expected ALLOW for {command:?} in {dialect:?}, got {:?} ({:?})",
        result.decision,
        result.pattern_info
    );
}

fn allowed(command: &str) {
    for dialect in WINDOWS_DIALECTS {
        allowed_in(command, dialect);
    }
}

/// Assert `command` is never attributed to `rule`.
///
/// Weaker than [`allowed`] on purpose: the pack may still hold a command for
/// review through its conservative unresolved-expansion path (a bare `$var`
/// sub-expression can expand to any executable), which is a separate,
/// pre-existing behaviour. What must not happen is a *delete* rule claiming a
/// command that performs no delete.
fn not_matched_by(command: &str, rule: &str) {
    for dialect in WINDOWS_DIALECTS {
        let result = evaluate(command, dialect);
        let matched = result
            .pattern_info
            .as_ref()
            .and_then(|info| info.pattern_name.as_deref());
        assert_ne!(
            matched,
            Some(rule),
            "{command:?} in {dialect:?} must not match {rule:?}"
        );
    }
}

/// The exact command from issue #222 and its accelerator spelling.
#[test]
fn issue_222_dotnet_directory_delete_recursive_is_denied() {
    denied(
        r"[System.IO.Directory]::Delete('E:\Dcg_test', $true)",
        "dotnet-directory-delete-recursive",
    );
    denied(
        r"[System.IO.Directory]::Delete($path, $true)",
        "dotnet-directory-delete-recursive",
    );
    denied(
        r"[IO.Directory]::Delete($path, $true)",
        "dotnet-directory-delete-recursive",
    );
}

#[test]
fn dotnet_directory_delete_recursive_spelling_variants_are_denied() {
    for command in [
        // No space after the comma — the original repro's exact shape.
        r"[IO.Directory]::Delete($path,$true)",
        // Whitespace around `[`, `]`, and `::`.
        r"[ System.IO.Directory ] :: Delete ( $path , $true )",
        // Case-insensitive type literal and method name.
        r"[system.io.directory]::delete($path, $true)",
        r"[SYSTEM.IO.DIRECTORY]::DELETE($PATH, $TRUE)",
        // Truthy non-`$true` recursive flags PowerShell coerces to true.
        r"[System.IO.Directory]::Delete($root, 1)",
        r#"[System.IO.Directory]::Delete($root, "true")"#,
        // Nested call expression in the path argument.
        r"[System.IO.Directory]::Delete((Join-Path $root 'sub'), $true)",
    ] {
        denied(command, "dotnet-directory-delete-recursive");
    }
}

#[test]
fn dotnet_directory_delete_recursive_is_denied_in_statement_positions() {
    for command in [
        // Assignment context.
        r"$x = [IO.Directory]::Delete($path, $true)",
        // Statement-separated, second statement.
        r"Write-Output 'cleanup'; [IO.Directory]::Delete($path, $true)",
        // Leading separator.
        r"; [IO.Directory]::Delete($path, $true)",
        // Call operator with a script block.
        r"& { [IO.Directory]::Delete($path, $true) }",
        // Pipeline position.
        r"Get-Date | Out-Null; [IO.Directory]::Delete($path, $true)",
        // Indented continuation line.
        "Write-Output 'a'\n    [IO.Directory]::Delete($path, $true)",
    ] {
        denied(command, "dotnet-directory-delete-recursive");
    }
}

#[test]
fn dotnet_directory_delete_other_forms_are_denied() {
    // A dynamic second argument still recurses: PowerShell coerces every
    // non-empty string to `$true`.
    denied(
        r"[System.IO.Directory]::Delete($path, $flag)",
        "dotnet-directory-delete",
    );
    // Single-argument form removes the directory (when empty) with no
    // Recycle Bin entry.
    denied(
        r"[IO.Directory]::Delete('C:\obsolete-empty')",
        "dotnet-directory-delete",
    );
}

#[test]
fn directoryinfo_member_delete_recursive_is_denied() {
    for command in [
        r"$dir.Delete($true)",
        r"(Get-Item 'C:\tmp\scratch').Delete($true)",
        r"(Get-Item $p).Delete($true)",
        r"([System.IO.DirectoryInfo]'C:\src').Delete($true)",
        r"(New-Object System.IO.DirectoryInfo 'C:\src').Delete( $true )",
    ] {
        denied(command, "directoryinfo-delete-recursive");
    }
}

/// The false-positive direction: benign lookalikes must stay allowed.
#[test]
fn benign_dotnet_directory_apis_are_allowed() {
    for command in [
        r"[System.IO.Directory]::Exists('C:\src')",
        r"[IO.Directory]::GetFiles('C:\src')",
        r"[System.IO.Directory]::CreateDirectory('C:\src\new')",
        r"[System.IO.Directory]::GetCurrentDirectory()",
        r"[System.IO.Directory]::EnumerateDirectories('C:\src')",
        r"[System.IO.File]::ReadAllText('C:\src\a.txt')",
        r"[System.IO.Path]::GetDirectoryName('C:\src\a.txt')",
    ] {
        allowed(command);
    }
}

/// A wholly quoted spelling in an ordinary statement is data. Executing it
/// needs a call operator or `Invoke-Expression`, which are analyzed elsewhere.
///
/// This is asserted for a caller-proven PowerShell dialect only. An `Unknown`
/// caller has proven no shell grammar, so the pack deliberately keeps its
/// conservative whole-string regex fallback there rather than trusting a
/// quoting analysis it cannot justify.
#[test]
fn quoted_dotnet_delete_text_is_data_not_an_invocation() {
    allowed_in(
        r"Write-Output '[System.IO.Directory]::Delete($p, $true)'",
        ShellDialect::PowerShell,
    );
    allowed_in(
        r"Write-Output '$dir.Delete($true)'",
        ShellDialect::PowerShell,
    );
    allowed(r"Write-Output 'documented in [IO.Directory]::Delete docs'");
}

#[test]
fn non_recursive_member_delete_calls_are_allowed() {
    // `.Delete(...)` without a literal `$true` recursive flag is not this
    // rule's target; `$false` is the non-recursive spelling.
    allowed(r"$dir.Delete()");
    allowed(r"(Get-Item 'C:\tmp\empty').Delete()");
    allowed(r"$queue.Delete('item')");
    not_matched_by(r"$dir.Delete($false)", "directoryinfo-delete-recursive");
    not_matched_by(r"$queue.Delete($item)", "directoryinfo-delete-recursive");
}
