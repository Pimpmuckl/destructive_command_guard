//! Regression tests for issue #255: escape-sequence scanning panicked on
//! multi-byte escaped characters.
//!
//! The scanners for PowerShell backticks, cmd.exe carets, and POSIX
//! backslashes advanced a fixed two bytes past the escape character
//! (`index = (index + 2).min(bytes.len())`). When the escaped character was
//! multi-byte UTF-8 (e.g. `中`, `）`, `é`), the cursor landed inside a code
//! point and a later `command[index..]` slice panicked, crashing
//! `dcg explain` / hook evaluation. The fix (`escape_sequence_end`) advances
//! past the full escaped character.
//!
//! The regression is a *panic*, so returning any decision is the primary pass
//! condition. Backtick-bearing fragments may legitimately fail closed as an
//! ambiguous POSIX command substitution under the default (Unknown) dialect
//! view; that conservative denial is asserted as Deny-not-panic, while the
//! escape-free controls must stay allowed.

use destructive_command_guard::evaluator::{EvaluationDecision, EvaluationResult};
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{
    config::Config, evaluator::evaluate_command, load_default_allowlists,
};

fn evaluate(cmd: &str) -> EvaluationResult {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    let enabled_packs = config.enabled_pack_ids();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

    evaluate_command(cmd, &config, &keywords, &compiled_overrides, &allowlists)
}

fn completes(cmd: &str) {
    let result = evaluate(cmd);
    assert!(
        matches!(
            result.decision,
            EvaluationDecision::Allow | EvaluationDecision::Deny
        ),
        "escaped multi-byte fragment must complete evaluation: {cmd:?} -> {:?}",
        result.decision
    );
}

fn allowed(cmd: &str) {
    let result = evaluate(cmd);
    assert!(
        result.is_allowed(),
        "benign fragment must evaluate to allow: {cmd:?} -> {:?}",
        result.pattern_info
    );
}

#[test]
fn powershell_backtick_before_multibyte_char_does_not_panic() {
    // 3-byte CJK char after a backtick escape.
    completes("s`中");
    // 3-byte fullwidth parenthesis — the character from the #255 report.
    completes("a`）");
    // 2-byte accented char.
    completes("s`é");
    // 4-byte emoji (surrogate-pair range).
    completes("s`😀");
    // Escape directly after a recognized keyword prefix.
    completes("git`）");
}

#[test]
fn cmd_caret_before_multibyte_char_does_not_panic() {
    // The cmd.exe caret escape shares the fixed-advance scanner shape.
    completes("s^中");
    completes("s^）");
    completes("s^é");
}

#[test]
fn posix_backslash_before_multibyte_char_does_not_panic() {
    // The POSIX backslash escape is the third scanner variant.
    completes("s\\中");
    completes("s\\）");
}

#[test]
fn escape_scanning_controls_still_work() {
    // Escape character as the final byte of the input.
    completes("s`");
    // Escape character at index 0.
    completes("`中");
    // Multi-byte char without any escape must stay allowed outright.
    allowed("s中");
    allowed("echo s中");
}

#[test]
fn multibyte_escapes_inside_larger_commands_still_evaluate() {
    // The escaped multi-byte char embedded in an otherwise ordinary command
    // must not derail scanning for the rest of the input.
    completes("echo s`中 && git status");
    completes("echo s^） & git status");
    // Destructive content after the escaped char must still be reachable.
    let result = evaluate("echo s`中; git reset --hard");
    assert!(
        result.is_denied(),
        "destructive segment after an escaped multi-byte char must stay denied: {:?}",
        result.decision
    );
    let caret = evaluate("echo s^中 & git reset --hard");
    assert!(
        caret.is_denied(),
        "destructive segment after a caret-escaped multi-byte char must stay denied: {:?}",
        caret.decision
    );
}
