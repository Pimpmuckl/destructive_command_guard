//! Regression tests for issue #256: leading `NAME=value` assignment prefixes
//! and non-flag operands were misread by the obfuscated POSIX inline-launcher
//! parse.
//!
//! `GH_TOKEN="$(python3 /tmp/x.py)" gh issue list --search '-label:x …'` was
//! denied because (a) the command substitution inside the *assignment value*
//! was treated as a dynamically assembled executable, and (b) the `-label:x`
//! search operand was misread as a short-flag cluster containing `c`. The fix
//! skips POSIX assignment prefixes when locating the executable and only
//! treats purely alphanumeric leading chunks as short-flag clusters, while
//! keeping substitutions in true command position and glued `-c'…'` clusters
//! fail-closed.

use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{
    config::Config, evaluator::evaluate_command, load_default_allowlists,
};

fn evaluate(cmd: &str) -> destructive_command_guard::evaluator::EvaluationResult {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    let enabled_packs = config.enabled_pack_ids();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

    evaluate_command(cmd, &config, &keywords, &compiled_overrides, &allowlists)
}

fn allowed(cmd: &str) {
    let result = evaluate(cmd);
    assert!(
        result.is_allowed(),
        "expected ALLOWED (assignment prefix / operand is not launcher code): {cmd:?} -> {:?}",
        result.pattern_info
    );
}

fn denied(cmd: &str) {
    let result = evaluate(cmd);
    assert!(
        result.is_denied(),
        "expected DENIED (genuine launcher / destructive payload): {cmd:?} -> {:?}",
        result.pattern_info
    );
}

#[test]
fn assignment_prefix_substitution_is_not_the_executable() {
    // The canonical report: a token-refresh command substitution in an
    // environment assignment, followed by a search operand starting with `-`.
    allowed("GH_TOKEN=\"$(python3 /tmp/x.py)\" gh issue list --search '-label:x sort:created-asc'");
    // A real short-flag cluster after the assignment: `gh` is not an inline
    // shell, so the cluster is irrelevant.
    allowed("GH_TOKEN=\"$(python3 /tmp/x.py)\" gh foo -abc");
    // The `-label:…` operand in a long-option value position.
    allowed("GH_TOKEN=\"$(python3 /tmp/x.py)\" gh foo --search '-label:cakes'");
    // A different assignment/command pair with a quoted `-a c` data operand.
    allowed("TOKEN=\"$(cat /tmp/t)\" curl -sS https://example.invalid --data '-a c'");
}

#[test]
fn substitution_in_command_position_stays_fail_closed() {
    // Without an assignment name, the substitution really is the executable;
    // followed by an inline-code flag it must stay denied.
    denied("\"$(python3 /tmp/x.py)\" foo -c");
}

#[test]
fn assignment_prefix_does_not_hide_a_real_inline_launcher() {
    // The assignment is skipped, but the launcher after it is still parsed
    // and its destructive payload denied.
    denied("FOO=bar sh -c 'rm -rf /'");
}

#[test]
fn glued_short_flag_cluster_is_still_detected() {
    // `-c'echo hi; …'` decodes to `-cecho hi; …`; the leading chunk is still
    // an alphanumeric cluster containing `c`, so the payload is evaluated.
    denied("sh -c'echo hi; rm -rf /'");
}

#[test]
fn glued_cluster_with_punctuation_leading_payload_is_still_detected() {
    // A glued payload may begin with punctuation right after the flag letter
    // (`-c"/bin/sh …"` decodes to `-c/bin/sh …`). The v0.9.0 narrowing to
    // whole-chunk-alphanumeric clusters missed it, letting a dynamic
    // executable with an inline-code flag through unverified (review
    // regression). The leading alphanumeric run (`c`) must be the cluster.
    denied("\"$(python3 /tmp/x.py)\" foo -c\"/bin/sh x\"");
    denied("sh -c\"/bin/sh x; rm -rf /\"");
}
