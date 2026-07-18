# Security Notes: Heredoc Detection

This document describes the threat model, assumptions, and incident response
for heredoc and inline-script scanning.

## Threat Model

Heredoc scanning is designed to catch destructive operations hidden inside
embedded scripts, including:

- Heredocs: `<<EOF ... EOF`
- Here-strings: `<<< "..."`
- Inline interpreter flags: `python -c`, `bash -c`, `node -e`
- Piped scripts: `cat <<EOF | bash`

The goal is to prevent accidental or automated destructive actions that the
outer command does not reveal.

## What It Protects Against

- Destructive filesystem commands inside scripts (for example, recursive delete)
- Destructive git operations embedded in scripts (for example, `git reset --hard`)
- Shell execution helpers in scripting languages (for example, `os.system`,
  `child_process.execSync`, `Kernel.system`)

## Out of Scope

- General malware detection
- Exploits that do not rely on heredocs or inline script payloads
- Non-shell destructive operations outside the supported language set
- Arbitrary interpreter behavior that is not represented in the AST patterns

These limits keep runtime overhead small and false positives manageable.

## Bounded Failure Behavior

dcg distinguishes malformed outer hook input from an evaluation that started
but could not finish:

- Malformed or oversized raw hook JSON is allowed with an audit warning by
  default; `general.fail_closed = true` (or `DCG_FAIL_CLOSED=1`) denies it.
- Heredoc extraction, parsing, and AST failures run the bounded fallback scanner
  when configured. Disabling the relevant fallback blocks instead.
- An exhausted absolute hook deadline, oversized extracted command, or
  incomplete nested evaluation is **indeterminate**, never a clean allow.
  Review-capable clients receive `ask`; clients without that state block.

This keeps raw transport failures configurable without treating elapsed
analysis time as evidence that a command is safe. Audit logs and `dcg explain`
surface the distinction.

## Performance Budgets

The heredoc pipeline is strictly bounded:

- Tier 1 trigger: <100us
- Tier 2 extraction: <1ms typical, 50ms max
- Tier 3 AST match: <5ms typical, 20ms max

When the absolute hook budget is exhausted, the system records a diagnostic
and returns an explicit indeterminate decision.

## Bypass Considerations

Heredoc scanning is not intended to be a perfect malware detector. Known
limitations include:

- Obfuscated payloads that evade AST parsing or use unsupported languages
- Dynamic command construction that cannot be resolved to literal payloads
- Non-standard interpreters or runtime-generated code

Mitigations:

- Favor stable rule IDs and allowlisting for known-safe cases
- Keep patterns narrowly scoped to avoid broad false positives
- Expand language support and pattern coverage based on real-world feedback

## Incident Response

### If a safe command is blocked

1. Run `dcg explain` on the command or use the printed rule ID.
2. Add a user-owned allowlist entry with a reason and repository-root `--path`
   scopes when the exception is project-specific.
3. Activate a checked-in project allowlist only after reviewing `.dcg.toml` and
   explicitly selecting it through `DCG_CONFIG`.

### If a dangerous command is allowed

1. Capture the command text and environment context.
2. File a security issue with the rule ID or gap description.
3. Add or refine a heredoc pattern and tests.

## Reporting

Security issues should be reported via GitHub issues with:

- The command and any heredoc payload (redacted as needed)
- The language detected (if any)
- The observed behavior (blocked or allowed)
- Expected behavior and rationale
