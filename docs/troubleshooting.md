# Troubleshooting Guide

Common issues and how to resolve them.

## dcg is not blocking anything

1. Confirm the hook is installed correctly.
2. Ensure the dcg binary is on PATH.
3. Verify trusted config loading (explicit/user/system) and pack enablement.
   Automatically discovered `.dcg.toml` files may enable packs and add other
   enforcement, but cannot disable protection or add allow rules.

If available, run:
- `dcg doctor` for a structured diagnostics report.

## Packs are not enabled

Check your config sources in order:
- `DCG_CONFIG=/path/to/config.toml` (explicit, fully trusted)
- `~/.config/dcg/config.toml` (user)
- `/etc/dcg/config.toml` (system)

An automatically discovered project `.dcg.toml` may add `[packs].enabled`, but
its `[packs].disabled` and `custom_paths` entries are ignored. Select a reviewed
project file explicitly with `DCG_CONFIG=.dcg.toml` if it needs full authority.

Also verify environment overrides:
- `DCG_PACKS`
- `DCG_DISABLE`

## False positives (safe command blocked)

1. Add a safe allowlist entry (project or user).
2. If recurring, file a bug report with the exact command.
3. Add a test case to prevent regressions.

## False negatives (dangerous command allowed)

1. File a bug report with the exact command and context.
2. Add a destructive pattern + test case.
3. Update the pack’s safe pattern list to avoid over-broad allow rules.

## Hook errors or timeouts

For heredoc or large script parsing:
- Lower `max_body_bytes` or `max_body_lines`.
- Increase `[heredoc].timeout_ms` if heredoc extraction itself is timing out.
- Ensure `fallback_on_parse_error` is true for hook mode.

For ordinary full evaluation on a slower workstation or modest VPS, tune the
separate absolute hook budget. For example:

```toml
[general]
hook_timeout_ms = 1500
```

The equivalent one-process override is `DCG_HOOK_TIMEOUT_MS=1500`. Confirm the
slow path with `dcg explain "<command>"`; deadline exhaustion must appear as
`INDETERMINATE`, never `ALLOW` or `quick-rejected`. Do not reduce the budget
below the measured full-evaluation latency for the host.

## Performance concerns

If hook latency is high:
- Reduce enabled pack count.
- Disable expensive packs temporarily.
- Capture performance logs and open an issue.

## Reporting issues

When filing a report, include:
- The exact command
- Expected vs actual decision
- Your enabled packs list
- Relevant config snippets (redact secrets)
