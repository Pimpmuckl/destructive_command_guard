#!/usr/bin/env pwsh
# Regression test for win-test-rollback-bom: Codex's strict JSON parser rejects a
# leading UTF-8 BOM ("expected value at line 1 column 1" — issue #125). install.ps1
# writes hooks.json via [System.IO.File]::WriteAllText(..., New-Object
# System.Text.UTF8Encoding $false), which must NOT emit a BOM. This test verifies
# that exact write approach produces bytes that do not start with EF BB BF, and
# that the bytes parse as JSON. Runnable on any OS with PowerShell (pwsh).

$ErrorActionPreference = 'Stop'

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_bom_test_" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $hooksFile = Join-Path $tmp 'hooks.json'
    $config = [pscustomobject][ordered]@{
        hooks = [pscustomobject][ordered]@{
            PreToolUse = @(
                [pscustomobject][ordered]@{
                    matcher = 'Bash'
                    hooks   = @([pscustomobject][ordered]@{ type = 'command'; command = 'C:\Users\me\.local\bin\dcg.exe' })
                }
            )
        }
    }

    # EXACTLY the approach install.ps1 uses (Configure-CodexHook).
    [System.IO.File]::WriteAllText(
        $hooksFile,
        ($config | ConvertTo-Json -Depth 20),
        (New-Object System.Text.UTF8Encoding $false)
    )

    $bytes = [System.IO.File]::ReadAllBytes($hooksFile)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        Write-Error "FAIL: hooks.json starts with a UTF-8 BOM (EF BB BF) — Codex's parser would reject it."
        exit 1
    }

    # Must still be valid JSON with the dcg hook.
    $parsed = Get-Content -Raw -Path $hooksFile | ConvertFrom-Json
    $cmd = $parsed.hooks.PreToolUse[0].hooks[0].command
    if ($cmd -ne 'C:\Users\me\.local\bin\dcg.exe') {
        Write-Error "FAIL: round-tripped command mismatch: '$cmd'"
        exit 1
    }

    Write-Host "OK: Codex hooks.json written without BOM and parses as valid JSON ($($bytes.Length) bytes)."
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
