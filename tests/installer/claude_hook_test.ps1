#!/usr/bin/env pwsh
# Tests Configure-ClaudeHook (and the shared Merge-PreToolUseBashHookFile) from
# install.ps1 by dot-sourcing it with -LoadFunctionsOnly (so the install body
# does not run). Runnable on any OS with PowerShell. Covers: create, merge with a
# coexisting hook, idempotency, UTF-8-no-BOM, refuse-invalid-JSON, and skip. The
# functions take a -HomeDir param so a temp home can be injected ($HOME is
# read-only in PowerShell).

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$installPs1 = Join-Path $repoRoot 'install.ps1'
. $installPs1 -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}
function New-TempHome {
    $h = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_claude_test_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $h | Out-Null
    $h
}
function Test-NoBom([string]$path) {
    $b = [System.IO.File]::ReadAllBytes($path)
    -not ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
}

$dcgPath = 'C:\Users\me\.local\bin\dcg.exe'

# --- Test 1: create + idempotent + no BOM ---
Write-Host "Test 1: create / idempotent / no-BOM"
$h1 = New-TempHome
try {
    $status = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h1
    Check ($status -eq 'created') "first run returns 'created' (got '$status')"
    $settings = Join-Path $h1 '.claude/settings.json'
    Check (Test-Path $settings) "settings.json created"
    Check (Test-NoBom $settings) "file has no UTF-8 BOM"
    $p = Get-Content -Raw $settings | ConvertFrom-Json
    Check ($p.hooks.PreToolUse[0].matcher -eq 'Bash') "matcher is Bash"
    Check ($p.hooks.PreToolUse[0].hooks[0].command -eq $dcgPath) "dcg command set to full path"
    $status2 = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h1
    Check ($status2 -eq 'already') "second run returns 'already' (got '$status2')"
} finally { Remove-Item -Recurse -Force $h1 -ErrorAction SilentlyContinue }

# --- Test 2: merge preserves coexisting hooks + hoists dcg first ---
Write-Host "Test 2: merge preserves coexisting hooks"
$h2 = New-TempHome
try {
    $cdir = Join-Path $h2 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    $existing = [ordered]@{
        hooks = [ordered]@{
            PreToolUse  = @([ordered]@{ matcher = 'Bash'; hooks = @([ordered]@{ type = 'command'; command = 'other-tool' }) })
            PostToolUse = @([ordered]@{ matcher = 'Write'; hooks = @([ordered]@{ type = 'command'; command = 'formatter' }) })
        }
        otherSetting = 'keep-me'
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $cdir 'settings.json')
    $status = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h2
    Check ($status -eq 'merged') "returns 'merged' (got '$status')"
    $p = Get-Content -Raw (Join-Path $cdir 'settings.json') | ConvertFrom-Json
    $bash = @($p.hooks.PreToolUse | Where-Object { $_.matcher -eq 'Bash' })[0]
    Check ($bash.hooks[0].command -eq $dcgPath) "dcg hoisted first in Bash hooks"
    Check ((@($bash.hooks | ForEach-Object { $_.command })) -contains 'other-tool') "coexisting Bash hook preserved"
    Check ($p.hooks.PostToolUse[0].hooks[0].command -eq 'formatter') "PostToolUse preserved"
    Check ($p.otherSetting -eq 'keep-me') "unrelated root setting preserved"
    Check (Test-NoBom (Join-Path $cdir 'settings.json')) "merged file has no BOM"
} finally { Remove-Item -Recurse -Force $h2 -ErrorAction SilentlyContinue }

# --- Test 3: refuse invalid JSON (leave untouched) ---
Write-Host "Test 3: refuse invalid JSON"
$h3 = New-TempHome
try {
    $cdir = Join-Path $h3 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    Set-Content -Path (Join-Path $cdir 'settings.json') -Value '{ not valid json'
    $threw = $false
    try { Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h3 } catch { $threw = $true }
    Check $threw "throws on invalid JSON"
    Check ((Get-Content -Raw (Join-Path $cdir 'settings.json')).Trim() -eq '{ not valid json') "invalid JSON left unchanged"
} finally { Remove-Item -Recurse -Force $h3 -ErrorAction SilentlyContinue }

# --- Test 4: skip when not detected and not forced ---
# Clear PATH so `claude` is not discoverable (this CI/dev box may have it on PATH);
# with ~/.claude absent and no -Force the result must be 'skipped'.
Write-Host "Test 4: skip when ~/.claude absent and not -Force"
$h4 = New-TempHome
$savedPath = $env:PATH
try {
    $env:PATH = ''
    $status = Configure-ClaudeHook -DcgPath $dcgPath -HomeDir $h4
    Check ($status -eq 'skipped') "returns 'skipped' (got '$status')"
} finally { $env:PATH = $savedPath; Remove-Item -Recurse -Force $h4 -ErrorAction SilentlyContinue }

if ($script:failures -gt 0) {
    Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red
    exit 1
}
Write-Host "All Configure-ClaudeHook tests passed." -ForegroundColor Green
