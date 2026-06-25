#!/usr/bin/env pwsh
# Tests Configure-HermesHook from install.ps1: pure-PowerShell Hermes config.yaml
# (no PyYAML). Fresh-create emits a valid minimal YAML; an existing config without
# the powershell-yaml module returns 'manual' (NEVER corrupts it); detection/skip.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}
function New-TempHome {
    $h = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_hermes_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path (Join-Path $h ".hermes") -Force | Out-Null  # make Hermes "detected"
    $h
}
function Test-NoBom([string]$p) {
    $b = [System.IO.File]::ReadAllBytes($p)
    -not ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
}
$dcgPath = 'C:\Users\me\.local\bin\dcg.exe'

Write-Host "Test 1: fresh create emits valid minimal YAML (no BOM)"
$h1 = New-TempHome
try {
    $s = Configure-HermesHook -DcgPath $dcgPath -HomeDir $h1
    Check ($s -eq 'created') "create returns 'created' (got '$s')"
    $cfg = Join-Path $h1 '.hermes/config.yaml'
    Check (Test-Path $cfg) "config.yaml created"
    Check (Test-NoBom $cfg) "config.yaml has no UTF-8 BOM"
    $text = Get-Content -Raw $cfg
    Check ($text -match 'hooks_auto_accept:\s*true') "hooks_auto_accept: true present"
    Check ($text -match 'pre_tool_call:') "hooks.pre_tool_call present"
    Check ($text -match 'matcher:\s*terminal') "matcher: terminal present"
    Check ($text -match [regex]::Escape($dcgPath)) "dcg path present (single-quoted, backslashes literal)"
    Check ($text -match 'timeout:\s*30') "timeout: 30 present"
} finally { Remove-Item -Recurse -Force $h1 -ErrorAction SilentlyContinue }

Write-Host "Test 2: existing config + no powershell-yaml -> 'manual' (NEVER corrupts)"
$h2 = New-TempHome
try {
    $cfg = Join-Path $h2 '.hermes/config.yaml'
    $original = "model: hermes-3`nhooks_auto_accept: false`nsome_user_key: keep-me`n"
    Set-Content -Path $cfg -Value $original -NoNewline
    $hasYaml = $null -ne (Get-Module -ListAvailable -Name powershell-yaml -ErrorAction SilentlyContinue)
    $s = Configure-HermesHook -DcgPath $dcgPath -HomeDir $h2
    if ($hasYaml) {
        Check ($s -eq 'merged' -or $s -eq 'already') "with powershell-yaml present, merges (got '$s')"
    } else {
        Check ($s -eq 'manual') "without module, returns 'manual' (got '$s')"
        Check ((Get-Content -Raw $cfg) -eq $original) "existing config.yaml left BYTE-FOR-BYTE unchanged"
    }
} finally { Remove-Item -Recurse -Force $h2 -ErrorAction SilentlyContinue }

Write-Host "Test 3: skipped when Hermes absent and not -Force"
$h3 = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_hermes_none_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $h3 | Out-Null
$savedPath = $env:PATH
try {
    $env:PATH = ''
    Check ((Configure-HermesHook -DcgPath $dcgPath -HomeDir $h3) -eq 'skipped') "no ~/.hermes + no hermes on PATH -> skipped"
} finally { $env:PATH = $savedPath; Remove-Item -Recurse -Force $h3 -ErrorAction SilentlyContinue }

Write-Host "Test 4: -Force creates even when absent"
$h4 = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_hermes_force_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $h4 | Out-Null
$savedPath2 = $env:PATH
try {
    $env:PATH = ''
    Check ((Configure-HermesHook -DcgPath $dcgPath -HomeDir $h4 -Force) -eq 'created') "-Force creates config.yaml even without detection"
} finally { $env:PATH = $savedPath2; Remove-Item -Recurse -Force $h4 -ErrorAction SilentlyContinue }

Write-Host "Test 5: Test-HermesIsDcgCommand basename match (.exe-agnostic, not substring)"
Check (Test-HermesIsDcgCommand 'C:\bin\dcg.exe') "matches dcg.exe by basename"
Check (Test-HermesIsDcgCommand '/usr/bin/dcg') "matches bare dcg"
Check (Test-HermesIsDcgCommand 'C:\Users\Jane Doe\.local\bin\dcg.exe') "matches unquoted dcg path containing spaces"
Check (Test-HermesIsDcgCommand 'C:\Users\Jane Doe\.local\bin\dcg.exe --robot test') "matches unquoted dcg path containing spaces with arguments"
Check (-not (Test-HermesIsDcgCommand 'mydcg.exe')) "does NOT match mydcg.exe (substring)"
Check (-not (Test-HermesIsDcgCommand 'echo dcg')) "does NOT match a non-dcg first token"
Check (-not (Test-HermesIsDcgCommand 'echo C:\bin\dcg.exe')) "does NOT match a dcg path used as data"
Check (-not (Test-HermesIsDcgCommand 'C:\Users\Jane Doe\tool.exe C:\bin\dcg.exe')) "does NOT match a dcg path passed to another executable"

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All Configure-HermesHook tests passed." -ForegroundColor Green
