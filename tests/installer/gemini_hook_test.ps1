#!/usr/bin/env pwsh
# Tests Configure-GeminiHook from install.ps1 (BeforeTool / run_shell_command
# hook shape with name+timeout). Dot-sources install.ps1 -LoadFunctionsOnly.

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}
function New-TempHome {
    $h = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_gemini_test_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $h | Out-Null
    $h
}
function Test-NoBom([string]$path) {
    $b = [System.IO.File]::ReadAllBytes($path)
    -not ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
}

$dcgPath = 'C:\Users\me\.local\bin\dcg.exe'

Write-Host "Test 1: create (BeforeTool/run_shell_command, name+timeout) + idempotent"
$h1 = New-TempHome
try {
    $status = Configure-GeminiHook -DcgPath $dcgPath -Force -HomeDir $h1
    Check ($status -eq 'created') "create returns 'created' (got '$status')"
    $settings = Join-Path $h1 '.gemini/settings.json'
    Check (Test-Path $settings) "settings.json created"
    Check (Test-NoBom $settings) "no UTF-8 BOM"
    $p = Get-Content -Raw $settings | ConvertFrom-Json
    $entry = @($p.hooks.BeforeTool | Where-Object { $_.matcher -eq 'run_shell_command' })[0]
    Check ($null -ne $entry) "BeforeTool/run_shell_command entry present"
    Check ($entry.hooks[0].command -eq $dcgPath) "dcg command set"
    Check ($entry.hooks[0].name -eq 'dcg') "name=dcg present (Gemini shape)"
    Check ($entry.hooks[0].timeout -eq 5000) "timeout=5000 present (Gemini shape)"
    $status2 = Configure-GeminiHook -DcgPath $dcgPath -Force -HomeDir $h1
    Check ($status2 -eq 'already') "idempotent returns 'already' (got '$status2')"
} finally { Remove-Item -Recurse -Force $h1 -ErrorAction SilentlyContinue }

Write-Host "Test 2: merge preserves a coexisting Gemini hook + unrelated agy file untouched"
$h2 = New-TempHome
try {
    $gdir = Join-Path $h2 '.gemini'; New-Item -ItemType Directory -Path $gdir | Out-Null
    # An unrelated agy config under .gemini/config must NOT be touched.
    $agyDir = Join-Path $gdir 'config'; New-Item -ItemType Directory -Path $agyDir | Out-Null
    Set-Content -Path (Join-Path $agyDir 'hooks.json') -Value '{"agy":"keep"}'
    $existing = [ordered]@{
        hooks = [ordered]@{
            BeforeTool = @([ordered]@{ matcher = 'run_shell_command'; hooks = @([ordered]@{ name='other'; type='command'; command='other-tool' }) })
        }
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $gdir 'settings.json')
    $status = Configure-GeminiHook -DcgPath $dcgPath -Force -HomeDir $h2
    Check ($status -eq 'merged') "returns 'merged' (got '$status')"
    $p = Get-Content -Raw (Join-Path $gdir 'settings.json') | ConvertFrom-Json
    $entry = @($p.hooks.BeforeTool | Where-Object { $_.matcher -eq 'run_shell_command' })[0]
    Check ($entry.hooks[0].command -eq $dcgPath) "dcg hoisted first"
    Check ((@($entry.hooks | ForEach-Object { $_.command })) -contains 'other-tool') "coexisting hook preserved"
    Check ((Get-Content -Raw (Join-Path $agyDir 'hooks.json')).Trim() -eq '{"agy":"keep"}') "agy config/hooks.json untouched"
} finally { Remove-Item -Recurse -Force $h2 -ErrorAction SilentlyContinue }

Write-Host "Test 3: skip when ~/.gemini absent and not -Force"
$h3 = New-TempHome
$savedPath = $env:PATH
try {
    $env:PATH = ''
    $status = Configure-GeminiHook -DcgPath $dcgPath -HomeDir $h3
    Check ($status -eq 'skipped') "returns 'skipped' (got '$status')"
} finally { $env:PATH = $savedPath; Remove-Item -Recurse -Force $h3 -ErrorAction SilentlyContinue }

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All Configure-GeminiHook tests passed." -ForegroundColor Green
