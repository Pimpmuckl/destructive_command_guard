#!/usr/bin/env pwsh
# Tests Remove-DcgPredecessor from install.ps1: strips ONLY the legacy
# git_safety_guard hook entries from ~/.claude/settings.json (preserving the
# modern dcg hook + coexisting hooks) and removes the predecessor script.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}
function New-TempHome {
    $h = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_pred_test_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $h | Out-Null
    $h
}

$dcgPath = 'C:\Users\me\.local\bin\dcg.exe'

Write-Host "Test 1: removes ONLY the predecessor hook, keeps dcg + coexisting"
$h1 = New-TempHome
try {
    $cdir = Join-Path $h1 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    $existing = [ordered]@{
        hooks = [ordered]@{
            PreToolUse = @([ordered]@{ matcher = 'Bash'; hooks = @(
                [ordered]@{ type = 'command'; command = 'python3 ~/.claude/hooks/git_safety_guard.py' },
                [ordered]@{ type = 'command'; command = $dcgPath },
                [ordered]@{ type = 'command'; command = 'other-tool' }
            )})
        }
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $cdir 'settings.json')
    $removed = Remove-DcgPredecessor -HomeDir $h1
    Check ($removed -eq $true) "returns true when predecessor present"
    $p = Get-Content -Raw (Join-Path $cdir 'settings.json') | ConvertFrom-Json
    $cmds = @($p.hooks.PreToolUse[0].hooks | ForEach-Object { $_.command })
    Check (-not ($cmds | Where-Object { $_ -match 'git_safety_guard' })) "git_safety_guard hook removed"
    Check ($cmds -contains $dcgPath) "modern dcg hook preserved"
    Check ($cmds -contains 'other-tool') "coexisting hook preserved"
} finally { Remove-Item -Recurse -Force $h1 -ErrorAction SilentlyContinue }

Write-Host "Test 2: no predecessor -> returns false, unchanged"
$h2 = New-TempHome
try {
    $cdir = Join-Path $h2 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    $existing = [ordered]@{ hooks = [ordered]@{ PreToolUse = @([ordered]@{ matcher = 'Bash'; hooks = @([ordered]@{ type = 'command'; command = $dcgPath }) }) } }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $cdir 'settings.json')
    $removed = Remove-DcgPredecessor -HomeDir $h2
    Check ($removed -eq $false) "returns false when no predecessor"
    $p = Get-Content -Raw (Join-Path $cdir 'settings.json') | ConvertFrom-Json
    Check ($p.hooks.PreToolUse[0].hooks[0].command -eq $dcgPath) "dcg hook untouched"
} finally { Remove-Item -Recurse -Force $h2 -ErrorAction SilentlyContinue }

Write-Host "Test 3: removes the predecessor script file + empty hooks dir"
$h3 = New-TempHome
try {
    $hookDir = Join-Path (Join-Path $h3 '.claude') 'hooks'
    New-Item -ItemType Directory -Path $hookDir -Force | Out-Null
    Set-Content -Path (Join-Path $hookDir 'git_safety_guard.py') -Value '# legacy'
    $removed = Remove-DcgPredecessor -HomeDir $h3
    Check ($removed -eq $true) "returns true when predecessor script present"
    Check (-not (Test-Path (Join-Path $hookDir 'git_safety_guard.py'))) "predecessor script deleted"
    Check (-not (Test-Path $hookDir)) "empty hooks dir removed"
} finally { Remove-Item -Recurse -Force $h3 -ErrorAction SilentlyContinue }

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All Remove-DcgPredecessor tests passed." -ForegroundColor Green
