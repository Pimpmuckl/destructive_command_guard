#!/usr/bin/env pwsh
# Tests Configure-CopilotHook from install.ps1: repo-local .github/hooks/dcg.json
# with preToolUse[] entries carrying bash+powershell platform fields. Verifies
# create/idempotent/merge, field-level dedup (preserves a coexisting platform
# hook sharing an entry with dcg), and no_repo.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}
function New-TempRepo {
    $r = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_copilot_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $r | Out-Null
    $r
}
$dcgPath = 'C:\Users\me\.local\bin\dcg.exe'

Write-Host "Test 1: create (bash+powershell+cwd+timeoutSec) + idempotent"
$r1 = New-TempRepo
try {
    $s = Configure-CopilotHook -DcgPath $dcgPath -RepoRoot $r1
    Check ($s -eq 'created') "create returns 'created' (got '$s')"
    $f = Join-Path $r1 '.github/hooks/dcg.json'
    Check (Test-Path $f) "repo-local .github/hooks/dcg.json created"
    $p = Get-Content -Raw $f | ConvertFrom-Json
    Check ($p.version -eq 1) "version=1"
    $e = $p.hooks.preToolUse[0]
    Check ($e.bash -eq $dcgPath) "bash field = dcg path"
    Check ($e.powershell -eq $dcgPath) "powershell field = dcg path (Windows support)"
    Check ($e.cwd -eq '.') "cwd = ."
    Check ($e.timeoutSec -eq 30) "timeoutSec = 30"
    $s2 = Configure-CopilotHook -DcgPath $dcgPath -RepoRoot $r1
    Check ($s2 -eq 'already') "idempotent returns 'already' (got '$s2')"
} finally { Remove-Item -Recurse -Force $r1 -ErrorAction SilentlyContinue }

Write-Host "Test 2: merge - field-level dedup preserves a coexisting platform hook"
$r2 = New-TempRepo
try {
    $hookDir = Join-Path $r2 '.github/hooks'; New-Item -ItemType Directory -Path $hookDir -Force | Out-Null
    $existing = [ordered]@{
        version = 1
        hooks = [ordered]@{
            preToolUse = @(
                [ordered]@{ type = 'command'; bash = '/old/bin/dcg'; powershell = 'my-formatter' },
                [ordered]@{ type = 'command'; bash = 'linter'; powershell = 'linter.exe' }
            )
        }
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $hookDir 'dcg.json')
    $s = Configure-CopilotHook -DcgPath $dcgPath -RepoRoot $r2
    Check ($s -eq 'merged') "returns 'merged' (got '$s')"
    $p = Get-Content -Raw (Join-Path $hookDir 'dcg.json') | ConvertFrom-Json
    Check ($p.hooks.preToolUse[0].bash -eq $dcgPath) "canonical dcg entry prepended (first)"
    # the entry that had bash=dcg + powershell=my-formatter: bash stripped, powershell kept
    $kept = @($p.hooks.preToolUse | Where-Object { $_.powershell -eq 'my-formatter' })[0]
    Check ($null -ne $kept) "entry with non-dcg powershell preserved"
    Check ($null -eq $kept.PSObject.Properties['bash']) "the dcg 'bash' field was stripped from that entry"
    # the fully-coexisting linter entry preserved intact
    $linter = @($p.hooks.preToolUse | Where-Object { $_.powershell -eq 'linter.exe' })[0]
    Check (($null -ne $linter) -and ($linter.bash -eq 'linter')) "coexisting non-dcg entry preserved intact"
} finally { Remove-Item -Recurse -Force $r2 -ErrorAction SilentlyContinue }

Write-Host "Test 3: no_repo when not in a git repo and no -RepoRoot"
$savedPath = $env:PATH
try {
    $env:PATH = ''  # git not discoverable
    $s = Configure-CopilotHook -DcgPath $dcgPath
    Check ($s -eq 'no_repo') "returns 'no_repo' (got '$s')"
} finally { $env:PATH = $savedPath }

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All Configure-CopilotHook tests passed." -ForegroundColor Green
