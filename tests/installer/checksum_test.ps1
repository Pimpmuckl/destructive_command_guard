#!/usr/bin/env pwsh
# Tests install.ps1 checksum hardening (.4.4): Test-Sha256Token (64-hex),
# Get-SiblingUrl, Resolve-ChecksumToken (per-file .sha256 -> SHA256SUMS.txt ->
# SHA256SUMS fallback, filename row match, junk rejection), and the minisign
# release-trust path. Uses local files.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}
function Set-MinisignApplicationMock([string]$Directory, [int]$ExitCode) {
    if ($env:OS -eq 'Windows_NT') {
        $path = Join-Path $Directory 'minisign.cmd'
        $body = "@echo off`r`necho %* > `"%DCG_MINISIGN_ARGS_FILE%`"`r`nexit /b $ExitCode`r`n"
        Set-Content -LiteralPath $path -Value $body -Encoding ascii -NoNewline
    } else {
        $path = Join-Path $Directory 'minisign'
        $body = "#!/bin/sh`nprintf '%s\n' `"`$*`" > `"`$DCG_MINISIGN_ARGS_FILE`"`nexit $ExitCode`n"
        Set-Content -LiteralPath $path -Value $body -Encoding ascii -NoNewline
        & chmod +x $path
        if ($LASTEXITCODE -ne 0) { throw "could not make mock minisign executable" }
    }
    return $path
}
$HASH = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"  # 64 hex
$OTHER = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

Write-Host "Test 1: Test-Sha256Token"
Check (Test-Sha256Token $HASH) "accepts a 64-hex token"
Check (Test-Sha256Token ($HASH.ToUpper())) "accepts upper-case hex"
Check (-not (Test-Sha256Token "deadbeef")) "rejects too-short"
Check (-not (Test-Sha256Token ($HASH + "0"))) "rejects too-long (65)"
Check (-not (Test-Sha256Token ($HASH.Substring(0,63) + "g"))) "rejects non-hex char"
Check (-not (Test-Sha256Token "")) "rejects empty"

Write-Host "Test 2: Convert-ContentToText decodes byte-array sidecars"
$bytes = [System.Text.Encoding]::UTF8.GetBytes("$HASH  dcg-x86_64-pc-windows-msvc.zip`n")
$decoded = (Convert-ContentToText -Content $bytes).Trim().Split(' ')[0]
Check ($decoded -eq $HASH) "decodes GitHub release .sha256 byte[] content"

Write-Host "Test 3: Get-SiblingUrl (http + file:// + local path)"
Check ((Get-SiblingUrl -Url "https://h/a/b/dcg.zip" -Leaf "SHA256SUMS.txt") -eq "https://h/a/b/SHA256SUMS.txt") "http sibling"
Check ((Get-SiblingUrl -Url "file:///x/y/dcg.zip" -Leaf "SHA256SUMS") -eq "file:///x/y/SHA256SUMS") "file:// sibling"
Check ((Get-SiblingUrl -Url "/x/y/dcg.zip" -Leaf "S") -eq "/x/y/S") "local-path sibling"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_csum_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$savedPath = $env:PATH
try {
    $zip = Join-Path $tmp "dcg-x86_64-pc-windows-msvc.zip"
    Set-Content -LiteralPath $zip -Value "ZIP" -NoNewline

    Write-Host "Test 4: per-file .sha256 is the primary path"
    Set-Content -LiteralPath "$zip.sha256" -Value "$HASH  dcg-x86_64-pc-windows-msvc.zip" -NoNewline
    Check ((Resolve-ChecksumToken -ArtifactUrl $zip -PerFileUrl "$zip.sha256") -eq $HASH) "resolves from per-file .sha256"
    Remove-Item -LiteralPath "$zip.sha256" -Force

    Write-Host "Test 5: fallback to SHA256SUMS.txt, selecting the matching filename row"
    $manifest = @(
        "$OTHER  some-other-file.tar.xz",
        "$HASH *dcg-x86_64-pc-windows-msvc.zip",   # coreutils binary marker '*'
        "deadbeef  malformed-line"
    ) -join "`n"
    Set-Content -LiteralPath (Join-Path $tmp "SHA256SUMS.txt") -Value $manifest
    # per-file absent -> falls through to the manifest
    Check ((Resolve-ChecksumToken -ArtifactUrl $zip -PerFileUrl "$zip.sha256") -eq $HASH) "picks the matching row from SHA256SUMS.txt"
    Remove-Item -LiteralPath (Join-Path $tmp "SHA256SUMS.txt") -Force

    Write-Host "Test 6: fallback to bare SHA256SUMS"
    Set-Content -LiteralPath (Join-Path $tmp "SHA256SUMS") -Value "$HASH  dcg-x86_64-pc-windows-msvc.zip"
    Check ((Resolve-ChecksumToken -ArtifactUrl $zip -PerFileUrl "$zip.sha256") -eq $HASH) "picks row from bare SHA256SUMS"
    Remove-Item -LiteralPath (Join-Path $tmp "SHA256SUMS") -Force

    Write-Host "Test 7: junk per-file content is rejected (no valid token -> throws)"
    Set-Content -LiteralPath "$zip.sha256" -Value "not-a-real-hash" -NoNewline
    $threw = $false
    try { Resolve-ChecksumToken -ArtifactUrl $zip -PerFileUrl "$zip.sha256" | Out-Null } catch { $threw = $true }
    Check $threw "junk .sha256 with no manifest fallback throws"

    Write-Host "Test 8: missing minisign sidecar is optional unless explicitly required"
    $missingSignature = Join-Path $tmp "missing.minisig"
    $optionalThrew = $false
    try {
        Invoke-DcgMinisignVerification -ArtifactPath $zip -ArtifactSource $zip `
            -SignatureSource $missingSignature -TempDirectory $tmp
    } catch { $optionalThrew = $true }
    Check (-not $optionalThrew) "optional missing signature warns and continues"
    $requiredThrew = $false
    try {
        Invoke-DcgMinisignVerification -ArtifactPath $zip -ArtifactSource $zip `
            -SignatureSource $missingSignature -TempDirectory $tmp -Require
    } catch { $requiredThrew = $true }
    Check $requiredThrew "required missing signature is fatal"

    Write-Host "Test 9: present signature invokes an external minisign with the embedded public key"
    $signature = Join-Path $tmp "release.minisig"
    Set-Content -LiteralPath $signature -Value "signature" -NoNewline
    $mockBin = Join-Path $tmp "mock-bin"
    New-Item -ItemType Directory -Path $mockBin | Out-Null
    $env:DCG_MINISIGN_ARGS_FILE = Join-Path $tmp "minisign.args"
    Set-MinisignApplicationMock -Directory $mockBin -ExitCode 0 | Out-Null
    $env:PATH = "$mockBin$([System.IO.Path]::PathSeparator)$savedPath"
    $global:DcgMinisignFunctionWasCalled = $false
    function global:minisign { $global:DcgMinisignFunctionWasCalled = $true }
    $verifyThrew = $false
    try {
        Invoke-DcgMinisignVerification -ArtifactPath $zip -ArtifactSource $zip `
            -SignatureSource $signature -TempDirectory $tmp -Require
    } catch { $verifyThrew = $true }
    Check (-not $verifyThrew) "external mock minisign verifier succeeds"
    Check (-not $global:DcgMinisignFunctionWasCalled) "ignores a PowerShell function shim"
    $minisignArgs = Get-Content -Raw -LiteralPath $env:DCG_MINISIGN_ARGS_FILE
    Check ($minisignArgs -match '(?:^|\s)-Vm(?:\s|$)') "passes verify-message mode"
    Check ($minisignArgs -match '(?:^|\s)-P(?:\s|$)') "passes an explicit public key"
    Check ($minisignArgs -match 'RWSoYi6NXJWzaRs1mJmOwwXrZfPWcq6MXnQlNMLBYKzlIQTLwuVQG6uO') `
        "uses the embedded release key"

    Write-Host "Test 10: the retired minisign key is scoped to v0.6.7"
    $legacyThrew = $false
    try {
        Invoke-DcgMinisignVerification -ArtifactPath $zip -ArtifactSource $zip `
            -SignatureSource $signature -TempDirectory $tmp -ReleaseVersion "v0.6.7" -Require
    } catch { $legacyThrew = $true }
    Check (-not $legacyThrew) "legacy release verification succeeds"
    $legacyArgs = Get-Content -Raw -LiteralPath $env:DCG_MINISIGN_ARGS_FILE
    Check ($legacyArgs -match 'RWTQoKUb0Ue4NsqTpPWnABCrIU0\+m25zsMlbv6UcRClQ7jmRP3A7NmTB') `
        "uses the retired key only for v0.6.7"

    Write-Host "Test 11: patched cosign version floors reject vulnerable builds"
    Check (-not (Test-DcgPatchedCosignVersion -VersionJson '{"gitVersion":"v2.6.1"}')) `
        "rejects cosign 2.6.1"
    Check (Test-DcgPatchedCosignVersion -VersionJson '{"gitVersion":"v2.6.2"}') `
        "accepts cosign 2.6.2"
    Check (-not (Test-DcgPatchedCosignVersion -VersionJson '{"gitVersion":"v3.0.3"}')) `
        "rejects cosign 3.0.3"
    Check (Test-DcgPatchedCosignVersion -VersionJson '{"gitVersion":"v3.0.4"}') `
        "accepts cosign 3.0.4"
    Check (Test-DcgPatchedCosignVersion -VersionJson '{"gitVersion":"v3.1.2"}') `
        "accepts newer cosign 3.x"
    Check (-not (Test-DcgPatchedCosignVersion -VersionJson '{"gitVersion":"v3.0.4-rc.1"}')) `
        "rejects prerelease builds at the patched floor"
    Check (-not (Test-DcgPatchedCosignVersion -VersionJson '{"gitVersion":"devel"}')) `
        "rejects unknown development builds"

    Write-Host "Test 12: a present invalid minisign signature is always fatal"
    Set-MinisignApplicationMock -Directory $mockBin -ExitCode 1 | Out-Null
    $invalidThrew = $false
    try {
        Invoke-DcgMinisignVerification -ArtifactPath $zip -ArtifactSource $zip `
            -SignatureSource $signature -TempDirectory $tmp
    } catch { $invalidThrew = $true }
    Check $invalidThrew "invalid signature fails even without -RequireMinisign"

    Write-Host "Test 13: strict mode rejects a function shim when no external verifier exists"
    $emptyPath = Join-Path $tmp "empty-path"
    New-Item -ItemType Directory -Path $emptyPath | Out-Null
    $env:PATH = $emptyPath
    $shimThrew = $false
    try {
        Invoke-DcgMinisignVerification -ArtifactPath $zip -ArtifactSource $zip `
            -SignatureSource $signature -TempDirectory $tmp -Require
    } catch { $shimThrew = $true }
    Check $shimThrew "function shim cannot satisfy -RequireMinisign"
} finally {
    $env:PATH = $savedPath
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All checksum-resolution tests passed." -ForegroundColor Green
