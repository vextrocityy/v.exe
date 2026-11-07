<#
.SYNOPSIS
  Builds the Sentinel-Lite installer (NSIS) with the engine bundled.

.PARAMETER UpdatePubKeys
  Comma-separated Ed25519 public keys (hex) trusted for official signature packs.
  Generate with: sentinel-service keygen. Without it, only community feeds work.

.NOTES
  Code signing: set TAURI_SIGNING / bundle.windows.signCommand (see docs/RELEASING.md).
#>
param([string]$UpdatePubKeys = $env:SENTINEL_UPDATE_PUBKEYS)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    $triple = ((rustc -vV) | Select-String '^host: (.+)$').Matches[0].Groups[1].Value
    if ($UpdatePubKeys) {
        $env:SENTINEL_UPDATE_PUBKEYS = $UpdatePubKeys
    } else {
        Write-Warning "No SENTINEL_UPDATE_PUBKEYS: the official signed update channel will be disabled in this build."
    }

    cargo build --release --locked -p sentinel-service
    if ($LASTEXITCODE -ne 0) { throw "engine build failed" }

    $bin = "ui/src-tauri/binaries"
    New-Item -ItemType Directory -Force $bin | Out-Null
    Copy-Item "target/release/sentinel-service.exe" "$bin/sentinel-service-$triple.exe" -Force

    Push-Location ui
    npm ci
    if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
    npm run tauri build -- --config src-tauri/tauri.bundle.conf.json
    if ($LASTEXITCODE -ne 0) { throw "tauri build failed" }
    Pop-Location

    Get-ChildItem "target/release/bundle/nsis/*.exe" | ForEach-Object { Write-Host "Installer: $($_.FullName)" }
} finally {
    Pop-Location
}
