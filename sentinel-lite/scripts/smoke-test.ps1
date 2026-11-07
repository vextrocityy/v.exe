<#
.SYNOPSIS
  End-to-end test of the engine on real Windows (run elevated; used by CI).
  Installs the service, proves each shield works, checks hardening and
  footprint, then uninstalls. Uses unique test hashes (no real malware, and
  nothing that other antivirus products would react to).
#>
param([string]$Service = "target/release/sentinel-service.exe")
$ErrorActionPreference = "Stop"
$svc = (Resolve-Path $Service).Path
$data = Join-Path $env:ProgramData "SentinelLite"
$work = "C:\sentinel-smoke"

function Invoke-Svc { $out = & $svc @args; if ($LASTEXITCODE) { throw "sentinel-service $args failed: $out" }; $out }
function Status { (Invoke-Svc status | Out-String | ConvertFrom-Json).data }
function Events { (Invoke-Svc events 100 | Out-String | ConvertFrom-Json).data }
function Wait-Until([scriptblock]$Condition, [string]$What, [int]$Seconds = 60) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try { if (& $Condition) { Write-Host "PASS: $What" -ForegroundColor Green; return } } catch { }
        Start-Sleep -Milliseconds 500
    }
    throw "FAIL (timeout): $What"
}
function New-UniqueCopy([string]$From, [string]$To) {
    Copy-Item $From $To -Force
    $tag = [Text.Encoding]::ASCII.GetBytes("sentinel-smoke-" + [guid]::NewGuid())
    $fs = [IO.File]::Open($To, "Append"); $fs.Write($tag, 0, $tag.Length); $fs.Close()   # PE overlay: still runs
    (Get-FileHash $To -Algorithm SHA256).Hash.ToLower()
}

try {
    # --- test artefacts with hashes nobody else knows -------------------------------
    New-Item -ItemType Directory -Force $work | Out-Null
    $payload = Join-Path $work "payload.bin"
    [IO.File]::WriteAllText($payload, "sentinel smoke payload " + [guid]::NewGuid())
    $fileHash = (Get-FileHash $payload -Algorithm SHA256).Hash.ToLower()
    $procExe = Join-Path $work "smokeproc.exe"
    $procHash = New-UniqueCopy "$env:SystemRoot\System32\PING.EXE" $procExe

    New-Item -ItemType Directory -Force "$data\signatures" | Out-Null
    @{ name = "smoke-test"; version = "1"; signatures = @(
        @{ sha256 = $fileHash; name = "Smoke.File"; severity = "high" },
        @{ sha256 = $procHash; name = "Smoke.Process"; severity = "critical" }) } |
        ConvertTo-Json -Depth 4 | Set-Content "$data\signatures\smoke.json" -Encoding ascii
    $downloads = Join-Path $env:USERPROFILE "Downloads"
    New-Item -ItemType Directory -Force $downloads | Out-Null

    # --- install as a real service --------------------------------------------------
    Invoke-Svc install | Out-Host
    Wait-Until { (Status).shields.Count -ge 4 } "service running and answering on the named pipe"
    $st = Status
    $st.shields | Format-Table name, enabled, running, detail -AutoSize | Out-Host
    foreach ($s in $st.shields) { if (-not $s.running) { throw "FAIL: shield '$($s.name)' not running: $($s.detail)" } }
    if (-not ($st.shields | Where-Object name -eq "Process Guard").detail.StartsWith("ETW")) { throw "FAIL: Process Guard fell back to polling" }
    Write-Host "PASS: all shields running, Process Guard on ETW" -ForegroundColor Green
    if ($st.signature_count -lt 4) { throw "FAIL: signature packs not loaded ($($st.signature_count))" }

    # --- File Shield ----------------------------------------------------------------
    $dropped = Join-Path $downloads "smoke-dropped.bin"
    Copy-Item $payload $dropped
    Wait-Until { -not (Test-Path $dropped) -and (Status).quarantine_count -ge 1 } "File Shield quarantined a file dropped in Downloads"

    # --- YARA (bundled self-test rule, via File Shield) -----------------------------
    Wait-Until { (Status).yara_rule_count -ge 1 } "YARA rules loaded"
    $script = Join-Path $downloads "smoke-yara.ps1"
    Set-Content $script "Write-Host 'hello'`n# SENTINEL-LITE-YARA-TEST-MARKER-7f3c9a" -Encoding ascii
    Wait-Until { -not (Test-Path $script) -and (Events | Where-Object { $_.title -like "YARA.Sentinel_SelfTest_Marker*" }) } "YARA rule match quarantined by File Shield"

    # --- Process Guard --------------------------------------------------------------
    Start-Process $procExe -ArgumentList "-n", "60", "127.0.0.1" -WindowStyle Hidden
    Wait-Until { Events | Where-Object { $_.title -like "*Smoke.Process*" } } "Process Guard detected the process at launch"
    Wait-Until { -not (Get-Process smokeproc -ErrorAction SilentlyContinue) } "Process Guard terminated it" 15

    # --- On-demand scan -------------------------------------------------------------
    $scanDir = Join-Path $work "scan"; New-Item -ItemType Directory -Force $scanDir | Out-Null
    Copy-Item $payload (Join-Path $scanDir "nested.bin")
    # start via the one-shot CLI path to exercise the scanner directly as well
    Invoke-Svc scan $scanDir | Out-Host
    if (Test-Path (Join-Path $scanDir "nested.bin")) { throw "FAIL: on-demand scan did not quarantine" }
    Write-Host "PASS: on-demand scan quarantined nested file" -ForegroundColor Green

    # --- Elevated settings path (what the dashboard uses after UAC) ----------------
    $settings = (Invoke-Svc settings | Out-String | ConvertFrom-Json).data
    $settings.exclusions = @("C:\sentinel-smoke-excluded")
    $settings.auto_update = $false      # keep the footprint measurement below free of background work
    $settings.scheduled_scan = $false
    if ($env:ABUSECH_AUTH_KEY) { $settings.abusech_auth_key = $env:ABUSECH_AUTH_KEY }
    $json = @{ type = "update_settings"; data = @{ settings = $settings } } | ConvertTo-Json -Depth 8 -Compress
    $hex = -join ([Text.Encoding]::UTF8.GetBytes($json) | ForEach-Object { $_.ToString("x2") })
    Invoke-Svc elevated-request $hex | Out-Host
    Wait-Until { (Invoke-Svc settings | Out-String | ConvertFrom-Json).data.exclusions -contains "C:\sentinel-smoke-excluded" } "elevated settings change applied"

    # --- YARA Forge feed: download, validate, compile; restart to load ----------------
    $out = & $svc update 2>&1 | Out-String
    if ($out -notmatch "YARA rules (updated|already current)") { throw "FAIL: YARA Forge feed update: $out" }
    Write-Host "PASS: YARA Forge rules downloaded and compiled" -ForegroundColor Green
    Invoke-Svc stop | Out-Host
    Invoke-Svc start | Out-Host
    Wait-Until { (Status).yara_rule_count -gt 1000 } "service loaded the full YARA rule set" 120
    Write-Host "      rules active: $((Status).yara_rule_count)"

    # --- False-positive survey: YARA Forge vs. clean Windows binaries (report only) --
    $fpDir = Join-Path $work "fp"; New-Item -ItemType Directory -Force $fpDir | Out-Null
    Get-ChildItem "$env:SystemRoot\System32\*.exe" | Select-Object -First 400 | Copy-Item -Destination $fpDir -ErrorAction SilentlyContinue
    $survey = & $svc yara-check "$data\rules\feeds" $fpDir 2>&1 | Out-String
    $survey.Trim().Split("`n") | Select-Object -Last 15 | Out-Host
    $fp = ([regex]::Matches($survey, "(?m)^MATCH ")).Count
    if ($fp -gt 0) { Write-Host "::warning::YARA Forge matched $fp clean System32 executable(s); these are never auto-quarantined (system/signed gate), review the rules above" }
    else { Write-Host "PASS: no YARA matches on clean System32 executables" -ForegroundColor Green }

    # --- Live community feed (needs the ABUSECH_AUTH_KEY secret) --------------------
    if ($env:ABUSECH_AUTH_KEY) {
        $out = & $svc update 2>&1 | Out-String
        if ($out -notmatch "MalwareBazaar: \d+ hashes") { throw "FAIL: community feed update: $out" }
        if ($out -match [regex]::Escape($env:ABUSECH_AUTH_KEY)) { throw "FAIL: Auth-Key leaked into output" }
        Write-Host "PASS: community feed update: $($out.Trim().Split("`n")[-1])" -ForegroundColor Green
    } else {
        Write-Warning "ABUSECH_AUTH_KEY secret not set: skipping the live community-feed check"
    }

    # --- Hardening ------------------------------------------------------------------
    $open = (Get-Acl $data).Access | Where-Object { $_.IdentityReference -match "\\Users$|Everyone|Authenticated Users" }
    if ($open) { throw "FAIL: data directory grants access to: $($open.IdentityReference -join ', ')" }
    Write-Host "PASS: data directory restricted to SYSTEM and Administrators" -ForegroundColor Green

    # --- Footprint ------------------------------------------------------------------
    Start-Sleep 5
    $p = Get-Process sentinel-service | Where-Object { $_.Path -eq $svc } | Select-Object -First 1
    $cpu0 = $p.TotalProcessorTime; Start-Sleep 20; $p.Refresh()
    $cpuPct = ($p.TotalProcessorTime - $cpu0).TotalMilliseconds / 20000 / [Environment]::ProcessorCount * 100
    $mb = $p.WorkingSet64 / 1MB
    "Idle CPU: {0:N2} %   Working set: {1:N1} MB" -f $cpuPct, $mb | Out-Host
    if ($mb -gt 150) { throw "FAIL: working set over 150 MB budget" }
    if ($cpuPct -gt 1) { throw "FAIL: idle CPU over 1 % budget" }
    Write-Host "PASS: within resource budget" -ForegroundColor Green
}
finally {
    Write-Host "--- recent events ---"
    try { Events | Select-Object -First 25 | Format-Table severity, kind, title, path -AutoSize | Out-Host } catch { }
    Write-Host "--- service log tail ---"
    Get-Content "$data\logs\service.log" -Tail 40 -ErrorAction SilentlyContinue | Out-Host
    & $svc uninstall | Out-Host
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
