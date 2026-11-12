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
function Quarantine { (Invoke-Svc quarantine | Out-String | ConvertFrom-Json).data }
function Hex($Request) { -join ([Text.Encoding]::UTF8.GetBytes(($Request | ConvertTo-Json -Depth 8 -Compress)) | ForEach-Object { $_.ToString("x2") }) }
# Any IPC request; returns the response's data (throws on an error response).
function Req($Request) {
    $r = (Invoke-Svc request (Hex $Request)) | Out-String | ConvertFrom-Json
    if ($r.type -eq "error") { throw "request $($Request.type) failed: $($r.data.message)" }
    $r.data
}
function Task-Enabled([string]$Name) { "$(([xml](schtasks /Query /TN $Name /XML | Out-String)).Task.Settings.Enabled)" -ne "false" }
function Invoke-Elevated($Request) {
    $json = $Request | ConvertTo-Json -Depth 8 -Compress
    $hex = -join ([Text.Encoding]::UTF8.GetBytes($json) | ForEach-Object { $_.ToString("x2") })
    Invoke-Svc elevated-request $hex | Out-Host
}
function Wait-Until([scriptblock]$Condition, [string]$What, [int]$Seconds = 60) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try { if (& $Condition) { Write-Host "PASS: $What" -ForegroundColor Green; return } } catch { }
        Start-Sleep -Milliseconds 500
    }
    throw "FAIL (timeout): $What"
}
$writeLoad = (Resolve-Path "target/release/examples/write_load.exe").Path
# Terminate quarantines a writer's executable, so every test runs its own copy.
function New-Writer([string]$Name) { $dst = Join-Path $work $Name; Copy-Item $writeLoad $dst -Force; $dst }
# Network Guard: a connection to the blocked TEST-NET range must be refused by WFP (WSAEACCES = 10013).
function Assert-Blocked([string]$When) {
    $client = New-Object System.Net.Sockets.TcpClient
    $code = 0
    try { $client.ConnectAsync("192.0.2.1", 443).Wait(5000) | Out-Null } catch { $code = $_.Exception.InnerException.InnerException.ErrorCode; if (-not $code) { $code = $_.Exception.InnerException.ErrorCode } }
    $client.Dispose()
    if ($code -ne 10013) { throw "FAIL: blocked range not refused by WFP $When (error $code; 10013 expected)" }
    Write-Host "PASS: connection to blocked range refused instantly $When (WSAEACCES)" -ForegroundColor Green
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
    $startupExe = Join-Path $work "startup-agent.exe"
    $startupHash = New-UniqueCopy "$env:SystemRoot\System32\PING.EXE" $startupExe
    $taskExe = Join-Path $work "task-agent.exe"
    $taskHash = New-UniqueCopy "$env:SystemRoot\System32\PING.EXE" $taskExe

    New-Item -ItemType Directory -Force "$data\signatures" | Out-Null
    @{ name = "smoke-test"; version = "1"; signatures = @(
        @{ sha256 = $fileHash; name = "Smoke.File"; severity = "high" },
        @{ sha256 = $procHash; name = "Smoke.Process"; severity = "critical" },
        @{ sha256 = $startupHash; name = "Smoke.Startup"; severity = "high" },
        @{ sha256 = $taskHash; name = "Smoke.Task"; severity = "high" }) } |
        ConvertTo-Json -Depth 4 | Set-Content "$data\signatures\smoke.json" -Encoding ascii
    # Network Guard test entry: TEST-NET-1 (RFC 5737), never routed on the internet.
    New-Item -ItemType Directory -Force "$data\network" | Out-Null
    Set-Content "$data\network\blocklist.txt" "192.0.2.0/24" -Encoding ascii
    $downloads = Join-Path $env:USERPROFILE "Downloads"
    New-Item -ItemType Directory -Force $downloads | Out-Null
    # Existing documents for the encryption-burst test (ransomware rewrites files
    # that already exist; brand-new files being written are extractions/downloads).
    $burst = Join-Path $env:USERPROFILE "Documents\sentinel-entropy-test"
    foreach ($n in 0..99) {
        $dir = Join-Path $burst "folder$($n % 4)"; New-Item -ItemType Directory -Force $dir | Out-Null
        Set-Content (Join-Path $dir "report$n.txt") ("Quarterly report $n. " * 400) -Encoding ascii
    }

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

    # --- File Check: on-demand inspection reports, changes nothing ------------------
    $fc = Join-Path $work "filecheck"; New-Item -ItemType Directory -Force $fc | Out-Null
    Copy-Item $payload (Join-Path $fc "known.bin")
    $trick = Join-Path $fc "invoice.pdf.exe"
    Set-Content $trick "just some bytes" -Encoding ascii
    Set-Content -Path $trick -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://files.example.test/invoice.pdf.exe"
    $reports = (Invoke-Svc inspect $fc | Out-String | ConvertFrom-Json).data.reports
    $reports | Format-Table verdict, summary -AutoSize | Out-Host
    $known = $reports | Where-Object { $_.path -like "*known.bin" }
    $trickR = $reports | Where-Object { $_.path -like "*invoice.pdf.exe" }
    if ($known.verdict -ne "malicious") { throw "FAIL: File Check verdict for known malware: $($known.verdict)" }
    if ($trickR.verdict -ne "suspicious") { throw "FAIL: File Check verdict for double extension: $($trickR.verdict)" }
    if ($trickR.downloaded_from -ne "https://files.example.test/invoice.pdf.exe") { throw "FAIL: Mark of the Web not read: '$($trickR.downloaded_from)'" }
    if (-not ((Test-Path (Join-Path $fc "known.bin")) -and (Test-Path $trick))) { throw "FAIL: File Check changed files" }
    Write-Host "PASS: File Check reported malicious / suspicious (with download origin) without touching files" -ForegroundColor Green

    # --- Archive scanning: payload inside a ZIP dropped in Downloads -----------------
    $zipSrc = Join-Path $work "zipsrc"; New-Item -ItemType Directory -Force $zipSrc | Out-Null
    Copy-Item $payload (Join-Path $zipSrc "invoice.pdf.exe")
    Compress-Archive -Path "$zipSrc\*" -DestinationPath (Join-Path $work "delivery.zip") -Force
    $zipDrop = Join-Path $downloads "delivery.zip"
    Copy-Item (Join-Path $work "delivery.zip") $zipDrop
    Wait-Until { -not (Test-Path $zipDrop) -and (Events | Where-Object { $_.title -like "*inside delivery.zip/invoice.pdf.exe*" }) } "archive scanning quarantined a ZIP with a malicious member"

    # --- Ransomware decoys: unsigned heavy writer + decoy modified -> suspended -------
    $decoy = Join-Path $env:USERPROFILE "Documents\!_Accounts_2026.xlsx"
    Wait-Until { Test-Path -LiteralPath $decoy } "ransomware decoys planted in Documents"
    $load = Start-Process (New-Writer "writer-decoy.exe") -ArgumentList "90" -PassThru -WindowStyle Hidden
    Start-Sleep 2
    $fs = [IO.File]::Open($decoy, "Open", "Write"); $fs.SetLength(0)
    $junk = [Text.Encoding]::ASCII.GetBytes("ENCRYPTED " * 100); $fs.Write($junk, 0, $junk.Length); $fs.Close()
    Wait-Until { Events | Where-Object { $_.kind -eq "process_suspended" -and $_.pid -eq $load.Id } } "decoy change suspended the heavy writer (pid $($load.Id))" 30
    # A thread still taking the suspend APC briefly reports "Executive"; give it a moment.
    $reasons = $null
    for ($i = 0; $i -lt 25; $i++) {
        $reasons = @((Get-Process -Id $load.Id).Threads | ForEach-Object { "$($_.WaitReason)" })
        if (-not ($reasons | Where-Object { $_ -ne "Suspended" })) { break }
        Start-Sleep -Milliseconds 200
    }
    if ($reasons | Where-Object { $_ -ne "Suspended" }) { throw "FAIL: writer not actually suspended (wait reasons: $($reasons -join ', '))" }
    Invoke-Elevated @{ type = "process_action"; data = @{ pid = $load.Id; action = "terminate" } }
    Wait-Until { $load.HasExited } "Terminate ended the suspended process" 15
    Wait-Until { Quarantine | Where-Object { $_.threat_name -eq "Behavior.Ransomware.Decoy" } } "its executable was quarantined"

    # --- Encryption burst (entropy) suspends the heavy writer ------------------------
    Start-Sleep 16   # decoy and entropy responses share a 15 s debounce
    # Not ransomware: an updater unpacking in Temp, and an archive extracted into
    # Documents (many brand-new files across folders). Neither may raise an alert.
    $before = @(Events | Where-Object { $_.title -like "Possible ransomware*" }).Count
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    foreach ($root in (Join-Path $env:TEMP "vigil-unpack-test"), (Join-Path $env:USERPROFILE "Documents\vigil-extract-test")) {
        foreach ($n in 0..99) {
            $dir = Join-Path $root "part$($n % 6)"; New-Item -ItemType Directory -Force $dir | Out-Null
            $bytes = New-Object byte[] 8192; $rng.GetBytes($bytes)
            [IO.File]::WriteAllBytes((Join-Path $dir "chunk$n.bin"), $bytes)
        }
    }
    Start-Sleep 4
    if (@(Events | Where-Object { $_.title -like "Possible ransomware*" -or $_.title -eq "Ransomware behaviour: files are being encrypted" }).Count -gt $before) {
        throw "FAIL: unpacking / extracting new files was reported as ransomware"
    }
    Write-Host "PASS: updater unpacking in Temp and archive extraction were not flagged" -ForegroundColor Green
    Remove-Item (Join-Path $env:TEMP "vigil-unpack-test"), (Join-Path $env:USERPROFILE "Documents\vigil-extract-test") -Recurse -Force

    $load2 = Start-Process (New-Writer "writer-entropy.exe") -ArgumentList "90" -PassThru -WindowStyle Hidden
    Start-Sleep 2
    foreach ($n in 0..99) {   # "encrypt" the existing documents
        $bytes = New-Object byte[] 8192; $rng.GetBytes($bytes)
        [IO.File]::WriteAllBytes((Join-Path $burst "folder$($n % 4)\report$n.txt"), $bytes)
    }
    Wait-Until { Events | Where-Object { $_.title -eq "Ransomware behaviour: files are being encrypted" } } "encryption burst detected (entropy)" 20
    Wait-Until { Events | Where-Object { $_.kind -eq "process_suspended" -and $_.pid -eq $load2.Id } } "heavy writer suspended after the encryption burst" 20
    Invoke-Elevated @{ type = "process_action"; data = @{ pid = $load2.Id; action = "terminate" } }
    Remove-Item $burst -Recurse -Force

    # --- Startup clean-up: Run key removed with the file, restored with it -----------
    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    Set-ItemProperty $runKey -Name "SentinelSmoke" -Value "`"$startupExe`" -n 1 127.0.0.1"
    Invoke-Svc scan $startupExe | Out-Null
    if (Test-Path $startupExe) { throw "FAIL: startup agent not quarantined" }
    if ((Get-ItemProperty $runKey)."SentinelSmoke") { throw "FAIL: Run value still present" }
    Write-Host "PASS: Run-key entry removed together with the quarantined file" -ForegroundColor Green
    $item = Quarantine | Where-Object { $_.original_path -eq $startupExe } | Select-Object -First 1
    Invoke-Elevated @{ type = "restore_quarantine"; data = @{ id = $item.id } }
    Wait-Until { (Test-Path $startupExe) -and (Get-ItemProperty $runKey)."SentinelSmoke" } "restore put the file and its Run-key entry back"
    Remove-ItemProperty $runKey -Name "SentinelSmoke"

    # --- Scheduled Tasks: new task reported, its program quarantined, task disabled ---
    $taskName = "VigilSmokeTask"
    schtasks /Create /TN $taskName /TR "`"$taskExe`" -n 1 127.0.0.1" /SC ONLOGON /RU SYSTEM /F | Out-Host
    Wait-Until { Events | Where-Object { $_.title -eq "New scheduled task" -and $_.path -eq "\$taskName" } } "Persistence Watch reported the new scheduled task" 90
    Wait-Until { -not (Test-Path $taskExe) } "the task's program was scanned and quarantined" 30
    Wait-Until { -not (Task-Enabled $taskName) } "startup clean-up disabled the task" 30
    $item = Quarantine | Where-Object { $_.original_path -eq $taskExe } | Select-Object -First 1
    Invoke-Elevated @{ type = "restore_quarantine"; data = @{ id = $item.id } }
    Wait-Until { (Test-Path $taskExe) -and (Task-Enabled $taskName) } "restoring the file re-enabled its task"
    Invoke-Elevated @{ type = "disable_task"; data = @{ name = "\$taskName" } }
    Wait-Until { -not (Task-Enabled $taskName) } "Disable task (dashboard button path) works"
    schtasks /Delete /TN $taskName /F | Out-Null

    # --- Backups: commands that delete shadow copies are stopped -------------------
    # (echo only: nothing is really deleted even if the rule failed)
    Start-Process "$env:SystemRoot\System32\cmd.exe" -ArgumentList "/c", "echo vssadmin delete shadows /all /quiet & ping -n 20 127.0.0.1 > nul" -WindowStyle Hidden
    Wait-Until { Events | Where-Object { $_.title -eq "Blocked an attempt to delete backups" } } "Process Guard blocked a shadow-copy deletion command" 15

    # --- Ransomware rollback: snapshot, "encrypt" + delete, preview, restore --------
    $rb = Join-Path $env:USERPROFILE "Documents\vigil-rollback-test"
    New-Item -ItemType Directory -Force $rb | Out-Null
    $report = Join-Path $rb "report.txt"; $gone = Join-Path $rb "gone.txt"
    Set-Content $report ("quarterly figures " * 2000) -Encoding ascii
    Set-Content $gone "keep me" -Encoding ascii
    Start-Sleep 2
    Req @{ type = "create_snapshot" } | Out-Null
    $snap = (Req @{ type = "list_snapshots" }) | Where-Object { $_.ours } | Select-Object -First 1
    if (-not $snap) { throw "FAIL: no rollback snapshot listed after create_snapshot" }
    Write-Host "PASS: rollback snapshot taken ($($snap.id), $($snap.volume))" -ForegroundColor Green
    $bytes = New-Object byte[] 65536; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    [IO.File]::WriteAllBytes($report, $bytes)
    Remove-Item $gone
    $preview = Req @{ type = "rollback_preview"; data = @{ snapshot_id = $snap.id; folders = @($rb) } }
    $preview.changes | Format-Table change, looks_encrypted, path -AutoSize | Out-Host
    if (-not ($preview.changes | Where-Object { $_.path -eq $report -and $_.looks_encrypted })) { throw "FAIL: encrypted file not flagged in the rollback preview" }
    if (-not ($preview.changes | Where-Object { $_.path -eq $gone -and $_.change -eq "deleted" })) { throw "FAIL: deleted file missing from the rollback preview" }
    Write-Host "PASS: rollback preview found the encrypted and the deleted file" -ForegroundColor Green
    Invoke-Elevated @{ type = "rollback_restore"; data = @{ snapshot_id = $snap.id; paths = @($report, $gone) } }
    if ((Get-Content $report -Raw) -notlike "quarterly figures*") { throw "FAIL: report.txt not restored" }
    if ((Get-Content $gone -Raw).Trim() -ne "keep me") { throw "FAIL: deleted file not restored" }
    $backup = Get-ChildItem (Join-Path $env:USERPROFILE "Vigil Restore Backup") -Recurse -Filter report.txt | Select-Object -First 1
    if (-not $backup -or (Get-Item $backup.FullName).Length -ne 65536) { throw "FAIL: the encrypted copy was not kept in the backup folder" }
    Write-Host "PASS: rollback restored both files and kept the replaced copy" -ForegroundColor Green
    Remove-Item $rb, (Join-Path $env:USERPROFILE "Vigil Restore Backup") -Recurse -Force

    # --- Privacy Monitor: camera use recorded by Windows -> notified ------------------
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $cam = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged\C:#sentinel-smoke#fake-cam.exe"
    New-Item $cam -Force | Out-Null
    New-ItemProperty $cam -Name LastUsedTimeStart -PropertyType QWord -Value ([DateTime]::UtcNow.ToFileTimeUtc()) -Force | Out-Null
    New-ItemProperty $cam -Name LastUsedTimeStop -PropertyType QWord -Value 0 -Force | Out-Null
    Wait-Until { Events | Where-Object { $_.kind -eq "device_access" -and $_.title -eq "Camera turned on by fake-cam.exe" } } "Privacy Monitor reported the camera turning on" 20
    Wait-Until { (Status).devices_in_use | Where-Object { $_.app -eq "fake-cam.exe" } } "dashboard status shows the camera in use"
    New-ItemProperty $cam -Name LastUsedTimeStop -PropertyType QWord -Value ([DateTime]::UtcNow.ToFileTimeUtc()) -Force | Out-Null
    Wait-Until { Events | Where-Object { $_.title -eq "Camera turned off by fake-cam.exe" } } "Privacy Monitor reported the camera turning off" 20
    Remove-Item $cam -Force

    # --- Network Guard: WFP refuses the connection immediately ----------------------
    Wait-Until { (Status).network_blocked_ranges -ge 1 } "Network Guard installed WFP filters"
    Assert-Blocked "after install"

    # --- Execution Guard: unsigned program from Downloads is stopped, then allowed --
    $tool = Join-Path $downloads "unsigned-tool.exe"
    Copy-Item $writeLoad $tool
    Start-Sleep 3   # let File Shield finish with the new file
    $p1 = Start-Process $tool -ArgumentList "30" -PassThru -WindowStyle Hidden
    Wait-Until { $p1.HasExited -and (Events | Where-Object { $_.title -eq "Blocked unsigned program from Downloads" }) } "Execution Guard stopped an unsigned program from Downloads" 15
    Invoke-Elevated @{ type = "trust_app"; data = @{ path = $tool } }
    Wait-Until { ((Invoke-Svc settings | Out-String | ConvertFrom-Json).data.trusted_apps | Where-Object { $_.path -eq $tool }) } "program added to trusted apps"
    Start-Sleep 2
    $p2 = Start-Process $tool -ArgumentList "30" -PassThru -WindowStyle Hidden
    Start-Sleep 4
    if ($p2.HasExited) { throw "FAIL: trusted program was still blocked" }
    Write-Host "PASS: trusted program runs" -ForegroundColor Green
    Stop-Process -Id $p2.Id -Force

    # --- Attack-surface rule: a document app launching a shell is stopped ----------
    $fakeWord = Join-Path $work "WINWORD.EXE"
    Copy-Item "$env:SystemRoot\System32\cmd.exe" $fakeWord
    Start-Process $fakeWord -ArgumentList "/c", "$env:SystemRoot\System32\cmd.exe /c ping -n 30 127.0.0.1 > nul" -WindowStyle Hidden
    Wait-Until { Events | Where-Object { $_.title -like "Blocked cmd.exe started by WINWORD.EXE" } } "attack-surface rule stopped cmd.exe launched by WINWORD.EXE" 15

    # --- Windows hardening report + LSA protection switch ----------------------------
    $h = (Status).hardening
    $h | Format-Table name, ok, fixable -AutoSize | Out-Host
    if (-not ($h | Where-Object id -eq "lsa_protection")) { throw "FAIL: hardening checks missing" }
    if (($h | Where-Object id -eq "lsa_protection").fixable) {
        Invoke-Elevated @{ type = "enable_hardening"; data = @{ id = "lsa_protection" } }
        if ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").RunAsPPL -ne 1) { throw "FAIL: RunAsPPL not set" }
    }
    Write-Host "PASS: hardening checks reported, LSA protection can be enabled" -ForegroundColor Green
    if ($null -eq (Status).cpu_percent) { [void](Status) }
    if ($null -eq (Status).cpu_percent) { throw "FAIL: resource meter has no CPU reading" }

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
    # The settings change restarted every shield, including Network Guard's WFP session.
    Wait-Until { (Status).network_blocked_ranges -ge 1 } "Network Guard reinstalled after the settings change"
    Assert-Blocked "after a settings change"

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
