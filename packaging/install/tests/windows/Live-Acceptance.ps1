# Acceptance of a PUBLISHED release on Windows: the real install.ps1, as a user runs it, against the real
# manifest and the real release, into a temporary prefix and data directory.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File Live-Acceptance.ps1 [-InstallerUrl URL] [-Version X.Y.Z] [-OlderVersion X.Y.Z]
#   pwsh       -NoProfile -ExecutionPolicy Bypass -File Live-Acceptance.ps1 ...
#
# Run it once under Windows PowerShell 5.1 and once under PowerShell 7: the installer is started by the same
# host that runs this script, so each run tests that host. Defaults to https://yadori.link/install.ps1. This
# is the counterpart of live-acceptance.sh and of Run-Acceptance.ps1 (which runs the same installer against a
# local fixture release). The prefix, the data directory and the downloaded installer live under one
# temporary directory that is removed at the end; the user PATH is never touched (-NoModifyPath), and the
# machine's own YadoriLink install and data directory are not read (YADORILINK_CONFIG_DIR points into the
# temporary directory). Python (its sqlite3 module) crafts the test databases; without it those cases are
# skipped, not failed. A daemon is not started. Prints `ok`/`FAIL`/`skip` and `passed: N, failed: M, skipped: K`.
#
# Run it from an interactive console, or detached from the caller's pipes (a plain `ssh host powershell
# -File ...` can wait for end-of-output of a child it started).
param(
    [string]$InstallerUrl = 'https://yadori.link/install.ps1',
    [string]$Version = '',
    [string]$OlderVersion = '0.1.0-beta.8'
)

$ErrorActionPreference = 'Continue'
$PsExe = (Get-Process -Id $PID).Path
$T = Join-Path $env:TEMP ("yll-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $T | Out-Null
$Installer = Join-Path $T 'install.ps1'
$Prefix = Join-Path $T 'prefix'
$Cfg = Join-Path $T 'cfg'
New-Item -ItemType Directory -Force -Path $Cfg | Out-Null
$env:YADORILINK_CONFIG_DIR = $Cfg
$script:Pass = 0; $script:Fail = 0; $script:Skip = 0
$script:Out = ''; $script:Rc = 0
function Ok($m) { $script:Pass++; Write-Host "ok   $m" }
function Bad($m, $out) { $script:Fail++; Write-Host "FAIL $m"; if ($out) { ($out -split "`n") | Select-Object -First 8 | ForEach-Object { Write-Host "     | $_" } } }
function Skip($m) { $script:Skip++; Write-Host "skip $m" }
function Has($s) { $script:Out -like "*$s*" }

function Inst([string[]]$More) {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Installer, '-Prefix', $Prefix, '-Yes', '-NoModifyPath') + $More
    $script:Out = (& $PsExe @a 2>&1 | ForEach-Object { "$_" }) -join "`n"
    $script:Rc = $LASTEXITCODE
}
function Snapshot {
    $files = if (Test-Path $Prefix) { (Get-ChildItem $Prefix -Recurse -Force | ForEach-Object { $_.FullName.Substring($Prefix.Length) + ':' + $_.Length }) -join '|' } else { '' }
    $r = Join-Path $Prefix 'install-receipt.txt'
    $files + '#' + $(if (Test-Path $r) { Get-Content $r -Raw } else { '' })
}
function Receipt([string]$Key) {
    $r = Join-Path $Prefix 'install-receipt.txt'
    if (Test-Path $r) { foreach ($l in Get-Content $r) { if ($l -like "$Key=*") { return $l.Substring($Key.Length + 1) } } }
    return ''
}

try {
    Write-Host "PowerShell $($PSVersionTable.PSVersion) on $([Environment]::OSVersion.VersionString)   installer: $InstallerUrl"
    try { Invoke-WebRequest -UseBasicParsing -Uri $InstallerUrl -OutFile $Installer } catch { Write-Host "FAIL could not download $InstallerUrl : $_"; $script:Fail++; throw }

    # 1 the installer installs the published release
    Inst $(if ($Version) { @('-Version', $Version) } else { @() })
    if ($Rc -eq 0 -and (Has 'Manifest signature verified')) { Ok 'install.ps1 installs; the manifest signature verifies' } else { Bad "install (rc=$Rc)" $Out; throw 'install failed' }
    $Bin = Join-Path $Prefix 'bin'
    $Yl = Join-Path $Bin 'yadorilink.exe'
    $Dm = Join-Path $Bin 'yadorilink-daemon.exe'
    if ((Test-Path $Yl) -and (Test-Path $Dm)) { Ok 'yadorilink.exe and yadorilink-daemon.exe are in <prefix>\bin' } else { Bad 'programs in bin' }
    # nothing on stderr: a loader or runtime complaint would show on every command
    $err = Join-Path $T 'err.txt'
    $v = (& cmd.exe /c ('"{0}" --version 2> "{1}"' -f $Yl, $err)) -join ''
    if ($LASTEXITCODE -eq 0 -and $v -match 'yadorilink' -and -not ((Test-Path $err) -and (Get-Item $err).Length -gt 0)) { Ok "yadorilink.exe --version: $v (nothing on stderr)" } else { Bad "--version ($v)" $(if (Test-Path $err) { Get-Content $err -Raw }) }
    & cmd.exe /c ('"{0}" --version > nul 2> "{1}"' -f $Dm, $err)
    if ($LASTEXITCODE -eq 0 -and -not ((Test-Path $err) -and (Get-Item $err).Length -gt 0)) { Ok 'yadorilink-daemon.exe --version runs and prints nothing on stderr' } else { Bad 'daemon --version' $(if (Test-Path $err) { Get-Content $err -Raw }) }
    if ((Receipt 'install_source') -eq 'script') { Ok 'install-receipt.txt records install_source=script' } else { Bad 'receipt' ((Get-Content (Join-Path $Prefix 'install-receipt.txt') -Raw -ErrorAction SilentlyContinue)) }
    $want = Receipt 'installer_sha256'
    $kept = Receipt 'installer'
    if ($want -and $kept -and (Test-Path $kept)) {
        $have = (Get-FileHash -Algorithm SHA256 $kept).Hash.ToLower()
        if ($have -eq $want.ToLower()) { Ok 'the kept installer exists and its SHA-256 equals the receipt''s installer_sha256' } else { Bad "kept installer hash $have, receipt $want" }
    } else { Ok 'the Windows install keeps no installer copy (the receipt has no installer_sha256; self-update only prints the command)' }

    # 2 re-running is a no-op; a pinned older version is refused and nothing changes
    Inst @()
    if ($Rc -eq 0 -and ((Has 'already installed') -or (Has 'up to date'))) { Ok 're-running the installer says the install is already current' } else { Bad "re-run (rc=$Rc)" $Out }
    $installed = Receipt 'version'
    if (-not $installed -or $installed -eq $OlderVersion) { Skip "no older version to pin ($OlderVersion is not older than the installed '$installed'); pass -OlderVersion" }
    else {
        $before = Snapshot
        Inst @('-Version', $OlderVersion)
        if ($Rc -eq 6 -and ((Snapshot) -eq $before)) { Ok "a pinned older version ($OlderVersion) is refused with exit 6 and nothing changes" } else { Bad "pinned older version (rc=$Rc)" $Out }
    }

    # 3 the data check, on databases made for the purpose (Python's sqlite3 makes them)
    $py = Get-Command python -ErrorAction SilentlyContinue
    & $Dm --check-data-compat 2>&1 | Out-Null
    $probe = $LASTEXITCODE
    if ($probe -eq 2) { Skip 'this release''s daemon has no --check-data-compat: the data cases' }
    elseif (-not $py) { Skip 'python is not installed here, so the test databases cannot be made: the data cases' }
    else {
        $db = Join-Path $Cfg 'sync-state.sqlite3'
        $stampPy = Join-Path $T 'stamp.py'
        Set-Content -Path $stampPy -Encoding ASCII -Value @'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1]); c.execute("pragma journal_mode=wal"); c.execute("create table if not exists files(id integer primary key)")
c.execute("pragma user_version=%d" % int(sys.argv[2])); c.commit(); c.close()
'@
        $holdPy = Join-Path $T 'hold.py'
        Set-Content -Path $holdPy -Encoding ASCII -Value @'
import sqlite3, sys, time
c = sqlite3.connect(sys.argv[1], isolation_level=None)
c.execute("pragma journal_mode=wal"); c.execute("pragma wal_autocheckpoint=0")
c.execute("create table if not exists files(id integer primary key)")
c.execute("pragma user_version=%d" % int(sys.argv[2]))
time.sleep(40)
'@
        Remove-Item $db, "$db-wal", "$db-shm" -Force -ErrorAction SilentlyContinue
        & $Dm --check-data-compat 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0 -and -not (Test-Path $db)) { Ok 'no data: --check-data-compat exits 0 and creates no database' } else { Bad "no data (rc=$LASTEXITCODE)" }
        & python $stampPy $db 1
        $o = (& $Dm --check-data-compat 2>&1 | ForEach-Object { "$_" }) -join "`n"
        if ($LASTEXITCODE -eq 0 -and $o -match 'warning') { Ok 'older data: exit 0 with a warning' } else { Bad "older data (rc=$LASTEXITCODE)" $o }
        & python $stampPy $db 999999
        $o = (& $Dm --check-data-compat 2>&1 | ForEach-Object { "$_" }) -join "`n"
        if ($LASTEXITCODE -eq 20 -and $o -match 'downgrad') { Ok 'newer data: exit 20, the message says downgrading is not supported' } else { Bad "newer data (rc=$LASTEXITCODE)" $o }
        $before = Snapshot
        Inst @('-Force')
        if ($Rc -eq 20 -and ((Snapshot) -eq $before)) { Ok 'the installer refuses over newer data (exit 20) and changes nothing' } else { Bad "installer over newer data (rc=$Rc)" $Out }
        Remove-Item $db, "$db-wal", "$db-shm" -Force -ErrorAction SilentlyContinue
        # a newer stamp only in the write-ahead log, another process holding the database
        $hold = Start-Process -FilePath python -ArgumentList @("`"$holdPy`"", "`"$db`"", '999999') -PassThru -WindowStyle Hidden
        Start-Sleep -Seconds 2
        $o = (& $Dm --check-data-compat 2>&1 | ForEach-Object { "$_" }) -join "`n"
        $rcLog = $LASTEXITCODE
        Stop-Process -Id $hold.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        if ($rcLog -eq 20) { Ok 'a newer stamp only in the write-ahead log, another process holding the database: exit 20' } else { Bad "stamp only in the log (rc=$rcLog)" $o }
        Remove-Item $db, "$db-wal", "$db-shm" -Force -ErrorAction SilentlyContinue
        Set-Content -Path $db -Encoding ASCII -Value 'this is not a database, but it is long enough to look like a header....'
        $o = (& $Dm --check-data-compat 2>&1 | ForEach-Object { "$_" }) -join "`n"
        if ($LASTEXITCODE -eq 21 -and $o -match 'start the daemon once and stop it cleanly') { Ok 'unreadable data: exit 21 with what to do' } else { Bad "unreadable data (rc=$LASTEXITCODE)" $o }
        Remove-Item $db, "$db-wal", "$db-shm" -Force -ErrorAction SilentlyContinue
    }

    # 4 uninstall keeps the data; reinstall works over it
    $keep = Join-Path $Cfg 'keep-me.txt'
    Set-Content -Path $keep -Value 'device state'
    Inst @('-Uninstall')
    if ($Rc -eq 0 -and -not (Test-Path $Yl) -and ((Get-Content $keep -Raw).Trim() -eq 'device state')) { Ok 'install.ps1 -Uninstall removes the programs and keeps the data directory' } else { Bad "uninstall (rc=$Rc)" $Out }
    Inst $(if ($Version) { @('-Version', $Version) } else { @() })
    if ($Rc -eq 0 -and (Test-Path $Yl) -and ((Get-Content $keep -Raw).Trim() -eq 'device state')) { Ok 'reinstalling after an uninstall works and the kept data directory is intact' } else { Bad "reinstall (rc=$Rc)" $Out }
} catch {
    if ("$_" -ne 'install failed') { Write-Host "FAIL unexpected: $_"; $script:Fail++ }
} finally {
    if ($hold) { Stop-Process -Id $hold.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
    Remove-Item $T -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:YADORILINK_CONFIG_DIR -ErrorAction SilentlyContinue
}
Write-Host ''
Write-Host "passed: $Pass, failed: $Fail, skipped: $Skip"
exit $(if ($Fail -eq 0) { 0 } else { 1 })
