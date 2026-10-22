# Installer acceptance on Windows with the REAL programs: install.ps1 against a LOCAL fixture
# release whose engine bundle holds the repo's own yadorilink.exe and yadorilink-daemon.exe.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File Run-Acceptance.ps1 -Root C:\Temp\lp-install -BinDir C:\bins
#
# Root holds install.ps1, build-fixture.py, serve.py. BinDir holds yadorilink.exe and
# yadorilink-daemon.exe, the daemon built with the fixture trust root (see ../acceptance.sh for the
# build commands). Everything lives under one temp directory: prefix, config dir, user data;
# 127.0.0.1 only. The user PATH is never touched (-NoModifyPath). This is the Windows counterpart
# of acceptance.sh: daemon-reported install_source=script, self-update gate, refusals that leave an
# existing install untouched, uninstall that keeps the user's data.
param(
    [string]$Root = (Split-Path -Parent $MyInvocation.MyCommand.Path),
    [Parameter(Mandatory = $true)][string]$BinDir
)

$ErrorActionPreference = 'Continue'
$Installer = Join-Path $Root 'install.ps1'
$T = Join-Path $env:TEMP ("yla-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
$Srv = Join-Path $T 'srv'
New-Item -ItemType Directory -Force -Path $Srv | Out-Null
$script:Pass = 0; $script:Fail = 0
function Ok($m) { $script:Pass++; Write-Host "ok   $m" }
function Bad($m, $out) { $script:Fail++; Write-Host "FAIL $m"; if ($out) { ($out -split "`n") | ForEach-Object { Write-Host "     | $_" } } }

$portFile = Join-Path $T 'port'
$server = Start-Process -FilePath python -ArgumentList @((Join-Path $Root 'serve.py'), $Srv, $portFile) -PassThru -WindowStyle Hidden
for ($i = 0; $i -lt 300 -and -not (Test-Path $portFile -PathType Leaf); $i++) { Start-Sleep -Milliseconds 100 }
if (-not (Test-Path $portFile)) { Write-Host 'acceptance: the fixture server did not start'; exit 2 }
Start-Sleep -Milliseconds 200
$Base = "http://127.0.0.1:$((Get-Content $portFile -Raw).Trim())"

$Prefix = Join-Path $T 'prefix'
$Cfg = Join-Path $T 'cfg'
$Data = Join-Path $T 'Sync'
$Bin = Join-Path $Prefix 'bin'
$Yl = Join-Path $Bin 'yadorilink.exe'
$script:Out = ''; $script:Rc = 0; $script:N = 0

function Fx([string]$Name, [string[]]$More) {
    & python (Join-Path $Root 'build-fixture.py') (Join-Path $Srv $Name) --base-url "$Base/$Name" --targets windows-x86_64 --bin-dir $BinDir --engine-api-version 1 @More
    if ($LASTEXITCODE -ne 0) { throw "fixture $Name failed" }
}
function Pub($Name) { (Get-Content (Join-Path $Srv "$Name\pubkey.hex") -Raw).Trim() }
function Inst([string]$Name, [string]$KeyFrom, [string[]]$More, [string]$MinGen = $null) {
    $env:YADORILINK_INSTALL_TEST = '1'
    $env:YADORILINK_INSTALL_PUBKEY_HEX = Pub $KeyFrom
    $env:YADORILINK_INSTALL_KEY_ID = (Get-Content (Join-Path $Srv "$KeyFrom\key_id") -Raw).Trim()
    $env:YADORILINK_INSTALL_BASE_URL = "$Base/$Name"
    $env:YADORILINK_INSTALL_MIN_GENERATED_AT = $MinGen
    $env:YADORILINK_INSTALL_ARCH = 'AMD64'
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Installer, '-Prefix', $Prefix, '-Yes', '-NoModifyPath') + $More
    $script:Out = (& powershell.exe @a 2>&1 | ForEach-Object { "$_" }) -join "`n"
    $script:Rc = $LASTEXITCODE
    foreach ($v in 'YADORILINK_INSTALL_TEST', 'YADORILINK_INSTALL_PUBKEY_HEX', 'YADORILINK_INSTALL_KEY_ID', 'YADORILINK_INSTALL_BASE_URL', 'YADORILINK_INSTALL_MIN_GENERATED_AT', 'YADORILINK_INSTALL_ARCH') { Remove-Item "Env:$v" -ErrorAction SilentlyContinue }
}
function Yl([string]$Rel, [string[]]$A) {
    $env:YADORILINK_CONFIG_DIR = $Cfg
    $env:YADORILINK_CREDENTIAL_STORE = 'file'
    $env:YADORILINK_HTTP_API_DISABLE = '1'
    $env:YADORILINK_UPDATE_MANIFEST_URL = "$Base/$Rel/beta/manifest.json"
    # Through cmd with output in a file: `daemon start` leaves the daemon running with the
    # caller's pipe handles inherited, and a PowerShell pipe would wait for it to exit.
    # A fresh file per call: the daemon keeps the file of the call that started it open.
    $script:N++
    $f = Join-Path $T "yl$($script:N).out"
    $bat = Join-Path $T "yl$($script:N).bat"
    Set-Content -Path $bat -Encoding ASCII -Value ('@"{0}" {1} > "{2}" 2>&1 < nul' -f $Yl, ($A -join ' '), $f)
    & cmd.exe /c $bat
    $script:Rc = $LASTEXITCODE
    $script:Out = if (Test-Path $f) { (Get-Content $f) -join "`n" } else { '' }
    foreach ($v in 'YADORILINK_CONFIG_DIR', 'YADORILINK_CREDENTIAL_STORE', 'YADORILINK_HTTP_API_DISABLE', 'YADORILINK_UPDATE_MANIFEST_URL') { Remove-Item "Env:$v" -ErrorAction SilentlyContinue }
}
function Has($s) { $script:Out -like "*$s*" }
function Snapshot {
    $files = if (Test-Path $Prefix) { (Get-ChildItem $Prefix -Recurse -Force | ForEach-Object { $_.FullName.Substring($Prefix.Length) }) -join '|' } else { '' }
    $r = Join-Path $Prefix 'install-receipt.txt'
    $files + '#' + $(if (Test-Path $r) { Get-Content $r -Raw } else { '' })
}

try {
    Write-Host "PowerShell $($PSVersionTable.PSVersion) on $([Environment]::OSVersion.VersionString)"
    New-Item -ItemType Directory -Force -Path $Data | Out-Null
    Set-Content (Join-Path $Data 'notes.txt') 'precious'

    # 1 install version 1.0.0
    Fx 'rel' '--version', '1.0.0'
    Inst 'rel' 'rel' @()
    if ($Rc -eq 0 -and (Has 'Manifest signature verified') -and (Has 'Installed YadoriLink 1.0.0')) { Ok 'install.ps1 installs the real programs' } else { Bad 'install' $Out }
    if ((Test-Path $Yl) -and (Test-Path (Join-Path $Bin 'yadorilink-daemon.exe'))) { Ok 'yadorilink.exe and yadorilink-daemon.exe are in <prefix>\bin' } else { Bad 'programs in bin' }
    if ((Get-Content (Join-Path $Prefix 'install-receipt.txt') -Raw) -match '(?m)^install_source=script') { Ok 'install-receipt.txt records install_source=script' } else { Bad 'receipt' ((Get-Content (Join-Path $Prefix 'install-receipt.txt') -Raw)) }
    $marker = Join-Path $Bin 'install-receipt.json'
    if ((Test-Path $marker) -and ((Get-Content $marker -Raw | ConvertFrom-Json).source -eq 'script')) { Ok 'install-receipt.json (the daemon-readable marker) sits beside the programs' } else { Bad 'marker' }
    $v = (& $Yl --version 2>&1) -join ''
    if ($LASTEXITCODE -eq 0 -and $v -like 'yadorilink*') { Ok "yadorilink.exe --version: $v" } else { Bad '--version' $v }

    # 2 the real daemon detects the script install
    Yl 'rel' @('daemon', 'start')
    if ($Rc -eq 0) { Ok 'yadorilink daemon start' } else { Bad 'daemon start' $Out }
    Yl 'rel' @('update', 'status')
    if ($Rc -eq 0 -and (Has 'install_source: script')) { Ok 'daemon reports install_source=script' } else { Bad 'daemon install_source' $Out }
    $own = Join-Path $Cfg 'install-owner.json'
    if ((Test-Path $own) -and ((Get-Content $own -Raw | ConvertFrom-Json).install_source -eq 'script')) { Ok 'ownership record says install_source=script' } else { Bad 'ownership record' $(if (Test-Path $own) { Get-Content $own -Raw }) }

    # 3 self-update gate. The daemon's manifest URL is fixed when it starts (<fixture>\rel), so each
    # step republishes `rel` in place with a later generated_at (replay protection).
    Fx 'rel' '--version', '2.0.0', '--extra-version', '1.0.0', '--generated-at', '2026-10-19T00:00:00Z'
    Yl 'rel' @('self-update', '--version', '2.0.0')
    if ($Rc -eq 0 -and (Has 'is allowed by the verified beta channel manifest') -and (Has 'install.ps1')) { Ok 'self-update --version 2.0.0 is allowed and prints the pinned installer command' } else { Bad 'self-update allowed' $Out }
    Yl 'rel' @('self-update')
    if ($Rc -eq 0 -and (Has 'version 2.0.0')) { Ok 'plain self-update finds 2.0.0 (rollout 100%)' } else { Bad 'plain self-update' $Out }
    Fx 'rel' '--version', '2.0.0', '--extra-version', '1.0.0', '--withdrawn', '2.0.0', '--generated-at', '2026-10-20T00:00:00Z'
    Yl 'rel' @('self-update', '--version', '2.0.0')
    if ($Rc -eq 4 -and (Has 'Nothing was downloaded or changed')) { Ok 'self-update refuses a withdrawn version (exit 4)' } else { Bad "self-update withdrawn (rc=$Rc)" $Out }
    Fx 'rel' '--version', '2.0.0', '--generated-at', '2026-10-21T00:00:00Z'
    $mp = Join-Path $Srv 'rel\beta\manifest.json'
    $e = Get-Content $mp -Raw | ConvertFrom-Json; $e.manifest_json = $e.manifest_json.Replace('"rollout_percentage": 100', '"rollout_percentage":  99'); [IO.File]::WriteAllText($mp, ($e | ConvertTo-Json -Compress))
    Yl 'rel' @('self-update', '--version', '2.0.0')
    if ($Rc -eq 4 -and -not (Has 'is allowed')) { Ok 'self-update refuses a tampered manifest (exit 4)' } else { Bad "self-update tampered (rc=$Rc)" $Out }
    Yl 'rel' @('self-update')
    if ($Rc -ne 0 -and -not (Has 'already up to date')) { Ok 'plain self-update does not report up to date on a manifest it cannot verify' } else { Bad "plain self-update, tampered (rc=$Rc)" $Out }
    Fx 'rel' '--version', '2.0.0', '--extra-version', '1.0.0', '--generated-at', '2026-10-22T00:00:00Z'
    Inst 'rel' 'rel' @('-Version', '2.0.0')
    if ($Rc -eq 0 -and (Has 'Installed YadoriLink 2.0.0')) { Ok 'pinned installer run switches to 2.0.0' } else { Bad 'update to 2.0.0' $Out }

    # 4 refusals leave the existing install untouched
    $before = Snapshot
    function Refused($name, $code, $text) {
        if ($Rc -eq $code -and (Has $text) -and ((Snapshot) -eq $before)) { Ok "refused without side effects: $name" } else { Bad "refusal: $name (rc=$Rc)" $Out }
    }
    Fx 't1' '--version', '3.0.0'
    $zp = Join-Path $Srv 't1\files\3.0.0\yadorilink-engine-beta-windows-x86_64.zip'
    $b = [IO.File]::ReadAllBytes($zp); $b[$b.Length / 2] = $b[$b.Length / 2] -bxor 1; [IO.File]::WriteAllBytes($zp, $b)
    Inst 't1' 't1' @(); Refused 'tampered archive' 4 'SHA-256 does not match the signed manifest'
    Fx 't2' '--version', '3.0.0'
    $mp = Join-Path $Srv 't2\beta\manifest.json'
    $e = Get-Content $mp -Raw | ConvertFrom-Json; $e.manifest_json = $e.manifest_json.Replace('"rollout_percentage": 100', '"rollout_percentage":  99'); [IO.File]::WriteAllText($mp, ($e | ConvertTo-Json -Compress))
    Inst 't2' 't2' @(); Refused 'tampered manifest (signature does not verify)' 4 'does NOT verify'
    Fx 't3' '--version', '3.0.0'; Fx 't3other' '--seed', '6f746865726f746865726f746865726f746865726f746865726f746865726f74'
    Inst 't3' 't3other' @(); Refused 'manifest signed by another key' 4 'does NOT verify'
    Fx 't4' '--version', '3.0.0', '--withdrawn', '3.0.0'
    Inst 't4' 't4' @('-Version', '3.0.0'); Refused 'withdrawn version' 4 'withdrawn'
    Fx 't5' '--version', '3.0.0', '--kill-switch'
    Inst 't5' 't5' @(); Refused 'kill switch' 4 'withdrawn'
    Fx 't6' '--version', '3.0.0', '--generated-at', '2026-10-01T00:00:00Z'
    Inst 't6' 't6' @() '2026-10-19T00:00:00Z'; Refused 'replayed (older than the pinned floor) manifest' 4 'oldest this installer accepts'
    Fx 't7' '--version', '1.5.0'
    Inst 't7' 't7' @(); Refused 'downgrade without -Version' 6 'not downgrading'

    # pinned downgrade of an existing install is refused even with an explicit -Version
    $before = Snapshot
    Inst 'rel' 'rel' @('-Version', '1.0.0'); Refused 'pinned downgrade 2.0.0 -> 1.0.0 of an existing install' 6 'not downgrading'

    # 5 uninstall: the CLI points at the installer on Windows; the installer's -Uninstall keeps data
    Yl 'rel' @('uninstall', '--dry-run')
    if ($Rc -ne 0 -and (Has 'install.ps1') -and (Has '-Uninstall') -and (Test-Path $Yl)) { Ok 'yadorilink uninstall on Windows points at install.ps1 -Uninstall and removes nothing' } else { Bad 'uninstall pointer' $Out }
    New-Item -ItemType Directory -Force -Path $Cfg | Out-Null
    Set-Content (Join-Path $Cfg 'keep-me.txt') 'device state'
    Yl 'rel' @('daemon', 'stop')
    Start-Sleep -Seconds 2
    Inst 'rel' 'rel' @('-Uninstall')
    if ($Rc -eq 0 -and -not (Test-Path (Join-Path $Prefix 'versions')) -and -not (Test-Path $Bin) -and -not (Test-Path (Join-Path $Prefix 'install-receipt.txt'))) { Ok 'install.ps1 -Uninstall removes the program tree and the receipt' } else { Bad 'uninstall' $Out }
    if ((Get-Content (Join-Path $Data 'notes.txt') -Raw).Trim() -eq 'precious' -and (Test-Path (Join-Path $Cfg 'keep-me.txt')) -and (Test-Path $own)) { Ok 'uninstall keeps the synced folder and the data directory' } else { Bad 'data after uninstall' }
    # fresh install of an older version (nothing installed after the uninstall); kept data stays untouched
    Inst 'rel' 'rel' @('-Version', '1.0.0')
    if ($Rc -eq 0 -and (Has 'Installed YadoriLink 1.0.0') -and (Test-Path (Join-Path $Cfg 'keep-me.txt'))) { Ok 'fresh install of an older version works and the data directory is intact' } else { Bad 'reinstall 1.0.0' $Out }
} finally {
    if (Test-Path $Yl) { $env:YADORILINK_CONFIG_DIR = $Cfg; & $Yl daemon stop 2>&1 | Out-Null; Remove-Item Env:YADORILINK_CONFIG_DIR -ErrorAction SilentlyContinue }
    if ($server) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
    Remove-Item $T -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host ''
Write-Host "passed: $Pass, failed: $Fail"
exit $(if ($Fail -eq 0) { 0 } else { 1 })
