# Installer tests for install.ps1 against a LOCAL fixture release.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File Run-Tests.ps1 -Root C:\Temp\lp-install
#
# Root holds: install.ps1, build-fixture.py, serve.py (this script's siblings
# are copied there). Python 3 must be on PATH. Everything runs under a temp
# directory with a throw-away prefix; the installer's test hooks work only
# because this script sets YADORILINK_INSTALL_TEST=1. The user PATH is touched
# in exactly one test and restored afterwards.
param([string]$Root = (Split-Path -Parent $MyInvocation.MyCommand.Path))

$ErrorActionPreference = 'Continue'
$Installer = Join-Path $Root 'install.ps1'
# GetFullPath expands 8.3 short names (a runner's TEMP is C:\Users\RUNNER~1\...), as the
# installer does to its prefix; without it the PATH entry the installer adds never matches $bin.
$T = [System.IO.Path]::GetFullPath((Join-Path $env:TEMP ("yl-install-tests-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))))
$Srv = Join-Path $T 'srv'
New-Item -ItemType Directory -Force -Path $Srv | Out-Null
$script:Pass = 0; $script:Fail = 0
function Ok($m) { $script:Pass++; Write-Host "ok   $m" }
function Bad($m, $out) { $script:Fail++; Write-Host "FAIL $m"; if ($out) { ($out -split "`n") | ForEach-Object { Write-Host "     | $_" } } }

# --- fake binaries (real PE files)
foreach ($spec in @(@('0.2.0', 0), @('0.3.0', 0), @('fail', 7), @('ph', 0))) {
    $name = $spec[0]; $code = $spec[1]
    # 'ph' answers `status --json` with whatever YL_FAKE_STATUS holds, like a daemon of any schema.
    $line = if ($name -eq 'fail') { '' } elseif ($name -eq 'ph') { 'if (a.Length > 0 && a[0] == "status") System.Console.WriteLine(System.Environment.GetEnvironmentVariable("YL_FAKE_STATUS"));' } else { "System.Console.WriteLine(`"yadorilink fake $name`");" }
    Add-Type -TypeDefinition "public static class P { public static int Main(string[] a) { $line return $code; } }" -OutputType ConsoleApplication -OutputAssembly (Join-Path $T "fake-$name.exe")
}

# --- fixture server
$portFile = Join-Path $T 'port'
$server = Start-Process -FilePath python -ArgumentList @((Join-Path $Root 'serve.py'), $Srv, $portFile) -PassThru -WindowStyle Hidden
for ($i = 0; $i -lt 100 -and -not (Test-Path $portFile -PathType Leaf); $i++) { Start-Sleep -Milliseconds 100 }
Start-Sleep -Milliseconds 200
$Port = (Get-Content $portFile -Raw).Trim()
$Base = "http://127.0.0.1:$Port"
$origUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')

function Fx([string]$Name, [string[]]$More) {
    & python (Join-Path $Root 'build-fixture.py') (Join-Path $Srv $Name) --base-url "$Base/$Name" --targets windows-x86_64 @More
    if ($LASTEXITCODE -ne 0) { throw "fixture $Name failed" }
}
function Pub($Name) { (Get-Content (Join-Path $Srv "$Name\pubkey.hex") -Raw).Trim() }

$script:Out = ''; $script:Rc = 0; $script:BaseOverride = $null; $script:MinGen = $null; $script:Now = $null
function Inst([string]$Name, [string]$KeyFrom, [string]$Prefix, [string[]]$More, [string]$Arch = 'AMD64', [bool]$TestOn = $true) {
    $env:YADORILINK_INSTALL_TEST = $(if ($TestOn) { '1' } else { $null })
    $env:YADORILINK_INSTALL_PUBKEY_HEX = Pub $KeyFrom
    $env:YADORILINK_INSTALL_KEY_ID = (Get-Content (Join-Path $Srv "$KeyFrom\key_id") -Raw).Trim()
    $env:YADORILINK_INSTALL_BASE_URL = $(if ($script:BaseOverride) { $script:BaseOverride } else { "$Base/$Name" })
    $env:YADORILINK_INSTALL_MIN_GENERATED_AT = $(if ($script:MinGen) { $script:MinGen } else { '2000-01-01T00:00:00Z' })
    $env:YADORILINK_INSTALL_NOW = $(if ($script:Now) { $script:Now } else { $null })
    $env:YADORILINK_INSTALL_ARCH = $Arch
    $args_ = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Installer, '-Prefix', $Prefix, '-Yes') + $More
    $script:Out = (& powershell.exe @args_ 2>&1 | ForEach-Object { "$_" }) -join "`n"
    $script:Rc = $LASTEXITCODE
    foreach ($v in 'YADORILINK_INSTALL_TEST', 'YADORILINK_INSTALL_PUBKEY_HEX', 'YADORILINK_INSTALL_KEY_ID', 'YADORILINK_INSTALL_BASE_URL', 'YADORILINK_INSTALL_ARCH', 'YADORILINK_INSTALL_MIN_GENERATED_AT', 'YADORILINK_INSTALL_NOW') { Remove-Item "Env:$v" -ErrorAction SilentlyContinue }
}
function Has($s) { $script:Out -like "*$s*" }
function NewPrefix($n) { $p = Join-Path $T "p$n"; if (Test-Path $p) { Remove-Item $p -Recurse -Force }; $p }
function NothingInstalled($p) { -not (Test-Path (Join-Path $p 'bin')) -and -not (Test-Path (Join-Path $p 'versions')) -and -not (Get-ChildItem $p -Force -Filter '.staging.*' -ErrorAction SilentlyContinue) }
function Ver($p) { (& (Join-Path $p 'bin\yadorilink.exe') --version) -join '' }

try {
    Write-Host "PowerShell $($PSVersionTable.PSVersion) on $([Environment]::OSVersion.VersionString)"

    # static: override variables are read only in the test branch
    $text = Get-Content $Installer -Raw
    $i0 = $text.IndexOf('if ($script:TestMode) {'); $i1 = $text.IndexOf('[Console]::Error.WriteLine(''yadorilink-install: TEST MODE')
    $outside = $text.Substring(0, $i0) + $text.Substring($i1)
    $stray = [regex]::Matches($outside, 'YADORILINK_INSTALL_[A-Z_]+') | Where-Object { $_.Value -ne 'YADORILINK_INSTALL_TEST' }
    if (-not $stray) { Ok 'override variables are read only in the test branch' } else { Bad 'override variables outside the test branch' ($stray.Value -join ',') }

    Fx 's1' '--exe', (Join-Path $T 'fake-0.2.0.exe')
    $p = NewPrefix 1
    Inst 's1' 's1' $p @('-NoModifyPath')
    if ($Rc -eq 0 -and (Ver $p) -eq 'yadorilink fake 0.2.0' -and (Has 'Manifest signature verified') -and (Has 'yadorilink daemon start') -and (Select-String -Path (Join-Path $p 'install-receipt.txt') -Pattern '^install_source=script$' -Quiet)) { Ok 'success: install, receipt, next steps' } else { Bad 'success' $Out }
    if (Test-Path (Join-Path $p 'bin\yadorilink-daemon.exe')) { Ok 'daemon present in bin' } else { Bad 'daemon present in bin' }

    # tampered zip
    Fx 's5' '--exe', (Join-Path $T 'fake-0.2.0.exe')
    $zp = Join-Path $Srv 's5\files\0.2.0\yadorilink-engine-beta-windows-x86_64.zip'
    $b = [IO.File]::ReadAllBytes($zp); $b[$b.Length / 2] = $b[$b.Length / 2] -bxor 1; [IO.File]::WriteAllBytes($zp, $b)
    $p = NewPrefix 5; Inst 's5' 's5' $p @('-NoModifyPath')
    if ($Rc -ne 0 -and (Has 'does not match the signed manifest') -and (NothingInstalled $p)) { Ok 'tampered zip rejected' } else { Bad 'tampered zip' $Out }

    # tampered manifest
    Fx 's6' '--exe', (Join-Path $T 'fake-0.2.0.exe')
    $mp = Join-Path $Srv 's6\beta\manifest.json'
    $m = Get-Content $mp -Raw; $m = $m.Replace('rollout_percentage\": 100', 'rollout_percentage\":  99'); [IO.File]::WriteAllText($mp, $m)
    $p = NewPrefix 6; Inst 's6' 's6' $p @('-NoModifyPath')
    if ($Rc -ne 0 -and (Has 'does NOT verify') -and (NothingInstalled $p)) { Ok 'tampered manifest rejected' } else { Bad 'tampered manifest' $Out }

    # wrong key / wrong key id
    Fx 's7other' '--exe', (Join-Path $T 'fake-0.2.0.exe'), '--seed', '6f746865726f746865726f746865726f746865726f746865726f746865726f74'
    $p = NewPrefix 7; Inst 's1' 's7other' $p @('-NoModifyPath')
    if ($Rc -ne 0 -and (Has 'does NOT verify') -and (NothingInstalled $p)) { Ok 'wrong key rejected' } else { Bad 'wrong key' $Out }
    Fx 's8' '--exe', (Join-Path $T 'fake-0.2.0.exe'), '--key-id', 'some-other-id'
    $p = NewPrefix 8; Inst 's8' 's1' $p @('-NoModifyPath')
    if ($Rc -ne 0 -and (Has 'not one of the pinned release keys') -and (NothingInstalled $p)) { Ok 'wrong key id rejected' } else { Bad 'wrong key id' $Out }

    # trust set: entry for the manifest key id decides
    $env:YADORILINK_INSTALL_TRUST_SET = "retired:$(Pub 's7other') yadorilink-test-key:$(Pub 's1')"
    $p = NewPrefix 22; Inst 's1' 's1' $p @('-NoModifyPath'); if ($Rc -eq 0) { Ok 'trust set: second entry accepted' } else { Bad 'trust set second entry' $Out }
    $env:YADORILINK_INSTALL_TRUST_SET = "yadorilink-test-key:$(Pub 's7other') next:$(Pub 's1')"
    $p = NewPrefix 23; Inst 's1' 's1' $p @('-NoModifyPath'); if ($Rc -ne 0 -and (Has 'does NOT verify')) { Ok 'trust set: key id bound to its own key' } else { Bad 'trust set binding' $Out }
    Remove-Item Env:YADORILINK_INSTALL_TRUST_SET -ErrorAction SilentlyContinue

    # bad bundles
    foreach ($v in @(
        @('corrupt-sums', 'does not match SHA256SUMS', '--corrupt-sums'),
        @('extra-file', 'differ from its SHA256SUMS', '--extra-file'),
        @('identity-channel', "expected 'beta'", '--identity-channel', 'stable'),
        @('asset-name', 'names asset', '--asset-name', 'other.zip'))) {
        $n = "b-$($v[0])"; Fx $n (@('--exe', (Join-Path $T 'fake-0.2.0.exe')) + $v[2..($v.Length - 1)])
        $p = NewPrefix 9; Inst $n $n $p @('-NoModifyPath')
        if ($Rc -ne 0 -and (Has $v[1]) -and (NothingInstalled $p)) { Ok "bad bundle rejected: $($v[0])" } else { Bad "bad bundle: $($v[0])" $Out }
    }
    Fx 'b-broken' '--exe', (Join-Path $T 'fake-fail.exe')
    $p = NewPrefix 9; Inst 'b-broken' 'b-broken' $p @('-NoModifyPath')
    if ($Rc -ne 0 -and (Has 'does not run on this system') -and (NothingInstalled $p)) { Ok 'bad bundle rejected: broken binary' } else { Bad 'broken binary' $Out }

    # wrong arch
    $p = NewPrefix 10; Inst 's1' 's1' $p @('-NoModifyPath') 'ARM64'
    if ($Rc -ne 0 -and (Has 'unsupported CPU') -and (NothingInstalled $p)) { Ok 'refused ARM64' } else { Bad 'refused ARM64' $Out }

    # upgrade, idempotence, failure keeps old, downgrade, force, version flag
    Fx 'u1' '--version', '0.2.0', '--exe', (Join-Path $T 'fake-0.2.0.exe')
    Fx 'u2' '--version', '0.3.0', '--exe', (Join-Path $T 'fake-0.3.0.exe')
    Fx 'u3' '--version', '0.4.0', '--exe', (Join-Path $T 'fake-fail.exe')
    $p = NewPrefix 12
    Inst 'u1' 'u1' $p @('-NoModifyPath'); if ($Rc -eq 0 -and (Ver $p) -like '*0.2.0') { Ok 'initial install 0.2.0' } else { Bad 'initial install' $Out }
    Inst 'u1' 'u1' $p @('-NoModifyPath'); if ($Rc -eq 0 -and (Has 'already installed and up to date')) { Ok 're-run is idempotent' } else { Bad 're-run' $Out }
    Inst 'u2' 'u1' $p @('-NoModifyPath'); if ($Rc -eq 0 -and (Ver $p) -like '*0.3.0' -and (Get-ChildItem (Join-Path $p 'versions')).Count -eq 2) { Ok 'upgrade to 0.3.0 keeps previous version' } else { Bad 'upgrade' $Out }
    Inst 'u3' 'u1' $p @('-NoModifyPath'); if ($Rc -ne 0 -and (Has 'does not run on this system') -and (Ver $p) -like '*0.3.0') { Ok 'failed upgrade leaves 0.3.0 active' } else { Bad 'failed upgrade' $Out }
    Inst 'u1' 'u1' $p @('-NoModifyPath'); if ($Rc -ne 0 -and (Has 'not downgrading') -and (Ver $p) -like '*0.3.0') { Ok 'downgrade refused' } else { Bad 'downgrade' $Out }
    Inst 'u1' 'u1' $p @('-NoModifyPath', '-Version', '0.2.0'); if ($Rc -eq 6 -and (Has 'not downgrading') -and (Ver $p) -like '*0.3.0' -and (Get-ChildItem (Join-Path $p 'versions')).Count -eq 2) { Ok 'explicit -Version older than the installed one: exit 6, nothing changed' } else { Bad 'pinned downgrade refused' $Out }
    Inst 'u2' 'u1' $p @('-NoModifyPath', '-Force'); if ($Rc -eq 0 -and (Has 'Installed YadoriLink 0.3.0')) { Ok '-Force reinstalls' } else { Bad 'force' $Out }
    Inst 'u2' 'u1' $p @('-NoModifyPath', '-Version', '9.9.9'); if ($Rc -ne 0 -and (Has 'has no published manifest')) { Ok '-Version without a published manifest refused' } else { Bad 'version unpublished' $Out }
    Inst 'u2' 'u1' $p @('-NoModifyPath', '-Version', 'v0.3.0'); if ($Rc -eq 0) { Ok '-Version accepts v-prefix' } else { Bad 'version v-prefix' $Out }

    # pruning touches only what the receipt recorded; a foreign directory under versions\ survives
    Fx 'u4' '--version', '0.5.0', '--exe', (Join-Path $T 'fake-0.3.0.exe')
    $p = NewPrefix 13
    Inst 'u1' 'u1' $p @('-NoModifyPath')
    $foreign = Join-Path $p 'versions\foreign-data'
    New-Item -ItemType Directory -Force -Path $foreign | Out-Null; [IO.File]::WriteAllText((Join-Path $foreign 'file'), 'keep')
    Inst 'u2' 'u1' $p @('-NoModifyPath'); Inst 'u4' 'u1' $p @('-NoModifyPath')
    if ($Rc -eq 0 -and (Test-Path (Join-Path $foreign 'file')) -and (Get-ChildItem (Join-Path $p 'versions')).Count -eq 3) { Ok 'unmanaged directory under versions\ is left alone; only the recorded old version is pruned' } else { Bad 'prune ownership' $Out }

    # a failed receipt write fails closed and puts the previous bin, receipt and version tree back
    $p = NewPrefix 14
    Inst 'u1' 'u1' $p @('-NoModifyPath')
    $recBefore = Get-Content (Join-Path $p 'install-receipt.txt') -Raw; $verBefore = Ver $p
    $dirsBefore = (Get-ChildItem (Join-Path $p 'versions') | ForEach-Object Name) -join ','
    $env:YADORILINK_INSTALL_FAIL_RECEIPT = '1'
    Inst 'u2' 'u1' $p @('-NoModifyPath')
    Remove-Item Env:YADORILINK_INSTALL_FAIL_RECEIPT -ErrorAction SilentlyContinue
    $recAfter = Get-Content (Join-Path $p 'install-receipt.txt') -Raw
    $dirsAfter = (Get-ChildItem (Join-Path $p 'versions') | ForEach-Object Name) -join ','
    if ($Rc -ne 0 -and (Has 'could not write the install receipt') -and -not (Has 'Installed YadoriLink') -and (Ver $p) -eq $verBefore -and $recAfter -eq $recBefore -and $dirsAfter -eq $dirsBefore -and -not (Get-ChildItem $p -Force -Filter 'bin.old.*')) { Ok 'receipt write failure fails closed and restores bin, receipt and versions' } else { Bad 'receipt failure rollback' $Out }


    # exit codes: 2 usage, 3 network, 4 signature/hash/withdrawal, 5 platform, 6 downgrade, 7 prefix
    $p = NewPrefix 40; Inst 's1' 's1' $p @('-Bogus'); if ($Rc -eq 2 -and (Has 'unknown option')) { Ok 'exit 2: unknown option' } else { Bad 'exit 2' $Out }
    $p = NewPrefix 40; Inst 's1' 's1' $p @('-NoModifyPath', '-Channel', 'stable'); if ($Rc -eq 2) { Ok 'exit 2: unknown channel' } else { Bad 'exit 2 channel' $Out }
    $script:BaseOverride = 'http://127.0.0.1:1'; $p = NewPrefix 41; Inst 's1' 's1' $p @('-NoModifyPath'); $script:BaseOverride = $null
    if ($Rc -eq 3 -and (NothingInstalled $p)) { Ok 'exit 3: network failure' } else { Bad 'exit 3' $Out }
    $p = NewPrefix 42; Inst 's1' 's1' $p @('-NoModifyPath') 'ARM64'; if ($Rc -eq 5) { Ok 'exit 5: unsupported platform' } else { Bad 'exit 5' $Out }
    $p = NewPrefix 12; Inst 'u1' 'u1' $p @('-NoModifyPath', '-Yes'); Inst 'u2' 'u1' $p @('-NoModifyPath'); Inst 'u1' 'u1' $p @('-NoModifyPath')
    if ($Rc -eq 6) { Ok 'exit 6: downgrade refused' } else { Bad 'exit 6' $Out }
    $p = NewPrefix 43; Set-Content $p 'a file'; Inst 's1' 's1' $p @('-NoModifyPath'); if ($Rc -eq 7) { Ok 'exit 7: prefix not writable' } else { Bad 'exit 7' $Out }
    Remove-Item $p -Force
    $p = NewPrefix 5; Inst 's5' 's5' $p @('-NoModifyPath'); if ($Rc -eq 4) { Ok 'exit 4: hash mismatch' } else { Bad 'exit 4' $Out }
    Fx 'xk' '--kill-switch', '--exe', (Join-Path $T 'fake-0.2.0.exe')
    $p = NewPrefix 14; Inst 'xk' 'xk' $p @('-NoModifyPath'); if ($Rc -eq 4) { Ok 'exit 4: kill switch' } else { Bad 'exit 4 kill' $Out }

    # replay floor pinned in the installer
    Fx 'rf' '--exe', (Join-Path $T 'fake-0.2.0.exe'), '--generated-at', '2026-10-18T00:00:00Z'
    $script:MinGen = '2026-10-19T00:00:00Z'; $p = NewPrefix 44; Inst 'rf' 'rf' $p @('-NoModifyPath')
    if ($Rc -eq 4 -and (Has 'oldest this installer accepts') -and (NothingInstalled $p)) { Ok 'manifest older than the pinned floor refused' } else { Bad 'replay floor' $Out }
    $script:MinGen = '2026-10-18T00:00:00Z'; $p = NewPrefix 45; Inst 'rf' 'rf' $p @('-NoModifyPath')
    if ($Rc -eq 0) { Ok 'manifest at the pinned floor accepted' } else { Bad 'floor equal' $Out }
    $script:MinGen = $null

    # manifest expiry: the live manifest is refused after its expires_at, never before
    Fx 'ex' '--exe', (Join-Path $T 'fake-0.2.0.exe'), '--generated-at', '2026-10-01T00:00:00Z', '--expires-at', '2026-10-02T00:00:00Z'
    $p = NewPrefix 60; Inst 'ex' 'ex' $p @('-NoModifyPath')
    if ($Rc -eq 4 -and (Has 'expired at 2026-10-02T00:00:00Z') -and (NothingInstalled $p)) { Ok 'expired manifest refused (real clock)' } else { Bad 'expired' $Out }
    $script:Now = '2026-10-02T00:00:01Z'; $p = NewPrefix 61; Inst 'ex' 'ex' $p @('-NoModifyPath')
    if ($Rc -eq 4 -and (Has 'expired at') -and (NothingInstalled $p)) { Ok 'manifest one second past expiry refused' } else { Bad 'expiry +1s' $Out }
    $script:Now = '2026-10-02T00:00:00Z'; $p = NewPrefix 62; Inst 'ex' 'ex' $p @('-NoModifyPath')
    if ($Rc -eq 0) { Ok 'manifest at its expiry second accepted' } else { Bad 'expiry boundary' $Out }
    $script:Now = $null
    Fx 'exgone' '--exe', (Join-Path $T 'fake-0.2.0.exe'), '--omit-expires'
    $p = NewPrefix 63; Inst 'exgone' 'exgone' $p @('-NoModifyPath')
    if ($Rc -eq 4 -and (Has 'invalid expires_at') -and (NothingInstalled $p)) { Ok 'manifest without expires_at refused' } else { Bad 'no expiry' $Out }

    # snapshots published before expires_at existed stay usable
    Fx 'lg' '--version', '0.3.0', '--extra-version', '0.2.0', '--legacy-snapshots', '--exe', (Join-Path $T 'fake-0.3.0.exe')
    $p = NewPrefix 64; Inst 'lg' 'lg' $p @('-NoModifyPath', '-Version', '0.2.0')
    if ($Rc -eq 0 -and (Has 'Installed YadoriLink 0.2.0')) { Ok 'pinned install from a legacy per-version manifest without expires_at' } else { Bad 'legacy pinned' $Out }

    # version-pinned installs: the live channel manifest has the last word
    Fx 'pv' '--version', '0.3.0', '--extra-version', '0.2.0', '--exe', (Join-Path $T 'fake-0.3.0.exe')
    $p = NewPrefix 47; Inst 'pv' 'pv' $p @('-NoModifyPath', '-Version', '0.3.0'); if ($Rc -eq 0 -and (Ver $p) -like '*0.3.0') { Ok 'pin to the channel current version' } else { Bad 'pin current' $Out }
    $p = NewPrefix 48; Inst 'pv' 'pv' $p @('-NoModifyPath', '-Version', '0.2.0'); if ($Rc -eq 0 -and (Has 'Installed YadoriLink 0.2.0')) { Ok 'pin to an older published version installs from its signed per-version manifest' } else { Bad 'pin older' $Out }
    Fx 'pk' '--version', '0.3.0', '--extra-version', '0.2.0', '--kill-switch', '--exe', (Join-Path $T 'fake-0.3.0.exe')
    $p = NewPrefix 49; Inst 'pk' 'pk' $p @('-NoModifyPath', '-Version', '0.3.0'); if ($Rc -eq 4 -and (Has 'withdrawn') -and (NothingInstalled $p)) { Ok 'REGRESSION: pinned killed version refused (exit 4) though its snapshot verifies' } else { Bad 'pinned killed' $Out }
    $p = NewPrefix 50; Inst 'pk' 'pk' $p @('-NoModifyPath', '-Version', '0.2.0'); if ($Rc -eq 0) { Ok 'a pin to another version is unaffected by the channel kill switch' } else { Bad 'pin other' $Out }
    Fx 'pw' '--version', '0.3.0', '--extra-version', '0.2.0', '--withdrawn', '0.2.0', '--exe', (Join-Path $T 'fake-0.3.0.exe')
    $p = NewPrefix 51; Inst 'pw' 'pw' $p @('-NoModifyPath', '-Version', '0.2.0'); if ($Rc -eq 4 -and (Has 'has been withdrawn') -and (NothingInstalled $p)) { Ok 'REGRESSION: pinned yanked version refused (exit 4)' } else { Bad 'pinned yanked' $Out }
    Fx 'pm' '--version', '0.3.0', '--extra-version', '0.2.0', '--min-version', '0.2.5', '--exe', (Join-Path $T 'fake-0.3.0.exe')
    $p = NewPrefix 52; Inst 'pm' 'pm' $p @('-NoModifyPath', '-Version', '0.2.0'); if ($Rc -eq 4 -and (Has 'below the minimum supported version') -and (NothingInstalled $p)) { Ok 'REGRESSION: pinned version below the minimum refused (exit 4)' } else { Bad 'pinned below minimum' $Out }
    New-Item -ItemType Directory -Force -Path (Join-Path $Srv 'pn') | Out-Null
    Copy-Item (Join-Path $Srv 'pv\0.2.0') (Join-Path $Srv 'pn\0.2.0') -Recurse; Copy-Item (Join-Path $Srv 'pv\files') (Join-Path $Srv 'pn\files') -Recurse
    Copy-Item (Join-Path $Srv 'pv\pubkey.hex'), (Join-Path $Srv 'pv\key_id') (Join-Path $Srv 'pn')
    $p = NewPrefix 53; Inst 'pn' 'pv' $p @('-NoModifyPath', '-Version', '0.2.0'); if ($Rc -ne 0 -and (NothingInstalled $p)) { Ok 'pinned install with no live manifest fails closed' } else { Bad 'pinned, live missing' $Out }
    Fx 'pq' '--version', '0.3.0', '--extra-version', '0.2.0', '--exe', (Join-Path $T 'fake-0.3.0.exe')
    Copy-Item (Join-Path $Srv 'pq\0.3.0\manifest.json') (Join-Path $Srv 'pq\0.2.0\manifest.json') -Force
    $p = NewPrefix 56; Inst 'pq' 'pq' $p @('-NoModifyPath', '-Version', '0.2.0'); if ($Rc -eq 4 -and (Has 'describes version 0.3.0') -and (NothingInstalled $p)) { Ok 'per-version manifest of another version refused' } else { Bad 'snapshot for another version' $Out }

    # offline installs (-From)
    $fd = Join-Path $T 'from'; New-Item -ItemType Directory -Force -Path $fd | Out-Null
    Copy-Item (Join-Path $Srv 'pv\0.2.0\manifest.json') (Join-Path $fd 'manifest.json') -Force
    Copy-Item (Join-Path $Srv 'pv\files\0.2.0\yadorilink-engine-beta-windows-x86_64.zip') $fd -Force
    $script:BaseOverride = 'http://127.0.0.1:1'
    $p = NewPrefix 57; Inst 'pv' 'pv' $p @('-NoModifyPath', '-From', (Join-Path $fd 'manifest.json'))
    if ($Rc -eq 0 -and (Has 'Withdrawal not checked') -and (Has 'offline install')) { Ok '-From installs offline and says withdrawal was not checked' } else { Bad '-From offline' $Out }
    $script:BaseOverride = $null
    $p = NewPrefix 58; Inst 'pv' 'pv' $p @('-NoModifyPath', '-From', (Join-Path $fd 'manifest.json'))
    if ($Rc -eq 0 -and (Has 'does not withdraw 0.2.0')) { Ok '-From with a reachable live manifest that does not withdraw' } else { Bad '-From live ok' $Out }
    Fx 'fw' '--version', '0.2.0', '--withdrawn', '0.2.0'
    $fw = Join-Path $T 'fromw'; New-Item -ItemType Directory -Force -Path $fw | Out-Null
    Copy-Item (Join-Path $Srv 'fw\beta\manifest.json') (Join-Path $fw 'manifest.json') -Force
    Copy-Item (Join-Path $Srv 'fw\files\0.2.0\yadorilink-engine-beta-windows-x86_64.zip') $fw -Force
    $script:BaseOverride = 'http://127.0.0.1:1'
    $p = NewPrefix 70; Inst 'fw' 'fw' $p @('-NoModifyPath', '-From', (Join-Path $fw 'manifest.json'))
    $script:BaseOverride = $null
    if ($Rc -eq 4 -and (Has 'has been withdrawn') -and (NothingInstalled $p)) { Ok '-From refuses a version its own manifest withdraws' } else { Bad '-From own withdrawn' $Out }
    $p = NewPrefix 59; Inst 'pw' 'pv' $p @('-NoModifyPath', '-From', (Join-Path $fd 'manifest.json'))
    if ($Rc -eq 4 -and (Has 'has been withdrawn') -and (NothingInstalled $p)) { Ok '-From is refused when the live manifest withdraws the version' } else { Bad '-From live withdraws' $Out }
    $script:BaseOverride = 'http://127.0.0.1:1'
    $p = NewPrefix 60; Inst 'pv' 'pv' $p @('-NoModifyPath', '-From', (Join-Path $fd 'manifest.json'), '-Version', '0.9.9')
    if ($Rc -eq 4 -and (Has 'is for version 0.2.0')) { Ok '-From with a different -Version refused' } else { Bad '-From version mismatch' $Out }
    Remove-Item (Join-Path $fd 'yadorilink-engine-beta-windows-x86_64.zip')
    $p = NewPrefix 62; Inst 'pv' 'pv' $p @('-NoModifyPath', '-From', (Join-Path $fd 'manifest.json'))
    if ($Rc -eq 2 -and (Has 'needs the engine bundle')) { Ok '-From needs the engine bundle next to the manifest' } else { Bad '-From no zip' $Out }
    $script:BaseOverride = $null

    # foreign bin directory is never replaced
    $p = NewPrefix 13; New-Item -ItemType Directory -Force -Path (Join-Path $p 'bin') | Out-Null; Set-Content (Join-Path $p 'bin\keep.txt') 'mine'
    Inst 's1' 's1' $p @('-NoModifyPath'); if ($Rc -ne 0 -and (Has 'was not created by this script') -and (Test-Path (Join-Path $p 'bin\keep.txt'))) { Ok 'foreign bin directory is never overwritten' } else { Bad 'foreign bin' $Out }

    # kill switch
    Fx 'k1' '--kill-switch', '--exe', (Join-Path $T 'fake-0.2.0.exe')
    $p = NewPrefix 14; Inst 'k1' 'k1' $p @('-NoModifyPath'); if ($Rc -ne 0 -and (Has 'withdrawn') -and (NothingInstalled $p)) { Ok 'kill switch honoured' } else { Bad 'kill switch' $Out }

    # interrupted download
    Fx 'i1' '--exe', (Join-Path $T 'fake-0.2.0.exe'); New-Item -ItemType File -Path (Join-Path $Srv 'i1\.truncate') | Out-Null
    $p = NewPrefix 15; Inst 'i1' 'i1' $p @('-NoModifyPath'); if ($Rc -ne 0 -and (Has 'download failed or was interrupted') -and (NothingInstalled $p)) { Ok 'interrupted download leaves nothing' } else { Bad 'interrupted download' $Out }

    # unwritable prefix: the prefix path is an existing file
    $p = NewPrefix 16; Set-Content $p 'a file'
    Inst 's1' 's1' $p @('-NoModifyPath'); if ($Rc -ne 0 -and (Has 'cannot write to')) { Ok 'unwritable prefix refused up front' } else { Bad 'unwritable prefix' $Out }
    Remove-Item $p -Force
    # read-only directory (deny ACL)
    $p = NewPrefix 16; New-Item -ItemType Directory -Path $p | Out-Null
    & icacls $p /deny "$($env:USERNAME):(OI)(CI)(WD,AD)" | Out-Null
    Inst 's1' 's1' $p @('-NoModifyPath')
    & icacls $p /remove:d $env:USERNAME | Out-Null
    if ($Rc -ne 0 -and (Has 'cannot write to')) { Ok 'read-only directory refused up front' } else { Bad 'read-only directory' $Out }

    # no network / no release yet
    $env:YADORILINK_INSTALL_TEST = '1'; $env:YADORILINK_INSTALL_PUBKEY_HEX = Pub 's1'; $env:YADORILINK_INSTALL_BASE_URL = 'http://127.0.0.1:1'
    $p = NewPrefix 17
    $o = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Installer -Prefix $p -Yes -NoModifyPath 2>&1 | ForEach-Object { "$_" }) -join "`n"; $rc = $LASTEXITCODE
    foreach ($v in 'YADORILINK_INSTALL_TEST', 'YADORILINK_INSTALL_PUBKEY_HEX', 'YADORILINK_INSTALL_BASE_URL') { Remove-Item "Env:$v" -ErrorAction SilentlyContinue }
    if ($rc -ne 0 -and $o -like '*could not reach*' -and (NothingInstalled $p)) { Ok 'no network fails cleanly' } else { Bad 'no network' $o }
    New-Item -ItemType Directory -Force -Path (Join-Path $Srv 'empty') | Out-Null
    $p = NewPrefix 18; Inst 'empty' 's1' $p @('-NoModifyPath'); if ($Rc -ne 0 -and (Has 'No release is published yet') -and (NothingInstalled $p)) { Ok '404 says no release is published yet' } else { Bad '404' $Out }

    # PATH edit and uninstall
    $p = NewPrefix 20
    Inst 's1' 's1' $p @()
    $bin = Join-Path $p 'bin'
    if ($Rc -eq 0 -and (([Environment]::GetEnvironmentVariable('Path', 'User') -split ';') -contains $bin)) { Ok 'user PATH gains bin' } else { Bad 'user PATH gains bin' $Out }
    Inst 's1' 's1' $p @('-Uninstall')
    if ($Rc -eq 0 -and -not (Test-Path (Join-Path $p 'versions')) -and -not (Test-Path $bin) -and -not (([Environment]::GetEnvironmentVariable('Path', 'User') -split ';') -contains $bin)) { Ok 'uninstall removes junction, files, PATH entry' } else { Bad 'uninstall' $Out }
    Inst 's1' 's1' $p @('-Uninstall'); if ($Rc -eq 0 -and (Has 'Nothing to uninstall')) { Ok 'uninstall twice is harmless' } else { Bad 'uninstall twice' $Out }

    # U5: removal warns about files that were never downloaded and never assumes consent
    $p = NewPrefix 74; Inst 's1' 's1' $p @('-NoModifyPath'); Inst 's1' 's1' $p @('-Uninstall')
    if ($Rc -eq 0 -and (Has 'WARNING') -and (Has 'cannot count files that were never downloaded')) { Ok 'uninstall warns that placeholders cannot be counted when the daemon does not answer' } else { Bad 'uninstall unknown count warning' $Out }
    Fx 'ph' '--exe', (Join-Path $T 'fake-ph.exe')
    $schemas = @(
        @{ n = 77; name = 'a folder without the count (older schema)'; json = '{"folders":[{"local_path":"C:/Y"}]}'; want = 'count is unknown'; warn = $true },
        @{ n = 78; name = 'a null count'; json = '{"folders":[{"local_path":"C:/Y","on_demand":true,"placeholder_count":null}]}'; want = 'count is unknown'; warn = $true },
        @{ n = 79; name = 'a folder without on_demand'; json = '{"folders":[{"local_path":"C:/Y","placeholder_count":0}]}'; want = 'count is unknown'; warn = $true },
        @{ n = 75; name = 'a count of 3'; json = '{"folders":[{"local_path":"C:/Y","on_demand":true,"placeholder_count":3}]}'; want = '3 file(s) were never downloaded'; warn = $true },
        @{ n = 80; name = 'a count of 0'; json = '{"folders":[{"local_path":"C:/Y","on_demand":true,"placeholder_count":0}]}'; want = $null; warn = $false }
    )
    foreach ($c in $schemas) {
        # with -Yes: the warning (or none) is printed and the removal goes on
        $env:YL_FAKE_STATUS = $c.json
        $p = NewPrefix $c.n; Inst 'ph' 'ph' $p @('-NoModifyPath'); Inst 'ph' 'ph' $p @('-Uninstall')
        $gone = -not (Test-Path (Join-Path $p 'install-receipt.txt'))
        if ($c.warn) { $okc = $Rc -eq 0 -and $gone -and (Has 'WARNING') -and (Has $c.want) } else { $okc = $Rc -eq 0 -and $gone -and -not (Has 'WARNING') }
        if ($okc) { Ok "uninstall -Yes, status with $($c.name)" } else { Bad "uninstall -Yes, status with $($c.name)" $Out }
        # without -Yes and nobody to ask: refused exactly when the warning applies
        $p = NewPrefix ($c.n + 20); Inst 'ph' 'ph' $p @('-NoModifyPath')
        $env:YADORILINK_INSTALL_TEST = '1'
        $o = ('' | & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Installer -Prefix $p -Uninstall 2>&1 | ForEach-Object { "$_" }) -join "`n"; $rc = $LASTEXITCODE
        Remove-Item Env:YADORILINK_INSTALL_TEST -ErrorAction SilentlyContinue
        $kept = Test-Path (Join-Path $p 'install-receipt.txt')
        if ($c.warn) { $okc = $rc -ne 0 -and $kept } else { $okc = $rc -eq 0 -and -not $kept }
        if ($okc) { Ok "uninstall without -Yes and nobody to ask, status with $($c.name)" } else { Bad "uninstall without -Yes, status with $($c.name)" $o }
        Remove-Item Env:YL_FAKE_STATUS -ErrorAction SilentlyContinue
        if ($kept) { Inst 'ph' 'ph' $p @('-Uninstall') }
    }

    # the daemon-readable script marker sits beside the binaries (install_source.rs)
    $p = NewPrefix 72; Inst 's1' 's1' $p @('-NoModifyPath')
    $marker = Join-Path $p 'bin\install-receipt.json'
    if ($Rc -eq 0 -and (Test-Path $marker) -and ((Get-Content $marker -Raw | ConvertFrom-Json).source -eq 'script')) { Ok 'install writes install-receipt.json beside the daemon' } else { Bad 'daemon-readable receipt' $Out }

    # uninstall keeps the receipt when a file under versions\ is locked (control: it goes once unlocked)
    $p = NewPrefix 73; Inst 's1' 's1' $p @('-NoModifyPath')
    $held = Get-ChildItem (Join-Path $p 'versions') -Recurse -File | Select-Object -First 1
    $fs = [System.IO.File]::Open($held.FullName, 'Open', 'Read', 'None')
    try { Inst 's1' 's1' $p @('-Uninstall') } finally { $fs.Dispose() }
    if ($Rc -ne 0 -and (Has 'receipt was kept') -and (Test-Path (Join-Path $p 'install-receipt.txt'))) { Ok 'uninstall with a locked file keeps the receipt' } else { Bad 'uninstall locked' $Out }
    Inst 's1' 's1' $p @('-Uninstall')
    if ($Rc -eq 0 -and -not (Test-Path (Join-Path $p 'install-receipt.txt'))) { Ok 'retry after unlocking completes the uninstall' } else { Bad 'uninstall retry' $Out }

    # help
    $o = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Installer -Help 2>&1 | ForEach-Object { "$_" }) -join "`n"
    if ($o -like '*-Prefix*' -and $o -like '*-Uninstall*') { Ok '-Help' } else { Bad '-Help' $o }

    # the `irm | iex` form: script text evaluated, configured through environment variables
    $p = NewPrefix 21
    $env:YADORILINK_INSTALL_TEST = '1'; $env:YADORILINK_INSTALL_PUBKEY_HEX = Pub 's1'; $env:YADORILINK_INSTALL_BASE_URL = "$Base/s1"; $env:YADORILINK_INSTALL_ARCH = 'AMD64'; $env:YADORILINK_INSTALL_KEY_ID = (Get-Content (Join-Path $Srv 's1\key_id') -Raw).Trim()
    $env:YADORILINK_PREFIX = $p; $env:YADORILINK_YES = '1'; $env:YADORILINK_NO_MODIFY_PATH = '1'
    $o = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-Content -Raw '$Installer' | Invoke-Expression; exit 0" 2>&1 | ForEach-Object { "$_" }) -join "`n"
    foreach ($v in 'YADORILINK_INSTALL_TEST', 'YADORILINK_INSTALL_PUBKEY_HEX', 'YADORILINK_INSTALL_BASE_URL', 'YADORILINK_INSTALL_ARCH', 'YADORILINK_INSTALL_KEY_ID', 'YADORILINK_PREFIX', 'YADORILINK_YES', 'YADORILINK_NO_MODIFY_PATH') { Remove-Item "Env:$v" -ErrorAction SilentlyContinue }
    if ((Test-Path (Join-Path $p 'bin\yadorilink.exe')) -and $o -like '*Installed YadoriLink 0.2.0*') { Ok 'iex form installs' } else { Bad 'iex form' $o }

    # a prompt that interpolates "$name?" prints nothing for the name (PowerShell reads "name?" as the variable)
    $bad = @(Select-String -LiteralPath $Installer -Pattern '"[^"]*\$[A-Za-z_]\w*\?[^"]*"' | ForEach-Object { "line $($_.LineNumber): $($_.Line.Trim())" })
    if ($bad.Count -eq 0) { Ok 'no prompt interpolates a name followed by a question mark' } else { Bad 'prompt text interpolates $name?' ($bad -join "`n") }

    # embedded verifier agrees with the independent Python signer on a manifest it signed (positive case is every success above)
} finally {
    [Environment]::SetEnvironmentVariable('Path', $origUserPath, 'User')
    if ($server) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 300
    Remove-Item $T -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host ''
Write-Host "passed: $Pass, failed: $Fail"
exit $(if ($Fail -eq 0) { 0 } else { 1 })
