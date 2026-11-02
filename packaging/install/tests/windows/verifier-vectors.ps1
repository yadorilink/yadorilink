# Prints the result of the installer's embedded Ed25519 verifier on known vectors, so the result under Windows
# PowerShell and under PowerShell 7 can be compared. It loads the verifier exactly as install.ps1 does: the
# source text and Initialize-Verifier are taken from the installer file itself, not copied here.
#
#   powershell -NoProfile -File verifier-vectors.ps1 -Installer C:\path\install.ps1
#   pwsh       -NoProfile -File verifier-vectors.ps1 -Installer C:\path\install.ps1
param([Parameter(Mandatory = $true)][string]$Installer)

$ast = [System.Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$null, [ref]$null)
$source = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$script:Ed25519Source' }, $true)
function Fail($m) { throw $m }
Invoke-Expression $source.Extent.Text
foreach ($name in 'ConvertFrom-Hex', 'Initialize-Verifier') {
    $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
    Invoke-Expression $fn.Extent.Text
}
# Initialize-Verifier compiles the verifier and checks it against RFC 8032 test vector 2 and a corrupted signature.
Initialize-Verifier

function V([string]$pub, [string]$msg, [string]$sig) { [YadoriEd25519]::Verify((ConvertFrom-Hex $pub), (ConvertFrom-Hex $msg), (ConvertFrom-Hex $sig)) }
# RFC 8032 section 7.1, test vectors 1 and 2.
$pub1 = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
$sig1 = 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
$pub2 = '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'
$sig2 = '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'
$flipLast = $sig2.Substring(0, $sig2.Length - 2) + '01'
$flipFirst = '93' + $sig2.Substring(2)
$r = [ordered]@{
    vector1                = V $pub1 '' $sig1
    vector2                = V $pub2 '72' $sig2
    'last bit flipped'     = V $pub2 '72' $flipLast
    'first bit flipped'    = V $pub2 '72' $flipFirst
    'other key'            = V $pub1 '72' $sig2
    'other message'        = V $pub2 '73' $sig2
}
($r.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';'
