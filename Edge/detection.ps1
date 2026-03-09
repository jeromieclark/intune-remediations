param()

$TargetVersion = [Version]"145.0.3800.97"

$edgePaths = @(
	"$Env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe",
	"$Env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
)

$edgePath = $edgePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $edgePath) {
	Write-Host "Microsoft Edge not found."
	exit 1
}

$currentVersionString = (Get-Item $edgePath).VersionInfo.ProductVersion
try {
	$currentVersion = [Version]$currentVersionString
} catch {
	Write-Host "Unable to parse Edge version: $currentVersionString"
	exit 1
}

Write-Host "Detected Edge version: $currentVersion"

if ($currentVersion -ge $TargetVersion) {
	Write-Host "Edge is compliant (>= $TargetVersion)."
	exit 0
}

Write-Host "Edge is non-compliant (< $TargetVersion)."
exit 1
