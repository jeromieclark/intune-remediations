param()

$TargetVersion = [Version]"145.0.3800.97"

$edgePaths = @(
    "$Env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe",
    "$Env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
)

$edgePath = $edgePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

function Get-WingetPath {
    $command = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $windowsApps = Join-Path $Env:ProgramFiles "WindowsApps"
    $candidates = Get-ChildItem -Path $windowsApps -Filter "Microsoft.DesktopAppInstaller_*" -Directory -ErrorAction SilentlyContinue |
        Sort-Object -Property Name -Descending |
        ForEach-Object {
            Join-Path $_.FullName "winget.exe"
        } |
        Where-Object { Test-Path $_ }

    return $candidates | Select-Object -First 1
}

$wingetPath = Get-WingetPath
if (-not $wingetPath) {
    Write-Host "winget is not available for SYSTEM context."
    exit 1
}

Write-Host "Running winget upgrade for Microsoft Edge..."
$arguments = @(
    "upgrade",
    "--id", "Microsoft.Edge",
    "--silent",
    "--disable-interactivity",
    "--accept-source-agreements",
    "--accept-package-agreements",
    "--scope", "machine"
)

$process = Start-Process -FilePath $wingetPath -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
Write-Host "winget exit code: $($process.ExitCode)"

Start-Sleep -Seconds 5

if (-not $edgePath) {
    $edgePath = $edgePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
}

if (-not $edgePath) {
    Write-Host "Microsoft Edge not found after remediation."
    exit 1
}

$currentVersionString = (Get-Item $edgePath).VersionInfo.ProductVersion
try {
    $currentVersion = [Version]$currentVersionString
} catch {
    Write-Host "Unable to parse Edge version: $currentVersionString"
    exit 1
}

Write-Host "Detected Edge version after remediation: $currentVersion"

if ($currentVersion -ge $TargetVersion) {
    Write-Host "Remediation succeeded (>= $TargetVersion)."
    exit 0
}

Write-Host "Remediation did not reach target version (< $TargetVersion)."
exit 1
