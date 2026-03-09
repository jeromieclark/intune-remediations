# Intune Detection - Ensure Google Chrome is up to date
# This script will be deployed via Intune and should run on Powershell 5 in the SYSTEM context
# If Chrome is installed, compare installed version with the latest available version via winget
# If Chrome is not present, exit 0 (compliant)
# If Chrome is present but out of date or version lookup fails, exit 1 (remediation required)

$ErrorActionPreference = 'Stop'

function Get-ChromeInfo {
	$paths = @(
		"$Env:ProgramFiles\Google\Chrome\Application\chrome.exe",
		"${Env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
	) | Where-Object { $_ -and (Test-Path $_) }

	if (-not $paths) { return $null }

	$exe = $paths | Select-Object -First 1
	$version = (Get-Item $exe).VersionInfo.ProductVersion

	[pscustomobject]@{
		Path    = $exe
		Version = [version]$version
	}
}

function Get-WingetPath {
	$searchRoots = @()
	if ($env:LOCALAPPDATA) {
		$searchRoots += (Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\WindowsApps")
	}
	if ($env:ProgramFiles) {
		$searchRoots += (Join-Path -Path $env:ProgramFiles -ChildPath "WindowsApps")
	}

	foreach ($root in $searchRoots) {
		if (-not (Test-Path -Path $root)) {
			continue
		}

		$appDirs = Get-ChildItem -Path $root -Directory -Filter "Microsoft.DesktopAppInstaller_*" -ErrorAction SilentlyContinue | Sort-Object Name -Descending
		foreach ($dir in $appDirs) {
			$candidate = Join-Path -Path $dir.FullName -ChildPath "winget.exe"
			if (Test-Path -Path $candidate) {
				return $candidate
			}
		}

		$fallback = Get-ChildItem -Path $root -Filter "winget.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
		if ($fallback) {
			return $fallback.FullName
		}
	}

	return $null
}

function Get-LatestChromeVersionViaWinget {
	$wingetPath = Get-WingetPath
	if (-not $wingetPath) { return $null }

	$info = & $wingetPath show --id "Google.Chrome" -e 2>$null
	if (-not $info) { return $null }

	$line = ($info | Select-String -Pattern 'Version:\s*(.+)$').Matches.Value
	if ($line) {
		$v = $line -replace 'Version:\s*',''
		return [version]$v
	}

	return $null
}

try {
	$chrome = Get-ChromeInfo
	if (-not $chrome) {
		Write-Output "Chrome not found."
		exit 0
	}

	Write-Output "Detected Chrome path: $($chrome.Path)"
	Write-Output "Detected Chrome version: $($chrome.Version)"

	$latest = Get-LatestChromeVersionViaWinget
	if (-not $latest) {
		Write-Output "Detection failed: unable to resolve latest Chrome version."
		exit 1
	}

	Write-Output "Latest Chrome version (winget): $latest"

	if ($chrome.Version -lt $latest) {
		Write-Output "Chrome is out of date."
		exit 1
	}

	Write-Output "Chrome is up to date."

	exit 0
} catch {
	Write-Output "Detection failed: $($_.Exception.Message)"
	exit 1
}
