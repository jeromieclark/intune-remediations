# Intune Remediation - Update Google Chrome to Latest Version
# This script will be deployed via Intune and should run on Powershell 5 in the SYSTEM context
# If Chrome is installed, update to the latest available version and restart Chrome if it was running
# If Chrome is not present or the upgrade completes successfully, exit 0
# If the upgrade fails, exit 1

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

function Invoke-WingetUpgrade {
	param(
		[Parameter(Mandatory = $true)]
		[string]$WingetPath,
		[Parameter(Mandatory = $true)]
		[string]$PackageId
	)

	$upgradeArgs = @(
		"upgrade",
		"--id", $PackageId,
		"--exact",
		"--silent",
		"--scope", "machine",
		"--disable-interactivity",
		"--accept-package-agreements",
		"--accept-source-agreements"
	)

	$output = & $WingetPath @upgradeArgs 2>&1
	$exitCode = $LASTEXITCODE

	return [pscustomobject]@{
		ExitCode = $exitCode
		Output   = $output
	}
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

function Test-WingetUpgradeSuccess {
	param(
		[Parameter(Mandatory = $true)]
		$Result
	)

	$text = ($Result.Output | Out-String).ToLowerInvariant()
	if ($text -match 'no available upgrade found' -or $text -match 'no newer package versions are available' -or $text -match 'no applicable update') {
		return $true
	}

	$successCodes = @(0, 3010, 1641)
	if ($successCodes -contains $Result.ExitCode) {
		return $true
	}

	if ($Result.ExitCode -eq 1 -and ($text -match 'no applicable update' -or $text -match 'no installed package found' -or $text -match 'successfully installed' -or $text -match 'already installed')) {
		return $true
	}

	return $false
}

try {
	$chrome = Get-ChromeInfo
	if (-not $chrome) {
		Write-Output "Chrome not found."
		exit 0
	}

	Write-Output "Detected Chrome path: $($chrome.Path)"
	Write-Output "Detected Chrome version: $($chrome.Version)"

	$wingetPath = Get-WingetPath
	if (-not $wingetPath) {
		Write-Output "Remediation failed: winget.exe was not found."
		exit 1
	}

	Write-Output "Using winget at: $wingetPath"

	$latest = Get-LatestChromeVersionViaWinget
	if ($latest) {
		Write-Output "Latest Chrome version (winget): $latest"
	} else {
		Write-Output "Unable to resolve latest Chrome version via winget."
	}
	if ($latest -and ($chrome.Version -ge $latest)) {
		Write-Output "Chrome is already current."
		exit 0
	}

	$wasRunning = $false
	$procs = Get-Process -Name chrome -ErrorAction SilentlyContinue
	if ($procs) {
		$wasRunning = $true
		Write-Output "Chrome is running. Stopping before upgrade."
		$procs | Stop-Process -Force -ErrorAction SilentlyContinue
		Start-Sleep -Seconds 2
	}

	Write-Output "Running winget upgrade for Google.Chrome..."
	$result = Invoke-WingetUpgrade -WingetPath $wingetPath -PackageId "Google.Chrome"
	if (-not (Test-WingetUpgradeSuccess -Result $result)) {
		$tail = $result.Output | Select-Object -Last 8
		Write-Output "Remediation failed: winget exit code $($result.ExitCode)."
		if ($tail) {
			Write-Output ($tail -join "`n")
		}
		exit 1
	}

	if ($wasRunning -and $chrome.Path -and (Test-Path -Path $chrome.Path)) {
		Write-Output "Restarting Chrome."
		Start-Process -FilePath $chrome.Path -ErrorAction SilentlyContinue
	}

	exit 0
} catch {
	Write-Output "Remediation failed: $($_.Exception.Message)"
	exit 1
}
