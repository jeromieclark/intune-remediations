
# Intune Remediation - Update Firefox to Latest Version
# This script will be deployed via Intune and should run on Powershell 5 in the SYSTEM context
# If Firefox is installed, update to the latest available version and restart Firefox if it is running
# If winget is required, remember to correctly resolve the path for execution in the SYSTEM context
# If Firefox is not present or the upgrade completes successfully, exit 0
# If the upgrade fails, exit 1

$ErrorActionPreference = 'Stop'

function Get-FirefoxInfo {
	$paths = @(
		"$Env:ProgramFiles\Mozilla Firefox\firefox.exe",
		"${Env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
	) | Where-Object { $_ -and (Test-Path $_) }

	$regUninstall = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
					"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

	$entries = foreach ($root in $regUninstall) {
		Get-ChildItem $root -ErrorAction SilentlyContinue |
		Where-Object {
			($_ | Get-ItemProperty -ErrorAction SilentlyContinue).DisplayName -like 'Mozilla Firefox*'
		} |
		ForEach-Object {
			$p = $_ | Get-ItemProperty -ErrorAction SilentlyContinue
			[pscustomobject]@{
				DisplayName     = $p.DisplayName
				DisplayVersion  = $p.DisplayVersion
				InstallLocation = $p.InstallLocation
				Path            = if ($p.InstallLocation) { Join-Path $p.InstallLocation 'firefox.exe' } else { $null }
			}
		}
	}

	if (-not $paths -and $entries) {
		$paths = $entries | Where-Object { $_.Path } | Select-Object -ExpandProperty Path
	}

	if (-not $paths) { return $null }

	$exe = $paths | Select-Object -First 1
	$channel = if ($exe -like "*ESR*") { "ESR" } else {
		if ($entries | Where-Object { $_.DisplayName -match 'ESR' }) { "ESR" } else { "Release" }
	}

	[pscustomobject]@{
		Path    = $exe
		Channel = $channel
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
	$fx = Get-FirefoxInfo
	if (-not $fx) {
		exit 0
	}

	$wingetPath = Get-WingetPath
	if (-not $wingetPath) {
		Write-Output "Remediation failed: winget.exe was not found."
		exit 1
	}

	$packageId = if ($fx.Channel -eq 'ESR') { 'Mozilla.Firefox.ESR' } else { 'Mozilla.Firefox' }

	$wasRunning = $false
	$procs = Get-Process -Name firefox -ErrorAction SilentlyContinue
	if ($procs) {
		$wasRunning = $true
		$procs | Stop-Process -Force -ErrorAction SilentlyContinue
		Start-Sleep -Seconds 2
	}

	$result = Invoke-WingetUpgrade -WingetPath $wingetPath -PackageId $packageId
	if (-not (Test-WingetUpgradeSuccess -Result $result)) {
		$tail = $result.Output | Select-Object -Last 8
		Write-Output "Remediation failed: winget exit code $($result.ExitCode)."
		if ($tail) {
			Write-Output ($tail -join "`n")
		}
		exit 1
	}

	if ($wasRunning -and $fx.Path -and (Test-Path -Path $fx.Path)) {
		Start-Process -FilePath $fx.Path -ErrorAction SilentlyContinue
	}

	exit 0
} catch {
	Write-Output "Remediation failed: $($_.Exception.Message)"
	exit 1
}
