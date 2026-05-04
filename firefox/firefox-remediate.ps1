# Intune Remediation - Update Firefox to Latest Version
# This script will be deployed via Intune and should run on Powershell 5 in the SYSTEM context
# If Firefox is installed, update to the latest available version and restart Firefox if it is running
# If winget is required, remember to correctly resolve the path for execution in the SYSTEM context
# If Firefox is not present or the upgrade completes successfully, exit 0
# If the upgrade fails, exit 1

$ErrorActionPreference = 'Stop'
$EnableNonStandardDiscovery = $true
$EnablePortableInPlaceRemediation = $true
$EnableEmbeddedRemediation = $false
$MaxNonStandardResults = 20

function Write-DebugLog {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Message
	)

	$timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
	Write-Output "DEBUG [$timestamp] $Message"
}

function ConvertTo-Version {
	param(
		[Parameter(Mandatory = $true)]
		[AllowEmptyString()]
		[string]$Value
	)

	if (-not $Value) {
		return $null
	}

	$matches = [regex]::Match($Value, '(\d+\.\d+(?:\.\d+){0,2})')
	if (-not $matches.Success) {
		return $null
	}

	try {
		return [version]$matches.Groups[1].Value
	} catch {
		return $null
	}
}

function Test-FirefoxRuntimeHeuristics {
	param(
		[Parameter(Mandatory = $true)]
		[string]$ExePath
	)

	if (-not (Test-Path -Path $ExePath)) {
		return $false
	}

	$dir = Split-Path -Path $ExePath -Parent
	$markers = @(
		(Join-Path -Path $dir -ChildPath 'application.ini'),
		(Join-Path -Path $dir -ChildPath 'omni.ja')
	)

	$hits = 0
	foreach ($marker in $markers) {
		if (Test-Path -Path $marker) {
			$hits++
		}
	}

	return ($hits -ge 1)
}

function Get-FirefoxCategory {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Path
	)

	$normalized = $Path.ToLowerInvariant()
	if ($normalized -match 'ms-playwright|\\\.playwright\\|\\playwright\\') {
		return 'Playwright'
	}

	if ($normalized -match '\\resources\\app|\\vendor\\|\\asar') {
		return 'Embedded'
	}

	return 'Portable'
}

function Get-RemediationMode {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Category
	)

	if ($Category -eq 'Portable' -and $EnablePortableInPlaceRemediation) {
		return 'InPlace'
	}

	if ($Category -eq 'Embedded' -and $EnableEmbeddedRemediation) {
		return 'InPlace'
	}

	return 'ReportOnly'
}

function Get-NonStandardFirefoxInstances {
	param(
		[Parameter(Mandatory = $true)]
		$StandardPaths,
		[Parameter(Mandatory = $true)]
		[int]$MaxResults
	)

	$standardPathSet = @{}
	foreach ($standardPath in @($StandardPaths)) {
		if ($standardPath) {
			$standardPathSet[$standardPath.ToLowerInvariant()] = $true
		}
	}

	$candidates = @()
	$patterns = @(
		"$Env:ProgramFiles\node_modules\ms-playwright\firefox-*\firefox\firefox.exe",
		"${Env:ProgramFiles(x86)}\node_modules\ms-playwright\firefox-*\firefox\firefox.exe",
		"$Env:ProgramData\.playwright\firefox-*\firefox\firefox.exe",
		"$Env:ProgramFiles\*\resources\app*\*\firefox.exe",
		"${Env:ProgramFiles(x86)}\*\resources\app*\*\firefox.exe",
		"$Env:ProgramData\*\*\firefox.exe",
		"C:\Firefox*\firefox.exe",
		"C:\Tools\*\firefox.exe",
		"C:\Apps\*\firefox.exe"
	)

	foreach ($pattern in $patterns) {
		try {
			$items = @(Get-ChildItem -Path $pattern -File -ErrorAction Stop)
			foreach ($item in $items) {
				if ($item -and $item.FullName) {
					$candidates += $item.FullName
				}
			}
		} catch {
			continue
		}
	}

	$results = @()
	$seen = @{}
	foreach ($path in ($candidates | Select-Object -Unique)) {
		if (@($results).Count -ge $MaxResults) {
			Write-DebugLog "Reached non-standard scan cap ($MaxResults)."
			break
		}

		if ($standardPathSet.ContainsKey($path.ToLowerInvariant())) {
			continue
		}

		$key = $path.ToLowerInvariant()
		if ($seen.ContainsKey($key)) {
			continue
		}
		$seen[$key] = $true

		if (-not (Test-FirefoxRuntimeHeuristics -ExePath $path)) {
			continue
		}

		$rawVersion = $null
		$parsedVersion = $null
		try {
			$rawVersion = (Get-Item -Path $path -ErrorAction Stop).VersionInfo.FileVersion
			$parsedVersion = ConvertTo-Version -Value ([string]$rawVersion)
		} catch {
			Write-DebugLog "Unable to read file version for '$path'."
		}

		$category = Get-FirefoxCategory -Path $path
		$results += [pscustomobject]@{
			Path            = $path
			Version         = $parsedVersion
			VersionRaw      = $rawVersion
			Category        = $category
			RemediationMode = Get-RemediationMode -Category $category
		}
	}

	return @($results)
}

function Invoke-PortableUpdater {
	param(
		[Parameter(Mandatory = $true)]
		$Instance,
		[Parameter(Mandatory = $true)]
		[version]$TargetVersion
	)

	$updaterPath = Join-Path -Path (Split-Path -Path $Instance.Path -Parent) -ChildPath 'updater.exe'
	if (-not (Test-Path -Path $updaterPath)) {
		Write-DebugLog "Portable remediation skipped, updater not found: $updaterPath"
		return $false
	}

	try {
		Write-DebugLog "Attempting in-place updater for '$($Instance.Path)'."
		Start-Process -FilePath $updaterPath -ArgumentList '/S' -Wait -WindowStyle Hidden -ErrorAction Stop | Out-Null
	} catch {
		Write-DebugLog "Portable updater failed to execute: $($_.Exception.Message)"
		return $false
	}

	try {
		$newVersion = ConvertTo-Version -Value ([string](Get-Item -Path $Instance.Path -ErrorAction Stop).VersionInfo.FileVersion)
		if ($newVersion -and ($newVersion -ge $TargetVersion)) {
			Write-DebugLog "Portable instance updated successfully to $newVersion."
			return $true
		}

		Write-DebugLog "Portable updater completed but version did not reach target. Current: $newVersion Target: $TargetVersion"
		return $false
	} catch {
		Write-DebugLog "Portable version verification failed: $($_.Exception.Message)"
		return $false
	}
}

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
	Write-DebugLog "Remediation started."
	$fx = Get-FirefoxInfo
	Write-DebugLog "Firefox detection: $([bool]$fx)."
	$standardPaths = @(
		"$Env:ProgramFiles\Mozilla Firefox\firefox.exe",
		"${Env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
	) | Where-Object { $_ -and (Test-Path -Path $_) }

	$nonStandard = @()
	if ($EnableNonStandardDiscovery) {
		$nonStandard = Get-NonStandardFirefoxInstances -StandardPaths $standardPaths -MaxResults $MaxNonStandardResults
		Write-DebugLog "Non-standard Firefox instances discovered: $($nonStandard.Count)."
	}

	$hasFirefox = [bool]$fx -or ($nonStandard.Count -gt 0)
	if (-not $hasFirefox) {
		Write-DebugLog "Firefox not installed in standard or non-standard paths. Exiting with success."
		exit 0
	}

	if ($fx) {
		Write-DebugLog "Detected channel: $($fx.Channel)."
		if ($fx.Path) {
			Write-DebugLog "Firefox path: $($fx.Path)."
		}
	}

	$wingetPath = $null
	if ($fx) {
		$wingetPath = Get-WingetPath
		if (-not $wingetPath) {
			Write-Output "Remediation failed: winget.exe was not found."
			exit 1
		}
		Write-DebugLog "winget path: $wingetPath"
	}

	$packageId = $null
	if ($fx) {
		$packageId = if ($fx.Channel -eq 'ESR') { 'Mozilla.Firefox.ESR' } else { 'Mozilla.Firefox' }
		Write-DebugLog "Package id: $packageId"
	}

	$wasRunning = $false
	$procs = Get-Process -Name firefox -ErrorAction SilentlyContinue
	if ($procs) {
		$wasRunning = $true
		Write-DebugLog "Firefox processes found: $($procs.Count). Stopping."
		$procs | Stop-Process -Force -ErrorAction SilentlyContinue
		Start-Sleep -Seconds 2
	} else {
		Write-DebugLog "No Firefox processes running."
	}

	if ($fx) {
		$result = Invoke-WingetUpgrade -WingetPath $wingetPath -PackageId $packageId
		Write-DebugLog "winget exit code: $($result.ExitCode)"
		if (-not (Test-WingetUpgradeSuccess -Result $result)) {
			$tail = $result.Output | Select-Object -Last 8
			Write-Output "Remediation failed: winget exit code $($result.ExitCode)."
			if ($tail) {
				Write-Output ($tail -join "`n")
			}
			exit 1
		}
	}

	$latestRelease = Get-WingetPath
	$releaseTarget = $null
	if ($latestRelease) {
		$showOutput = & $latestRelease show --id 'Mozilla.Firefox' -e 2>$null
		$line = ($showOutput | Select-String -Pattern 'Version:\s*(.+)$').Matches.Value
		if ($line) {
			$releaseTarget = ConvertTo-Version -Value (($line -replace 'Version:\s*', '').Trim())
		}
	}

	$needsManualAction = $false
	foreach ($instance in $nonStandard) {
		$stale = $true
		if ($releaseTarget -and $instance.Version) {
			$stale = ($instance.Version -lt $releaseTarget)
		}

		if (-not $stale) {
			Write-DebugLog "Non-standard instance already compliant: $($instance.Path)"
			continue
		}

		if ($instance.RemediationMode -eq 'InPlace') {
			if ($releaseTarget -and (Invoke-PortableUpdater -Instance $instance -TargetVersion $releaseTarget)) {
				continue
			}
		}

		Write-Output "NonStandardActionRequired category=$($instance.Category) mode=$($instance.RemediationMode) version=$($instance.Version) path=$($instance.Path)"
		$needsManualAction = $true
	}

	if ($wasRunning -and $fx.Path -and (Test-Path -Path $fx.Path)) {
		Write-DebugLog "Restarting Firefox."
		Start-Process -FilePath $fx.Path -ErrorAction SilentlyContinue
	}

	if ($needsManualAction) {
		Write-Output "Remediation completed with manual action required for non-standard Firefox instances."
		exit 1
	}

	Write-DebugLog "Remediation completed successfully."
	exit 0
} catch {
	Write-Output "Remediation failed: $($_.Exception.Message)"
	exit 1
}
