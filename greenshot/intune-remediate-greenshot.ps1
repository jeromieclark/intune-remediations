# Intune remediation script for unsanctioned Greenshot installations
# This script runs in PowerShell 5 under the SYSTEM context.
# Removes Greenshot from machine-wide and per-user locations when detected.

$ErrorActionPreference = 'Stop'

function Get-GreenshotInstallIndicators {
	$results = New-Object System.Collections.Generic.List[object]

	$machineUninstallRoots = @(
		'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
		'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
	)

	foreach ($root in $machineUninstallRoots) {
		if (-not (Test-Path -Path $root)) { continue }

		Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
			$props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
			if (-not $props -or -not $props.DisplayName) { return }

			if ($props.DisplayName -match 'Greenshot') {
				$results.Add([pscustomobject]@{
					Scope             = 'Machine'
					Source            = 'Registry'
					DisplayName       = [string]$props.DisplayName
					RegistryPath      = [string]$_.PSPath
					QuietUninstallRaw = [string]$props.QuietUninstallString
					UninstallRaw      = [string]$props.UninstallString
					WindowsInstaller  = [int]$props.WindowsInstaller
				})
			}
		}
	}

	$machineFilePaths = @(
		'C:\Program Files\Greenshot\Greenshot.exe',
		'C:\Program Files (x86)\Greenshot\Greenshot.exe'
	)

	foreach ($path in $machineFilePaths) {
		if (Test-Path -Path $path) {
			$results.Add([pscustomobject]@{
				Scope             = 'Machine'
				Source            = 'File'
				DisplayName       = 'Greenshot'
				RegistryPath      = $null
				QuietUninstallRaw = $null
				UninstallRaw      = $null
				WindowsInstaller  = 0
				Path              = $path
			})
		}
	}

	$userProfiles = Get-ChildItem -Path 'C:\Users' -Directory -ErrorAction SilentlyContinue |
		Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }

	foreach ($profile in $userProfiles) {
		$userFileCandidates = @(
			(Join-Path -Path $profile.FullName -ChildPath 'AppData\Local\Greenshot\Greenshot.exe'),
			(Join-Path -Path $profile.FullName -ChildPath 'AppData\Local\Programs\Greenshot\Greenshot.exe'),
			(Join-Path -Path $profile.FullName -ChildPath 'AppData\Roaming\Greenshot\Greenshot.exe')
		)

		foreach ($candidate in $userFileCandidates) {
			if (Test-Path -Path $candidate) {
				$results.Add([pscustomobject]@{
					Scope             = 'User'
					Source            = 'File'
					DisplayName       = 'Greenshot'
					RegistryPath      = $null
					QuietUninstallRaw = $null
					UninstallRaw      = $null
					WindowsInstaller  = 0
					Path              = $candidate
					ProfilePath       = $profile.FullName
				})
			}
		}
	}

	$hkuSids = Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
		Where-Object { $_.PSChildName -match '^S-1-5-21-.+' }

	foreach ($sid in $hkuSids) {
		$root = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
		if (-not (Test-Path -Path $root)) { continue }

		Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
			$props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
			if (-not $props -or -not $props.DisplayName) { return }

			if ($props.DisplayName -match 'Greenshot') {
				$results.Add([pscustomobject]@{
					Scope             = 'User'
					Source            = 'Registry'
					DisplayName       = [string]$props.DisplayName
					RegistryPath      = [string]$_.PSPath
					QuietUninstallRaw = [string]$props.QuietUninstallString
					UninstallRaw      = [string]$props.UninstallString
					WindowsInstaller  = [int]$props.WindowsInstaller
					Sid               = [string]$sid.PSChildName
				})
			}
		}
	}

	return $results | Sort-Object Scope, Source, RegistryPath, Path, DisplayName -Unique
}

function Split-UninstallString {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Text
	)

	$trimmed = $Text.Trim()
	if (-not $trimmed) { return $null }

	if ($trimmed.StartsWith('"')) {
		$match = [regex]::Match($trimmed, '^"([^"]+)"\s*(.*)$')
		if ($match.Success) {
			return [pscustomobject]@{
				FilePath     = $match.Groups[1].Value
				ArgumentList = $match.Groups[2].Value
			}
		}
	}

	$parts = $trimmed.Split(' ', 2)
	return [pscustomobject]@{
		FilePath     = $parts[0]
		ArgumentList = if ($parts.Count -gt 1) { $parts[1] } else { '' }
	}
}

function Build-UninstallCommands {
	param(
		[Parameter(Mandatory = $true)]
		[pscustomobject]$Indicator
	)

	$commands = New-Object System.Collections.Generic.List[object]

	$rawCandidates = @($Indicator.QuietUninstallRaw, $Indicator.UninstallRaw) | Where-Object { $_ }
	foreach ($raw in $rawCandidates) {
		$split = Split-UninstallString -Text $raw
		if (-not $split -or -not $split.FilePath) { continue }

		$fileName = [System.IO.Path]::GetFileName($split.FilePath)
		$args = $split.ArgumentList

		if ($split.FilePath -match '(?i)msiexec(\.exe)?$') {
			if ($args -notmatch '(?i)\s/qn\b') { $args = "$args /qn".Trim() }
			if ($args -notmatch '(?i)\s/norestart\b') { $args = "$args /norestart".Trim() }
			if ($args -notmatch '(?i)\s/x\b' -and $args -match '(?i)\s/i\b') {
				$args = $args -replace '(?i)\s/i\b', ' /x '
			}
		} elseif ($fileName -match '(?i)^unins\d+\.exe$|^uninstall\.exe$') {
			if ($args -notmatch '(?i)/SILENT|/VERYSILENT') { $args = "$args /VERYSILENT".Trim() }
			if ($args -notmatch '(?i)/SUPPRESSMSGBOXES') { $args = "$args /SUPPRESSMSGBOXES".Trim() }
			if ($args -notmatch '(?i)/NORESTART') { $args = "$args /NORESTART".Trim() }
		}

		$commands.Add([pscustomobject]@{
			FilePath = $split.FilePath
			Args     = $args
			Source   = 'RegistryUninstall'
		})
	}

	if ($Indicator.Path) {
		$installDir = Split-Path -Path $Indicator.Path -Parent
		$innoCandidates = @(
			(Join-Path -Path $installDir -ChildPath 'unins000.exe'),
			(Join-Path -Path $installDir -ChildPath 'uninstall.exe')
		)

		foreach ($candidate in $innoCandidates) {
			if (Test-Path -Path $candidate) {
				$commands.Add([pscustomobject]@{
					FilePath = $candidate
					Args     = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
					Source   = 'FileFallback'
				})
			}
		}
	}

	return $commands | Sort-Object FilePath, Args -Unique
}

function Invoke-UninstallCommand {
	param(
		[Parameter(Mandatory = $true)]
		[pscustomobject]$Command
	)

	if (-not (Test-Path -Path $Command.FilePath)) {
		Write-Output "Skipping uninstall command because executable is missing: $($Command.FilePath)"
		return $false
	}

	try {
		Write-Output "Executing uninstall command ($($Command.Source)): $($Command.FilePath) $($Command.Args)"
		$process = Start-Process -FilePath $Command.FilePath -ArgumentList $Command.Args -Wait -PassThru -WindowStyle Hidden
		$successCodes = @(0, 1605, 1614, 1641, 3010)
		if ($successCodes -contains $process.ExitCode) {
			Write-Output "Uninstall command returned success code: $($process.ExitCode)"
			return $true
		}

		Write-Output "Uninstall command failed with exit code: $($process.ExitCode)"
		return $false
	} catch {
		Write-Output "Uninstall command execution failed: $($_.Exception.Message)"
		return $false
	}
}

function Remove-GreenshotResidualPaths {
	$removedAny = $false

	$residualDirs = @(
		'C:\Program Files\Greenshot',
		'C:\Program Files (x86)\Greenshot'
	)

	$userProfiles = Get-ChildItem -Path 'C:\Users' -Directory -ErrorAction SilentlyContinue |
		Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }

	foreach ($profile in $userProfiles) {
		$residualDirs += Join-Path -Path $profile.FullName -ChildPath 'AppData\Local\Greenshot'
		$residualDirs += Join-Path -Path $profile.FullName -ChildPath 'AppData\Local\Programs\Greenshot'
		$residualDirs += Join-Path -Path $profile.FullName -ChildPath 'AppData\Roaming\Greenshot'
	}

	foreach ($dir in ($residualDirs | Select-Object -Unique)) {
		if (-not (Test-Path -Path $dir)) { continue }

		try {
			Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
			Write-Output "Removed residual path: $dir"
			$removedAny = $true
		} catch {
			Write-Output "Could not remove residual path: $dir. Error: $($_.Exception.Message)"
		}
	}

	return $removedAny
}

try {
	Write-Output 'Starting Greenshot remediation...'

	Get-Process -Name 'Greenshot' -ErrorAction SilentlyContinue | ForEach-Object {
		try {
			Stop-Process -Id $_.Id -Force -ErrorAction Stop
			Write-Output "Stopped running Greenshot process (PID $($_.Id))."
		} catch {
			Write-Output "Could not stop process PID $($_.Id): $($_.Exception.Message)"
		}
	}

	$initialIndicators = Get-GreenshotInstallIndicators
	if (-not $initialIndicators -or $initialIndicators.Count -eq 0) {
		Write-Output 'No Greenshot installation indicators detected. No remediation needed.'
		exit 0
	}

	Write-Output "Found $($initialIndicators.Count) indicator(s) to remediate."

	$attempted = 0
	$successfulCommands = 0

	foreach ($indicator in $initialIndicators) {
		$commands = Build-UninstallCommands -Indicator $indicator
		if (-not $commands -or $commands.Count -eq 0) {
			continue
		}

		foreach ($cmd in $commands) {
			$attempted++
			if (Invoke-UninstallCommand -Command $cmd) {
				$successfulCommands++
			}
		}
	}

	if ($attempted -eq 0) {
		Write-Output 'No uninstall commands were available from current indicators. Running constrained residual cleanup.'
	} else {
		Write-Output "Uninstall command summary: attempted=$attempted successful=$successfulCommands"
	}

	[void](Remove-GreenshotResidualPaths)

	$remaining = Get-GreenshotInstallIndicators
	if ($remaining -and $remaining.Count -gt 0) {
		Write-Output "Remediation incomplete. Remaining Greenshot indicators: $($remaining.Count)"
		$remaining | ForEach-Object {
			$location = if ($_.RegistryPath) { $_.RegistryPath } elseif ($_.Path) { $_.Path } else { 'Unknown location' }
			Write-Output "- [$($_.Scope)] $($_.Source) at $location"
		}
		exit 1
	}

	Write-Output 'Greenshot remediation completed successfully. No remaining indicators found.'
	exit 0
} catch {
	Write-Output "Remediation failed: $($_.Exception.Message)"
	exit 1
}
