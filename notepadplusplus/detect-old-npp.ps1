$ErrorActionPreference = 'Stop'

$DesiredVersion = [Version]'8.9.2'
$AppName = 'Notepad++'

function Get-InstalledNppVersion {
	$uninstallPaths = @(
		'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
		'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
	)

	foreach ($path in $uninstallPaths) {
		$apps = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
		foreach ($app in $apps) {
			$props = Get-ItemProperty -Path $app.PSPath -ErrorAction SilentlyContinue
			if ($null -ne $props.DisplayName -and $props.DisplayName -like "$AppName*") {
				if ([string]::IsNullOrWhiteSpace($props.DisplayVersion)) {
					continue
				}

				try {
					return [Version]$props.DisplayVersion
				} catch {
					continue
				}
			}
		}
	}

	return $null
}

$installedVersion = Get-InstalledNppVersion

if ($null -eq $installedVersion) {
	Write-Output "$AppName is not installed."
	exit 1
}

if ($installedVersion -lt $DesiredVersion) {
	Write-Output "$AppName version $installedVersion is older than $DesiredVersion."
	exit 1
}

Write-Output "$AppName version $installedVersion is compliant."
exit 0
