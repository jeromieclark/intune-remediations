# Detects the configuration of the Adobe Acrobat JavaScript lockdown setting.
# This script checks if the registry key for disabling JavaScript in Adobe Acrobat DC is set
# to the desired value (1) as a DWORD in the 64-bit HKLM registry view.
# If it is compliant, it outputs "Compliant" and exits with code 0.
# If it is not compliant, it outputs "Non-compliant" and exits with code 1.

$Path = "SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown"
$Name = "bDisableJavaScript"
$DesiredValue = 1

if (-not [Environment]::Is64BitOperatingSystem) {
    Write-Output "Non-compliant"
    exit 1
}

$baseKey = $null
$policyKey = $null

try {
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64
    )

    $policyKey = $baseKey.OpenSubKey($Path, $false)
    if ($null -ne $policyKey) {
        $currentValue = $policyKey.GetValue($Name, $null)
        if ($null -ne $currentValue) {
            $valueKind = $policyKey.GetValueKind($Name)
            if ($valueKind -eq [Microsoft.Win32.RegistryValueKind]::DWord -and [int]$currentValue -eq $DesiredValue) {
                Write-Output "Compliant"
                exit 0
            }
        }
    }
} catch {
    Write-Output "Detection error: $($_.Exception.Message)"
} finally {
    if ($null -ne $policyKey) {
        $policyKey.Close()
    }

    if ($null -ne $baseKey) {
        $baseKey.Close()
    }
}

Write-Output "Non-compliant"
exit 1