#requires -Version 5.1
<#
.SYNOPSIS
    Performs a non-invasive Windows health and security assessment.

.DESCRIPTION
    SN-Windows-HealthAudit collects a concise set of operational and security
    indicators from a Windows workstation or server.

    The script is intentionally read-only: it does not change system settings,
    install software, create scheduled tasks, write registry values, or send
    telemetry.

    By default, no report file is created. Use -OutputPath only when a JSON
    report is explicitly required.

.PARAMETER OutputFormat
    Controls the primary output:
      Console - Human-readable assessment (default)
      Json    - JSON representation of the complete report
      Object  - PowerShell object suitable for further processing

.PARAMETER OutputPath
    Optional path used to save the complete report as JSON.
    No file is written when this parameter is omitted.

.PARAMETER SkipUpdateScan
    Skips the Windows Update Agent scan for pending updates.
    Useful when a fast, offline assessment is preferred.

.PARAMETER IncludeNetworkDetails
    Includes configured gateway and DNS server addresses in the report.
    By default, only the presence of a valid network configuration is reported.

.PARAMETER DiskWarningPercent
    Free-space percentage below which a fixed disk is reported as Warning.

.PARAMETER DiskCriticalPercent
    Free-space percentage below which a fixed disk is reported as Critical.

.PARAMETER UptimeWarningDays
    Uptime in days above which the system is reported as Warning.

.PARAMETER UptimeCriticalDays
    Uptime in days above which the system is reported as Critical.

.PARAMETER UpdateWarningDays
    Age in days of the latest installed hotfix above which a Warning is raised.

.PARAMETER UpdateCriticalDays
    Age in days of the latest installed hotfix above which a Critical result is raised.

.EXAMPLE
    .\SN-Windows-HealthAudit.ps1

.EXAMPLE
    .\SN-Windows-HealthAudit.ps1 -OutputFormat Json

.EXAMPLE
    .\SN-Windows-HealthAudit.ps1 -OutputPath C:\Temp\WindowsHealthAudit.json

.EXAMPLE
    .\SN-Windows-HealthAudit.ps1 -SkipUpdateScan -IncludeNetworkDetails

.NOTES
    Project : SN-Windows-HealthAudit
    Version : 1.0.0
    Author  : Scarafiotti Network
    Website : https://www.scarafiotti.it
    License : MIT

    Designed as a public, reusable example of Windows assessment automation.
    Customer-specific logic and proprietary Scarafiotti Network operational
    standards are intentionally not included.
#>

[CmdletBinding()]
param(
    [ValidateSet('Console', 'Json', 'Object')]
    [string]$OutputFormat = 'Console',

    [string]$OutputPath,

    [switch]$SkipUpdateScan,

    [switch]$IncludeNetworkDetails,

    [ValidateRange(1, 99)]
    [int]$DiskWarningPercent = 20,

    [ValidateRange(1, 99)]
    [int]$DiskCriticalPercent = 10,

    [ValidateRange(1, 3650)]
    [int]$UptimeWarningDays = 30,

    [ValidateRange(1, 3650)]
    [int]$UptimeCriticalDays = 60,

    [ValidateRange(1, 3650)]
    [int]$UpdateWarningDays = 30,

    [ValidateRange(1, 3650)]
    [int]$UpdateCriticalDays = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptVersion = '1.0.0'

function New-CheckResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('OK', 'Warning', 'Critical', 'Info', 'NotAvailable')]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Details,

        [string]$Category = 'General'
    )

    [pscustomobject][ordered]@{
        Category = $Category
        Name     = $Name
        Status   = $Status
        Details  = $Details
    }
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-OSAssessment {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $architecture = $os.OSArchitecture
        $details = '{0} | Version {1} | Build {2} | {3}' -f $os.Caption.Trim(), $os.Version, $os.BuildNumber, $architecture

        New-CheckResult -Name 'Operating system' -Status 'Info' -Details $details -Category 'System'
    }
    catch {
        New-CheckResult -Name 'Operating system' -Status 'NotAvailable' -Details 'Unable to query operating-system information.' -Category 'System'
    }
}

function Get-PrivilegeAssessment {
    $isAdmin = Test-IsAdministrator

    if ($isAdmin) {
        New-CheckResult -Name 'Execution context' -Status 'OK' -Details 'Running with administrative privileges.' -Category 'System'
    }
    else {
        New-CheckResult -Name 'Execution context' -Status 'Info' -Details 'Running without administrative privileges; some checks may be unavailable.' -Category 'System'
    }
}

function Get-UptimeAssessment {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $uptime = (Get-Date) - $os.LastBootUpTime
        $days = [math]::Round($uptime.TotalDays, 1)

        if ($days -ge $UptimeCriticalDays) {
            $status = 'Critical'
        }
        elseif ($days -ge $UptimeWarningDays) {
            $status = 'Warning'
        }
        else {
            $status = 'OK'
        }

        New-CheckResult -Name 'System uptime' -Status $status -Details ('{0} days since last boot.' -f $days) -Category 'System'
    }
    catch {
        New-CheckResult -Name 'System uptime' -Status 'NotAvailable' -Details 'Unable to determine system uptime.' -Category 'System'
    }
}

function Get-PendingRebootAssessment {
    try {
        $reasons = New-Object System.Collections.Generic.List[string]

        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
            $reasons.Add('CBS')
        }

        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
            $reasons.Add('Windows Update')
        }

        $sessionManagerPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        if (Test-Path $sessionManagerPath) {
            $pendingRename = (Get-ItemProperty -Path $sessionManagerPath -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
            if ($null -ne $pendingRename) {
                $reasons.Add('Pending file rename')
            }
        }

        if ($reasons.Count -gt 0) {
            New-CheckResult -Name 'Pending reboot' -Status 'Warning' -Details ('Required or indicated by: {0}.' -f ($reasons -join ', ')) -Category 'System'
        }
        else {
            New-CheckResult -Name 'Pending reboot' -Status 'OK' -Details 'No common pending-reboot indicators detected.' -Category 'System'
        }
    }
    catch {
        New-CheckResult -Name 'Pending reboot' -Status 'NotAvailable' -Details 'Unable to evaluate pending-reboot indicators.' -Category 'System'
    }
}

function Get-DiskSpaceAssessment {
    try {
        $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3')

        if ($disks.Count -eq 0) {
            return New-CheckResult -Name 'Disk free space' -Status 'NotAvailable' -Details 'No fixed disks were returned by the operating system.' -Category 'Storage'
        }

        foreach ($disk in $disks) {
            if ([double]$disk.Size -le 0) {
                continue
            }

            $freePercent = [math]::Round(([double]$disk.FreeSpace / [double]$disk.Size) * 100, 1)
            $freeGB = [math]::Round([double]$disk.FreeSpace / 1GB, 1)
            $sizeGB = [math]::Round([double]$disk.Size / 1GB, 1)

            if ($freePercent -lt $DiskCriticalPercent) {
                $status = 'Critical'
            }
            elseif ($freePercent -lt $DiskWarningPercent) {
                $status = 'Warning'
            }
            else {
                $status = 'OK'
            }

            New-CheckResult -Name ('Disk {0} free space' -f $disk.DeviceID) -Status $status -Details ('{0} GB free of {1} GB ({2}%).' -f $freeGB, $sizeGB, $freePercent) -Category 'Storage'
        }
    }
    catch {
        New-CheckResult -Name 'Disk free space' -Status 'NotAvailable' -Details 'Unable to query fixed-disk free space.' -Category 'Storage'
    }
}

function Get-PhysicalDiskAssessment {
    if (-not (Get-Command -Name Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
        return New-CheckResult -Name 'Physical disk health' -Status 'NotAvailable' -Details 'Storage health cmdlets are not available on this system.' -Category 'Storage'
    }

    try {
        $physicalDisks = @(Get-PhysicalDisk)

        if ($physicalDisks.Count -eq 0) {
            return New-CheckResult -Name 'Physical disk health' -Status 'NotAvailable' -Details 'No physical-disk health information was returned.' -Category 'Storage'
        }

        $unhealthy = @($physicalDisks | Where-Object { $_.HealthStatus -ne 'Healthy' })

        if ($unhealthy.Count -gt 0) {
            $states = ($unhealthy | ForEach-Object { $_.HealthStatus } | Sort-Object -Unique) -join ', '
            New-CheckResult -Name 'Physical disk health' -Status 'Critical' -Details ('One or more physical disks report a non-healthy state: {0}.' -f $states) -Category 'Storage'
        }
        else {
            New-CheckResult -Name 'Physical disk health' -Status 'OK' -Details ('{0} physical disk(s) report Healthy.' -f $physicalDisks.Count) -Category 'Storage'
        }
    }
    catch {
        New-CheckResult -Name 'Physical disk health' -Status 'NotAvailable' -Details 'Unable to query physical-disk health.' -Category 'Storage'
    }
}

function Get-MemoryAssessment {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $totalKB = [double]$os.TotalVisibleMemorySize
        $freeKB = [double]$os.FreePhysicalMemory

        if ($totalKB -le 0) {
            return New-CheckResult -Name 'Memory availability' -Status 'NotAvailable' -Details 'Operating system returned an invalid memory size.' -Category 'System'
        }

        $freePercent = [math]::Round(($freeKB / $totalKB) * 100, 1)
        $totalGB = [math]::Round(($totalKB * 1KB) / 1GB, 1)
        $freeGB = [math]::Round(($freeKB * 1KB) / 1GB, 1)

        if ($freePercent -lt 5) {
            $status = 'Critical'
        }
        elseif ($freePercent -lt 15) {
            $status = 'Warning'
        }
        else {
            $status = 'OK'
        }

        New-CheckResult -Name 'Memory availability' -Status $status -Details ('{0} GB free of {1} GB ({2}%).' -f $freeGB, $totalGB, $freePercent) -Category 'System'
    }
    catch {
        New-CheckResult -Name 'Memory availability' -Status 'NotAvailable' -Details 'Unable to query physical-memory availability.' -Category 'System'
    }
}

function Get-TpmAssessment {
    if (-not (Get-Command -Name Get-Tpm -ErrorAction SilentlyContinue)) {
        return New-CheckResult -Name 'TPM' -Status 'NotAvailable' -Details 'TPM cmdlets are not available on this system.' -Category 'Security'
    }

    try {
        $tpm = Get-Tpm

        if (-not $tpm.TpmPresent) {
            return New-CheckResult -Name 'TPM' -Status 'Warning' -Details 'No TPM is reported as present.' -Category 'Security'
        }

        if ($tpm.TpmReady) {
            New-CheckResult -Name 'TPM' -Status 'OK' -Details 'TPM is present and ready.' -Category 'Security'
        }
        else {
            New-CheckResult -Name 'TPM' -Status 'Warning' -Details 'TPM is present but not reported as ready.' -Category 'Security'
        }
    }
    catch {
        New-CheckResult -Name 'TPM' -Status 'NotAvailable' -Details 'Unable to query TPM state.' -Category 'Security'
    }
}

function Get-SecureBootAssessment {
    if (-not (Get-Command -Name Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
        return New-CheckResult -Name 'Secure Boot' -Status 'NotAvailable' -Details 'Secure Boot cmdlet is not available on this system.' -Category 'Security'
    }

    try {
        $enabled = Confirm-SecureBootUEFI

        if ($enabled) {
            New-CheckResult -Name 'Secure Boot' -Status 'OK' -Details 'Secure Boot is enabled.' -Category 'Security'
        }
        else {
            New-CheckResult -Name 'Secure Boot' -Status 'Warning' -Details 'Secure Boot is supported but disabled.' -Category 'Security'
        }
    }
    catch {
        New-CheckResult -Name 'Secure Boot' -Status 'NotAvailable' -Details 'Secure Boot state is unavailable or the system is not using UEFI Secure Boot.' -Category 'Security'
    }
}

function Get-BitLockerAssessment {
    if (-not (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        return New-CheckResult -Name 'BitLocker' -Status 'NotAvailable' -Details 'BitLocker cmdlets are not available on this system.' -Category 'Security'
    }

    try {
        $systemDrive = $env:SystemDrive
        $volume = Get-BitLockerVolume -MountPoint $systemDrive

        if ($null -eq $volume) {
            return New-CheckResult -Name 'BitLocker' -Status 'NotAvailable' -Details 'No BitLocker information was returned for the system drive.' -Category 'Security'
        }

        $protection = [string]$volume.ProtectionStatus
        $volumeStatus = [string]$volume.VolumeStatus
        $encryptionPercent = $volume.EncryptionPercentage

        if ($protection -eq 'On' -and $volumeStatus -eq 'FullyEncrypted') {
            $status = 'OK'
        }
        elseif ($protection -eq 'On') {
            $status = 'Warning'
        }
        else {
            $status = 'Warning'
        }

        $details = '{0}: Protection {1}; Volume {2}; Encryption {3}%.' -f $systemDrive, $protection, $volumeStatus, $encryptionPercent
        New-CheckResult -Name 'BitLocker system drive' -Status $status -Details $details -Category 'Security'
    }
    catch {
        New-CheckResult -Name 'BitLocker' -Status 'NotAvailable' -Details 'Unable to query BitLocker state.' -Category 'Security'
    }
}

function Get-FirewallAssessment {
    if (-not (Get-Command -Name Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        return New-CheckResult -Name 'Windows Firewall' -Status 'NotAvailable' -Details 'Windows Firewall profile cmdlets are not available.' -Category 'Security'
    }

    try {
        $profiles = @(Get-NetFirewallProfile)
        $disabled = @($profiles | Where-Object { -not $_.Enabled })

        if ($disabled.Count -gt 0) {
            $names = ($disabled | Select-Object -ExpandProperty Name) -join ', '
            New-CheckResult -Name 'Windows Firewall' -Status 'Critical' -Details ('Disabled profile(s): {0}.' -f $names) -Category 'Security'
        }
        else {
            $names = ($profiles | Select-Object -ExpandProperty Name) -join ', '
            New-CheckResult -Name 'Windows Firewall' -Status 'OK' -Details ('Enabled profile(s): {0}.' -f $names) -Category 'Security'
        }
    }
    catch {
        New-CheckResult -Name 'Windows Firewall' -Status 'NotAvailable' -Details 'Unable to query Windows Firewall profiles.' -Category 'Security'
    }
}

function Get-EndpointProtectionAssessment {
    try {
        $productNames = @()

        try {
            $products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
            $productNames = @($products | Select-Object -ExpandProperty displayName | Where-Object { $_ } | Sort-Object -Unique)
        }
        catch {
            $productNames = @()
        }

        $defenderAvailable = $null -ne (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue)

        if ($defenderAvailable) {
            try {
                $defender = Get-MpComputerStatus

                $defenderHealthy = [bool]$defender.AntivirusEnabled -and [bool]$defender.RealTimeProtectionEnabled
                $runningMode = [string]$defender.AMRunningMode

                if ($defenderHealthy) {
                    $signatureText = ''
                    if ($null -ne $defender.AntivirusSignatureLastUpdated) {
                        $signatureAge = [math]::Round(((Get-Date) - $defender.AntivirusSignatureLastUpdated).TotalDays, 1)
                        $signatureText = ' Signature age: {0} day(s).' -f $signatureAge
                    }

                    return New-CheckResult -Name 'Endpoint protection' -Status 'OK' -Details ('Microsoft Defender antivirus and real-time protection are enabled.{0}' -f $signatureText) -Category 'Security'
                }

                if ($runningMode -match 'Passive' -and $productNames.Count -gt 0) {
                    return New-CheckResult -Name 'Endpoint protection' -Status 'OK' -Details ('Microsoft Defender is in passive mode; detected security product(s): {0}.' -f ($productNames -join ', ')) -Category 'Security'
                }
            }
            catch {
                # Continue with SecurityCenter2 detection below.
            }
        }

        if ($productNames.Count -gt 0) {
            New-CheckResult -Name 'Endpoint protection' -Status 'Info' -Details ('Detected antivirus product(s): {0}. Enabled state was not independently validated.' -f ($productNames -join ', ')) -Category 'Security'
        }
        else {
            New-CheckResult -Name 'Endpoint protection' -Status 'Warning' -Details 'No active endpoint-protection state could be validated with the available Windows interfaces.' -Category 'Security'
        }
    }
    catch {
        New-CheckResult -Name 'Endpoint protection' -Status 'NotAvailable' -Details 'Unable to evaluate endpoint-protection state.' -Category 'Security'
    }
}

function Get-WindowsUpdateAssessment {
    $results = @()

    try {
        $hotfixes = @(Get-HotFix | Where-Object { $null -ne $_.InstalledOn } | Sort-Object InstalledOn -Descending)

        if ($hotfixes.Count -gt 0) {
            $latest = $hotfixes[0]
            $ageDays = [math]::Floor(((Get-Date) - [datetime]$latest.InstalledOn).TotalDays)

            if ($ageDays -ge $UpdateCriticalDays) {
                $status = 'Critical'
            }
            elseif ($ageDays -ge $UpdateWarningDays) {
                $status = 'Warning'
            }
            else {
                $status = 'OK'
            }

            $results += New-CheckResult -Name 'Latest installed hotfix' -Status $status -Details ('Latest reported hotfix installed {0} day(s) ago.' -f $ageDays) -Category 'Updates'
        }
        else {
            $results += New-CheckResult -Name 'Latest installed hotfix' -Status 'NotAvailable' -Details 'No dated hotfix information was returned.' -Category 'Updates'
        }
    }
    catch {
        $results += New-CheckResult -Name 'Latest installed hotfix' -Status 'NotAvailable' -Details 'Unable to query installed hotfix history.' -Category 'Updates'
    }

    if ($SkipUpdateScan) {
        $results += New-CheckResult -Name 'Pending Windows updates' -Status 'Info' -Details 'Windows Update Agent scan skipped by parameter.' -Category 'Updates'
        return $results
    }

    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $searchResult = $searcher.Search('IsInstalled=0 and IsHidden=0')
        $pendingCount = $searchResult.Updates.Count

        if ($pendingCount -gt 0) {
            $results += New-CheckResult -Name 'Pending Windows updates' -Status 'Warning' -Details ('{0} applicable update(s) are reported as not installed.' -f $pendingCount) -Category 'Updates'
        }
        else {
            $results += New-CheckResult -Name 'Pending Windows updates' -Status 'OK' -Details 'No applicable pending updates were reported by Windows Update Agent.' -Category 'Updates'
        }
    }
    catch {
        $results += New-CheckResult -Name 'Pending Windows updates' -Status 'NotAvailable' -Details 'Unable to complete the Windows Update Agent scan.' -Category 'Updates'
    }

    return $results
}

function Get-TimeSyncAssessment {
    try {
        $service = Get-Service -Name W32Time -ErrorAction Stop

        $source = $null
        try {
            $sourceOutput = & w32tm.exe /query /source 2>$null
            if ($LASTEXITCODE -eq 0 -and $sourceOutput) {
                $source = ($sourceOutput | Select-Object -First 1).ToString().Trim()
            }
        }
        catch {
            $source = $null
        }

        if ($service.Status -eq 'Running') {
            $status = 'OK'
        }
        else {
            $status = 'Warning'
        }

        if ($source) {
            $details = 'Windows Time service: {0}; source: {1}.' -f $service.Status, $source
        }
        else {
            $details = 'Windows Time service: {0}; time source unavailable.' -f $service.Status
        }

        New-CheckResult -Name 'Time synchronization' -Status $status -Details $details -Category 'Network'
    }
    catch {
        New-CheckResult -Name 'Time synchronization' -Status 'NotAvailable' -Details 'Unable to query Windows Time service.' -Category 'Network'
    }
}

function Get-NetworkAssessment {
    if (-not (Get-Command -Name Get-NetIPConfiguration -ErrorAction SilentlyContinue)) {
        return New-CheckResult -Name 'Network configuration' -Status 'NotAvailable' -Details 'Network configuration cmdlets are not available.' -Category 'Network'
    }

    try {
        $configs = @(Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' })
        $withGateway = @($configs | Where-Object { $null -ne $_.IPv4DefaultGateway })

        if ($withGateway.Count -eq 0) {
            return New-CheckResult -Name 'Network configuration' -Status 'Warning' -Details 'No active adapter with an IPv4 default gateway was detected.' -Category 'Network'
        }

        $dnsAddresses = @()
        foreach ($config in $withGateway) {
            if ($null -ne $config.DNSServer) {
                $dnsAddresses += @($config.DNSServer.ServerAddresses)
            }
        }
        $dnsAddresses = @($dnsAddresses | Where-Object { $_ } | Sort-Object -Unique)

        if ($dnsAddresses.Count -eq 0) {
            return New-CheckResult -Name 'Network configuration' -Status 'Warning' -Details 'An active default gateway is present, but no DNS server address was detected.' -Category 'Network'
        }

        if ($IncludeNetworkDetails) {
            $gateways = @($withGateway.IPv4DefaultGateway.NextHop | Where-Object { $_ } | Sort-Object -Unique)
            $details = 'Active gateway(s): {0}; DNS server(s): {1}.' -f ($gateways -join ', '), ($dnsAddresses -join ', ')
        }
        else {
            $details = 'Active IPv4 default gateway and DNS configuration detected. Address details suppressed.'
        }

        New-CheckResult -Name 'Network configuration' -Status 'OK' -Details $details -Category 'Network'
    }
    catch {
        New-CheckResult -Name 'Network configuration' -Status 'NotAvailable' -Details 'Unable to evaluate network configuration.' -Category 'Network'
    }
}

function Get-CriticalServicesAssessment {
    $serviceNames = @('EventLog', 'RpcSs', 'Winmgmt', 'DcomLaunch')

    try {
        $services = @(Get-Service -Name $serviceNames -ErrorAction Stop)
        $notRunning = @($services | Where-Object { $_.Status -ne 'Running' })

        if ($notRunning.Count -gt 0) {
            $names = ($notRunning | Select-Object -ExpandProperty Name) -join ', '
            New-CheckResult -Name 'Core Windows services' -Status 'Critical' -Details ('Core service(s) not running: {0}.' -f $names) -Category 'System'
        }
        else {
            New-CheckResult -Name 'Core Windows services' -Status 'OK' -Details 'EventLog, RpcSs, Winmgmt and DcomLaunch are running.' -Category 'System'
        }
    }
    catch {
        New-CheckResult -Name 'Core Windows services' -Status 'NotAvailable' -Details 'Unable to query one or more core Windows services.' -Category 'System'
    }
}

function Get-SystemEventAssessment {
    try {
        $startTime = (Get-Date).AddHours(-24)

        $criticalEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1; StartTime = $startTime } -ErrorAction SilentlyContinue)
        $errorEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 2; StartTime = $startTime } -ErrorAction SilentlyContinue)

        if ($criticalEvents.Count -gt 0) {
            $status = 'Critical'
        }
        elseif ($errorEvents.Count -gt 0) {
            $status = 'Warning'
        }
        else {
            $status = 'OK'
        }

        $details = 'Last 24 hours: {0} Critical, {1} Error event(s) in System log. Event messages are not collected.' -f $criticalEvents.Count, $errorEvents.Count
        New-CheckResult -Name 'System event log' -Status $status -Details $details -Category 'Events'
    }
    catch {
        New-CheckResult -Name 'System event log' -Status 'NotAvailable' -Details 'Unable to query recent System event counts.' -Category 'Events'
    }
}

function Get-FastStartupAssessment {
    try {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
        $value = (Get-ItemProperty -Path $path -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled

        if ([int]$value -eq 1) {
            $details = 'Enabled.'
        }
        else {
            $details = 'Disabled.'
        }

        New-CheckResult -Name 'Fast Startup' -Status 'Info' -Details $details -Category 'Configuration'
    }
    catch {
        New-CheckResult -Name 'Fast Startup' -Status 'NotAvailable' -Details 'Fast Startup configuration could not be determined.' -Category 'Configuration'
    }
}

function Get-PowerPlanAssessment {
    try {
        $output = & powercfg.exe /getactivescheme 2>$null

        if ($LASTEXITCODE -eq 0 -and $output) {
            $details = ($output | Select-Object -First 1).ToString().Trim()
            New-CheckResult -Name 'Active power plan' -Status 'Info' -Details $details -Category 'Configuration'
        }
        else {
            New-CheckResult -Name 'Active power plan' -Status 'NotAvailable' -Details 'powercfg did not return an active power plan.' -Category 'Configuration'
        }
    }
    catch {
        New-CheckResult -Name 'Active power plan' -Status 'NotAvailable' -Details 'Unable to query the active power plan.' -Category 'Configuration'
    }
}

function Get-OverallStatus {
    param(
        [Parameter(Mandatory)]
        [object[]]$Checks
    )

    if (@($Checks | Where-Object { $_.Status -eq 'Critical' }).Count -gt 0) {
        return 'Critical'
    }

    if (@($Checks | Where-Object { $_.Status -eq 'Warning' }).Count -gt 0) {
        return 'Warning'
    }

    return 'OK'
}

function New-AuditReport {
    param(
        [Parameter(Mandatory)]
        [object[]]$Checks
    )

    $summary = [pscustomobject][ordered]@{
        Total        = $Checks.Count
        OK           = @($Checks | Where-Object { $_.Status -eq 'OK' }).Count
        Warning      = @($Checks | Where-Object { $_.Status -eq 'Warning' }).Count
        Critical     = @($Checks | Where-Object { $_.Status -eq 'Critical' }).Count
        Info         = @($Checks | Where-Object { $_.Status -eq 'Info' }).Count
        NotAvailable = @($Checks | Where-Object { $_.Status -eq 'NotAvailable' }).Count
    }

    [pscustomobject][ordered]@{
        Tool           = 'SN-Windows-HealthAudit'
        Version        = $ScriptVersion
        GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        OverallStatus  = Get-OverallStatus -Checks $Checks
        Summary        = $summary
        Checks         = $Checks
    }
}

function Write-ConsoleAssessment {
    param(
        [Parameter(Mandatory)]
        [object]$Report
    )

    Write-Host ''
    Write-Host '============================================================'
    Write-Host ' Scarafiotti Network - Windows Health Audit'
    Write-Host (' Version {0}' -f $Report.Version)
    Write-Host '============================================================'

    foreach ($check in $Report.Checks) {
        $statusText = '[{0}]' -f $check.Status

        switch ($check.Status) {
            'OK'           { $color = 'Green' }
            'Warning'      { $color = 'Yellow' }
            'Critical'     { $color = 'Red' }
            'Info'         { $color = 'Cyan' }
            'NotAvailable' { $color = 'DarkGray' }
            default        { $color = 'Gray' }
        }

        Write-Host ('{0,-15}' -f $statusText) -ForegroundColor $color -NoNewline
        Write-Host (' {0,-28} {1}' -f $check.Name, $check.Details)
    }

    Write-Host '------------------------------------------------------------'
    Write-Host (' Checks performed : {0}' -f $Report.Summary.Total)
    Write-Host (' OK               : {0}' -f $Report.Summary.OK)
    Write-Host (' Warnings         : {0}' -f $Report.Summary.Warning)
    Write-Host (' Critical         : {0}' -f $Report.Summary.Critical)
    Write-Host (' Informational    : {0}' -f $Report.Summary.Info)
    Write-Host (' Not available    : {0}' -f $Report.Summary.NotAvailable)
    Write-Host (' Overall status   : {0}' -f $Report.OverallStatus)
    Write-Host '============================================================'
    Write-Host ''
}

function Save-JsonReport {
    param(
        [Parameter(Mandatory)]
        [object]$Report,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $parent = Split-Path -Path $Path -Parent
    if ($parent -and -not (Test-Path $parent)) {
        $null = New-Item -ItemType Directory -Path $parent -Force
    }

    $json = $Report | ConvertTo-Json -Depth 6
    Set-Content -Path $Path -Value $json -Encoding UTF8
}

$checks = @()

$checks += Get-OSAssessment
$checks += Get-PrivilegeAssessment
$checks += Get-UptimeAssessment
$checks += Get-PendingRebootAssessment
$checks += Get-DiskSpaceAssessment
$checks += Get-PhysicalDiskAssessment
$checks += Get-MemoryAssessment
$checks += Get-TpmAssessment
$checks += Get-SecureBootAssessment
$checks += Get-BitLockerAssessment
$checks += Get-FirewallAssessment
$checks += Get-EndpointProtectionAssessment
$checks += Get-WindowsUpdateAssessment
$checks += Get-TimeSyncAssessment
$checks += Get-NetworkAssessment
$checks += Get-CriticalServicesAssessment
$checks += Get-SystemEventAssessment
$checks += Get-FastStartupAssessment
$checks += Get-PowerPlanAssessment

$report = New-AuditReport -Checks $checks

if ($OutputPath) {
    try {
        Save-JsonReport -Report $report -Path $OutputPath
    }
    catch {
        if ($OutputFormat -eq 'Console') {
            Write-Warning ('Unable to save JSON report to "{0}".' -f $OutputPath)
        }
    }
}

switch ($OutputFormat) {
    'Console' {
        Write-ConsoleAssessment -Report $report
    }

    'Json' {
        $report | ConvertTo-Json -Depth 6
    }

    'Object' {
        Write-Output $report
    }
}

switch ($report.OverallStatus) {
    'Critical' { exit 2 }
    'Warning'  { exit 1 }
    default    { exit 0 }
}
