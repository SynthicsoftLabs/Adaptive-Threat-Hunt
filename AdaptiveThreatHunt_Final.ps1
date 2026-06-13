#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Adaptive Threat Hunt + Auto-Hardening - CLM Compatible
.DESCRIPTION
    Fully compatible with PowerShell Constrained Language Mode.
    No Add-Type, no [reflection], no direct .NET instantiation.
    Uses only approved cmdlets, native Windows binaries, and
    REST calls via Invoke-RestMethod / Invoke-WebRequest.
#>

$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportPath = "$env:SystemDrive\AdaptiveHunt_$Timestamp.txt"
$FeedCache  = "$env:TEMP\Feeds_$Timestamp"
cmd /c mkdir "$FeedCache" 2>$null

$Global:AlertCount  = 0
$Global:HardenCount = 0
$Global:CVEMatches  = @()
$Global:IOCMatches  = @()
$Global:BlockedIPs  = @()

$Global:NVDReqCount  = 0
$Global:NVDWindowStart = Get-Date

function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $colors = @{ INFO="White"; WARN="Yellow"; ALERT="Red"; OK="Green"; ACTION="Magenta" }
    $out = "[$Level][$(Get-Date -Format 'HH:mm:ss')] $Msg"
    Write-Host $out -ForegroundColor $colors[$Level]
    Add-Content -Path $ReportPath -Value $out -ErrorAction SilentlyContinue
    if ($Level -eq "ALERT") { $Global:AlertCount++ }
}

function Write-Section {
    param([string]$Title)
    $line = "=" * 70
    $out  = "`n$line`n  $Title`n$line"
    Write-Host $out -ForegroundColor Cyan
    Add-Content -Path $ReportPath -Value $out -ErrorAction SilentlyContinue
}

function Set-RegValue {
    param([string]$Path, [string]$Name, [string]$Value, [string]$Type = "REG_DWORD")
    $regPath = $Path -replace "^HKLM:\\", "HKEY_LOCAL_MACHINE\" -replace "^HKCU:\\", "HKEY_CURRENT_USER\"
    reg add "$regPath" /v "$Name" /t $Type /d "$Value" /f 2>&1 | Out-Null
}

function Ensure-RegPath {
    param([string]$Path)
    $regPath = $Path -replace "^HKLM:\\", "HKEY_LOCAL_MACHINE\" -replace "^HKCU:\\", "HKEY_CURRENT_USER\"
    reg add "$regPath" /f 2>&1 | Out-Null
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        return $val
    } catch { return $null }
}

function Get-SHA256 {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return $null }
    $out = certutil -hashfile "$FilePath" SHA256 2>$null
    if ($out) {
        $hashLine = $out | Select-String -Pattern "^[0-9a-fA-F]{64}$"
        if (-not $hashLine) { return $null }
        $hash = "$hashLine".Trim()
        return $hash.ToUpper()
    }
    return $null
}

function Invoke-NVDQuery {
    param([string]$Keyword, [int]$Max = 5)
    $Global:NVDReqCount++
    if ($Global:NVDReqCount -ge 5) {
        $elapsed = ((Get-Date) - $Global:NVDWindowStart).TotalSeconds
        if ($elapsed -lt 32) {
            Write-Log "NVD rate limit pause ($( ([int](32 - $elapsed)) )s)..."
            Start-Sleep -Seconds (([int](32 - $elapsed + 1)))
        }
        $Global:NVDReqCount = 0
        $Global:NVDWindowStart = Get-Date
    }
    try {
        $kw = $Keyword -replace ' ', '+' -replace '&', '%26' -replace '=', '%3D' -replace '#', '%23'
        $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$kw&resultsPerPage=$Max"
        $resp = Invoke-RestMethod -Uri $url -Method GET -TimeoutSec 25 -ErrorAction Stop
        return $resp.vulnerabilities
    } catch {
        Write-Log "NVD query failed for '$Keyword': $_" "WARN"
        return $null
    }
}

function Invoke-MBCheck {
    param([string]$Hash)
    try {
        $body = "query=get_info&hash=$Hash"
        return Invoke-RestMethod -Uri "https://mb-api.abuse.ch/api/v1/" -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -TimeoutSec 15 -ErrorAction Stop
    } catch { return $null }
}

function Invoke-ThreatFoxCheck {
    param([string]$IOC)
    try {
        $body = '{"query":"search_ioc","search_term":"' + $IOC + '"}'
        return Invoke-RestMethod -Uri "https://threatfox-api.abuse.ch/api/v1/" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 15 -ErrorAction Stop
    } catch { return $null }
}

function Invoke-URLhausCheck {
    param([string]$TargetHost)
    try {
        $body = "host=$TargetHost"
        return Invoke-RestMethod -Uri "https://urlhaus-api.abuse.ch/v1/host/" -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -TimeoutSec 15 -ErrorAction Stop
    } catch { return $null }
}

function Apply-Hardening {
    param([string]$Desc, [scriptblock]$Action)
    Write-Log "HARDENING: $Desc" "ACTION"
    try {
        & $Action
        $Global:HardenCount++
        Write-Log "  OK: $Desc" "OK"
    } catch {
        Write-Log "  FAILED: $Desc | $_" "WARN"
    }
}

Add-Content -Path $ReportPath -Value "ADAPTIVE THREAT HUNT REPORT (CLM-SAFE)"
Add-Content -Path $ReportPath -Value "Generated : $(Get-Date)"
Add-Content -Path $ReportPath -Value "Host      : $env:COMPUTERNAME | User: $env:USERNAME"
Add-Content -Path $ReportPath -Value ("=" * 70)

Write-Section "PHASE 1: MACHINE FINGERPRINT"
$bios  = Get-CimInstance Win32_BIOS
$board = Get-CimInstance Win32_BaseBoard
$cpu   = Get-CimInstance Win32_Processor
$gpu   = Get-CimInstance Win32_VideoController | Select-Object -First 1
$os    = Get-CimInstance Win32_OperatingSystem
$cs    = Get-CimInstance Win32_ComputerSystem
$disks = Get-CimInstance Win32_DiskDrive
$ram   = Get-CimInstance Win32_PhysicalMemory
$nics  = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
$tpm   = Get-CimInstance -Namespace "root\cimv2\security\microsofttpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue

$MachineGUID = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Cryptography" "MachineGuid"
$ProductID   = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" "ProductId"
$BuildLab    = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" "BuildLabEx"
$OSBuild     = $os.BuildNumber
$TotalRAMGB  = ([int](($ram | Measure-Object -Property Capacity -Sum).Sum / 1GB))

Write-Log "Machine GUID      : $MachineGUID"
Write-Log "Product ID        : $ProductID"
Write-Log "OS                : $($os.Caption) Build $OSBuild"
Write-Log "OS Version        : $($os.Version)"
Write-Log "Build Lab         : $BuildLab"
Write-Log "Architecture      : $($os.OSArchitecture)"
Write-Log "Install Date      : $($os.InstallDate)"
Write-Log "Last Boot         : $($os.LastBootUpTime)"
Write-Log "Computer Name     : $($cs.Name)"
Write-Log "Domain            : $($cs.Domain)"
Write-Log "BIOS Manufacturer : $($bios.Manufacturer)"
Write-Log "BIOS Version      : $($bios.SMBIOSBIOSVersion)"
Write-Log "BIOS Date         : $($bios.ReleaseDate)"
Write-Log "BIOS Serial       : $($bios.SerialNumber)"
Write-Log "Board Mfr         : $($board.Manufacturer)"
Write-Log "Board Product     : $($board.Product)"
Write-Log "Board Serial      : $($board.SerialNumber)"
Write-Log "CPU               : $($cpu.Name)"
Write-Log "CPU Manufacturer  : $($cpu.Manufacturer)"
Write-Log "CPU Cores         : $($cpu.NumberOfCores) / $($cpu.NumberOfLogicalProcessors) logical"
Write-Log "CPU ID            : $($cpu.ProcessorId)"
Write-Log "GPU               : $($gpu.Name) | Driver: $($gpu.DriverVersion)"
Write-Log "Total RAM         : $TotalRAMGB GB"

foreach ($d in $disks) { Write-Log "Disk              : $($d.Model) | $(([int]($d.Size/1GB)))GB | S/N: $($d.SerialNumber)" }
foreach ($n in $nics) { Write-Log "NIC               : $($n.Description) | MAC: $($n.MACAddress) | IP: $($n.IPAddress -join ',') | DNS: $($n.DNSServerSearchOrder -join ',')" }
if ($tpm) { Write-Log "TPM               : Version $($tpm.SpecVersion) | Enabled: $($tpm.IsEnabled_InitialValue)" } else { Write-Log "TPM               : Not detected" "WARN" }

$NVDTerms = @(
    ($cpu.Name -replace "\(R\)|\(TM\)|CPU|@.*", "").Trim(),
    $bios.Manufacturer,
    "$($board.Manufacturer) $($board.Product)",
    $gpu.Name,
    "Windows 11",
    "Windows Build $OSBuild",
    "Win32k",
    "CLFS",
    "HTTP.sys",
    "Print Spooler",
    "Task Scheduler"
) | Where-Object { $_ -ne $null -and $_.Trim() -ne '' } | Select-Object -Unique

Write-Section "PHASE 2A: CISA KEV FEED"
$CISAData = $null
try {
    $CISAFile = "$FeedCache\cisa_kev.json"
    Invoke-WebRequest -Uri "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" -OutFile $CISAFile -TimeoutSec 30 -UseBasicParsing -ErrorAction Stop
    $CISAData = Get-Content $CISAFile -Raw | ConvertFrom-Json
    Write-Log "CISA KEV loaded: $($CISAData.vulnerabilities.Count) entries." "OK"
} catch { Write-Log "CISA KEV failed: $_" "WARN" }

Write-Section "PHASE 2B: NVD CVE QUERIES"
$NVDResults = @{}
$Global:NVDWindowStart = Get-Date
foreach ($term in $NVDTerms) {
    Write-Log "NVD query: $term"
    $res = Invoke-NVDQuery -Keyword $term -Max 5
    if ($res) { $NVDResults[$term] = $res; Write-Log "  $($res.Count) CVE(s) found for '$term'" "WARN" }
}

Write-Section "PHASE 3A: CISA KEV CROSS-REFERENCE"
$MatchedKEV = @()
if ($CISAData) {
    $kevKeywords = @("Windows", "Microsoft", "Win32k", "CLFS", "NTFS", "HTTP", "SMB", "Print Spooler", "Task Scheduler", "MSHTML", "Hyper-V", "Kernel", "Remote Desktop", "Exchange", $cpu.Manufacturer, $bios.Manufacturer, $board.Manufacturer, $gpu.Name) | Where-Object { $_ -ne $null -and $_.Trim() -ne '' }
    foreach ($v in $CISAData.vulnerabilities) {
        foreach ($kw in $kevKeywords) {
            if ($v.product -like "*$kw*" -or $v.vendorProject -like "*$kw*" -or $v.vulnerabilityName -like "*$kw*") { $MatchedKEV += $v; break }
        }
    }
    $MatchedKEV = $MatchedKEV | Select-Object -Unique
    Write-Log "CISA KEV matches: $($MatchedKEV.Count)" "WARN"
    foreach ($v in $MatchedKEV | Select-Object -First 30) {
        $Global:CVEMatches += $v.cveID
        Write-Log "KEV: $($v.cveID) | $($v.vendorProject) $($v.product) | $($v.vulnerabilityName) | Due: $($v.dueDate)" "ALERT"
        Write-Log "     Action: $($v.requiredAction)" "WARN"
    }
}

Write-Section "PHASE 3B: NVD CVE DETAILS"
foreach ($term in $NVDResults.Keys) {
    Write-Log "--- $term ---" "WARN"
    foreach ($entry in $NVDResults[$term]) {
        $cve = $entry.cve; $cvss = $null
        if ($cve.metrics.cvssMetricV31) { $cvss = $cve.metrics.cvssMetricV31[0].cvssData }
        elseif ($cve.metrics.cvssMetricV30) { $cvss = $cve.metrics.cvssMetricV30[0].cvssData }
        elseif ($cve.metrics.cvssMetricV2) { $cvss = $cve.metrics.cvssMetricV2[0].cvssData }
        $score = if ($cvss) { $cvss.baseScore } else { "N/A" }
        $severity = if ($cvss) { $cvss.baseSeverity } else { "N/A" }
        $desc = ($cve.descriptions | Where-Object { $_.lang -eq "en" } | Select-Object -First 1).value
        if (($desc | Measure-Object -Character).Characters -gt 130) { $desc = ($desc -replace '(?s)^(.{130}).*$','$1') + '...' }
        $level = "INFO"
        if ($severity -eq "CRITICAL" -or $severity -eq "HIGH") { $level = "ALERT" }
        elseif ($severity -eq "MEDIUM") { $level = "WARN" }
        $Global:CVEMatches += $cve.id
        Write-Log "  $($cve.id) | Score: $score ($severity) | $desc" $level
    }
}

Write-Section "PHASE 3C: PROCESS HASH vs MALWAREBAZAAR"
$Processes = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath }
$CheckedHashes = @{}
Write-Log "Checking $($Processes.Count) process binaries via certutil + MalwareBazaar..."
foreach ($proc in $Processes) {
    $path = $proc.ExecutablePath
    if (-not (Test-Path $path -ErrorAction SilentlyContinue)) { continue }
    $hash = Get-SHA256 -FilePath $path
    if (-not $hash -or $CheckedHashes.ContainsKey($hash)) { continue }
    $CheckedHashes[$hash] = $true
    $result = Invoke-MBCheck -Hash $hash
    if ($result -and $result.query_status -eq "ok") {
        $sample = $result.data | Select-Object -First 1
        $Global:IOCMatches += $hash
        Write-Log "MALWARE HIT: $($proc.Name) PID:$($proc.ProcessId) | Family:$($sample.signature) | Path:$path" "ALERT"
    }
    Start-Sleep -Milliseconds 250
}

Write-Section "PHASE 3D: EXTERNAL CONNECTIONS vs THREATFOX"
$ExtConns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|0\.0\.0\.0|fe80)" }
$CheckedIPs = @{}
foreach ($conn in $ExtConns) {
    $ioc = "$($conn.RemoteAddress):$($conn.RemotePort)"
    if ($CheckedIPs.ContainsKey($ioc)) { continue }
    $CheckedIPs[$ioc] = $true
    $procName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).Name
    $result = Invoke-ThreatFoxCheck -IOC $ioc
    if ($result -and $result.query_status -eq "ok") {
        $data = $result.data | Select-Object -First 1
        $Global:IOCMatches += $ioc; $Global:BlockedIPs += $conn.RemoteAddress
        Write-Log "THREATFOX HIT: $ioc | Process:$procName | Malware:$($data.malware_printable)" "ALERT"
    } else { Write-Log "ThreatFox clean: $ioc ($procName)" }
    Start-Sleep -Milliseconds 300
}

Write-Section "PHASE 3E: DNS CACHE vs URLHAUS"
$DnsEntries = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -Unique -ExpandProperty Entry
$CheckedDomains = @{}
foreach ($entry in $DnsEntries) {
    $parts = $entry -split "\."; $root = if ($parts.Count -ge 2) { "$($parts[-2]).$($parts[-1])" } else { $entry }
    if ($CheckedDomains.ContainsKey($root) -or $root -match "microsoft|windows|bing|msftncsi|apple|google|cloudflare|digicert|verisign") { continue }
    $CheckedDomains[$root] = $true
    $result = Invoke-URLhausCheck -TargetHost $root
    if ($result -and $result.query_status -eq "is_host") {
        $Global:IOCMatches += $root
        Write-Log "URLHAUS HIT: $entry (root: $root) | Malicious URLs: $($result.urls.Count)" "ALERT"
    }
    Start-Sleep -Milliseconds 200
}

Write-Section "PHASE 4: AUTO-HARDENING (CLM-SAFE)"
Apply-Hardening "Defender real-time protection" {
    Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -EnableNetworkProtection Enabled -EnableControlledFolderAccess Enabled -PUAProtection Enabled -CloudBlockLevel High -CloudExtendedTimeout 50 -MAPSReporting 2 -SubmitSamplesConsent 2
}
Apply-Hardening "Defender ASR rules - all block mode" {
    $rules = @("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "3b576869-9746-47e2-9a5f-92408df01fdc", "756eaac2-8075-4728-a7e9-9116a2853504", "d1e49fe7-93a8-47f1-98f3-6b99e4057346", "d3e0399e-aaab-4085-885a-7e1d5d807a50", "92e417f7-6058-47eb-859f-8886dd94d029", "5beb7efe-fd9a-4556-801d-275e5ffc04cc", "c1db035a-3c4a-4a17-a525-816332d657d4", "26190891-c973-4b0a-964a-e739d20c6e08", "01443614-cd74-433a-b99e-2ecdc779763d", "56a863a9-875e-4185-98a7-b882c57b53d5", "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "b2b3f03d-2e65-4772-8545-1c70c812d285")
    foreach ($r in $rules) { Add-MpPreference -AttackSurfaceReductionRules_Ids $r -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue }
}
Apply-Hardening "LSASS RunAsPPL" { Ensure-RegPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL" "1"; Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPLBoot" "1" }
Apply-Hardening "Disable WDigest cleartext credentials" { Ensure-RegPath "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" "0" }
Apply-Hardening "Memory Integrity (HVCI)" { Ensure-RegPath "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"; Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled" "1"; Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Locked" "0" }
Apply-Hardening "Virtualization Based Security (VBS)" { Ensure-RegPath "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity" "1"; Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "RequirePlatformSecurityFeatures" "3"; Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "LsaCfgFlags" "1" }
Apply-Hardening "UAC Always Notify" { Ensure-RegPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" "2"; Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" "1"; Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" "1" }
Apply-Hardening "Disable AutoRun / AutoPlay" { Ensure-RegPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" "255"; Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun" "1" }
Apply-Hardening "Restrict anonymous SAM/share access" { Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" "1"; Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" "1"; Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous" "0"; Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse" "1" }
Apply-Hardening "NTLM hardening" { Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LMCompatibilityLevel" "5"; Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinClientSec" "537395200"; Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinServerSec" "537395200" }
Apply-Hardening "Disable LLMNR" { Ensure-RegPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" "0" }
Apply-Hardening "Block MDM enrollment" { Ensure-RegPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM"; Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM" "DisableEnrollment" "1"; Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM" "AutoEnrollMDM" "0" }
Apply-Hardening "PowerShell Logging" { Ensure-RegPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" "1"; Ensure-RegPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging" "1" }
Apply-Hardening "Disable RDP" { Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" "1"; netsh advfirewall firewall set rule group="Remote Desktop" new enable=no 2>&1 | Out-Null }
Apply-Hardening "Kernel font parsing exploit mitigation" { Ensure-RegPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"; Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" "MitigationOptions" "1000000000000" "REG_QWORD" }
Apply-Hardening "Tamper Protection" { Ensure-RegPath "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"; Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" "TamperProtection" "5" }
Apply-Hardening "DNS over HTTPS auto-upgrade" { Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableAutoDoh" "2" }
Apply-Hardening "Windows Update - automatic" { Ensure-RegPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" "0"; Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" "4" }
Apply-Hardening "Disable DCOM remote access" { reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole" /v "EnableDCOM" /t REG_SZ /d "N" /f 2>&1 | Out-Null }
Apply-Hardening "Block known malicious ports via netsh" { $ports = @(4444, 4445, 1337, 31337, 5555, 6666, 6667, 7777, 8888, 9001, 9002, 1080, 54321, 65535); foreach ($p in $ports) { netsh advfirewall firewall add rule name="BLOCK_OUT_$p" dir=out protocol=tcp remoteport=$p action=block 2>&1 | Out-Null; netsh advfirewall firewall add rule name="BLOCK_IN_$p" dir=in protocol=tcp localport=$p action=block 2>&1 | Out-Null } }
Apply-Hardening "Disable Print Spooler" { sc.exe stop Spooler 2>&1 | Out-Null; sc.exe config Spooler start= disabled 2>&1 | Out-Null }
Apply-Hardening "Disable SMBv1" { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue }
Apply-Hardening "Advanced audit policies" { $policies = @("Process Creation", "Process Termination", "Logon", "Logoff", "Account Lockout", "Special Logon", "Security Group Management", "User Account Management", "Audit Policy Change", "Sensitive Privilege Use", "Credential Validation", "System Integrity", "File System", "Registry", "Removable Storage", "Detailed File Share"); foreach ($pol in $policies) { auditpol /set /subcategory:"$pol" /success:enable /failure:enable 2>&1 | Out-Null }; Ensure-RegPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" "1" }
Apply-Hardening "Windows Firewall - all profiles on" { netsh advfirewall set allprofiles state on 2>&1 | Out-Null; netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound 2>&1 | Out-Null }

if ($Global:BlockedIPs.Count -gt 0) {
    Write-Section "PHASE 4B: IOC IP BLOCKING"
    foreach ($ip in ($Global:BlockedIPs | Select-Object -Unique)) { Apply-Hardening "Block IOC IP: $ip" { netsh advfirewall firewall add rule name="BLOCK_IOC_OUT_$ip" dir=out remoteip=$ip action=block 2>&1 | Out-Null; netsh advfirewall firewall add rule name="BLOCK_IOC_IN_$ip" dir=in remoteip=$ip action=block 2>&1 | Out-Null } }
    Apply-Hardening "Flush DNS cache" { ipconfig /flushdns 2>&1 | Out-Null }
}

Apply-Hardening "Update Defender signatures" { Update-MpSignature -ErrorAction SilentlyContinue }
Apply-Hardening "Defender quick scan" { Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue }
Apply-Hardening "Schedule weekly hunt" { $dest = "$env:SystemDrive\AdaptiveHunt"; cmd /c mkdir "$dest" 2>$null; $scriptDest = "$dest\HuntAndHarden.ps1"; if ($PSCommandPath) { Copy-Item -Path $PSCommandPath -Destination $scriptDest -Force -ErrorAction SilentlyContinue } else { Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptDest -Force -ErrorAction SilentlyContinue }; schtasks /create /tn "WeeklyAdaptiveThreatHunt" /tr "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File \"$scriptDest\"" /sc weekly /d SUN /st 03:00 /ru SYSTEM /rl HIGHEST /f 2>&1 | Out-Null }

Write-Section "PHASE 5: SUMMARY"
Write-Log "Machine GUID    : $MachineGUID"
Write-Log "OS              : $($os.Caption) Build $OSBuild"
Write-Log "CPU             : $($cpu.Name)"
Write-Log "BIOS            : $($bios.Manufacturer) $($bios.SMBIOSBIOSVersion)"
Write-Log "-----------------------------------------------------------------"
Write-Log "CISA KEV Matches: $($MatchedKEV.Count) known exploited CVEs" "WARN"
Write-Log "NVD CVE Matches : $($Global:CVEMatches.Count) CVEs across hardware/software" "WARN"
Write-Log "IOC Hits        : $($Global:IOCMatches.Count)" $(if ($Global:IOCMatches.Count -gt 0) {"ALERT"} else {"OK"})
Write-Log "Hardening Applied: $($Global:HardenCount) controls enforced" "OK"
Write-Log "Total Alerts    : $($Global:AlertCount)" $(if ($Global:AlertCount -gt 0) {"ALERT"} else {"OK"})
Write-Log "-----------------------------------------------------------------"
Write-Log "Report saved    : $ReportPath" "OK"
Write-Log "Feed cache      : $FeedCache" "OK"
Write-Log "-----------------------------------------------------------------"
Write-Log "REBOOT REQUIRED to apply HVCI, VBS, and kernel-level mitigations." "WARN"
