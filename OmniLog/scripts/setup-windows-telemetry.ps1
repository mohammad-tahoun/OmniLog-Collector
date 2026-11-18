<#
.SYNOPSIS
    Force-Fields Windows Telemetry Setup Script
.DESCRIPTION
    Configures Windows Advanced Audit Policies, enables Command Line auditing,
    enables PowerShell Script Block Logging, and deploys high-fidelity Sysmon configuration.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   FORCE-FIELDS SOC: WINDOWS TELEMETRY SETUP & AUDITING   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Verify Administrative Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[-] This script must be executed in an elevated PowerShell session (Run as Administrator)."
    exit 1
}
Write-Host "[+] Elevated Administrator privileges confirmed." -ForegroundColor Green

# 2. Configure Windows Advanced Audit Policies via auditpol
Write-Host "[+] Configuring Advanced Audit Policies..." -ForegroundColor Yellow

$auditRules = @(
    "Detailed Tracking`tProcess Creation`tsuccess:enable /failure:enable",
    "Detailed Tracking`tProcess Termination`tsuccess:enable /failure:disable",
    "Logon/Logoff`tLogon`tsuccess:enable /failure:enable",
    "Logon/Logoff`tLogoff`tsuccess:enable /failure:disable",
    "Logon/Logoff`tAccount Lockout`tsuccess:enable /failure:enable",
    "Logon/Logoff`tSpecial Logon`tsuccess:enable /failure:disable",
    "Account Management`tUser Account Management`tsuccess:enable /failure:enable",
    "Account Management`tSecurity Group Management`tsuccess:enable /failure:enable",
    "Privilege Use`tSensitive Privilege Use`tsuccess:enable /failure:enable",
    "Policy Change`tAudit Policy Change`tsuccess:enable /failure:enable",
    "Policy Change`tAuthentication Policy Change`tsuccess:enable /failure:enable",
    "DS Access`tDirectory Service Access`tsuccess:enable /failure:enable",
    "DS Access`tDirectory Service Changes`tsuccess:enable /failure:enable",
    "Object Access`tFile System`tsuccess:enable /failure:enable",
    "Object Access`tRegistry`tsuccess:enable /failure:enable"
)

foreach ($rule in $auditRules) {
    $parts = $rule -split "`t"
    $subcat = $parts[1]
    $switches = $parts[2] -split " "
    
    $args = @("/set", "/subcategory:$subcat") + $switches
    & auditpol.exe $args | Out-Null
}
Write-Host "[+] Audit policies successfully applied." -ForegroundColor Green

# 3. Enable Command Line in Process Creation (Event 4688)
Write-Host "[+] Enabling full Command Line auditing in Process Creation (Event 4688)..." -ForegroundColor Yellow
$auditRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $auditRegPath)) {
    New-Item -Path $auditRegPath -Force | Out-Null
}
Set-ItemProperty -Path $auditRegPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
Write-Host "[+] ProcessCreationIncludeCmdLine_Enabled set to 1." -ForegroundColor Green

# 4. Enable PowerShell Script Block Logging (Event 4104) & Transcription
Write-Host "[+] Enabling PowerShell Script Block Logging & Transcription..." -ForegroundColor Yellow
$psScriptBlockPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psScriptBlockPath)) {
    New-Item -Path $psScriptBlockPath -Force | Out-Null
}
Set-ItemProperty -Path $psScriptBlockPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force

$psTransPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (-not (Test-Path $psTransPath)) {
    New-Item -Path $psTransPath -Force | Out-Null
}
Set-ItemProperty -Path $psTransPath -Name "EnableTranscripting" -Value 1 -Type DWord -Force
Write-Host "[+] PowerShell script block telemetry active." -ForegroundColor Green

# 5. Generate and Deploy Sysmon Configuration
Write-Host "[+] Generating production-grade Sysmon XML configuration..." -ForegroundColor Yellow
$sysmonConfigXml = @"
<Sysmon schemaversion="4.90">
  <HashAlgorithms>MD5,SHA256,IMPHASH</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>
    <!-- Event ID 1: Process Creation -->
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <IntegrityLevel condition="is">AppContainer</IntegrityLevel>
      </ProcessCreate>
    </RuleGroup>

    <!-- Event ID 3: Network Connection -->
    <RuleGroup name="NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationPort condition="is">443</DestinationPort>
        <DestinationPort condition="is">80</DestinationPort>
        <DestinationPort condition="is">53</DestinationPort>
        <DestinationPort condition="is">22</DestinationPort>
        <DestinationPort condition="is">3389</DestinationPort>
        <DestinationPort condition="is">445</DestinationPort>
        <DestinationPort condition="is">88</DestinationPort>
        <DestinationPort condition="is">389</DestinationPort>
      </NetworkConnect>
      <NetworkConnect onmatch="exclude">
        <DestinationIp condition="is">127.0.0.1</DestinationIp>
      </NetworkConnect>
    </RuleGroup>

    <!-- Event ID 10: Process Access (LSASS & Memory Dumping) -->
    <RuleGroup name="ProcessAccess" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="end with">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>

    <!-- Event ID 11: File Creation -->
    <RuleGroup name="FileCreate" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\Temp\</TargetFilename>
        <TargetFilename condition="contains">\AppData\</TargetFilename>
        <TargetFilename condition="contains">\Downloads\</TargetFilename>
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.dll</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
        <TargetFilename condition="end with">.bat</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <!-- Event ID 12, 13, 14: Registry Persistence -->
    <RuleGroup name="RegistryEvent" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">Services</TargetObject>
        <TargetObject condition="contains">Winlogon</TargetObject>
        <TargetObject condition="contains">Policies\Explorer\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Event ID 22: DNS Query -->
    <RuleGroup name="DnsQuery" groupRelation="or">
      <DnsQuery onmatch="exclude">
        <QueryName condition="end with">.local</QueryName>
        <QueryName condition="end with">.microsoft.com</QueryName>
      </DnsQuery>
    </RuleGroup>

    <!-- Event ID 23 & 26: File Delete -->
    <RuleGroup name="FileDelete" groupRelation="or">
      <FileDelete onmatch="include">
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
        <TargetFilename condition="end with">.log</TargetFilename>
      </FileDelete>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"@

$configPath = Join-Path $PSScriptRoot "sysmonconfig.xml"
$sysmonConfigXml | Out-File -FilePath $configPath -Encoding UTF8 -Force
Write-Host "[+] Sysmon config written to: $configPath" -ForegroundColor Green

# 6. Check for Sysmon executable and install/update
$sysmonBin = Get-Command "sysmon64.exe" -ErrorAction SilentlyContinue
if (-not $sysmonBin) {
    $sysmonBin = Get-Command "sysmon.exe" -ErrorAction SilentlyContinue
}

if ($sysmonBin) {
    Write-Host "[+] Detected Sysmon binary at $($sysmonBin.Source). Updating configuration..." -ForegroundColor Yellow
    & $sysmonBin.Source -c $configPath
    Write-Host "[+] Sysmon configured and active." -ForegroundColor Green
} else {
    Write-Host "[!] Sysmon binary not found in PATH." -ForegroundColor Yellow
    Write-Host "[!] To complete Sysmon installation:" -ForegroundColor Yellow
    Write-Host "    1. Download Sysmon from: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon" -ForegroundColor Yellow
    Write-Host "    2. Execute: sysmon64.exe -accepteula -i `"$configPath`"" -ForegroundColor Yellow
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[SUCCESS] Windows Telemetry setup completed successfully!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
