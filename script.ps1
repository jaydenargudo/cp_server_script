# CyberPatriots Windows Server Hardening Script
# Run as Administrator
# Read README carefully before running

Write-Host "=== CyberPatriots Windows Server Hardening Script ===" -ForegroundColor Cyan
Write-Host "WARNING: Review and customize this script before running!" -ForegroundColor Yellow
Write-Host ""

# Create log file
$logFile = "C:\hardening_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Start-Transcript -Path $logFile

# 1. USER MANAGEMENT
Write-Host "`n[1] USER MANAGEMENT" -ForegroundColor Green

# List all users
Write-Host "Current users:"
Get-LocalUser | Select-Object Name, Enabled, Description

# Remove unauthorized users (CUSTOMIZE THIS LIST)
$unauthorizedUsers = @()  # Add usernames here, e.g., @("hacker", "baduser")
foreach ($user in $unauthorizedUsers) {
    try {
        Remove-LocalUser -Name $user -ErrorAction Stop
        Write-Host "Removed user: $user" -ForegroundColor Yellow
    } catch {
        Write-Host "Could not remove $user : $_" -ForegroundColor Red
    }
}

# Disable Guest account
Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
Write-Host "Guest account disabled"

# Reset Administrator password
Write-Host "Consider resetting Administrator password manually"

# 2. PASSWORD POLICY
Write-Host "`n[2] PASSWORD POLICY" -ForegroundColor Green

net accounts /minpwlen:12
net accounts /maxpwage:90
net accounts /minpwage:1
net accounts /uniquepw:5
Write-Host "Password policy updated: 12 char min, 90 day max age, 5 password history"

# Set account lockout policy
net accounts /lockoutthreshold:5
net accounts /lockoutduration:30
net accounts /lockoutwindow:30
Write-Host "Account lockout: 5 attempts, 30 min lockout"

# 3. WINDOWS UPDATES
Write-Host "`n[3] WINDOWS UPDATES" -ForegroundColor Green

# Enable Windows Update service
Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name wuauserv -ErrorAction SilentlyContinue
Write-Host "Windows Update service enabled and started"

# Install PSWindowsUpdate module for update installation
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Host "PSWindowsUpdate module not found. Install manually: Install-Module PSWindowsUpdate"
}

# 4. FIREWALL
Write-Host "`n[4] FIREWALL CONFIGURATION" -ForegroundColor Green

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Host "Firewall enabled for all profiles"

# Log dropped packets
Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True -LogAllowed False
Write-Host "Firewall logging configured"

# 5. REMOVE PROHIBITED SOFTWARE
Write-Host "`n[5] SOFTWARE AUDIT" -ForegroundColor Green

# List installed programs
Write-Host "Installed programs:"
Get-WmiObject -Class Win32_Product | Select-Object Name, Version | Sort-Object Name

# Common prohibited software to check for
$prohibitedSoftware = @("Wireshark", "Cain", "John", "Ophcrack", "Nmap")
Write-Host "`nCheck for prohibited software: $($prohibitedSoftware -join ', ')"
Write-Host "Remove manually via Programs and Features or using: Get-WmiObject -Class Win32_Product -Filter `"Name = 'SoftwareName'`" | ForEach-Object { `$_.Uninstall() }"

# 6. DISABLE UNNECESSARY SERVICES
Write-Host "`n[6] SERVICE HARDENING" -ForegroundColor Green

$servicesToDisable = @(
    "RemoteRegistry",
    "Telnet",
    "TlntSvr",
    "simptcp",
    "fax",
    "SNMPTRAP",
    "SSDPSRV",
    "upnphost",
    "RemoteAccess"
)

foreach ($svc in $servicesToDisable) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "Disabled service: $svc" -ForegroundColor Yellow
    }
}

# 7. AUDIT POLICIES
Write-Host "`n[7] AUDIT POLICY" -ForegroundColor Green

auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
Write-Host "Audit policies enabled"

# 8. SECURITY OPTIONS
Write-Host "`n[8] SECURITY OPTIONS" -ForegroundColor Green

# Disable anonymous SID enumeration
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f

# Disable LM hash storage
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f

# Enable UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f

# Disable AutoPlay
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f

Write-Host "Security registry settings applied"

# 9. FILE SYSTEM SECURITY
Write-Host "`n[9] FILE SYSTEM CHECKS" -ForegroundColor Green

# Check for media files (common point deduction)
Write-Host "Scanning for media files (this may take time)..."
$mediaExtensions = @("*.mp3", "*.mp4", "*.avi", "*.mov", "*.wav", "*.mkv", "*.flv")
foreach ($ext in $mediaExtensions) {
    $files = Get-ChildItem -Path C:\ -Filter $ext -Recurse -ErrorAction SilentlyContinue -Force | Select-Object -First 10 FullName
    if ($files) {
        Write-Host "Found $ext files:" -ForegroundColor Yellow
        $files | ForEach-Object { Write-Host "  $($_.FullName)" }
    }
}

# Check shares
Write-Host "`nNetwork shares:"
Get-SmbShare | Where-Object { $_.Name -notlike "*$" }

# 10. REMOTE ACCESS
Write-Host "`n[10] REMOTE ACCESS" -ForegroundColor Green

# Disable RDP if not needed (check README first!)
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
Write-Host "RDP status: Review if required for scenario"

# Check RDP settings
$rdp = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
Write-Host "RDP Enabled: $($rdp.fDenyTSConnections -eq 0)"

# 11. GROUP POLICY
Write-Host "`n[11] GROUP POLICY" -ForegroundColor Green
Write-Host "Run: gpupdate /force"
Write-Host "Consider configuring Local Security Policy manually"

# 12. ANTIVIRUS
Write-Host "`n[12] ANTIVIRUS" -ForegroundColor Green

# Check Windows Defender status
$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defender) {
    Write-Host "Defender Enabled: $($defender.AntivirusEnabled)"
    Write-Host "Defender Updated: $($defender.AntivirusSignatureLastUpdated)"
    
    # Update definitions
    Update-MpSignature -ErrorAction SilentlyContinue
    Write-Host "Defender signatures updated"
    
    # Run quick scan
    Write-Host "Starting quick scan..."
    Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue
}

# 13. SUMMARY
Write-Host "`n=== HARDENING COMPLETE ===" -ForegroundColor Cyan
Write-Host "Log saved to: $logFile"
Write-Host "`nMANUAL TASKS REMAINING:" -ForegroundColor Yellow
Write-Host "1. Review README for forensic questions"
Write-Host "2. Check for required services (don't disable critical ones!)"
Write-Host "3. Verify authorized users and administrators"
Write-Host "4. Remove prohibited media files found above"
Write-Host "5. Configure Local Security Policy (secpol.msc)"
Write-Host "6. Install all Windows Updates"
Write-Host "7. Review Event Viewer for suspicious activity"
Write-Host "8. Check scheduled tasks for malicious entries"
Write-Host "9. Verify group memberships (especially Administrators)"
Write-Host "10. Document all changes made"

Stop-Transcript