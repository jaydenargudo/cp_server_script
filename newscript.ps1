# Run as Administrator

Write-Host "=== CyberPatriots Windows Server Hardening Script ===" -ForegroundColor Cyan
Write-Host "Critical Services: RDP, MailEnable, IIS" -ForegroundColor Cyan
Write-Host "WARNING: Review and customize this script before running!" -ForegroundColor Yellow
Write-Host ""

# Create log file
$logFile = "C:\hardening_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Start-Transcript -Path $logFile

# 1. USER MANAGEMENT
Write-Host "`n[1] USER MANAGEMENT" -ForegroundColor Green

# List all users
Write-Host "Current users:"
Get-LocalUser | Select-Object Name, Enabled, Description, LastLogon

# Remove unauthorized users (CUSTOMIZE THIS LIST BASED ON README)
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

# Check Administrators group
Write-Host "`nMembers of Administrators group:"
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass

# Check Remote Desktop Users group
Write-Host "`nMembers of Remote Desktop Users group:"
Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue | Select-Object Name, ObjectClass

Write-Host "`nREVIEW: Remove unauthorized users from Administrator and RDP groups manually if needed"

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

# Force users to change passwords at next logon (for authorized users with weak passwords)
Write-Host "`nConsider forcing password resets for users with weak passwords"

# 3. WINDOWS UPDATES
Write-Host "`n[3] WINDOWS UPDATES" -ForegroundColor Green

# Enable Windows Update service
Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name wuauserv -ErrorAction SilentlyContinue
Write-Host "Windows Update service enabled and started"

Write-Host "MANUAL: Check for updates in Settings > Update & Security"
Write-Host "Install all critical and security updates"

# 4. FIREWALL CONFIGURATION
Write-Host "`n[4] FIREWALL CONFIGURATION" -ForegroundColor Green

# Enable firewall for all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Host "Firewall enabled for all profiles"

# Log dropped packets
Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True -LogAllowed False
Write-Host "Firewall logging configured"

# Ensure RDP (3389) is allowed
Write-Host "`nConfiguring firewall rules for critical services..."

# RDP - Port 3389
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
Write-Host "RDP firewall rules enabled (Port 3389)"

# HTTP/HTTPS for IIS - Ports 80 and 443
New-NetFirewallRule -DisplayName "IIS HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "IIS HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -ErrorAction SilentlyContinue
Write-Host "IIS firewall rules configured (Ports 80, 443)"

# MailEnable - Common ports: SMTP(25), POP3(110), IMAP(143), Secure variants(465,587,993,995)
$mailPorts = @(25, 110, 143, 465, 587, 993, 995)
foreach ($port in $mailPorts) {
    New-NetFirewallRule -DisplayName "MailEnable Port $port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -ErrorAction SilentlyContinue
}
Write-Host "MailEnable firewall rules configured (SMTP, POP3, IMAP ports)"

# 5. REMOTE DESKTOP HARDENING
Write-Host "`n[5] REMOTE DESKTOP HARDENING" -ForegroundColor Green

# Enable RDP (required for scenario)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Write-Host "Remote Desktop ENABLED (required service)"

# Enable Network Level Authentication (more secure)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
Write-Host "Network Level Authentication enabled for RDP"

# Set RDP encryption level to high
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 3
Write-Host "RDP encryption set to High"

# Disable RDP clipboard redirection (security hardening)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "fDisableClip" -Value 1 -ErrorAction SilentlyContinue
Write-Host "RDP clipboard redirection disabled"

# 6. IIS WEB SERVER HARDENING
Write-Host "`n[6] IIS WEB SERVER HARDENING" -ForegroundColor Green

# Check if IIS is installed
$iis = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
if ($iis) {
    Write-Host "IIS Service found - Status: $($iis.Status)"
    
    # Ensure IIS is running
    Set-Service -Name W3SVC -StartupType Automatic
    Start-Service -Name W3SVC -ErrorAction SilentlyContinue
    Write-Host "IIS service set to Automatic and started"
    
    # Import WebAdministration module
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    
    # Remove default IIS headers for security
    Write-Host "Configure IIS security manually:"
    Write-Host "  - Remove X-Powered-By header"
    Write-Host "  - Disable directory browsing"
    Write-Host "  - Review application pools (use separate identities)"
    Write-Host "  - Enable HTTPS and disable weak SSL/TLS"
    Write-Host "  - Remove unnecessary IIS modules"
    Write-Host "  - Configure request filtering"
    
    # Check for suspicious files in wwwroot
    $wwwroot = "C:\inetpub\wwwroot"
    if (Test-Path $wwwroot) {
        Write-Host "`nScanning wwwroot for suspicious files..."
        $suspiciousExtensions = @("*.exe", "*.bat", "*.cmd", "*.vbs", "*.ps1")
        foreach ($ext in $suspiciousExtensions) {
            $files = Get-ChildItem -Path $wwwroot -Filter $ext -Recurse -ErrorAction SilentlyContinue
            if ($files) {
                Write-Host "WARNING: Found $ext files in wwwroot:" -ForegroundColor Red
                $files | ForEach-Object { Write-Host "  $($_.FullName)" -ForegroundColor Red }
            }
        }
    }
} else {
    Write-Host "IIS not found - install if required!" -ForegroundColor Red
}

# 7. MAILENABLE HARDENING
Write-Host "`n[7] MAILENABLE CONFIGURATION" -ForegroundColor Green

# Check MailEnable services
$mailServices = @("MailEnable Management", "MailEnable SMTP Service", "MailEnable POP3 Service", "MailEnable IMAP Service")
foreach ($svcName in $mailServices) {
    $svc = Get-Service -DisplayName "*$svcName*" -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "$($svc.DisplayName): $($svc.Status)"
        if ($svc.Status -ne "Running") {
            Start-Service -Name $svc.Name -ErrorAction SilentlyContinue
            Write-Host "  Started $($svc.DisplayName)" -ForegroundColor Yellow
        }
        Set-Service -Name $svc.Name -StartupType Automatic -ErrorAction SilentlyContinue
    }
}

Write-Host "`nMailEnable Security Checklist:"
Write-Host "  - Disable anonymous relay in SMTP"
Write-Host "  - Require authentication for POP3/IMAP"
Write-Host "  - Enable TLS/SSL encryption"
Write-Host "  - Configure spam filtering"
Write-Host "  - Set message size limits"
Write-Host "  - Review postoffice directory permissions"

# Check MailEnable directory
$mailEnableDir = "C:\Program Files (x86)\Mail Enable"
if (Test-Path $mailEnableDir) {
    Write-Host "`nMailEnable installation found at: $mailEnableDir"
} else {
    Write-Host "`nMailEnable directory not found at default location" -ForegroundColor Yellow
}

# 8. REMOVE PROHIBITED SOFTWARE
Write-Host "`n[8] SOFTWARE AUDIT" -ForegroundColor Green

Write-Host "Scanning for installed programs..."
$programs = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
            Select-Object DisplayName, DisplayVersion, Publisher | 
            Where-Object { $_.DisplayName -ne $null } | 
            Sort-Object DisplayName

$programs | ForEach-Object { Write-Host "  $($_.DisplayName)" }

# Check for common prohibited software
$prohibitedSoftware = @("Wireshark", "Cain", "Abel", "John", "Ophcrack", "Nmap", "Netcat", "THC", "Metasploit")
Write-Host "`nChecking for prohibited software..."
foreach ($prog in $prohibitedSoftware) {
    $found = $programs | Where-Object { $_.DisplayName -like "*$prog*" }
    if ($found) {
        Write-Host "WARNING: Found prohibited software: $($found.DisplayName)" -ForegroundColor Red
        Write-Host "  Uninstall immediately!" -ForegroundColor Red
    }
}

# 9. DISABLE UNNECESSARY SERVICES
Write-Host "`n[9] SERVICE HARDENING" -ForegroundColor Green

# Services to disable (carefully selected to not affect RDP, IIS, or MailEnable)
$servicesToDisable = @(
    "RemoteRegistry",      # Remote registry access
    "TlntSvr",            # Telnet server
    "SNMPTRAP",           # SNMP Trap
    "simptcp",            # Simple TCP/IP Services
    "fax",                # Fax
    "SSDPSRV",            # SSDP Discovery
    "upnphost",           # UPnP Device Host
    "RemoteAccess",       # Routing and Remote Access
    "Browser"             # Computer Browser
)

Write-Host "Disabling unnecessary services (preserving RDP, IIS, MailEnable)..."
foreach ($svc in $servicesToDisable) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "Disabled: $svc" -ForegroundColor Yellow
    }
}

# Ensure critical services are NOT disabled
$criticalServices = @(
    "W3SVC",              # IIS
    "WAS",                # Windows Process Activation Service (IIS)
    "TermService",        # Remote Desktop Services
    "Netlogon",           # If domain joined
    "DNS"                 # If DNS server
)

Write-Host "`nVerifying critical services are enabled..."
foreach ($svc in $criticalServices) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.StartType -eq "Disabled") {
            Set-Service -Name $svc -StartupType Automatic -ErrorAction SilentlyContinue
            Write-Host "RE-ENABLED critical service: $svc" -ForegroundColor Green
        }
        Write-Host "$svc : $($service.Status) / $($service.StartType)"
    }
}

# 10. AUDIT POLICIES
Write-Host "`n[10] AUDIT POLICY" -ForegroundColor Green

auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
Write-Host "Audit policies enabled for security monitoring"

# 11. SECURITY OPTIONS
Write-Host "`n[11] SECURITY OPTIONS" -ForegroundColor Green

# Disable anonymous SID enumeration
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f

# Disable LM hash storage
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f

# Enable UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f

# Disable AutoPlay
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f

# Disable NetBIOS over TCP/IP (if not needed for file sharing)
Write-Host "Consider disabling NetBIOS over TCP/IP if not needed"

Write-Host "Security registry settings applied"

# 12. FILE SYSTEM SECURITY
Write-Host "`n[12] FILE SYSTEM CHECKS" -ForegroundColor Green

# Check for media files (common point deduction)
Write-Host "Scanning for prohibited media files..."
$mediaPaths = @("C:\Users", "C:\inetpub", "C:\Program Files")
$mediaExtensions = @("*.mp3", "*.mp4", "*.avi", "*.mov", "*.wav", "*.mkv", "*.flv", "*.wmv")

foreach ($path in $mediaPaths) {
    if (Test-Path $path) {
        foreach ($ext in $mediaExtensions) {
            $files = Get-ChildItem -Path $path -Filter $ext -Recurse -ErrorAction SilentlyContinue -Force | 
                     Select-Object -First 5 FullName
            if ($files) {
                Write-Host "Found $ext files in $path :" -ForegroundColor Yellow
                $files | ForEach-Object { Write-Host "  $($_.FullName)" -ForegroundColor Yellow }
            }
        }
    }
}

# Check network shares
Write-Host "`nNetwork shares:"
Get-SmbShare | Where-Object { $_.Name -notlike "*$" } | Select-Object Name, Path, Description

# Review share permissions
Write-Host "Review share permissions manually - remove unnecessary shares"

# 13. ANTIVIRUS
Write-Host "`n[13] ANTIVIRUS" -ForegroundColor Green

# Check Windows Defender status
$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defender) {
    Write-Host "Defender Status:"
    Write-Host "  Antivirus Enabled: $($defender.AntivirusEnabled)"
    Write-Host "  Real-time Protection: $($defender.RealTimeProtectionEnabled)"
    Write-Host "  Last Signature Update: $($defender.AntivirusSignatureLastUpdated)"
    
    # Enable real-time protection
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    
    # Update definitions
    Update-MpSignature -ErrorAction SilentlyContinue
    Write-Host "Defender signatures updated"
    
    # Run quick scan
    Write-Host "Starting Windows Defender quick scan..."
    Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue
}

# 14. SCHEDULED TASKS
Write-Host "`n[14] SCHEDULED TASKS AUDIT" -ForegroundColor Green

Write-Host "Checking for suspicious scheduled tasks..."
$tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" -and $_.Principal.UserId -notlike "S-1-5-18" }
$tasks | Select-Object TaskName, TaskPath, State | Format-Table -AutoSize

Write-Host "Review tasks manually for suspicious entries"

# 15. GROUP POLICY AND LOCAL SECURITY POLICY
Write-Host "`n[15] LOCAL SECURITY POLICY" -ForegroundColor Green

Write-Host "Additional Local Security Policy settings to configure manually (secpol.msc):"
Write-Host "  Account Policies > Password Policy:"
Write-Host "    - Password must meet complexity requirements: Enabled"
Write-Host "    - Store passwords using reversible encryption: Disabled"
Write-Host "  Local Policies > Security Options:"
Write-Host "    - Accounts: Limit local account use of blank passwords: Enabled"
Write-Host "    - Network access: Do not allow anonymous enumeration: Enabled"
Write-Host "    - Network security: LAN Manager authentication level: NTLMv2 only"
Write-Host "  Local Policies > User Rights Assignment:"
Write-Host "    - Allow log on through Remote Desktop Services: Review users"
Write-Host "    - Deny log on through Remote Desktop Services: Add Guest"

# 16. EVENT VIEWER CHECK
Write-Host "`n[16] EVENT VIEWER CHECKS" -ForegroundColor Green

Write-Host "Review Event Viewer for suspicious activity:"
Write-Host "  - Security logs for failed logons (Event ID 4625)"
Write-Host "  - Security logs for account changes (Event IDs 4720, 4722, 4724)"
Write-Host "  - System logs for service failures"
Write-Host "  - Application logs for IIS and MailEnable errors"

# Get recent security events
Write-Host "`nRecent failed logon attempts:"
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 10 -ErrorAction SilentlyContinue | 
    Select-Object TimeCreated, Message | Format-Table -Wrap

# 17. SUMMARY AND NEXT STEPS
Write-Host "`n=== HARDENING COMPLETE ===" -ForegroundColor Cyan
Write-Host "Log saved to: $logFile" -ForegroundColor Cyan

Write-Host "`n=== CRITICAL SERVICES STATUS ===" -ForegroundColor Green
Write-Host "Remote Desktop: ENABLED and SECURED"
Write-Host "IIS Web Server: Check status above"
Write-Host "MailEnable: Check services above"

Write-Host "`n=== MANUAL TASKS REMAINING ===" -ForegroundColor Yellow
Write-Host "HIGH PRIORITY:"
Write-Host "  1. Read README for forensic questions and authorized users"
Write-Host "  2. Remove unauthorized users from Administrators group"
Write-Host "  3. Reset passwords for all authorized users (especially Administrator)"
Write-Host "  4. Remove prohibited software found above"
Write-Host "  5. Delete prohibited media files found above"
Write-Host "  6. Install ALL Windows Updates (Settings > Update & Security)"
Write-Host ""
Write-Host "IIS CONFIGURATION:"
Write-Host "  7. Open IIS Manager (inetmgr) and review:"
Write-Host "     - Remove default website if not needed"
Write-Host "     - Disable directory browsing"
Write-Host "     - Remove unnecessary HTTP response headers"
Write-Host "     - Configure HTTPS with valid certificate"
Write-Host "     - Set appropriate application pool identities"
Write-Host "     - Enable request filtering"
Write-Host ""
Write-Host "MAILENABLE CONFIGURATION:"
Write-Host "  8. Open MailEnable Administration and review:"
Write-Host "     - Disable SMTP relay for unauthorized users"
Write-Host "     - Require authentication for all services"
Write-Host "     - Enable SSL/TLS encryption"
Write-Host "     - Configure spam filtering"
Write-Host "     - Review and secure postoffice directories"
Write-Host ""
Write-Host "ADDITIONAL TASKS:"
Write-Host "  9. Configure Local Security Policy (secpol.msc) per checklist above"
Write-Host " 10. Review Scheduled Tasks for suspicious entries"
Write-Host " 11. Check Event Viewer for suspicious activity"
Write-Host " 12. Review network shares and permissions"
Write-Host " 13. Verify backup jobs are configured (if applicable)"
Write-Host " 14. Document all changes for competition report"
Write-Host " 15. Test RDP connectivity after hardening"
Write-Host " 16. Test website functionality"
Write-Host " 17. Test email sending/receiving"

Write-Host "`n=== SCORING REMINDERS ===" -ForegroundColor Cyan
Write-Host "  - Answer README forensic questions (usually worth points)"
Write-Host "  - Check Scoring Report frequently to track progress"
Write-Host "  - Don't break critical services (RDP, IIS, MailEnable)"
Write-Host "  - Remove ALL prohibited content (media files, hacking tools)"
Write-Host "  - Secure all user accounts (passwords, group memberships)"

Stop-Transcript

Write-Host "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")