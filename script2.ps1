# Run as Administrator

Write-Host "=== AFA Law Firm Server Hardening Script ===" -ForegroundColor Cyan
Write-Host "Critical Services: RDP, MailEnable, IIS Web Server" -ForegroundColor Cyan
Write-Host ""

# Create detailed log file
$logFile = "C:\AFA_Hardening_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Start-Transcript -Path $logFile

Write-Host "[!] IMPORTANT: Read scenario carefully before running!" -ForegroundColor Yellow
Write-Host "[!] This script will make significant system changes" -ForegroundColor Yellow
Write-Host ""

# ============================================================================
# 1. USER ACCOUNT MANAGEMENT
# ============================================================================
Write-Host "`n[1] USER ACCOUNT MANAGEMENT" -ForegroundColor Green

# Define authorized users based on scenario
$authorizedAdmins = @("benjamin", "rzane2", "hspecter", "llitt", "mross")
$authorizedUsers = @("awilliams", "swheeler", "kbennett", "pporter", "baltman", "rzane", "scarter", "dpaulson", "gbodinski")
$specialAccounts = @("IME_ADMIN", "IME_USER")  # MailEnable required accounts
$allAuthorized = $authorizedAdmins + $authorizedUsers + $specialAccounts + @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount")

Write-Host "`nAuthorized Administrators: $($authorizedAdmins -join ', ')"
Write-Host "Authorized Users: $($authorizedUsers -join ', ')"
Write-Host "Special Accounts (MailEnable): $($specialAccounts -join ', ')"

# Get all local users
$allUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
Write-Host "`nCurrent enabled users:"
$allUsers | Select-Object Name, Enabled, Description, LastLogon | Format-Table -AutoSize

# Identify unauthorized users
$unauthorizedUsers = $allUsers | Where-Object { $allAuthorized -notcontains $_.Name }

if ($unauthorizedUsers) {
    Write-Host "`n[!] UNAUTHORIZED USERS FOUND:" -ForegroundColor Red
    foreach ($user in $unauthorizedUsers) {
        Write-Host "  - $($user.Name)" -ForegroundColor Red
        # Remove unauthorized users
        try {
            Remove-LocalUser -Name $user.Name -ErrorAction Stop
            Write-Host "    [REMOVED] $($user.Name)" -ForegroundColor Yellow
        } catch {
            Write-Host "    [ERROR] Could not remove $($user.Name): $_" -ForegroundColor Red
        }
    }
} else {
    Write-Host "[+] No unauthorized users found" -ForegroundColor Green
}

# Disable Guest account
Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
Write-Host "[+] Guest account disabled"

# Verify Administrators group membership
Write-Host "`n[+] Checking Administrators group membership..."
$adminGroupMembers = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name

foreach ($member in $adminGroupMembers) {
    $username = $member.Split('\')[-1]
    if ($authorizedAdmins -notcontains $username -and $username -ne "Administrator") {
        Write-Host "[!] Unauthorized admin found: $username" -ForegroundColor Red
        try {
            Remove-LocalGroupMember -Group "Administrators" -Member $username -ErrorAction Stop
            Write-Host "    [REMOVED] $username from Administrators group" -ForegroundColor Yellow
        } catch {
            Write-Host "    [ERROR] Could not remove $username from Administrators: $_" -ForegroundColor Red
        }
    }
}

# Ensure authorized admins are in Administrators group
foreach ($admin in $authorizedAdmins) {
    $userExists = Get-LocalUser -Name $admin -ErrorAction SilentlyContinue
    if ($userExists) {
        try {
            Add-LocalGroupMember -Group "Administrators" -Member $admin -ErrorAction SilentlyContinue
            Write-Host "[+] Ensured $admin is in Administrators group"
        } catch {
            # User already in group
        }
    }
}

# Ensure regular users are NOT in Administrators group
foreach ($user in $authorizedUsers) {
    try {
        Remove-LocalGroupMember -Group "Administrators" -Member $user -ErrorAction SilentlyContinue
        Write-Host "[+] Removed $user from Administrators (if present)"
    } catch {
        # User not in group, which is correct
    }
}

# Set known passwords for authorized admins (CHANGE THESE AFTER COMPETITION)
Write-Host "`n[+] Setting secure passwords for authorized administrators..."
$adminPasswords = @{
    "benjamin" = "W1llH4ck4B4con!"
    "rzane2" = "zane"
    "hspecter" = "L1f3!5LikeTH1s"
    "llitt" = "ugotlittup"
    "mross" = "Ross999"
}

foreach ($admin in $adminPasswords.Keys) {
    $userExists = Get-LocalUser -Name $admin -ErrorAction SilentlyContinue
    if ($userExists) {
        $securePassword = ConvertTo-SecureString $adminPasswords[$admin] -AsPlainText -Force
        Set-LocalUser -Name $admin -Password $securePassword -PasswordNeverExpires $false
        Write-Host "[+] Password set for $admin"
    }
}

# Force password change for regular users with weak passwords
Write-Host "`n[+] Forcing password changes for authorized users at next logon..."
foreach ($user in $authorizedUsers) {
    $userExists = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
    if ($userExists) {
        Set-LocalUser -Name $user -PasswordNeverExpires $false
        # Note: Can't force password change via Set-LocalUser in PS, use net user
        net user $user /logonpasswordchg:yes 2>$null
        Write-Host "[+] $user will be required to change password at next logon"
    }
}

# ============================================================================
# 2. PASSWORD POLICY
# ============================================================================
Write-Host "`n[2] PASSWORD POLICY CONFIGURATION" -ForegroundColor Green

net accounts /minpwlen:14
net accounts /maxpwage:90
net accounts /minpwage:1
net accounts /uniquepw:5
Write-Host "[+] Password policy: 14 char minimum, 90 day max age, 5 password history"

# Account lockout policy
net accounts /lockoutthreshold:5
net accounts /lockoutduration:30
net accounts /lockoutwindow:30
Write-Host "[+] Account lockout: 5 failed attempts, 30 min lockout"

# ============================================================================
# 3. WINDOWS UPDATES
# ============================================================================
Write-Host "`n[3] WINDOWS UPDATES CONFIGURATION" -ForegroundColor Green

# Enable and start Windows Update service
Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name wuauserv -ErrorAction SilentlyContinue
Write-Host "[+] Windows Update service enabled and started"
Write-Host "[!] MANUAL: Install security updates via Settings (NOT Feature Updates!)"

# ============================================================================
# 4. FIREWALL CONFIGURATION
# ============================================================================
Write-Host "`n[4] FIREWALL CONFIGURATION" -ForegroundColor Green

# Enable Windows Firewall for all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Host "[+] Windows Firewall enabled for all profiles"

# Configure logging
Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True -LogAllowed False
Write-Host "[+] Firewall logging configured"

# Ensure critical service ports are allowed
Write-Host "[+] Configuring firewall rules for critical services..."

# RDP - Port 3389
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
Write-Host "  [+] RDP (Port 3389) allowed"

# HTTP/HTTPS for IIS - Ports 80 and 443
New-NetFirewallRule -DisplayName "AFA IIS HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "AFA IIS HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -ErrorAction SilentlyContinue
Write-Host "  [+] IIS HTTP/HTTPS (Ports 80, 443) allowed"

# MailEnable ports
$mailPorts = @(25, 110, 143, 465, 587, 993, 995)
foreach ($port in $mailPorts) {
    New-NetFirewallRule -DisplayName "AFA MailEnable Port $port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -ErrorAction SilentlyContinue
}
Write-Host "  [+] MailEnable ports (SMTP, POP3, IMAP) allowed"

# Block known attack IP from forensics
New-NetFirewallRule -DisplayName "Block Enumeration Attack 192.168.43.128" -Direction Inbound -RemoteAddress 192.168.43.128 -Action Block -ErrorAction SilentlyContinue
Write-Host "  [+] Blocked attack IP 192.168.43.128"

# ============================================================================
# 5. REMOTE DESKTOP HARDENING
# ============================================================================
Write-Host "`n[5] REMOTE DESKTOP (RDP) CONFIGURATION" -ForegroundColor Green

# Enable RDP (required for scenario)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Write-Host "[+] Remote Desktop ENABLED (required)"

# Enable Network Level Authentication
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
Write-Host "[+] Network Level Authentication enabled"

# Set RDP encryption to High
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 3
Write-Host "[+] RDP encryption set to High"

# Ensure RDP service is running
Set-Service -Name TermService -StartupType Automatic
Start-Service -Name TermService -ErrorAction SilentlyContinue
Write-Host "[+] Terminal Services running"

# Configure Remote Desktop Users group
Write-Host "[+] Configuring Remote Desktop Users group..."
$rdpGroup = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
Write-Host "  Current RDP Users: $($rdpGroup.Name -join ', ')"

# ============================================================================
# 6. IIS WEB SERVER HARDENING
# ============================================================================
Write-Host "`n[6] IIS WEB SERVER CONFIGURATION" -ForegroundColor Green

# Check if IIS is installed
$iis = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
if ($iis) {
    Write-Host "[+] IIS Service found - Status: $($iis.Status)"
    
    # Ensure IIS is running (CRITICAL - DO NOT DISABLE)
    Set-Service -Name W3SVC -StartupType Automatic
    Start-Service -Name W3SVC -ErrorAction SilentlyContinue
    Write-Host "[+] IIS Web Server set to Automatic and started"
    
    # Also ensure related services are running
    Set-Service -Name WAS -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name WAS -ErrorAction SilentlyContinue
    Write-Host "[+] Windows Process Activation Service running"
    
    # Import WebAdministration module
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    
    # Check SSL certificate
    $certPath = "C:\inetpub\SSL\AFACERT.pfx"
    if (Test-Path $certPath) {
        Write-Host "[+] SSL Certificate found at $certPath"
        Write-Host "    Password: Law2025!"
    } else {
        Write-Host "[!] SSL Certificate NOT found at expected location" -ForegroundColor Yellow
    }
    
    # Scan wwwroot for suspicious files
    $wwwroot = "C:\inetpub\wwwroot"
    if (Test-Path $wwwroot) {
        Write-Host "[+] Scanning wwwroot for suspicious files..."
        $suspiciousExtensions = @("*.exe", "*.bat", "*.cmd", "*.vbs", "*.ps1", "*.dll")
        foreach ($ext in $suspiciousExtensions) {
            $files = Get-ChildItem -Path $wwwroot -Filter $ext -Recurse -ErrorAction SilentlyContinue
            if ($files) {
                Write-Host "  [!] WARNING: Found $ext files in wwwroot:" -ForegroundColor Red
                $files | ForEach-Object { Write-Host "      $($_.FullName)" -ForegroundColor Red }
            }
        }
    }
    
    Write-Host "[!] MANUAL IIS TASKS:" -ForegroundColor Yellow
    Write-Host "    - Open IIS Manager (inetmgr)"
    Write-Host "    - Configure HTTPS bindings with AFACERT.pfx certificate"
    Write-Host "    - Disable directory browsing"
    Write-Host "    - Remove unnecessary HTTP headers"
    Write-Host "    - Configure SSL settings (Require SSL where possible)"
    Write-Host "    - Review application pool identities"
    
} else {
    Write-Host "[!] IIS NOT FOUND - This should be installed!" -ForegroundColor Red
}

# ============================================================================
# 7. MAILENABLE HARDENING
# ============================================================================
Write-Host "`n[7] MAILENABLE MAIL SERVER CONFIGURATION" -ForegroundColor Green

# Verify IME_ADMIN and IME_USER accounts exist (required)
$imeAccounts = @("IME_ADMIN", "IME_USER")
foreach ($account in $imeAccounts) {
    $userExists = Get-LocalUser -Name $account -ErrorAction SilentlyContinue
    if ($userExists) {
        Write-Host "[+] Required account exists: $account"
    } else {
        Write-Host "[!] WARNING: Required account NOT found: $account" -ForegroundColor Red
    }
}

# Check MailEnable services
$mailServices = @(
    "MailEnable Management",
    "MailEnable SMTP Service",
    "MailEnable POP3 Service",
    "MailEnable IMAP Service"
)

Write-Host "[+] Checking MailEnable services..."
foreach ($svcName in $mailServices) {
    $svc = Get-Service | Where-Object { $_.DisplayName -like "*$svcName*" }
    if ($svc) {
        Write-Host "  [+] $($svc.DisplayName): $($svc.Status)"
        if ($svc.Status -ne "Running") {
            Start-Service -Name $svc.Name -ErrorAction SilentlyContinue
            Write-Host "      [STARTED] $($svc.DisplayName)" -ForegroundColor Yellow
        }
        Set-Service -Name $svc.Name -StartupType Automatic -ErrorAction SilentlyContinue
    }
}

# Check MailEnable directories
$mailEnableDirs = @(
    "C:\Program Files (x86)\Mail Enable",
    "C:\Program Files (x86)\Mail Enable\Postoffices"
)

foreach ($dir in $mailEnableDirs) {
    if (Test-Path $dir) {
        Write-Host "[+] MailEnable directory found: $dir"
        
        # Secure postoffices directory (mail stored in plaintext!)
        if ($dir -like "*Postoffices*") {
            Write-Host "  [!] SECURING POSTOFFICES - Mail data is in plaintext!" -ForegroundColor Yellow
            
            # Remove permissions for Users group
            $acl = Get-Acl $dir
            $usersRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","Read","ContainerInherit,ObjectInherit","None","Allow")
            $acl.RemoveAccessRule($usersRule) | Out-Null
            Set-Acl $dir $acl -ErrorAction SilentlyContinue
            Write-Host "  [+] Removed Users group read access to Postoffices"
        }
    }
}

# Disable VRFY command to prevent enumeration (found in forensics)
Write-Host "`n[!] CRITICAL MAILENABLE SECURITY TASKS:" -ForegroundColor Yellow
Write-Host "    1. Open MailEnable Administration"
Write-Host "    2. SMTP Connector > Properties > Advanced tab:"
Write-Host "       - DISABLE VRFY command (prevents mailbox enumeration)"
Write-Host "       - DISABLE EXPN command"
Write-Host "       - Disable anonymous relay"
Write-Host "    3. Configure SSL/TLS for all services:"
Write-Host "       - SMTP: Enable STARTTLS on port 587"
Write-Host "       - POP3: Enable SSL on port 995"
Write-Host "       - IMAP: Enable SSL on port 993"
Write-Host "       - Use certificate at C:\inetpub\SSL\AFACERT.pfx (password: Law2025!)"
Write-Host "    4. Require authentication for all services"
Write-Host "    5. Do NOT use Integrated Authentication (per scenario)"
Write-Host "    6. Configure spam filtering"
Write-Host "    7. Set message size limits (25MB recommended)"

# ============================================================================
# 8. AUTHORIZED SOFTWARE CHECK
# ============================================================================
Write-Host "`n[8] SOFTWARE AUDIT" -ForegroundColor Green

Write-Host "[+] Authorized software: Google Chrome, Notepad++, 7-Zip, Wireshark"

# List installed programs
$programs = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                             HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
            Select-Object DisplayName, DisplayVersion, Publisher |
            Where-Object { $_.DisplayName -ne $null } |
            Sort-Object DisplayName -Unique

Write-Host "[+] Installed programs:"
$programs | ForEach-Object { Write-Host "    $($_.DisplayName)" }

# Check for prohibited software (hacking tools)
$prohibitedSoftware = @(
    "Cain", "Abel", "John", "Ophcrack", "Nmap", "Netcat", "THC", "Metasploit",
    "Aircrack", "Burp", "SQLMap", "Hydra", "Nikto", "Armitage"
)

Write-Host "`n[+] Checking for prohibited hacking tools..."
foreach ($prohibited in $prohibitedSoftware) {
    $found = $programs | Where-Object { $_.DisplayName -like "*$prohibited*" }
    if ($found) {
        Write-Host "  [!] PROHIBITED SOFTWARE FOUND: $($found.DisplayName)" -ForegroundColor Red
        Write-Host "      REMOVE IMMEDIATELY via Programs and Features" -ForegroundColor Red
    }
}

# Verify authorized software is installed
$authorizedSoftware = @{
    "Chrome" = "Google Chrome"
    "Notepad++" = "Notepad++"
    "7-Zip" = "7-Zip"
    "Wireshark" = "Wireshark"
}

Write-Host "`n[+] Verifying authorized business software..."
foreach ($software in $authorizedSoftware.Keys) {
    $found = $programs | Where-Object { $_.DisplayName -like "*$($authorizedSoftware[$software])*" }
    if ($found) {
        Write-Host "  [+] $software installed: $($found.DisplayName)"
    } else {
        Write-Host "  [!] $software NOT found - may need installation" -ForegroundColor Yellow
    }
}

# ============================================================================
# 9. REMOVE PROHIBITED MEDIA FILES
# ============================================================================
Write-Host "`n[9] SCANNING FOR PROHIBITED MEDIA FILES" -ForegroundColor Green

Write-Host "[!] Company policy prohibits non-work related media files"

$scanPaths = @("C:\Users", "C:\inetpub", "C:\Program Files", "C:\Program Files (x86)")
$mediaExtensions = @("*.mp3", "*.mp4", "*.avi", "*.mov", "*.wav", "*.mkv", "*.flv", "*.wmv", "*.m4a", "*.flac")

Write-Host "[+] Scanning for media files (this may take time)..."

foreach ($path in $scanPaths) {
    if (Test-Path $path) {
        foreach ($ext in $mediaExtensions) {
            $files = Get-ChildItem -Path $path -Filter $ext -Recurse -ErrorAction SilentlyContinue -Force |
                     Select-Object -First 10 FullName
            if ($files) {
                Write-Host "  [!] Found $ext files in $path :" -ForegroundColor Red
                $files | ForEach-Object {
                    Write-Host "      $($_.FullName)" -ForegroundColor Red
                    # Uncomment to auto-delete (USE WITH CAUTION):
                    # Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

Write-Host "[!] REVIEW and DELETE prohibited media files listed above"

# ============================================================================
# 10. DISABLE UNNECESSARY SERVICES
# ============================================================================
Write-Host "`n[10] SERVICE HARDENING" -ForegroundColor Green

# Services safe to disable (NOT affecting RDP, IIS, or MailEnable)
$servicesToDisable = @(
    "RemoteRegistry",
    "TlntSvr",
    "simptcp",
    "SNMPTRAP",
    "SSDPSRV",
    "upnphost",
    "Browser",
    "fax"
)

Write-Host "[+] Disabling unnecessary services..."
foreach ($svc in $servicesToDisable) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "  [+] Disabled: $svc" -ForegroundColor Yellow
    }
}

# CRITICAL: Verify critical services are NOT disabled
$criticalServices = @(
    "W3SVC",           # IIS
    "WAS",             # Windows Process Activation (IIS)
    "TermService",     # Remote Desktop
    "IISADMIN"         # IIS Admin
)

Write-Host "`n[+] Verifying critical services are ENABLED..."
foreach ($svc in $criticalServices) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.StartType -eq "Disabled") {
            Set-Service -Name $svc -StartupType Automatic
            Write-Host "  [+] RE-ENABLED critical service: $svc" -ForegroundColor Green
        }
        if ($service.Status -ne "Running") {
            Start-Service -Name $svc -ErrorAction SilentlyContinue
            Write-Host "  [+] STARTED critical service: $svc" -ForegroundColor Green
        }
        Write-Host "  [+] $svc : $($service.Status) / $($service.StartType)"
    }
}

# ============================================================================
# 11. AUDIT POLICIES
# ============================================================================
Write-Host "`n[11] AUDIT POLICY CONFIGURATION" -ForegroundColor Green

auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
Write-Host "[+] Comprehensive audit policies enabled"

# ============================================================================
# 12. SECURITY REGISTRY SETTINGS
# ============================================================================
Write-Host "`n[12] SECURITY REGISTRY CONFIGURATION" -ForegroundColor Green

# Disable anonymous SID/SAM enumeration
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[+] Anonymous enumeration disabled"

# Disable LM hash storage
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[+] LM hash storage disabled"

# Enable UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[+] UAC enabled"

# Disable AutoPlay
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f | Out-Null
Write-Host "[+] AutoPlay disabled"

# Set LAN Manager authentication level to NTLMv2 only
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null
Write-Host "[+] LAN Manager authentication set to NTLMv2 only"

# ============================================================================
# 13. WINDOWS DEFENDER / ANTIVIRUS
# ============================================================================
Write-Host "`n[13] ANTIVIRUS CONFIGURATION" -ForegroundColor Green

# Check Windows Defender status
$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defender) {
    Write-Host "[+] Windows Defender Status:"
    Write-Host "    Antivirus Enabled: $($defender.AntivirusEnabled)"
    Write-Host "    Real-time Protection: $($defender.RealTimeProtectionEnabled)"
    Write-Host "    Last Signature Update: $($defender.AntivirusSignatureLastUpdated)"
    
    # Enable real-time protection
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Write-Host "[+] Real-time protection enabled"
    
    # Update definitions
    Update-MpSignature -ErrorAction SilentlyContinue
    Write-Host "[+] Defender signatures updated"
    
    # Run quick scan
    Write-Host "[+] Starting Windows Defender quick scan..."
    Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue
}

# ============================================================================
# 14. ACTION CENTER
# ============================================================================
Write-Host "`n[14] WINDOWS ACTION CENTER" -ForegroundColor Green

# Enable Windows Security Center service (Action Center)
Set-Service -Name wscsvc -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name wscsvc -ErrorAction SilentlyContinue
Write-Host "[+] Windows Action Center / Security Center service enabled"

# ============================================================================
# 15. NETWORK SHARES
# ============================================================================
Write-Host "`n[15] NETWORK SHARES AUDIT" -ForegroundColor Green

Write-Host "[+] Current network shares:"
$shares = Get-SmbShare | Where-Object { $_.Name -notlike "*$" }
$shares | Select-Object Name, Path, Description | Format-Table -AutoSize

if ($shares) {
    Write-Host "[!] Review shares - remove unnecessary ones" -ForegroundColor Yellow
}

# ============================================================================
# 16. SCHEDULED TASKS
# ============================================================================
Write-Host "`n[16] SCHEDULED TASKS AUDIT" -ForegroundColor Green

Write-Host "[+] Checking for suspicious scheduled tasks..."
$tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" -and $_.Principal.UserId -notlike "S-1-5-18" }

Write-Host "[+] Active scheduled tasks:"
$tasks | Select-Object TaskName, TaskPath, State, @{Name="User";Expression={$_.Principal.UserId}} |
         Format-Table -AutoSize

Write-Host "[!] Review tasks for suspicious entries"

# ============================================================================
# 17. EVENT VIEWER - MAILBOX ENUMERATION ATTACK
# ============================================================================
Write-Host "`n[17] FORENSICS: MAILBOX ENUMERATION ATTACK" -ForegroundColor Green

Write-Host "[+] Based on log analysis:"
Write-Host "    Attack IP: 192.168.43.128"
Write-Host "    Mailboxes Enumerated: 53"
Write-Host "    Valid Mailboxes Found: 8"
Write-Host "    Attack Method: VRFY command enumeration"
Write-Host "    [+] Attack IP has been BLOCKED in firewall"

# Check recent failed logons
Write-Host "`n[+] Checking recent failed logon attempts..."
try {
    $failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 20 -ErrorAction SilentlyContinue
    if ($failedLogons) {
        Write-Host "  [!] Recent failed logon attempts found - review Event Viewer"
    }
} catch {
    Write-Host "  [+] No recent failed logons found"
}
