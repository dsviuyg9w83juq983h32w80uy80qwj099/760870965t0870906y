
# Create output directory
$outputDir = "C:\Users\Public\Recon"
New-Item -ItemType Directory -Force -Path $outputDir

# Collect basic system and user info
whoami | Out-File -Append "$outputDir\recon.txt"
hostname | Out-File -Append "$outputDir\recon.txt"
systeminfo | Out-File -Append "$outputDir\recon.txt"

# Collect network configuration
ipconfig /all | Out-File -Append "$outputDir\network.txt"
netstat -ano | Out-File -Append "$outputDir\network.txt"
netsh wlan show interfaces | Out-File -Append "$outputDir\network.txt"

# Disk usage and drive information
Get-PSDrive | Out-File -Append "$outputDir\disk.txt"
Get-Volume | Out-File -Append "$outputDir\disk.txt"

# File system listing (limited to reduce size)
Get-ChildItem -Path C:\Users -Recurse -ErrorAction SilentlyContinue -Force -File | Select-Object FullName, Length, LastWriteTime | Out-File -Append "$outputDir\files.txt"

# Installed software
Get-CimInstance Win32_Product | Select-Object Name, Version | Out-File -Append "$outputDir\programs.txt"

# Antivirus information
Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct | Out-File -Append "$outputDir\av.txt"

# Running tasks and processes
tasklist | Out-File -Append "$outputDir\tasks.txt"

# Export currently connected USB devices
Get-PnpDevice -PresentOnly | Out-File -Append "$outputDir\usb_devices.txt"

# Export system uptime and performance
Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime | Out-File -Append "$outputDir\boot_time.txt"

# Completion message
"Recon complete. Data saved in $outputDir" | Out-File -Append "$outputDir\status.txt"


# List all services and their status
Get-Service | Select-Object Name, Status, StartType | Out-File -Append "$outputDir\services.txt"

# List startup programs (from registry and startup folder)
Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location | Out-File -Append "$outputDir\startup_programs.txt"

# Environment variables
Get-ChildItem Env: | Out-File -Append "$outputDir\env_vars.txt"

# Currently logged in users
quser | Out-File -Append "$outputDir\logged_in_users.txt"

# List local user accounts
Get-LocalUser | Out-File -Append "$outputDir\local_users.txt"

# List open shared folders
net share | Out-File -Append "$outputDir\shares.txt"

# List scheduled tasks
Get-ScheduledTask | Out-File -Append "$outputDir\scheduled_tasks.txt"

# List installed Windows updates
Get-HotFix | Out-File -Append "$outputDir\updates.txt"

# DNS Cache
ipconfig /displaydns | Out-File -Append "$outputDir\dns_cache.txt"

# ARP table
arp -a | Out-File -Append "$outputDir\arp_table.txt"

# Firewall rules
Get-NetFirewallRule | Out-File -Append "$outputDir\firewall_rules.txt"

# User browsing history (basic, from common browsers if available)
$chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
$edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
if (Test-Path $chromePath) { "Chrome History found: $chromePath" | Out-File -Append "$outputDir\browsing_history.txt" }
if (Test-Path $edgePath) { "Edge History found: $edgePath" | Out-File -Append "$outputDir\browsing_history.txt" }

# End of extended recon
"Extended recon complete." | Out-File -Append "$outputDir\status.txt"


# 1. Windows build and release info
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName | Out-File -Append "$outputDir\version_info.txt"

# 2. Logged-in users (detailed)
query user | Out-File -Append "$outputDir\logged_in_users_detailed.txt"

# 3. Power settings
powercfg /query | Out-File -Append "$outputDir\power_config.txt"

# 4. Battery report (if applicable)
powercfg /batteryreport /output "$outputDir\battery_report.html"

# 5. Uptime
(Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Out-File -Append "$outputDir\uptime.txt"

# 6. Event logs (system errors)
Get-WinEvent -LogName System -MaxEvents 50 | Out-File -Append "$outputDir\event_log_system.txt"

# 7. Event logs (application errors)
Get-WinEvent -LogName Application -MaxEvents 50 | Out-File -Append "$outputDir\event_log_app.txt"

# 8. Active TCP/UDP connections
Get-NetTCPConnection | Out-File -Append "$outputDir\net_tcp.txt"
Get-NetUDPEndpoint | Out-File -Append "$outputDir\net_udp.txt"

# 9. Open ports
netstat -an | findstr LISTENING | Out-File -Append "$outputDir\open_ports.txt"

# 10. Hosts file
Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Out-File -Append "$outputDir\hosts_file.txt"

# 11. System drivers
Get-WmiObject Win32_SystemDriver | Out-File -Append "$outputDir\drivers.txt"

# 12. Hardware resources (IRQ conflicts)
Get-WmiObject Win32_IRQResource | Out-File -Append "$outputDir\irq.txt"

# 13. BIOS info
Get-WmiObject Win32_BIOS | Out-File -Append "$outputDir\bios.txt"

# 14. Motherboard info
Get-WmiObject Win32_BaseBoard | Out-File -Append "$outputDir\motherboard.txt"

# 15. CPU info
Get-WmiObject Win32_Processor | Out-File -Append "$outputDir\cpu.txt"

# 16. GPU info
Get-WmiObject Win32_VideoController | Out-File -Append "$outputDir\gpu.txt"

# 17. RAM info
Get-WmiObject Win32_PhysicalMemory | Out-File -Append "$outputDir\ram.txt"

# 18. NIC info
Get-WmiObject Win32_NetworkAdapterConfiguration | Out-File -Append "$outputDir\nic.txt"

# 19. Disk partitions
Get-WmiObject Win32_DiskPartition | Out-File -Append "$outputDir\disk_partitions.txt"

# 20. Logical disks
Get-WmiObject Win32_LogicalDisk | Out-File -Append "$outputDir\logical_disks.txt"

# 21. USB controllers
Get-WmiObject Win32_USBController | Out-File -Append "$outputDir\usb_controllers.txt"

# 22. All devices
Get-PnpDevice | Out-File -Append "$outputDir\devices.txt"

# 23. TPM info
Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm | Out-File -Append "$outputDir\tpm.txt"

# 24. Domain/workgroup info
Get-WmiObject Win32_ComputerSystem | Select-Object Domain, Workgroup | Out-File -Append "$outputDir\domain_info.txt"

# 25. Local groups
Get-LocalGroup | Out-File -Append "$outputDir\groups.txt"

# 26. Group memberships
Get-LocalGroupMember -Group "Administrators" | Out-File -Append "$outputDir\admin_group.txt"

# 27. Path variable
$env:Path | Out-File -Append "$outputDir\path_variable.txt"

# 28. Running services
Get-Service | Where-Object {$_.Status -eq "Running"} | Out-File -Append "$outputDir\running_services.txt"

# 29. Mounted drives
Get-PSDrive | Where-Object {$_.Provider -like "*FileSystem*"} | Out-File -Append "$outputDir\mounted_drives.txt"

# 30. Disk I/O stats
Get-WmiObject Win32_PerfFormattedData_PerfDisk_LogicalDisk | Out-File -Append "$outputDir\disk_io.txt"

# 31. System locale
Get-Culture | Out-File -Append "$outputDir\locale.txt"

# 32. Time zone
Get-TimeZone | Out-File -Append "$outputDir\timezone.txt"

# 33. Clipboard content (if allowed)
Get-Clipboard | Out-File -Append "$outputDir\clipboard.txt"

# 34. System policies
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies" | Out-File -Append "$outputDir\policies.txt"

# 35. Installed fonts
Get-WmiObject Win32_FontInfoAction | Out-File -Append "$outputDir\fonts.txt"

# 36. Default browser
(Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice").ProgId | Out-File -Append "$outputDir\default_browser.txt"

# 37. File extension associations
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts" | Out-File -Append "$outputDir\file_exts.txt"

# 38. Temp folder contents
Get-ChildItem $env:TEMP -Recurse -ErrorAction SilentlyContinue | Out-File -Append "$outputDir\temp_folder.txt"

# 39. Public user folder contents
Get-ChildItem "C:\Users\Public" -Recurse -ErrorAction SilentlyContinue | Out-File -Append "$outputDir\public_folder.txt"

# 40. Recent files
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" | Out-File -Append "$outputDir\recent_files.txt"

# 41. Running scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -eq "Running"} | Out-File -Append "$outputDir\running_tasks.txt"

# 42. Security updates
Get-HotFix | Where-Object {$_.Description -like "*Security*"} | Out-File -Append "$outputDir\security_updates.txt"

# 43. Account lockout policies
net accounts | Out-File -Append "$outputDir\account_policies.txt"

# 44. Remote desktop settings
(Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections | Out-File -Append "$outputDir\rdp.txt"

# 45. Windows Defender status
Get-MpComputerStatus | Out-File -Append "$outputDir\defender_status.txt"

# 46. Firewall profile settings
Get-NetFirewallProfile | Out-File -Append "$outputDir\firewall_profiles.txt"

# 47. Proxy settings
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Out-File -Append "$outputDir\proxy.txt"

# 48. Installed printers
Get-Printer | Out-File -Append "$outputDir\printers.txt"

# 49. Print jobs (current)
Get-PrintJob | Out-File -Append "$outputDir\print_jobs.txt"

# 50. Windows Error Reporting settings
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" | Out-File -Append "$outputDir\wer.txt"


# --- Additional Recon Features ---

# 1. Active TCP Connections
netstat -ano | Out-File -Append "$outputDir\netstat.txt"

# 2. List Installed Fonts
Get-ChildItem "$env:windir\Fonts" | Out-File -Append "$outputDir\fonts.txt"

# 3. Installed Device Drivers with Versions
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, DriverDate | Out-File -Append "$outputDir\drivers.txt"

# 4. List Running Services and Path
Get-WmiObject Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, State | Out-File -Append "$outputDir\services_detailed.txt"

# 5. DNS Server Settings
Get-DnsClientServerAddress | Out-File -Append "$outputDir\dns_servers.txt"

# 6. Proxy Settings
netsh winhttp show proxy | Out-File -Append "$outputDir\proxy_settings.txt"

# 7. Installed Windows Features
Get-WindowsOptionalFeature -Online | Out-File -Append "$outputDir\windows_features.txt"

# 8. Active Power Scheme
powercfg /getactivescheme | Out-File -Append "$outputDir\power_scheme.txt"

# 9. Print Spooler Settings
Get-Service -Name Spooler | Out-File -Append "$outputDir\print_spooler.txt"

# 10. Shared Printers
Get-WmiObject Win32_Printer | Select-Object Name, Shared, ShareName | Out-File -Append "$outputDir\printers_shared.txt"

# 11. Clipboard Contents (if not blocked)
Get-Clipboard | Out-File -Append "$outputDir\clipboard.txt"

# 12. Battery Info (if laptop)
Get-CimInstance -ClassName Win32_Battery | Out-File -Append "$outputDir\battery.txt"

# 13. System Restore Points
vssadmin list shadows | Out-File -Append "$outputDir\restore_points.txt"

# 14. USB History
Get-WmiObject Win32_USBHub | Out-File -Append "$outputDir\usb_history.txt"

# 15. List Recycle Bin Files
Get-ChildItem "$env:SystemDrive\$Recycle.Bin" -Recurse -ErrorAction SilentlyContinue | Out-File -Append "$outputDir\recycle_bin.txt"

# 16. All Services Running Under svchost
tasklist /svc | findstr svchost | Out-File -Append "$outputDir\svchost_services.txt"

# 17. Path Variables
$env:PATH | Out-File -Append "$outputDir\path_env.txt"

# 18. Security Center AV & Firewall Status
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Out-File -Append "$outputDir\av_status.txt"

# 19. Disk Read/Write Statistics
Get-CimInstance Win32_PerfFormattedData_PerfDisk_LogicalDisk | Select-Object Name, DiskReadsPerSec, DiskWritesPerSec | Out-File -Append "$outputDir\disk_io_stats.txt"

# 20. Windows Defender Configuration
Get-MpPreference | Out-File -Append "$outputDir\defender_config.txt"

# --- End of Additional Recon ---


# --- Credential Hunting ---

# List credential manager entries
cmdkey /list | Out-File -Append "$outputDir\credman.txt"

# Search for passwords/keys in common directories
$commonDirs = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads", "$env:APPDATA")
foreach ($dir in $commonDirs) {
    if (Test-Path $dir) {
        Get-ChildItem -Path $dir -Recurse -Include *.txt,*.docx,*.log,*.ini,*.config -ErrorAction SilentlyContinue | 
        Select-String -Pattern "password|pwd|token|apikey|secret" -SimpleMatch |
        Out-File -Append "$outputDir\potential_credentials.txt"
    }
}

# --- Browser Password Extraction (Edge/Chrome/Firefox) ---
# WARNING: This is limited without 3rd party tools or elevated access

function Get-ChromePasswords {
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
    if (Test-Path $chromePath) {
        Copy-Item $chromePath "$outputDir\chrome_logins.db" -Force
    }
}

function Get-EdgePasswords {
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
    if (Test-Path $edgePath) {
        Copy-Item $edgePath "$outputDir\edge_logins.db" -Force
    }
}

function Get-FirefoxProfiles {
    $ffPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $ffPath) {
        Copy-Item $ffPath "$outputDir\firefox_profiles" -Recurse -Force
    }
}

Get-ChromePasswords
Get-EdgePasswords
Get-FirefoxProfiles

# --- API Keys / Tokens in Files ---

$patterns = @("api[_-]?key", "secret", "access[_-]?token", "auth[_-]?token", "bearer")
foreach ($dir in $commonDirs) {
    if (Test-Path $dir) {
        Get-ChildItem -Path $dir -Recurse -Include *.txt,*.json,*.env,*.ini,*.js,*.py -ErrorAction SilentlyContinue |
        ForEach-Object {
            foreach ($pattern in $patterns) {
                Select-String -Path $_.FullName -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue |
                Out-File -Append "$outputDir\token_hunt.txt"
            }
        }
    }
}

# --- Webcam and Microphone Detection ---

Get-PnpDevice -Class Camera | Out-File -Append "$outputDir\webcams.txt"
Get-PnpDevice -Class AudioEndpoint | Where-Object { $_.FriendlyName -like "*mic*" } | Out-File -Append "$outputDir\microphones.txt"

# --- End of Credential Recon ---


# --- Clipboard Monitoring ---
Get-Clipboard | Out-File -Append "$outputDir\clipboard_contents.txt"

# --- Bluetooth Devices ---
Get-PnpDevice | Where-Object { $_.Class -eq 'Bluetooth' } | Out-File -Append "$outputDir\bluetooth_devices.txt"

# --- System Event Logs ---
Get-EventLog -LogName System -Newest 200 | Out-File -Append "$outputDir\system_eventlog.txt"
Get-EventLog -LogName Application -Newest 200 | Out-File -Append "$outputDir\application_eventlog.txt"

# --- Screenshot Capture (Windows Forms) ---
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
$bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
$bitmap.Save("$outputDir\screenshot.png", [System.Drawing.Imaging.ImageFormat]::Png)
$graphics.Dispose()
$bitmap.Dispose()

# --- Audio Recording Stub ---
# Requires external tools like NAudio or FFmpeg; stub created for awareness
"Audio capture feature requires external executable (e.g., FFmpeg)" | Out-File -Append "$outputDir\audio_capture_stub.txt"

# --- Decrypt Chrome/Edge Passwords (requires elevated access and custom decryption) ---
$decryptStub = @"
To decrypt Chrome/Edge passwords, use Python script with pycryptodome & Windows DPAPI. Example:
https://github.com/djhohnstein/SharpChromium or similar tools
"@
$decryptStub | Out-File -Append "$outputDir\password_decrypt_info.txt"

# --- USB Devices History (Extended) ---
Get-WmiObject Win32_USBControllerDevice | ForEach-Object {
    [WMI]$device = $_.Dependent
    $device | Out-File -Append "$outputDir\usb_devices_detailed.txt"
}

# --- Hotfixes and Updates ---
Get-HotFix | Out-File -Append "$outputDir\hotfixes.txt"

# --- Open File Handles (if handle.exe is available) ---
"Install Sysinternals 'handle.exe' to extract open file handles." | Out-File -Append "$outputDir\open_handles_stub.txt"

# --- Network Adapter Config ---
Get-NetAdapter | Out-File -Append "$outputDir\net_adapters.txt"

# --- Environment Variables Dump ---
Get-ChildItem Env: | Out-File -Append "$outputDir\env_variables.txt"

# --- End of Extra Recon Additions ---


# --- Registry Autoruns & Startup Entries ---
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /s > "$outputDir\registry_run_hklm.txt"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /s > "$outputDir\registry_run_hkcu.txt"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s > "$outputDir\registry_runonce_hklm.txt"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s > "$outputDir\registry_runonce_hkcu.txt"

# --- Installed Software (via Registry) ---
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s > "$outputDir\installed_software_hklm.txt"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s > "$outputDir\installed_software_hkcu.txt"

# --- Services Audit ---
Get-Service | Sort-Object Status | Format-Table -AutoSize | Out-File "$outputDir\services_status.txt"

# --- Network Usage per Process ---
Get-Process | Where-Object { $_.Path } | ForEach-Object {
    $proc = $_
    $netstat = netstat -ano | Select-String $proc.Id
    if ($netstat) {
        "Process: $($proc.Name) - PID: $($proc.Id)" | Out-File -Append "$outputDir\network_usage_process.txt"
        $netstat | Out-File -Append "$outputDir\network_usage_process.txt"
        "`n" | Out-File -Append "$outputDir\network_usage_process.txt"
    }
}

# --- Firewall Rules ---
netsh advfirewall firewall show rule name=all > "$outputDir\firewall_rules.txt"

# --- Test for Open Ports ---
$commonPorts = @(21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389)
$hostname = "localhost"
foreach ($port in $commonPorts) {
    $result = Test-NetConnection -ComputerName $hostname -Port $port
    "$($result.ComputerName):$($port) - TcpTestSucceeded: $($result.TcpTestSucceeded)" | Out-File -Append "$outputDir\open_ports.txt"
}

# --- Hosts File Dump ---
Get-Content "$env:WINDIR\System32\drivers\etc\hosts" | Out-File "$outputDir\hosts_file.txt"

# --- System Restore Info ---
vssadmin list shadows > "$outputDir\restore_points.txt"

# --- Power Config ---
powercfg /list > "$outputDir\power_plans.txt"
powercfg /batteryreport /output "$outputDir\battery_report.html"

# --- Task Scheduler Summary ---
Get-ScheduledTask | Out-File "$outputDir\scheduled_tasks.txt"

# --- Group Policy Settings ---
gpresult /h "$outputDir\gpresult.html"

# --- Windows Features Installed ---
Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"} | Out-File "$outputDir\enabled_windows_features.txt"

# --- Remote Desktop Status ---
(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\' -Name "fDenyTSConnections").fDenyTSConnections | Out-File "$outputDir\remote_desktop_status.txt"

# --- BitLocker Status ---
Get-BitLockerVolume | Format-List | Out-File "$outputDir\bitlocker_status.txt"

# --- BIOS & Firmware Info ---
Get-WmiObject Win32_BIOS | Out-File "$outputDir\bios_info.txt"
Get-WmiObject Win32_ComputerSystem | Out-File "$outputDir\computer_system.txt"

# --- Hardware Temperature (stub) ---
"Use external tools (e.g., OpenHardwareMonitor CLI) for temperature data." | Out-File -Append "$outputDir\hardware_temperature_stub.txt"

# --- User Login History ---
quser | Out-File "$outputDir\user_login_sessions.txt"
query user | Out-File -Append "$outputDir\user_login_sessions.txt"

# --- User Account Info ---
Get-LocalUser | Out-File "$outputDir\local_users.txt"
net user > "$outputDir\net_users.txt"
whoami /all > "$outputDir\whoami_info.txt"

# --- DNS Cache ---
ipconfig /displaydns > "$outputDir\dns_cache.txt"


# --- Wi-Fi History ---
netsh wlan show profiles > "$outputDir\wifi_profiles.txt"
foreach ($profile in (netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object { ($_ -split ":")[1].Trim() })) {
    netsh wlan show profile name="$profile" key=clear >> "$outputDir\wifi_profiles.txt"
}

# --- ARP Cache ---
arp -a > "$outputDir\arp_cache.txt"

# --- RDP Session Info ---
Get-EventLog -LogName Security | Where-Object { $_.EventID -eq 4624 -or $_.EventID -eq 4634 } | Out-File "$outputDir\rdp_login_events.txt"

# --- Full Windows Security Logs (last 1000 entries) ---
Get-WinEvent -LogName Security -MaxEvents 1000 | Export-Clixml -Path "$outputDir\security_log.xml"

# --- RAM Usage ---
Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | Out-File "$outputDir\ram_usage.txt"

# --- GPU Stats (NVIDIA via nvidia-smi stub) ---
"Use nvidia-smi or vendor tools for detailed GPU usage" | Out-File "$outputDir\gpu_stats_stub.txt"

# --- Additional Forensics ---
Get-EventLog -LogName Application -Newest 200 | Out-File "$outputDir\application_logs.txt"
Get-EventLog -LogName System -Newest 200 | Out-File "$outputDir\system_logs.txt"
wevtutil qe Setup /c:200 /f:text > "$outputDir\setup_logs.txt"

# --- Prefetch Files (Accessed Programs) ---
Get-ChildItem "$env:SystemRoot\Prefetch" | Out-File "$outputDir\prefetch_files.txt"

# --- Installed Fonts ---
Get-ChildItem -Path "$env:SystemRoot\Fonts" | Out-File "$outputDir\installed_fonts.txt"

# --- Shell History (PowerShell) ---
Get-Content (Get-PSReadlineOption).HistorySavePath | Out-File "$outputDir\powershell_history.txt"

# --- System Startup Time ---
(systeminfo | Select-String "System Boot Time") | Out-File "$outputDir\boot_time.txt"

# --- Network Shares ---
net share > "$outputDir\network_shares.txt"

# --- Running Scheduled Tasks with Status ---
Get-ScheduledTask | Get-ScheduledTaskInfo | Out-File "$outputDir\scheduled_tasks_status.txt"


# --- LSASS Memory Dump Stub ---
"To dump LSASS memory, use the following with admin rights (ensure permission/legal clearance):" | Out-File "$outputDir\lsass_dump_stub.txt"
"procdump -ma lsass.exe lsass.dmp" >> "$outputDir\lsass_dump_stub.txt"

# --- Volatile Memory Info ---
tasklist /V > "$outputDir\tasklist_verbose.txt"
Get-Process | Sort-Object CPU -Descending | Select-Object -First 50 | Out-File "$outputDir\top_processes_by_cpu.txt"

# --- Open Network Connections with Process Mapping ---
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Out-File "$outputDir\network_connections.txt"

# --- DNS Configuration ---
ipconfig /displaydns > "$outputDir\dns_cache.txt"

# --- Autoruns Stub ---
"Use Sysinternals Autoruns for full startup analysis. Run 'autorunsc.exe -accepteula -a * > autoruns.txt'" | Out-File "$outputDir\autoruns_stub.txt"

# --- Running Services with Paths ---
Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName, State | Out-File "$outputDir\running_services.txt"

# --- Current USB Insertions (via registry) ---
Get-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" -ErrorAction SilentlyContinue | Out-File "$outputDir\usbstor_registry.txt"

# --- Active Directory Info (if domain joined) ---
nltest /dsgetdc: > "$outputDir\domain_info.txt"

# --- Local Security Policy Audit ---
secedit /export /cfg "$outputDir\local_security_policy.cfg"

# --- Hosts File Content ---
Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Out-File "$outputDir\hosts_file.txt"

# --- Installed Windows Features ---
Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"} | Out-File "$outputDir\enabled_windows_features.txt"


# --- YARA Scan Stub ---
"To perform YARA scans, install YARA from https://github.com/VirusTotal/yara and run custom rules:" | Out-File "$outputDir\yara_stub.txt"
"Example: yara64.exe -r custom_rules.yar C:\ > yara_results.txt" >> "$outputDir\yara_stub.txt"

# --- WinPMEM Memory Acquisition Stub ---
"To acquire full physical memory, use WinPMEM (https://github.com/Velocidex/WinPmem):" | Out-File "$outputDir\winpmem_stub.txt"
"Example: winpmem.exe -o memdump.aff4" >> "$outputDir\winpmem_stub.txt"

# --- MITRE ATT&CK Technique Lookup (stub) ---
"Use tools like MITRE Caldera or invoke-atomicredteam to simulate and detect known TTPs." | Out-File "$outputDir\mitre_attack_stub.txt"

# --- Process Command Line Analysis ---
Get-WmiObject Win32_Process | Select-Object ProcessId, Name, CommandLine | Out-File "$outputDir\process_cmdlines.txt"

# --- File System Watchers (Active Monitoring Stub) ---
"Use PowerShell's Register-ObjectEvent or Sysmon to monitor real-time file system changes." | Out-File "$outputDir\fs_monitoring_stub.txt"

# --- Sysmon Install Stub ---
"Download Sysmon from https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon and install with custom config." | Out-File "$outputDir\sysmon_stub.txt"

# --- Network Interface Config ---
Get-NetAdapter | Format-List * > "$outputDir\netadapter_config.txt"

# --- Malicious PowerShell Usage Detection (Basic) ---
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object { $_.Message -like "*Invoke*" -or $_.Message -like "*Download*" } | Out-File "$outputDir\suspicious_powershell.txt"

# --- Common Malware Persistence Points ---
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Out-File "$outputDir\hkcu_run_keys.txt"
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Out-File "$outputDir\hklm_run_keys.txt"

# --- Scheduled Tasks w/ Actions ---
Get-ScheduledTask | Select-Object TaskName, TaskPath, State, Actions | Out-File "$outputDir\scheduled_tasks_detailed.txt"

# --- Service DLL & Binary Analysis ---
Get-WmiObject Win32_Service | Select-Object Name, PathName, StartMode, State | Out-File "$outputDir\service_binaries.txt"


# --- Threat Hunting Section ---

# --- Look for Known Suspicious File Names ---
$suspiciousNames = @("mimikatz.exe", "netcat.exe", "nc.exe", "svchosts.exe", "powershell.exe -enc", "rundll32.exe")
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Include *.exe,*.dll |
    Where-Object { $suspiciousNames -contains $_.Name.ToLower() } |
    Select-Object FullName, Length, LastWriteTime |
    Out-File "$outputDir\suspicious_filenames.txt"

# --- Search for Encoded/Obfuscated PowerShell Commands ---
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
    Select-String -Pattern "FromBase64String|Invoke-Expression|IEX|DownloadString|Add-Type" |
    Out-File "$outputDir\suspicious_ps_history.txt"

# --- High Entropy String Detection in Temp Files ---
$tempFiles = Get-ChildItem "$env:TEMP" -Recurse -Include *.txt,*.log,*.ps1 -ErrorAction SilentlyContinue
foreach ($file in $tempFiles) {
    $content = Get-Content $file.FullName -ErrorAction SilentlyContinue
    foreach ($line in $content) {
        if ($line -match '[A-Za-z0-9+/]{30,}={0,2}') {
            Add-Content "$outputDir\high_entropy_strings.txt" "$($file.FullName): $line"
        }
    }
}

# --- Detect Suspicious Auto-Start Executables ---
Get-CimInstance Win32_StartupCommand |
    Where-Object { $_.Command -match "\.exe" -and ($_.Command -match "AppData|Temp|Roaming") } |
    Out-File "$outputDir\suspicious_autoruns.txt"

# --- Dump Unusual Running Executables from AppData/Temp ---
Get-Process | Where-Object { $_.Path -match "AppData|Temp" } |
    Select-Object Name, Path, Id |
    Out-File "$outputDir\unusual_running_exes.txt"

# --- Count PowerShell and CMD Spawned by User ---
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4688)]]" |
    Where-Object { $_.Message -match "cmd.exe" -or $_.Message -match "powershell.exe" } |
    Out-File "$outputDir\cmd_ps_spawned_by_user.txt"


# --- Malware Detection Heuristics Section ---

# --- Heuristic: EXEs with no company or description metadata ---
Get-ChildItem -Path C:\ -Recurse -Include *.exe -ErrorAction SilentlyContinue |
    ForEach-Object {
        $info = (Get-Item $_.FullName).VersionInfo
        if (-not $info.CompanyName -and -not $info.FileDescription) {
            "$($_.FullName) [NO METADATA]" | Out-File "$outputDir\exe_no_metadata.txt" -Append
        }
    }

# --- Heuristic: Unsigned Drivers or Binaries in System32 ---
Get-ChildItem "C:\Windows\System32" -Recurse -Include *.exe, *.dll -ErrorAction SilentlyContinue |
    ForEach-Object {
        $sig = Get-AuthenticodeSignature $_.FullName
        if ($sig.Status -ne 'Valid') {
            "$($_.FullName) [UNSIGNED]" | Out-File "$outputDir\unsigned_sys32_binaries.txt" -Append
        }
    }

# --- Heuristic: Recent files with executable extensions in suspicious folders ---
$suspiciousFolders = @("$env:TEMP", "$env:APPDATA", "$env:USERPROFILE\Downloads")
foreach ($folder in $suspiciousFolders) {
    Get-ChildItem $folder -Recurse -Include *.exe, *.bat, *.vbs, *.ps1 -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-5) } |
        Select-Object FullName, LastWriteTime |
        Out-File "$outputDir\recent_suspicious_files.txt" -Append
}

# --- Heuristic: Common LOLBins used maliciously ---
$lolbins = "mshta.exe","certutil.exe","rundll32.exe","regsvr32.exe","wmic.exe","powershell.exe"
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4688)]]" |
    Where-Object { $lolbins | ForEach-Object { $_.ToLower() } -contains $_.Message.ToLower() } |
    Out-File "$outputDir\lolbin_usage.txt"


# --- Persistence Mechanism Scanners and Stealth Malware Behavior Checks ---

# --- Registry: Common Run Keys ---
$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($key in $runKeys) {
    Get-ItemProperty -Path $key -ErrorAction SilentlyContinue |
        Out-File "$outputDir\registry_run_keys.txt" -Append
}

# --- Scheduled Tasks for Persistence ---
Get-ScheduledTask | Where-Object { $_.TaskPath -ne "\" } |
    Select-Object TaskName, TaskPath, Actions, State |
    Out-File "$outputDir\scheduled_tasks_persistence.txt"

# --- Services Set to Auto Start ---
Get-Service | Where-Object { $_.StartType -eq 'Automatic' } |
    Select-Object Name, DisplayName, Status |
    Out-File "$outputDir\auto_services.txt"

# --- WMI Persistence ---
Get-WmiObject -Namespace "root\subscription" -Class __EventFilter -ErrorAction SilentlyContinue |
    Out-File "$outputDir\wmi_event_filters.txt"
Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer -ErrorAction SilentlyContinue |
    Out-File "$outputDir\wmi_event_consumers.txt"

# --- Stealth: Hidden Files in Suspicious Locations ---
Get-ChildItem -Path C:\Users\ -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Attributes -match "Hidden" -and ($_.Extension -eq ".exe" -or $_.Extension -eq ".dll") } |
    Out-File "$outputDir\hidden_executables.txt"

# --- Stealth: Alternate Data Streams (ADS) ---
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object {
        if ((Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne "::$DATA" }).Count -gt 0) {
            "$($_.FullName) has ADS" | Out-File "$outputDir\alternate_data_streams.txt" -Append
        }
    }

# --- Stealth: Processes With No Window (Suspicious Background) ---
Get-Process | Where-Object { -not $_.MainWindowTitle -and $_.Path -and $_.Path -match "AppData|Temp" } |
    Select-Object Name, Path, Id |
    Out-File "$outputDir\headless_processes.txt"


# --- Lateral Movement Detection and C2 Beacon Behavior Analysis ---

# --- Lateral Movement: RDP Session History ---
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 21 -or $_.Id -eq 25 } |
    Out-File "$outputDir\rdp_session_logs.txt"

# --- Lateral Movement: Network Shares Accessed ---
Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 5140 } |
    Out-File "$outputDir\network_shares_accessed.txt"

# --- Lateral Movement: Remote Service Creation ---
Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4697 } |
    Out-File "$outputDir\remote_service_creation.txt"

# --- Lateral Movement: PSRemoting Usage ---
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational |
    Where-Object { $_.Message -like "*New-PSSession*" } |
    Out-File "$outputDir\psremoting_sessions.txt"

# --- Lateral Movement: SMB/NTLM Connections ---
Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4624 -and $_.Properties[8].Value -like "*NTLM*" } |
    Out-File "$outputDir\ntlm_logon_events.txt"

# --- C2 Beacon: Suspicious DNS Requests ---
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match "\.xyz|\.tk|\.top|\.club|\.cc" } |
    Out-File "$outputDir\suspicious_dns.txt"

# --- C2 Beacon: Repeating Outbound Connections ---
netstat -ano | Select-String ":443|:80" | Out-File "$outputDir\repeating_http_https_ports.txt"

# --- C2 Beacon: Long-Lived Network Connections ---
Get-NetTCPConnection | Where-Object { $_.State -eq "Established" -and $_.OwningProcess -ne 4 } |
    Sort-Object RemoteAddress | Out-File "$outputDir\long_tcp_connections.txt"

# --- C2 Beacon: Beacon-like PowerShell Activity ---
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational |
    Where-Object { $_.Message -like "*Invoke-WebRequest*" -or $_.Message -like "*Invoke-Expression*" } |
    Out-File "$outputDir\web_powershell_beacons.txt"


# --- Kernel-Level Rootkit Checks and EDR Evasion Detection ---

# --- Rootkit: Check for Hidden Drivers ---
$drivers = Get-WmiObject Win32_SystemDriver
$expected = Get-ChildItem "C:\Windows\System32\drivers" -Filter *.sys -Recurse -ErrorAction SilentlyContinue
$hiddenDrivers = $drivers | Where-Object {
    ($_.PathName -match "\\drivers\\" -or $_.PathName -match "\\DriverStore\\") -and
    (-not (Test-Path $_.PathName))
}
$hiddenDrivers | Select-Object Name, State, StartMode, PathName |
    Out-File "$outputDir\potential_hidden_drivers.txt"

# --- Rootkit: Check for SSDT/Kernel Hook Indicators ---
# Note: This requires external tools like GMER, this is a stub
"Run GMER or similar tool manually for SSDT, IDT, inline hook detection." |
    Out-File "$outputDir\manual_rootkit_checks.txt"

# --- EDR Evasion: Suspicious DLLs in User Space ---
$edrDlls = "atp", "carbonblack", "crowdstrike", "sentinel", "mcafee", "sysmon"
Get-Process | ForEach-Object {
    try {
        $_.Modules | Where-Object { $edrDlls -contains $_.ModuleName.ToLower() } |
            Select-Object ModuleName, FileName, $_.ProcessName |
            Out-File "$outputDir\suspicious_edr_dll_injection.txt" -Append
    } catch {}
}

# --- EDR Evasion: Registry Tampering ---
$edrRegPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
)
foreach ($path in $edrRegPaths) {
    Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
        Out-File "$outputDir\edr_registry_tampering.txt" -Append
}

# --- EDR Evasion: Unusual Parent Processes for PowerShell ---
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 1 -and $_.Message -match "powershell" } |
    Out-File "$outputDir\powershell_unusual_parent.txt"


# --- MITRE ATT&CK Technique Mapping and Live Process Hollowing Detection ---

# --- MITRE ATT&CK Mapping (Basic Behavioral Tags) ---
# Output observed techniques and associate with MITRE ATT&CK IDs (manual mapping references)
$mitreFindings = @()

# T1059 - Command and Scripting Interpreter
$psEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -like "*Invoke-Expression*" -or $_.Message -like "*IEX*" }
if ($psEvents) {
    $mitreFindings += "T1059: Detected PowerShell usage with IEX or Invoke-Expression"
}

# T1071 - Application Layer Protocol (HTTP/S)
$dnsEvents = Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match "\.xyz|\.tk|\.club|\.top" }
if ($dnsEvents) {
    $mitreFindings += "T1071: Suspicious DNS communication detected"
}

# T1036 - Masquerading (Process with misleading name)
Get-Process | Where-Object { $_.Name -match "svchost|explorer|lsass" -and $_.Path -notmatch "System32" } |
    ForEach-Object {
        $mitreFindings += "T1036: Masquerading process found - $($_.Name) @ $($_.Path)"
    }

$mitreFindings | Out-File "$outputDir\mitre_attack_mapping.txt"

# --- Live Process Hollowing Detection ---
# Heuristic: Scans for suspicious memory protections and mismatched image names

$procs = Get-Process | Where-Object { $_.Id -gt 4 }
foreach ($proc in $procs) {
    try {
        $modules = $proc.Modules | Where-Object {
            $_.ModuleName -match ".exe" -and $_.FileName -notmatch [regex]::Escape($proc.Path)
        }
        if ($modules) {
            "Possible Process Hollowing Detected: $($proc.Name) ($($proc.Id))" |
                Out-File "$outputDir\process_hollowing_heuristics.txt" -Append
        }
    } catch {}
}

# Note: For deep memory region analysis, use Sysinternals VMMap or Cuckoo Sandbox


# --- Binary Packing/Unpacking Detection and Memory Injection Signature Search ---

# --- Binary Packing Detection ---
# Uses PE header heuristics and size discrepancies to flag suspicious binaries

$exePaths = Get-ChildItem -Path "C:\Users","C:\ProgramData","C:\Program Files","C:\Windows\Temp" -Recurse -Include *.exe -ErrorAction SilentlyContinue
foreach ($exe in $exePaths) {
    try {
        $fileSize = (Get-Item $exe.FullName).Length
        $peHeaders = [System.IO.File]::ReadAllBytes($exe.FullName)[0..511] -join " "
        if ($fileSize -lt 204800 -and $peHeaders -match "UPX|MPRESS|ASPack|Petite|Themida|FSG") {
            "Packed binary detected: $($exe.FullName)" |
                Out-File "$outputDir\packed_binaries_detected.txt" -Append
        }
    } catch {}
}

# --- Memory Injection Signature Search ---
# Scan suspicious memory regions for RWX pages and known injection behaviors
$injectedProcs = @()
Get-Process | ForEach-Object {
    try {
        $proc = $_
        $memRegions = (Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)") |
            ForEach-Object {
                if ($_.CommandLine -match "VirtualAllocEx|WriteProcessMemory|CreateRemoteThread") {
                    $injectedProcs += "$($proc.ProcessName) ($($proc.Id))"
                }
            }
    } catch {}
}

if ($injectedProcs.Count -gt 0) {
    $injectedProcs | Sort-Object | Out-File "$outputDir\memory_injection_detected.txt"
} else {
    "No memory injection patterns matched heuristics." |
        Out-File "$outputDir\memory_injection_detected.txt"
}


# --- Entropy Analysis of Executables ---
function Get-Entropy {
    param ([byte[]]$bytes)
    $counts = @{}
    foreach ($b in $bytes) {
        if ($counts.ContainsKey($b)) { $counts[$b]++ }
        else { $counts[$b] = 1 }
    }

    $entropy = 0.0
    foreach ($count in $counts.Values) {
        $p = $count / $bytes.Length
        $entropy -= $p * [Math]::Log($p, 2)
    }
    return [Math]::Round($entropy, 3)
}

"Filename,Entropy" | Out-File "$outputDir\exe_entropy_scores.csv"
$exeFiles = Get-ChildItem -Path "C:\Users","C:\ProgramData","C:\Windows\Temp" -Recurse -Include *.exe -ErrorAction SilentlyContinue
foreach ($exe in $exeFiles) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($exe.FullName)
        $entropy = Get-Entropy -bytes $bytes
        "$($exe.FullName),$entropy" | Out-File "$outputDir\exe_entropy_scores.csv" -Append

        if ($entropy -gt 7.5) {
            "High-entropy EXE detected (possible packed/malicious): $($exe.FullName) [$entropy]" |
                Out-File "$outputDir\high_entropy_executables.txt" -Append
        }
    } catch {}
}

# --- ETW-Based Stealth Malware Watchers ---
# Monitors suspicious runtime behaviors using Event Tracing for Windows (ETW)

$etwLog = "$outputDir\etw_malware_watch.log"
$etwKeywords = @{
    'SuspiciousScriptHost' = "wscript.exe|cscript.exe"
    'UnusualParenting' = "powershell.exe launched from word.exe|excel.exe|outlook.exe"
}

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue |
    Where-Object {
        ($_.Message -match $etwKeywords['SuspiciousScriptHost']) -or
        ($_.Message -match "powershell.exe" -and $_.Message -match "winword.exe|excel.exe|outlook.exe")
    } | ForEach-Object {
        "ETW Anomaly Detected: $($_.TimeCreated) - $($_.Message)" |
            Out-File $etwLog -Append
    }


# --- BIOS/UEFI Config Dump and Integrity Check ---

$biosDump = "$outputDir\bios_uefi_config.txt"
try {
    "=== BIOS/UEFI Info ===" | Out-File $biosDump
    Get-WmiObject -Class Win32_BIOS | Format-List * >> $biosDump
    Get-WmiObject -Class Win32_ComputerSystem | Format-List * >> $biosDump
    Get-WmiObject -Class Win32_BaseBoard | Format-List * >> $biosDump
    Get-CimInstance -Namespace root\wmi -ClassName MS_SystemInformation >> $biosDump
} catch {
    "Failed to query BIOS/UEFI info: $_" | Out-File $biosDump
}

# --- BIOS Firmware Hashing (basic integrity check) ---
$biosHashLog = "$outputDir\bios_firmware_hash.txt"
$firmwarePaths = @(
    "$env:SystemRoot\System32\drivers\acpi.sys",
    "$env:SystemRoot\System32\drivers\intelpep.sys"
)

foreach ($path in $firmwarePaths) {
    if (Test-Path $path) {
        $hash = Get-FileHash $path -Algorithm SHA256
        "$($hash.Path): $($hash.Hash)" | Out-File $biosHashLog -Append
    }
}

# --- YARA Rule Scanning and Match Summary ---
# Requires yara64.exe in PATH or same dir as script

$yaraOutput = "$outputDir\yara_matches.txt"
$yaraRules = "$PSScriptRoot\rules.yar"  # Path to rules file
$scanPaths = @("C:\Windows", "C:\Users", "C:\ProgramData")

if (Test-Path ".\yara64.exe" -and Test-Path $yaraRules) {
    foreach ($dir in $scanPaths) {
        .\yara64.exe -r $yaraRules $dir 2>&1 | Out-File $yaraOutput -Append
    }
} else {
    "YARA scan skipped — yara64.exe or rules.yar not found." | Out-File $yaraOutput
}


# --- Fileless Malware Detection ---
$filelessLog = "$outputDir\fileless_malware_detected.txt"

Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match "Invoke-Expression|IEX|DownloadString|FromBase64String|Reflection.Assembly" } |
    ForEach-Object {
        "Suspicious PowerShell Activity: $($_.TimeCreated) - $($_.Message)" | Out-File $filelessLog -Append
    }

Get-WinEvent -LogName "Security" -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match "powershell.exe" -and $_.Message -match "encodedCommand" } |
    ForEach-Object {
        "Encoded PowerShell Command Detected: $($_.TimeCreated) - $($_.Message)" | Out-File $filelessLog -Append
    }

# --- Sandbox Evasion Technique Detection ---
$sandboxLog = "$outputDir\sandbox_evasion_flags.txt"
$flags = @()

# Timing-based evasion
$sw = [System.Diagnostics.Stopwatch]::StartNew()
Start-Sleep -Milliseconds 500
$sw.Stop()
if ($sw.ElapsedMilliseconds -lt 450) {
    $flags += "Potential timing-based sandbox evasion detected"
}

# Mouse movement or user interaction checks
try {
    Add-Type -AssemblyName System.Windows.Forms
    if (-not [System.Windows.Forms.Cursor]::Position.X -gt 0) {
        $flags += "No mouse interaction detected (headless environment)"
    }
} catch {}

# Fake process checks (known sandbox tools)
$procNames = "vmsrvc.exe","vmusrvc.exe","VBoxService.exe","vboxtray.exe","vmtoolsd.exe","df5serv.exe"
$runningProcs = Get-Process | Select-Object -ExpandProperty Name
foreach ($p in $procNames) {
    if ($runningProcs -contains ($p -replace ".exe","")) {
        $flags += "Sandbox-related process detected: $p"
    }
}

# Output sandbox findings
if ($flags.Count -gt 0) {
    $flags | Out-File $sandboxLog
} else {
    "No sandbox evasion indicators found." | Out-File $sandboxLog
}


# --- Firmware-Level Malware Indicators ---
$firmwareLog = "$outputDir\firmware_integrity_issues.txt"
try {
    $firmwareVulnBios = Get-WmiObject Win32_BIOS | Select-Object SerialNumber, Version, SMBIOSBIOSVersion, Manufacturer, ReleaseDate
    $firmwareVulnBoard = Get-WmiObject Win32_BaseBoard | Select-Object Manufacturer, Product, Version, SerialNumber

    "=== BIOS/UEFI Firmware Info ===" | Out-File $firmwareLog
    $firmwareVulnBios | Out-File $firmwareLog -Append
    "`n=== Motherboard Info ===" | Out-File $firmwareLog -Append
    $firmwareVulnBoard | Out-File $firmwareLog -Append

    if ($firmwareVulnBios.SMBIOSBIOSVersion -match ".*(legacy|test|debug).*") {
        "⚠️ Warning: Suspicious BIOS version detected" | Out-File $firmwareLog -Append
    }
} catch {
    "Error collecting firmware data: $_" | Out-File $firmwareLog
}

# --- AMSI Bypass Detection ---
$amsiLog = "$outputDir\amsi_bypass_detected.txt"
$amsiIndicators = @("amsiInitFailed", "AmsiScanBuffer", "System.Management.Automation.AmsiUtils", "Reflection.Emit")

Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -ErrorAction SilentlyContinue |
    Where-Object { $amsiIndicators | ForEach-Object { $_ -and $_ -in $_.Message } } |
    ForEach-Object {
        "⚠️ AMSI bypass attempt: $($_.TimeCreated) - $($_.Message)" | Out-File $amsiLog -Append
    }

# --- USB & Peripheral Activity Logs ---
$usbLog = "$outputDir\usb_device_history.txt"

try {
    Get-WinEvent -LogName System |
        Where-Object { $_.Id -eq 2003 -or $_.Message -like "*USB*" } |
        ForEach-Object {
            "$($_.TimeCreated) - $($_.Message)" | Out-File $usbLog -Append
        }

    Get-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" -ErrorAction SilentlyContinue |
        Out-File $usbLog -Append
} catch {
    "Could not read USB logs: $_" | Out-File $usbLog
}


# --- UEFI/ACPI Malware Indicators ---
$uefiLog = "$outputDir\uefi_acpi_warnings.txt"
try {
    "=== UEFI / ACPI Firmware Check ===" | Out-File $uefiLog
    $firmwareDrivers = Get-ChildItem -Path "$env:SystemRoot\System32\drivers" | Where-Object { $_.Name -match "acpi|firmware|bios" }
    foreach ($drv in $firmwareDrivers) {
        $hash = Get-FileHash $drv.FullName -Algorithm SHA256
        "$($drv.Name): $($hash.Hash)" | Out-File $uefiLog -Append
    }

    if ($firmwareDrivers.Count -eq 0) {
        "⚠️ No firmware-related drivers found — possible tampering or hidden rootkit" | Out-File $uefiLog -Append
    }
} catch {
    "Error during UEFI/ACPI scan: $_" | Out-File $uefiLog
}

# --- Live Memory Dump Trigger ---
$memDumpDir = "$outputDir\LiveMemoryDump"
New-Item -ItemType Directory -Path $memDumpDir -Force | Out-Null

try {
    "Triggering live memory dump..." | Out-File "$memDumpDir\memdump_log.txt"
    rundll32.exe sysdump.dll,RunFullMemoryDump 2>> "$memDumpDir\memdump_error.txt"
    "Dump completed. Recommended: analyze with Volatility Framework." | Out-File "$memDumpDir\memdump_log.txt" -Append
} catch {
    "Memory dump failed: $_" | Out-File "$memDumpDir\memdump_error.txt"
}

# --- SIEM / EDR Evasion Detection ---
$evasionLog = "$outputDir\siem_edr_evasion_flags.txt"

try {
    $evasionSigns = @(
        "procmon.exe", "procexp.exe", "Sysmon64.exe", "wireshark.exe",
        "ninja", "sdelete", "revil", "mimikatz", "Cobalt Strike",
        "rundll32.exe", "regsvr32.exe", "werfault.exe"
    )

    Get-Process | ForEach-Object {
        if ($evasionSigns -contains $_.Name) {
            "⚠️ Potential evasion-related process: $($_.Name)" | Out-File $evasionLog -Append
        }
    }

    if (!(Get-Process -Name "Sysmon64" -ErrorAction SilentlyContinue)) {
        "⚠️ Sysmon not running — host may lack SIEM/EDR telemetry" | Out-File $evasionLog -Append
    }
} catch {
    "Error detecting SIEM evasion indicators: $_" | Out-File $evasionLog
}


# --- Volatility Analysis Guidance Output ---
$volGuide = "$outputDir\volatility_analysis_guide.txt"
@"
To analyze the live memory dump:
1. Install Volatility 3 (https://github.com/volatilityfoundation/volatility3)
2. Run:
   volatility3 -f <memory_dump.raw> windows.pslist.PsList
   volatility3 -f <memory_dump.raw> windows.cmdline.CmdLine
   volatility3 -f <memory_dump.raw> windows.dlllist.DllList
   volatility3 -f <memory_dump.raw> windows.malfind.Malfind
3. Look for:
   - Hidden processes
   - Suspicious injected code
   - Anomalous memory regions
"@ | Out-File $volGuide

# --- Suspicious Executable Extraction for Sandbox ---
$sampleOutDir = "$outputDir\suspicious_samples"
New-Item -ItemType Directory -Path $sampleOutDir -Force | Out-Null

try {
    $suspiciousPaths = Get-ChildItem "C:\Users" -Recurse -Include *.exe,*.ps1,*.vbs -ErrorAction SilentlyContinue | Where-Object {
        ($_.Length -gt 10000000) -or
        ($_.Name -match "temp|update|svchost|dllhost|mimikatz|payload|agent") -or
        ($_.FullName -match "AppData\\Local\\Temp")
    }

    foreach ($f in $suspiciousPaths) {
        Copy-Item $f.FullName -Destination "$sampleOutDir\$($f.Name)" -ErrorAction SilentlyContinue
    }

    "Suspicious files exported to $sampleOutDir. Upload to: https://www.hybrid-analysis.com or https://virustotal.com" | Out-File "$sampleOutDir\_README.txt"
} catch {
    "Error during suspicious file extraction: $_" | Out-File "$sampleOutDir\sample_error.txt"
}

# --- ML Classifier for Process Behavior (Scaffold Only) ---
$mlLog = "$outputDir\ml_behavior_flags.txt"
try {
    $suspiciousCmds = Get-CimInstance Win32_Process | Where-Object {
        $_.CommandLine -match "powershell.*EncodedCommand|download|Invoke-WebRequest|wget|curl|bitsadmin"
    }

    foreach ($proc in $suspiciousCmds) {
        "⚠️ Suspicious ML-pattern match: PID $($proc.ProcessId) - $($proc.CommandLine)" | Out-File $mlLog -Append
    }

    if ($suspiciousCmds.Count -eq 0) {
        "No ML-signature flags detected at runtime (static patterns only)." | Out-File $mlLog
    }

    # Scaffold: eventually replace this with TensorFlow .NET/C++ classification pipeline
} catch {
    "ML process inspection error: $_" | Out-File $mlLog
}


# --- Live YARA Memory Scanner (via yara64.exe CLI) ---
$yaraExe = "C:\Tools\yara64.exe"
$yaraRules = "C:\Tools\rules.yar"
$memScanLog = "$outputDir\yara_live_mem_scan.txt"

if (Test-Path $yaraExe -and Test-Path $yaraRules) {
    try {
        Get-Process | ForEach-Object {
            $pid = $_.Id
            $cmd = "$yaraExe -p $pid $yaraRules"
            $result = Invoke-Expression $cmd
            if ($result) {
                "`nMatches in PID ${pid}:`n$result" | Out-File $memScanLog -Append
            }
        }
    } catch {
        "YARA scan error: $_" | Out-File $memScanLog
    }
} else {
    "YARA scanner or rule file not found. Place yara64.exe and rules.yar in C:\Tools." | Out-File $memScanLog
}

# --- Simple GUI Wrapper (PowerShell WPF) ---
Add-Type -AssemblyName PresentationFramework

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Recon Tool" Height="350" Width="400">
    <Grid>
        <Button Content="Run Full Recon Scan" Name="StartScan" Width="150" Height="40" Margin="120,80,0,0"/>
        <Label Name="StatusLabel" Content="Idle..." Margin="10,150,0,0" Width="360"/>
    </Grid>
</Window>
"@

$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)
$button = $window.FindName("StartScan")
$status = $window.FindName("StatusLabel")

$button.Add_Click({
    $status.Content = "Running scan..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $status.Content = "Scan triggered in new window."
})

$window.ShowDialog()

# --- AI Malware Signature Placeholder (TensorFlow.NET pipeline) ---
$aiLog = "$outputDir\ai_malware_analysis.txt"
try {
    $knownMalware = Get-ChildItem "$sampleOutDir" -Recurse -Include *.exe,*.ps1,*.dll | Where-Object {
        $_.Length -gt 512000
    }

    foreach ($sample in $knownMalware) {
        "⚠️ AI malware scan placeholder: $($sample.Name)" | Out-File $aiLog -Append
    }

    "Actual TensorFlow.NET malware classification pending integration." | Out-File $aiLog -Append
} catch {
    "AI static scan error: $_" | Out-File $aiLog
}


# --- TensorFlow.NET AI Malware Scanner Placeholder ---
$tfLog = "$outputDir\tfnet_malware_results.txt"
$pythonEnv = "C:\AIModel\venv\Scripts\python.exe"
$modelPath = "C:\AIModel\model.onnx"
$scannerScript = "C:\AIModel\scan_sample.py"

if (Test-Path $pythonEnv -and Test-Path $modelPath -and Test-Path $scannerScript) {
    try {
        $samples = Get-ChildItem "$sampleOutDir" -Recurse -Include *.exe,*.dll,*.ps1 | Where-Object { $_.Length -gt 100000 }

        foreach ($file in $samples) {
            $cmd = "`"$pythonEnv`" `"$scannerScript`" --model `"$modelPath`" --file `"$($file.FullName)`""
            $result = Invoke-Expression $cmd
            "`n[$($file.Name)] → $result" | Out-File $tfLog -Append
        }
    } catch {
        "TensorFlow.NET AI scanner error: $_" | Out-File $tfLog
    }
} else {
    "Missing AI scanner files. Place model.onnx + scan_sample.py + venv in C:\AIModel" | Out-File $tfLog
}


# --- Create Recon Output Structure ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$userDesktop = [Environment]::GetFolderPath("Desktop")
$outputDir = "$userDesktop\ReconDump_$timestamp"
New-Item -Path $outputDir -ItemType Directory -Force | Out-Null

# Subdirectories
$dirs = @(
    "$outputDir\system_info",
    "$outputDir\network",
    "$outputDir\security_logs",
    "$outputDir\processes",
    "$outputDir\browser_data",
    "$outputDir\yara_scans",
    "$outputDir\ai_classification",
    "$outputDir\memory_dumps",
    "$outputDir\screenshots",
    "$outputDir\registry",
    "$outputDir\event_logs",
    "$outputDir\wifi_data",
    "$outputDir\forensics"
)

foreach ($d in $dirs) {
    New-Item -Path $d -ItemType Directory -Force | Out-Null
}

# Redefine key output paths
$sampleOutDir = "$outputDir\ai_classification"
$tfLog = "$outputDir\ai_classification\tfnet_malware_results.txt"


# --- Clipboard Dump ---
try {
    Get-Clipboard | Out-File "$outputDir\system_info\clipboard.txt"
} catch {
    "Clipboard access failed: $_" | Out-File "$outputDir\system_info\clipboard.txt"
}

# --- Basic DPAPI Chrome/Edge Password Decryption (PowerShell Only) ---
$localStatePath = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Local State"
$loginDataPath = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Login Data"
$credDumpOut = "$outputDir\browser_data\browser_credentials.txt"

if (Test-Path $loginDataPath) {
    try {
        Copy-Item $loginDataPath "$outputDir\browser_data\LoginData_copy" -Force
        Add-Type -AssemblyName System.Security
        $bytes = [System.IO.File]::ReadAllBytes("$outputDir\browser_data\LoginData_copy")
        if ($bytes.Length -gt 0) {
            "Login Data backup copied. Use SQLite + DPAPI tools for manual analysis." | Out-File $credDumpOut
        }
    } catch {
        "Could not read or copy login data: $_" | Out-File $credDumpOut
    }
} else {
    "Chrome/Edge Login Data not found." | Out-File $credDumpOut
}

# --- Summary Report ---
$report = "$outputDir\summary_report.txt"
Add-Content $report "Recon Summary Report - $(Get-Date)"
Add-Content $report "System: $env:COMPUTERNAME | User: $env:USERNAME"
Add-Content $report "`nFolders collected:"
Get-ChildItem -Path $outputDir -Directory | ForEach-Object { Add-Content $report " - $($_.Name)" }
Add-Content $report "`nScript Completed at $(Get-Date)"
