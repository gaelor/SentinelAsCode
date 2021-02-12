![](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg "Metsys")
# Hunting Rules
## T0000_Console_History
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T0000_Console_History.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T0000_Console_History

> Query:

```// Name: Console History // Description: Checks for execution of MITRE ATT&CK T0000 // // Severity: Medium // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Collection // Sysmon | where EventID == 1 and (process_command_line contains "Get-History" or process_command_line contains "AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt" or process_command_line contains "(Get-PSReadlineOption).HistorySavePath")```
## T0000_Named_Pipes
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T0000_Named_Pipes.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T0000_Named_Pipes

> Query:

```// Name: Named Pipes // Description: Checks for execution of MITRE ATT&CK T0000 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Lateral Movement // Sysmon | where EventID == 17 and (pipe_name contains "\\isapi_http" or pipe_name contains "\\isapi_dg" or pipe_name contains "\\isapi_dg2" or pipe_name contains "\\isapi_http" or pipe_name contains "\\sdlrpc" or pipe_name contains "\\aheec" or pipe_name contains "\\winsession" or pipe_name contains "\\lsassw" or pipe_name contains "\\rpchlp_3" or pipe_name contains "\\NamePipe_MoreWindows" or pipe_name contains "\\pcheap_reuse" or pipe_name contains "\\PSEXESVC" or pipe_name contains "\\PowerShellISEPipeName_" or pipe_name contains "\\csexec" or pipe_name contains "\\paexec" or pipe_name contains "\\remcom")```
## T0000_Named_Pipes_CobaltStrike
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T0000_Named_Pipes_CobaltStrike.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T0000_Named_Pipes_CobaltStrike

> Query:

```// Name: Named Pipes - CobaltStrike // Description: Checks for execution of MITRE ATT&CK T0000 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Lateral Movement // Sysmon | where EventID == 17 and pipe_name contains "\\msagent_"```
## T0000_Remotely_Query_Login_Sessions_Network
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T0000_Remotely_Query_Login_Sessions_Network.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T0000_Remotely_Query_Login_Sessions_Network

> Query:

```// Name: Remotely Query Login Sessions - Network // Description: Checks for execution of MITRE ATT&CK T0000 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 3 and process_path contains "qwinsta.exe"```
## T0000_Remotely_Query_Login_Sessions_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T0000_Remotely_Query_Login_Sessions_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T0000_Remotely_Query_Login_Sessions_Process

> Query:

```// Name: Remotely Query Login Sessions - Process // Description: Checks for execution of MITRE ATT&CK T0000 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 1 and process_path contains "qwinsta.exe"```
## T0000_Suspicious_Filename_Used
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T0000_Suspicious_Filename_Used.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T0000_Suspicious_Filename_Used

> Query:

```// Name: Suspicious filename used // Description: Checks for execution of MITRE ATT&CK T0000 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Privilege Escalation #Defense Evasion // Sysmon | where EventID == 1 and (process_path == "a.exe" or process_path == "b.exe" or process_path == "c.exe" or process_path == "d.exe" or process_path == "e.exe" or process_path == "f.exe" or process_path == "g.exe" or process_path == "h.exe" or process_path == "i.exe" or process_path == "j.exe" or process_path == "k.exe" or process_path == "l.exe" or process_path == "m.exe" or process_path == "n.exe" or process_path == "o.exe" or process_path == "p.exe" or process_path == "q.exe" or process_path == "r.exe" or process_path == "s.exe" or process_path == "t.exe" or process_path == "u.exe" or process_path == "v.exe" or process_path == "w.exe" or process_path == "x.exe" or process_path == "y.exe" or process_path == "z.exe" or process_path == "1.exe" or process_path == "2.exe" or process_path == "3.exe" or process_path == "4.exe" or process_path == "5.exe" or process_path == "6.exe" or process_path == "7.exe" or process_path == "8.exe" or process_path == "9.exe" or process_path == "0.exe" or process_path == "10.exe")```
## T1002_Data_Compressed
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1002_Data_Compressed.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1002_Data_Compressed

> Query:

```// Name: Data Compressed // Description: Checks for execution of MITRE ATT&CK T1002 // // Severity: Medium // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Exfiltration // Sysmon | where EventID == 1 and (process_path contains "powershell.exe" and process_command_line contains "-Recurse | Compress-Archive") or (process_path contains "rar.exe" and process_command_line contains "rar*a*")```
## T1003_Credential_Dumping_ImageLoad
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1003_Credential_Dumping_ImageLoad.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1003_Credential_Dumping_ImageLoad

> Query:

```// Name: Credential Dumping ImageLoad // Description: Checks for execution of MITRE ATT&CK T1003 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Credential Access // Sysmon | where EventID == 7 and (module_loaded contains "C:\\Windows\\System32\\samlib.dll" or module_loaded contains "C:\\Windows\\System32\\WinSCard.dll" or module_loaded contains "C:\\Windows\\System32\\cryptdll.dll" or module_loaded contains "C:\\Windows\\System32\\hid.dll" or module_loaded contains "C:\\Windows\\System32\\vaultcli.dll") and (process_path !contains "\\Sysmon.exe" or process_path !contains "\\svchost.exe" or process_path !contains "\\logonui.exe")```
## T1003_Credential_Dumping_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1003_Credential_Dumping_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1003_Credential_Dumping_Process

> Query:

```// Name: Credential Dumping - Process // Description: Checks for execution of MITRE ATT&CK T1003 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Credential Access // Sysmon | where EventID == 1 and (process_command_line contains "Invoke-Mimikatz -DumpCreds" or process_command_line contains "gsecdump -a" or process_command_line contains "wce -o" or process_command_line contains "procdump -ma lsass.exe" or process_command_line contains "ntdsutil*ac i ntds*ifm*create full")```
## T1003_Credential_Dumping_Process_Access
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1003_Credential_Dumping_Process_Access.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1003_Credential_Dumping_Process_Access

> Query:

```// Name: Credential Dumping - Process Access // Description: Checks for execution of MITRE ATT&CK T1003 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Credential Access // Sysmon | where EventID == 10 and target_process_path contains "C:\\Windows\\system32\\lsass.exe" and (process_granted_access contains "0x1010" or process_granted_access contains "0x1410" or process_granted_access contains "0x147a" or process_granted_access contains "0x143a") and process_call_trace contains "C:\\Windows\\SYSTEM32\\ntdll.dll" and process_call_trace contains "C:\\Windows\\system32\\KERNELBASE.dll" and process_call_trace contains "|UNKNOWN(*)"```
## T1003_Credential_Dumping_Registry
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1003_Credential_Dumping_Registry.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1003_Credential_Dumping_Registry

> Query:

```// Name: Credential Dumping - Registry // Description: Checks for execution of MITRE ATT&CK T1003 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Credential Access // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and process_path !contains "C:\\WINDOWS\\system32\\lsass.exe" and (registry_key_path contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider\\" or registry_key_path contains "\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\" or registry_key_path contains "\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SecurityProviders\\" or registry_key_path contains "\\Control\\SecurityProviders\\WDigest\\") and registry_key_path !contains "\\Lsa\\RestrictRemoteSamEventThrottlingWindow"```
## T1003_Credential_Dumping_Registry_Save
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1003_Credential_Dumping_Registry_Save.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1003_Credential_Dumping_Registry_Save

> Query:

```// Name: Credential Dumping - Registry Save // Description: Checks for execution of MITRE ATT&CK T1003 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Credential Access // Sysmon | where EventID == 1 and process_path contains "reg.exe" and (process_command_line contains "*save*HKLM\\sam*" or process_command_line contains "*save*HKLM\\system*")```
## T1004_Win_Logon_Helper_DLL
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1004_Win_Logon_Helper_DLL.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1004_Win_Logon_Helper_DLL

> Query:

```// Name: Winlogon Helper DLL // Description: Checks for execution of MITRE ATT&CK T1004 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and (registry_key_path contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\user_nameinit\\" or registry_key_path contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\" or registry_key_path contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\")```
## T1007_System_Service_Discovery
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1007_System_Service_Discovery.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1007_System_Service_Discovery

> Query:

```// Name: System Service Discovery // Description: Checks for execution of MITRE ATT&CK T1007 // // Severity: Medium // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 1 and (process_path contains "net.exe" or process_path contains "tasklist.exe" or process_path contains "sc.exe" or process_path contains "wmic.exe") and (file_directory contains "net.exe\" start" or file_directory contains "tasklist.exe\" /SVC" and file_directory contains "sc.exe\" query" or file_directory contains "wmic.exe\" service where")```
## T1012_Query_Registry_Network
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1012_Query_Registry_Network.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1012_Query_Registry_Network

> Query:

```// Name: Query Registry - Network // Description: Checks for execution of MITRE ATT&CK T1012 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 3 and process_path contains "reg.exe" and process_command_line contains "reg query"```
## T1012_Query_Registry_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1012_Query_Registry_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1012_Query_Registry_Process

> Query:

```// Name: Query Registry - Process // Description: Checks for execution of MITRE ATT&CK T1012 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 1 and process_path contains "reg.exe" and process_command_line contains "reg query"```
## T1013_Local_Port_Monitor
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1013_Local_Port_Monitor.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1013_Local_Port_Monitor

> Query:

```// Name: Local Port Monitor // Description: Checks for execution of MITRE ATT&CK T1013 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence, #Privilege Escalation // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and registry_key_path contains "\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\"```
## T1015_Accessibility_Features
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1015_Accessibility_Features.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1015_Accessibility_Features

> Query:

```// Name: Accessibility features // Description: Checks for execution of MITRE ATT&CK T1015 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence, #Privilege Escalation // Sysmon | where EventID == 1 and process_parent_path contains"winlogon.exe" and (process_path contains "sethc.exe" or process_path contains "utilman.exe" or process_path contains "osk.exe" or process_path contains "magnify.exe" or process_path contains "displayswitch.exe" or process_path contains "narrator.exe" or process_path contains "atbroker.exe")```
## T1015_Accessibility_Features_Registry
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1015_Accessibility_Features_Registry.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1015_Accessibility_Features_Registry

> Query:

```// Name: Accessibility Features - Registry // Description: Checks for execution of MITRE ATT&CK T1015 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence #Privilege_Escalation // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and registry_key_path contains "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*"```
## T1016_System_Network_Configuration_Discovery
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1016_System_Network_Configuration_Discovery.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1016_System_Network_Configuration_Discovery

> Query:

```// Name: Remote System Discovery - Network // Description: Checks for execution of MITRE ATT&CK T1018 // // Severity: Medium // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 1 and (process_command_line contains "net.exe" and file_directory contains "config") or (process_command_line contains "ipconfig.exe" or process_command_line contains "netsh.exe" or process_command_line contains "arp.exe" or process_command_line contains "nbtstat.exe")```
## T1018_Remote_System_Discovery_Network
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1018_Remote_System_Discovery_Network.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1018_Remote_System_Discovery_Network

> Query:

```// Name: Remote System Discovery - Network // Description: Checks for execution of MITRE ATT&CK T1018 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 3 and (process_path contains "net.exe" or process_path contains "ping.exe") and (process_command_line contains "view" or process_command_line contains "ping")```
## T1018_Remote_System_Discovery_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1018_Remote_System_Discovery_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1018_Remote_System_Discovery_Process

> Query:

```// Name: Remote System Discovery - Process // Description: Checks for execution of MITRE ATT&CK T1018 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where (process_path contains "net.exe" or process_path contains "ping.exe") and (process_command_line contains "view" or process_command_line contains "ping")```
## T1027_Obfuscated_Files_Or_Information
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1027_Obfuscated_Files_Or_Information.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1027_Obfuscated_Files_Or_Information

> Query:

```// Name: Obfuscated Files or Information // Description: Checks for execution of MITRE ATT&CK T1027 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion // Sysmon | where EventID == 1 and (process_path contains "certutil.exe" and process_command_line contains "encode") or process_command_line contains "ToBase64String"```
## T1028_Windows_Remote_Management
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1028_Windows_Remote_Management.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1028_Windows_Remote_Management

> Query:

```// Name: Windows Remote Management // Description: Checks for execution of MITRE ATT&CK T1028 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Lateral Movement #Execution // Sysmon | where EventID == 1 and (process_path contains "wsmprovhost.exe" or process_path contains "winrm.cmd") and (process_command_line contains "Enable-PSRemoting -Force" or process_command_line contains "Invoke-Command -computer_name" or process_command_line contains "wmic*node*process call create")```
## T1031_Modify_Existing_Service
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1031_Modify_Existing_Service.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1031_Modify_Existing_Service

> Query:

```// Name: Modify Existing Service // Description: Checks for execution of MITRE ATT&CK T1031 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence // Sysmon | where EventID == 1 and (process_path contains "sc.exe" or process_path contains "powershell.exe" or process_path contains "cmd.exe") and process_command_line contains "*sc*config*binpath*"```
## T1033_System_Owner_User_Discovery
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1033_System_Owner_User_Discovery.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1033_System_Owner_User_Discovery

> Query:

```// Name: System Owner/User Discovery // Description: Checks for execution of MITRE ATT&CK T1033 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 1 and (process_path contains "whoami.exe" or process_command_line contains "whoami" or file_directory contains "useraccount get /ALL" or process_path contains "qwinsta.exe" or process_path contains "quser.exe" or process_path contains "systeminfo.exe")```
## T1036_Masquerading_Extension
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1036_Masquerading_Extension.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1036_Masquerading_Extension

> Query:

```// Name: Masquerading - Extension // Description: Checks for execution of MITRE ATT&CK T1036 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion // Sysmon | where EventID == 1 and (process_path contains ".doc." or process_path contains ".docx." or process_path contains ".xls." or process_path contains ".xlsx." or process_path contains ".pdf." or process_path contains ".rtf." or process_path contains ".jpg." or process_path contains ".png." or process_path contains ".jpeg." or process_path contains ".zip." or process_path contains ".rar." or process_path contains ".ppt." or process_path contains ".pptx.")```
## T1036_Masquerading_Location
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1036_Masquerading_Location.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1036_Masquerading_Location

> Query:

```// Name: Masquerading - Location // Description: Checks for execution of MITRE ATT&CK T1036 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion // Sysmon | where EventID == 11 and (process_path contains "SysWOW64" or process_path contains "System32" or process_path contains "AppData" or process_path contains "Temp") and (file_name contains ".exe" or file_name contains ".dll" or file_name contains ".bat" or file_name contains ".com" or file_name contains ".ps1" or file_name contains ".py" or file_name contains ".js" or file_name contains ".vbs" or file_name contains ".hta")```
## T1037_Logon_Scripts
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1037_Logon_Scripts.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1037_Logon_Scripts

> Query:

```// Name: Logon Scripts // Description: Checks for execution of MITRE ATT&CK T1037 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Lateral Movement #Persistence // Sysmon | where EventID == 1 and process_command_line contains "*REG*ADD*HKCU\\Environment*UserInitMprLogonScript*"```
## T1040_Network_Sniffing
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1040_Network_Sniffing.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1040_Network_Sniffing

> Query:

```// Name: Network Sniffing // Description: Checks for execution of MITRE ATT&CK T1040 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Credential Access #Discovery // Sysmon | where EventID == 1 and (process_path contains "tshark.exe" or process_path contains "windump.exe" or process_path contains "logman.exe" or process_path contains "tcpdump.exe" or process_path contains "wprui.exe" or process_path contains "wpr.exe")```
## T1042_Change_Default_File_Association
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1042_Change_Default_File_Association.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1042_Change_Default_File_Association

> Query:

```// Name: Change Default File Association // Description: Checks for execution of MITRE ATT&CK T1042 // // Severity: Medium // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Exfiltration // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and (registry_key_path contains "\\SOFTWARE\\Classes\\" or registry_key_path contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\GlobalAssocChangedCounter")```
## T1044_File_System_Permissions_Weakness
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1044_File_System_Permissions_Weakness.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1044_File_System_Permissions_Weakness

> Query:

```// Name: File System Permissions Weakness // Description: Checks for execution of MITRE ATT&CK T1044 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Credential Access // Sysmon | where EventID == 7 and (module_loaded contains "\\Temp\\" or module_loaded contains "C:\\Users\\" or driver_signature_status !contains "Valid")```
## T1047_Windows_Management_Instrumentation_Active_Script_Event_Consumer_FileAccess
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1047_Windows_Management_Instrumentation_Active_Script_Event_Consumer_FileAccess.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1047_Windows_Management_Instrumentation_Active_Script_Event_Consumer_FileAccess

> Query:

```// Name: Windows Management Instrumentation - Instances of an Active Script Event Consumer - FileAccess // Description: Checks for execution of MITRE ATT&CK T1047 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Execution // Sysmon | where EventID == 11 and process_command_line contains "C:\\WINDOWS\\system32\\wbem\\scrcons.exe"```
## T1047_Windows_Management_Instrumentation_Active_Script_Event_Consumer_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1047_Windows_Management_Instrumentation_Active_Script_Event_Consumer_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1047_Windows_Management_Instrumentation_Active_Script_Event_Consumer_Process

> Query:

```// Name: Windows Management Instrumentation - Instances of an Active Script Event Consumer - Process // Description: Checks for execution of MITRE ATT&CK T1047 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Execution // Sysmon | where EventID == 1 and (process_parent_command_line contains "C:\\Windows\\System32\\svchost.exe" or process_command_line contains "C:\\WINDOWS\\system32\\wbem\\scrcons.exe")```
## T1047_Windows_Management_Instrumentation_Network
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1047_Windows_Management_Instrumentation_Network.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1047_Windows_Management_Instrumentation_Network

> Query:

```// Name: Windows Management Instrumentation - Process // Description: Checks for execution of MITRE ATT&CK T1047 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Execution // Sysmon | where EventID == 3 and (process_path contains "wmic.exe" or process_command_line contains "wmic")```
## T1047_Windows_Management_Instrumentation_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1047_Windows_Management_Instrumentation_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1047_Windows_Management_Instrumentation_Process

> Query:

```// Name: Windows Management Instrumentation - Process // Description: Checks for execution of MITRE ATT&CK T1047 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Execution // Sysmon | where EventID == 1 and (process_parent_command_line contains "wmiprvse.exe" or process_path contains "wmic.exe" or process_command_line contains "wmic")```
## T1047_WMI_Command_Execution
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1047_WMI_Command_Execution.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1047_WMI_Command_Execution

> Query:

```// Name: WMI command execution // Description: Checks for execution of MITRE ATT&CK T1047 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Lateral Movement // Sysmon | where EventID == 20 and wmi_consumer_type contains "Command Line"```
## T1049_System_Network_Connections_Discovery
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1049_System_Network_Connections_Discovery.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1049_System_Network_Connections_Discovery

> Query:

```// Name: System Network Connections Discovery // Description: Checks for execution of MITRE ATT&CK T1049 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 1 and (process_path contains "net.exe" or process_path contains "netstat.exe") and (process_command_line contains "*net* use*" or process_command_line contains "*net* sessions*" or process_command_line contains "*net* file*" or process_command_line contains "*netstat*") or process_command_line contains "*Get-NetTCPConnection*"```
## T1050_New_Service_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1050_New_Service_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1050_New_Service_Process

> Query:

```// Name: New Service - Process // Description: Checks for execution of MITRE ATT&CK T1050 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence // Sysmon | where EventID == 1 and (process_path contains "sc.exe" or process_path contains "powershell.exe" or process_path contains "cmd.exe") and (process_command_line contains "*New-Service*BinaryPathName*" or process_command_line contains "*sc*create*binpath*" or process_command_line contains "*Get-WmiObject*Win32_Service*create*")```
## T1053_Scheduled_Task_FileAccess
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1053_Scheduled_Task_FileAccess.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1053_Scheduled_Task_FileAccess

> Query:

```// Name: Scheduled Task - FileAccess // Description: Checks for execution of MITRE ATT&CK T1053 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence #Privilege Escalation #Execution // Sysmon | where EventID == 11 and process_command_line contains "C:\\WINDOWS\\system32\\svchost.exe" or file_name contains "C:\\Windows\\System32\\Tasks\\" or file_name contains "C:\\Windows\\Tasks\\"```
## T1053_Scheduled_Task_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1053_Scheduled_Task_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1053_Scheduled_Task_Process

> Query:

```// Name: Scheduled Task - Process // Description: Checks for execution of MITRE ATT&CK T1053 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence #Privilege Escalation #Execution // Sysmon | where EventID == 1 and (process_path contains "taskeng.exe" or process_path contains "schtasks.exe" or (process_path contains "svchost.exe" and process_parent_command_line != "C:\\Windows\\System32\\services.exe"))```
## T1054_Indicator_Blocking_Driver_Unloaded
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1054_Indicator_Blocking_Driver_Unloaded.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1054_Indicator_Blocking_Driver_Unloaded

> Query:

```// Name: Indicator Blocking - Driver unloaded // Description: Checks for execution of MITRE ATT&CK T1054 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion // Sysmon | where EventID == 1 and (process_path contains "fltmc.exe" or process_command_line contains "*fltmc*unload*")```
## T1054_Indicator_Blocking_Sysmon_Registry_Edited_From_Other_Source
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1054_Indicator_Blocking_Sysmon_Registry_Edited_From_Other_Source.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1054_Indicator_Blocking_Sysmon_Registry_Edited_From_Other_Source

> Query:

```// Name: Indicator Blocking - Sysmon registry edited from other source // Description: Checks for execution of MITRE ATT&CK T1054 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and  (registry_key_path contains "HKLM\\System\\CurrentControlSet\\Services\\SysmonDrv\\*" or registry_key_path contains "HKLM\\System\\CurrentControlSet\\Services\\Sysmon\\*" or registry_key_path contains "HKLM\\System\\CurrentControlSet\\Services\\Sysmon64\\*") and (process_path !contains "Sysmon64.exe" or process_path !contains "Sysmon.exe")```
## T1055_Process_Injection_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1055_Process_Injection_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1055_Process_Injection_Process

> Query:

```// Name: Process Injection - Process // Description: Checks for execution of MITRE ATT&CK T1055 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Privilege Escalation #Defense Evasion // Sysmon | where EventID == 1 and process_command_line contains "*Invoke-DllInjection*" or process_command_line contains "C:\\windows\\sysnative\\"```
## T1057_Process_Discovery
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1057_Process_Discovery.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1057_Process_Discovery

> Query:

```// Name: Process Discovery // Description: Checks for execution of MITRE ATT&CK T1075 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Execution // Sysmon | where EventID == 1 and process_path contains "tasklist.exe" or process_command_line contains "Get-Process"```
## T1059_Command_Line_Interface
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1059_Command_Line_Interface.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1059_Command_Line_Interface

> Query:

```// Name: Command-Line Interface // Description: Checks for execution of MITRE ATT&CK T1059 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Execution // Sysmon | where EventID == 1 and process_path contains "cmd.exe"```
## T1060_Registry_Run_Keys_Or_Start_Folder
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1060_Registry_Run_Keys_Or_Start_Folder.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1060_Registry_Run_Keys_Or_Start_Folder

> Query:

```// Name: Registry Run Keys or Start Folder // Description: Checks for execution of MITRE ATT&CK T1060 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and (registry_key_path contains "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*" or registry_key_path contains "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\*Shell Folders")```
## T1063_Security_Software_Discovery
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1063_Security_Software_Discovery.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1063_Security_Software_Discovery

> Query:

```// Name: Security Software Discovery // Description: Checks for execution of MITRE ATT&CK T1063 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 1 and (process_path contains "netsh.exe" or process_path contains "reg.exe" or process_path contains "tasklist.exe") and (process_command_line contains "*reg* query*" or process_command_line contains "*tasklist *" or process_command_line contains "*netsh*" or process_command_line contains "*fltmc*|*findstr*")```
## T1069_Permission_Groups_Discovery
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1069_Permission_Groups_Discovery.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1069_Permission_Groups_Discovery

> Query:

```// Name: Permission Groups Discovery // Description: Checks for execution of MITRE ATT&CK T1069 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where process_path contains "net" and (file_directory contains "user" or file_directory contains "group" or file_directory contains "localgroup")```
## T1069_Permission_Groups_Discovery_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1069_Permission_Groups_Discovery_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1069_Permission_Groups_Discovery_Process

> Query:

```// Name: Permission Groups Discovery - Process // Description: Checks for execution of MITRE ATT&CK T1069 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 1 and process_path contains "net.exe" and (process_command_line contains "*net* user*" or process_command_line contains "*net* group*" or process_command_line contains "*net* localgroup*" or process_command_line contains "*get-localgroup*" or process_command_line contains "*get-ADPrinicipalGroupMembership*")```
## T1070_Indicator_Removal_On_Host
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1070_Indicator_Removal_On_Host.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1070_Indicator_Removal_On_Host

> Query:

```// Name: Indicator removal on host // Description: Checks for execution of MITRE ATT&CK T1070 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion // Sysmon | where process_path contains "wevtutil"```
## T1074_Datal_Staged_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1074_Datal_Staged_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1074_Datal_Staged_Process

> Query:

```// Name: Data Staged - Process // Description: Checks for execution of MITRE ATT&CK T1074 // // Severity: Medium // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Collection // Sysmon | where EventID == 1 and (process_command_line contains "DownloadString" and process_command_line contains "Net.WebClient") or (process_command_line contains "New-Object" and process_command_line contains "IEX")```
## T1076_Remote_Desktop_Protocol_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1076_Remote_Desktop_Protocol_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1076_Remote_Desktop_Protocol_Process

> Query:

```// Name: Remote Desktop Protocol - Process // Description: Checks for execution of MITRE ATT&CK T1076 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Lateral Movement // Sysmon | where EventID == 1 and(process_path contains "tscon.exe" or process_path contains "mstsc.exe")```
## T1076_Remote_Desktop_Protocol_Registry
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1076_Remote_Desktop_Protocol_Registry.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1076_Remote_Desktop_Protocol_Registry

> Query:

```// Name: Remote Desktop Protocol - Process // Description: Checks for execution of MITRE ATT&CK T1076 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Lateral Movement // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and (process_path contains "LogonUI.exe" or registry_key_path contains "\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\")```
## T1077_Windows_Admin_Shares
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1077_Windows_Admin_Shares.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1077_Windows_Admin_Shares

> Query:

```// Name: Windows Admin Shares - Network // Description: Checks for execution of MITRE ATT&CK T1077 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Lateral Movement // Sysmon | where EventID == 3 and process_path contains "net.exe" and (process_command_line contains "use" or process_command_line contains "session" or process_command_line contains "file")```
## T1077_Windows_Admin_Shares_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1077_Windows_Admin_Shares_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1077_Windows_Admin_Shares_Process

> Query:

```// Name: Windows Admin Shares - Process // Description: Checks for execution of MITRE ATT&CK T1077 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Lateral Movement // Sysmon | where EventID == 1 and (process_path contains "net.exe" or process_path contains "powershell.exe") and ((process_command_line contains "*net* use*$" or process_command_line contains "*net* session*$" or process_command_line contains "*net* file*$") or process_command_line contains "*New-PSDrive*root*")```
## T1077_Windows_Admin_Shares_Process_Created
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1077_Windows_Admin_Shares_Process_Created.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1077_Windows_Admin_Shares_Process_Created

> Query:

```// Name: Windows Admin Shares - Process - Created // Description: Checks for execution of MITRE ATT&CK T1077 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Lateral Movement // Sysmon | where EventID == 1 and process_path contains "net.exe" and process_command_line contains "net share"```
## T1081_Credentials_In_Files
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1081_Credentials_In_Files.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1081_Credentials_In_Files

> Query:

```// Name: Credentials in Files // Description: Checks for execution of MITRE ATT&CK T1081 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Credential Access // Sysmon | where EventID == 1 and (process_command_line contains "*findstr* /si pass*" or process_command_line contains "*select-string -Pattern pass*" or process_command_line contains "*list vdir*/text:password*")```
## T1082_System_Information_Discovery
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1082_System_Information_Discovery.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1082_System_Information_Discovery

> Query:

```// Name: System Information Discovery // Description: Checks for execution of MITRE ATT&CK T1082 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 1 and (process_path contains"sysinfo.exe" or process_path contains "reg.exe") and process_command_line contains "reg*query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum"```
## T1085_Rundll32
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1085_Rundll32.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1085_Rundll32

> Query:

```// Name: Rundll32 // Description: Checks for execution of MITRE ATT&CK T1085 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion, #Execution // Sysmon | where EventID == 1 and (process_parent_path contains "\\rundll32.exe" or process_path contains "rundll32.exe")```
## T1086_PowerShell
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1086_PowerShell.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1086_PowerShell

> Query:

```// Name: PowerShell // Description: Checks for execution of MITRE ATT&CK T1086 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Execution // Sysmon | where EventID == 1 and (process_path contains "powershell.exe" or process_path contains "powershell_ise.exe" or process_path contains "psexec.exe")```
## T1086_PowerShell_Downloads_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1086_PowerShell_Downloads_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1086_PowerShell_Downloads_Process

> Query:

```// Name: PowerShell Downloads - Process // Description: Checks for execution of MITRE ATT&CK T1086 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Execution // Sysmon | where EventID == 1 and (process_command_line contains "*.Download*" or process_command_line contains "*Net.WebClient*")```
## T1087_Account_Discovery
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1087_Account_Discovery.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1087_Account_Discovery

> Query:

```// Name: Account Discovery // Description: Checks for execution of MITRE ATT&CK T1087 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 1 and (process_path contains "net.exe" or process_path contains "powershell.exe") and (process_command_line contains "*net* user*" or process_command_line contains "*net* group*" or process_command_line contains "*net* localgroup*" or process_command_line contains "cmdkey*\\/list*" or process_command_line contains "*get-localuser*" or process_command_line contains "*get-localgroupmembers*" or process_command_line contains "*get-aduser*" or process_command_line contains "query*user*")```
## T1088_Bypass_User_Account_Control_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1088_Bypass_User_Account_Control_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1088_Bypass_User_Account_Control_Process

> Query:

```// Name: Bypass User Account Control - Process // Description: Checks for execution of MITRE ATT&CK T1088 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Privilege Escalation, #Persistence // Sysmon | where EventID == 1 and (process_parent_command_line contains "eventvwr.exe" or process_parent_command_line contains "fodhelper.exe" or process_path contains "ShellRunas.exe")```
## T1088_Bypass_User_Account_Control_Registry
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1088_Bypass_User_Account_Control_Registry.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1088_Bypass_User_Account_Control_Registry

> Query:

```// Name: Bypass User Account Control - Registry // Description: Checks for execution of MITRE ATT&CK T1088 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Privilege Escalation #Defense Evasion // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and (registry_key_path contains "*\\mscfile\\shell\\open\\command\\*" or registry_key_path contains "*\\ms-settings\\shell\\open\\command\\*")```
## T1089_Disabling_Security_Tools_Service_Stopped
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1089_Disabling_Security_Tools_Service_Stopped.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1089_Disabling_Security_Tools_Service_Stopped

> Query:

```// Name: Disabling Security Tools - Service stopped // Description: Checks for execution of MITRE ATT&CK T1089 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion // Sysmon | where EventID == 1 and (process_path contains "net.exe" or process_path contains "sc.exe") and file_directory contains "stop"```
## T1093_Process_Hollowing
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1093_Process_Hollowing.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1093_Process_Hollowing

> Query:

```// Name: Process Hollowing // Description: Checks for execution of MITRE ATT&CK T1093 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion // Sysmon | where EventID == 1 and (     (         process_path contains "smss.exe" and          process_parent_command_line !contains "smss.exe"     ) or (         process_path contains "csrss.exe" and (             process_parent_command_line !contains "smss.exe" and              process_parent_command_line !contains "svchost.exe"         )     ) or (         process_path contains "wininit.exe"and          process_parent_command_line !contains "smss.exe"     ) or (         process_path contains "winlogon.exe" and          process_parent_command_line !contains "smss.exe"     ) or (         process_path contains "lsass.exe" and          process_parent_command_line !contains "wininit.exe"     ) or (         process_path contains "LogonUI.exe" and (             process_parent_command_line !contains "winlogon.exe" and              process_parent_command_line !contains "wininit.exe"         )     ) or (         process_path contains "services.exe" and          process_parent_command_line !contains "wininit.exe"     ) or (         process_path contains "spoolsv.exe" and          process_parent_command_line !contains "services.exe"     ) or (         process_path contains "taskhost.exe" and (             process_parent_command_line !contains "services.exe" and              process_parent_command_line !contains "svchost.exe"         )     ) or (         process_path contains "taskhostw.exe" and (             process_parent_command_line !contains "services.exe" and              process_parent_command_line !contains "svchost.exe"         )     ) or (         process_path contains "userinit.exe" and (             process_parent_command_line !contains "dwm.exe" and              process_parent_command_line !contains "winlogon.exe"         )     ) ) | extend AccountCustomEntity = UserName | extend HostCustomEntity = Computer | extend FileHashCustomEntity = hash_sha256```
## T1096_NTFS_File_Attributes
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1096_NTFS_File_Attributes.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1096_NTFS_File_Attributes

> Query:

```// Name: NTFS File Attributes // Description: Checks for execution of MITRE ATT&CK T1096 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion // Sysmon | where EventID == 1 and process_path contains "fsutil.exe" and process_command_line contains "*usn*deletejournal*"```
## T1103_AppInit_DLLs
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1103_AppInit_DLLs.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1103_AppInit_DLLs

> Query:

```// Name: AppInit DLLs // Description: Checks for execution of MITRE ATT&CK T1103 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Privilege Escalation, #Persistence // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and (registry_key_path contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Appinit_Dlls\\" or registry_key_path contains "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Appinit_Dlls\\")```
## T1107_File_Deletion
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1107_File_Deletion.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1107_File_Deletion

> Query:

```// Name: File Deletion // Description: Checks for execution of MITRE ATT&CK T1107 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion // Sysmon | where EventID == 1 and (process_command_line contains "*remove-item*" or process_command_line contains "vssadmin*Delete Shadows /All /Q*" or process_command_line contains "*wmic*shadowcopy delete*" or process_command_line contains "*wbdadmin* delete catalog -q*" or process_command_line contains "*bcdedit*bootstatuspolicy ignoreallfailures*" or process_command_line contains "*bcdedit*recoveryenabled no*")```
## T1112_Modify_Registry
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1112_Modify_Registry.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1112_Modify_Registry

> Query:

```// Name: Modify Registry // Description: Checks for execution of MITRE ATT&CK T1112 // // Severity: Medium // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion // Sysmon | where process_path contains "reg.exe" and file_directory contains "reg.exe\" query"```
## T1115_Clipboard_Data
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1115_Clipboard_Data.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1115_Clipboard_Data

> Query:

```// Name: Clipboard Data // Description: Checks for execution of MITRE ATT&CK T1115 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Collection // Sysmon | where EventID == 1 and (process_path contains "clip.exe" or process_command_line contains "*Get-Clipboard*")```
## T1117_Bypassing_Application_Whitelisting_With_Regsvr32
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1117_Bypassing_Application_Whitelisting_With_Regsvr32.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1117_Bypassing_Application_Whitelisting_With_Regsvr32

> Query:

```// Name: Bypassing Application Whitelisting with Regsvr32 // Description: Checks for execution of MITRE ATT&CK T1117 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion // Sysmon | where EventID == 1 and (process_path contains "regsvr32.exe" or process_path contains "rundll32.exe" or process_path contains "certutil.exe") or process_command_line contains "scrobj.dll"```
## T1117_Regsvr32_Network
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1117_Regsvr32_Network.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1117_Regsvr32_Network

> Query:

```// Name: Regsvr32 // Description: Checks for execution of MITRE ATT&CK T1117 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion, #Execution // Sysmon | where EventID == 3 and (process_parent_path contains "\\regsvr32.exe" or process_path contains "\\regsvr32.exe")```
## T1118_InstallUtil
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1118_InstallUtil.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1118_InstallUtil

> Query:

```// Name: InstallUtil // Description: Checks for execution of MITRE ATT&CK T1118 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion, #Execution // Sysmon | where EventID == 3 and (process_path contains "InstallUtil.exe" or process_command_line contains "\\/logfile= \\/LogToConsole=false \\/U")```
## T1121_Regsvcs_Regasm
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1121_Regsvcs_Regasm.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1121_Regsvcs_Regasm

> Query:

```// Name: Regsvcs/Regasm // Description: Checks for execution of MITRE ATT&CK T1121 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion, #Execution // Sysmon | where EventID == 3 and (process_path contains "regsvcs.exe" or process_path contains "regasm.exe")```
## T1122_Component_Object_Model_Hijacking
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1122_Component_Object_Model_Hijacking.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1122_Component_Object_Model_Hijacking

> Query:

```// Name: Component Object Model Hijacking // Description: Checks for execution of MITRE ATT&CK T1122 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion, #Execution // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and registry_key_path contains "\\Software\\Classes\\CLSID\\"```
## T1123_Audio_Capture
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1123_Audio_Capture.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1123_Audio_Capture

> Query:

```// Name: Audio Capture // Description: Checks for execution of MITRE ATT&CK T1115 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Collection // Sysmon | where EventID == 1 and (process_path contains "SoundRecorder.exe" or process_command_line contains "*Get-AudioDevice*" or process_command_line contains "*WindowsAudioDevice-Powershell-Cmdlet*")```
## T1124_System_Time_Discovery
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1124_System_Time_Discovery.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1124_System_Time_Discovery

> Query:

```// Name: System Time Discovery // Description: Checks for execution of MITRE ATT&CK T1124 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 1 and (process_path contains "*\\net.exe" and process_command_line contains "*net* time*") or process_path contains "w32tm.exe" or process_command_line contains "*Get-Date*"```
## T1126_Network_Share_Connection_Removal
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1126_Network_Share_Connection_Removal.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1126_Network_Share_Connection_Removal

> Query:

```// Name: Network Share Connection Removal // Description: Checks for execution of MITRE ATT&CK T1126 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion // Sysmon | where EventID == 1 and (process_path contains "net.exe" and process_command_line contains "net delete") or process_command_line contains "Remove-SmbShare" or process_command_line contains "Remove-FileShare"```
## T1127_Trusted_Developer_Utilities
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1127_Trusted_Developer_Utilities.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1127_Trusted_Developer_Utilities

> Query:

```// Name: Trusted Developer Utilities // Description: Checks for execution of MITRE ATT&CK T1127 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion #Execution // Sysmon | where EventID == 1 and (process_path contains "MSBuild.exe" or process_path contains "msxsl.exe")```
## T1128_Narsh_Helper_DLL_Registry
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1128_Narsh_Helper_DLL_Registry.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1128_Narsh_Helper_DLL_Registry

> Query:

```// Name: Netsh Helper DLL - Registry // Description: Checks for execution of MITRE ATT&CK T1128 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and registry_key_path contains "*\\SOFTWARE\\Microsoft\\Netsh\\*"```
## T1128_Netsh_Helper_DLL_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1128_Netsh_Helper_DLL_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1128_Netsh_Helper_DLL_Process

> Query:

```// Name: Netsh Helper DLL - Process // Description: Checks for execution of MITRE ATT&CK T1128 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence // Sysmon | where EventID == 1 and (process_path contains "netsh.exe" and process_command_line contains "*helper*")```
## T1130_Install_Root_Certificates
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1130_Install_Root_Certificates.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1130_Install_Root_Certificates

> Query:

```// Name: Install Root Certificate // Description: Checks for execution of MITRE ATT&CK T1130 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and process_path !contains "svchost.exe" and (registry_key_path contains "*\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root\\Certificates\\*" or registry_key_path contains "*\\Microsoft\\SystemCertificates\\Root\\Certificates\\*")```
## T1131_Authentication_Package
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1131_Authentication_Package.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1131_Authentication_Package

> Query:

```// Name: Authentication Package // Description: Checks for execution of MITRE ATT&CK T1131 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and (registry_key_path contains "*\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\*") and (process_path !contains "C:\\WINDOWS\\system32\\lsass.exe" or process_path !contains "C:\\Windows\\system32\\svchost.exe" or process_path !contains "C:\\Windows\\system32\\services.exe")```
## T1135_Network_Share_Discovery
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1135_Network_Share_Discovery.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1135_Network_Share_Discovery

> Query:

```// Name: Network Share Discovery // Description: Checks for execution of MITRE ATT&CK T1135 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where process_path contains "net.exe" and (process_command_line contains "view" or process_command_line contains "share")```
## T1135_Network_Share_Discovery_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1135_Network_Share_Discovery_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1135_Network_Share_Discovery_Process

> Query:

```// Name: Network Share Discovery - Process // Description: Checks for execution of MITRE ATT&CK T1135 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 1 and (process_path contains "net.exe" and (process_command_line contains "net view" or process_command_line contains "net share")) or process_command_line contains "get-smbshare -Name"```
## T1136_Create_Account
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1136_Create_Account.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1136_Create_Account

> Query:

```// Name: Create Account // Description: Checks for execution of MITRE ATT&CK T1136 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence // Sysmon | where EventID == 1 and (process_command_line contains "New-LocalUser" or process_command_line contains "net user add")```
## T1138_Application_Shimming_FileAccess
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1138_Application_Shimming_FileAccess.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1138_Application_Shimming_FileAccess

> Query:

```// Name: Application Shimming - FileAccess // Description: Checks for execution of MITRE ATT&CK T1138 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Privilege Escalation, #Persistence // Sysmon | where EventID == 11 and file_name contains "C:\\Windows\\AppPatch\\Custom\\"```
## T1138_Application_Shimming_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1138_Application_Shimming_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1138_Application_Shimming_Process

> Query:

```// Name: Application Shimming - Process // Description: Checks for execution of MITRE ATT&CK T1138 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Privilege Escalation, #Persistence // Sysmon | where EventID == 1 and process_path contains "sdbinst.exe"```
## T1138_Application_Shimming_Registry
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1138_Application_Shimming_Registry.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1138_Application_Shimming_Registry

> Query:

```// Name: Application Shimming - Registry // Description: Checks for execution of MITRE ATT&CK T1138 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Privilege Escalation, #Persistence // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and registry_key_path contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB\\"```
## T1140_Deobfuscate_Decode_Files_Or_Information
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1140_Deobfuscate_Decode_Files_Or_Information.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1140_Deobfuscate_Decode_Files_Or_Information

> Query:

```// Name: Deobfuscate/Decode Files or Information // Description: Checks for execution of MITRE ATT&CK T1140 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion // Sysmon | where EventID == 1 and (process_path contains "certutil.exe" and process_command_line contains "decode")```
## T1146_Clear_Command_History
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1146_Clear_Command_History.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1146_Clear_Command_History

> Query:

```// Name: Clear Command History // Description: Checks for execution of MITRE ATT&CK T1146 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Collection // Sysmon | where EventID == 1 and (process_command_line contains "*rm (Get-PSReadlineOption).HistorySavePath*" or process_command_line contains "*del (Get-PSReadlineOption).HistorySavePath*" or process_command_line contains "*Set-PSReadlineOption ?HistorySaveStyle SaveNothing*" or process_command_line contains "*Remove-Item (Get-PSReadlineOption).HistorySavePath*")```
## T1158_Hidden_Files_And_Directories
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1158_Hidden_Files_And_Directories.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1158_Hidden_Files_And_Directories

> Query:

```// Name: Hidden Files and Directories // Description: Checks for execution of MITRE ATT&CK T1158 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence #Defense Evasion // Sysmon | where EventID == 1 and process_path contains "attrib.exe" and (process_command_line contains "+h" or process_command_line contains "+s")```
## T1158_Hidden_Files_And_Directories_VSS
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1158_Hidden_Files_And_Directories_VSS.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1158_Hidden_Files_And_Directories_VSS

> Query:

```// Name: Hidden Files and Directories - VSS // Description: Checks for execution of MITRE ATT&CK T1158 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion #Persistence // Sysmon | where EventID == 1 and (process_path contains "*\\VolumeShadowCopy*\\*" or process_command_line contains "*\\VolumeShadowCopy*\\*")```
## T1170_MSHTA_FileAccess
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1170_MSHTA_FileAccess.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1170_MSHTA_FileAccess

> Query:

```// Name: MSHTA - FileAccess // Description: Checks for execution of MITRE ATT&CK T1170 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion #Execution // Sysmon | where (EventID == 11 or EventID == 15) and file_name contains ".hta"```
## T1170_MSHTA_Network
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1170_MSHTA_Network.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1170_MSHTA_Network

> Query:

```// Name: MSHTA - Network // Description: Checks for execution of MITRE ATT&CK T1170 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion #Execution // Sysmon | where EventID == 3 and (process_command_line contains "mshta.exe" or process_parent_command_line contains "mshta.exe")```
## T1170_MSHTA_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1170_MSHTA_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1170_MSHTA_Process

> Query:

```// Name: MSHTA - Process // Description: Checks for execution of MITRE ATT&CK T1170 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion #Execution // Sysmon | where EventID == 1 and (process_command_line contains "mshta.exe" or process_parent_command_line contains "mshta.exe")```
## T1179_Hooking
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1179_Hooking.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1179_Hooking

> Query:

```// Name: Hooking // Description: Checks for execution of MITRE ATT&CK T1179 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence #Privilege Escalation #Credential Access // Sysmon | where EventID == 1 and (process_path contains "mavinject.exe" or process_command_line contains "/INJECTRUNNING")```
## T1180_Screensaver
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1180_Screensaver.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1180_Screensaver

> Query:

```// Name: Screensaver // Description: Checks for execution of MITRE ATT&CK T1180 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and (registry_key_path contains "*\\Control Panel\\Desktop\\SCRNSAVE.EXE") and (process_parent_command_line !contains "explorer.exe" or process_path !contains "rundll32.exe" or process_command_line !contains "*shell32.dll,Control_RunDLL desk.cpl,ScreenSaver,*")```
## T1182_AppCert_DLLs
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1182_AppCert_DLLs.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1182_AppCert_DLLs

> Query:

```// Name: AppCert DLLs // Description: Checks for execution of MITRE ATT&CK T1182 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Privilege Escalation, #Persistence // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and registry_key_path contains "\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls\\"```
## T1183_Image_File_Execution_Options_Injection
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1183_Image_File_Execution_Options_Injection.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1183_Image_File_Execution_Options_Injection

> Query:

```// Name: Image File Execution Options Injection // Description: Checks for execution of MITRE ATT&CK T1183 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence #Privilege Escalation // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and (registry_key_path contains "\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" or registry_key_path contains "\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\")```
## T1187_Forced_Authentication
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1187_Forced_Authentication.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1187_Forced_Authentication

> Query:

```// Name: Forced Authentication // Description: Checks for execution of MITRE ATT&CK T1187 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Credential Access // Sysmon | where EventID == 11 and (file_name contains ".lnk" or file_name contains ".scf")```
## T1191_CMSTP
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1191_CMSTP.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1191_CMSTP

> Query:

```// Name: CMSTP // Description: Checks for execution of MITRE ATT&CK T1191 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion, #Execution // Sysmon | where EventID == 1 and process_path contains "CMSTP.exe"```
## T1196_Control_Panel_Items_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1196_Control_Panel_Items_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1196_Control_Panel_Items_Process

> Query:

```// Name: Control Panel Items - Process // Description: Checks for execution of MITRE ATT&CK T1196 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion, #Execution // Sysmon | where EventID == 1 and (process_command_line contains "control \\/name" or process_commandline contains "rundll32 shell32.dll,Control_RunDLL")```
## T1196_Control_Panel_Items_Registry
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1196_Control_Panel_Items_Registry.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1196_Control_Panel_Items_Registry

> Query:

```// Name: Control Panel Items - Registry // Description: Checks for execution of MITRE ATT&CK T1196 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion, #Execution // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and (registry_key_path contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ControlPanel\\NameSpace" or registry_key_path contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Controls Folder\\*\\Shellex\\PropertySheetHandlers\\" or registry_key_path contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\")```
## T1197_BITS_Jobs_Network
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1197_BITS_Jobs_Network.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1197_BITS_Jobs_Network

> Query:

```// Name: BITS Jobs - Network // Description: Checks for execution of MITRE ATT&CK T1197 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion, #Persistence // Sysmon | where EventID == 3 and process_path contains "bitsadmin.exe"```
## T1197_BITS_Jobs_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1197_BITS_Jobs_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1197_BITS_Jobs_Process

> Query:

```// Name: BITS Jobs - Process // Description: Checks for execution of MITRE ATT&CK T1197 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Persistence #Privilege Escalation // Sysmon | where EventID == 1 and (process_path contains "bitsamin.exe" or process_command_line contains "Start-BitsTransfer")```
## T1201_Password_Policy_Discovery
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1201_Password_Policy_Discovery.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1201_Password_Policy_Discovery

> Query:

```// Name: Password Policy Discovery // Description: Checks for execution of MITRE ATT&CK T1201 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 11 and (process_command_line contains "net accounts" or process_command_line contains "net accounts \\/domain")```
## T1202_Indirect_Command_Execution
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1202_Indirect_Command_Execution.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1202_Indirect_Command_Execution

> Query:

```// Name: Indirect Command Execution // Description: Checks for execution of MITRE ATT&CK T1202 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 1 and (process_parent_command_line contains "pcalua.exe" or process_path contains "pcalua.exe" or process_path contains "bash.exe" or process_path contains "forfiles.exe")```
## T1209_Time_Providers
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1209_Time_Providers.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1209_Time_Providers

> Query:

```// Name: Time Providers // Description: Checks for execution of MITRE ATT&CK T1209 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where (EventID == 12 or EventID == 13 or EventID == 14) and registry_key_path contains "\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\"```
## T1214_Credentials_In_Registry
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1214_Credentials_In_Registry.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1214_Credentials_In_Registry

> Query:

```// Name: Credentials in Registry // Description: Checks for execution of MITRE ATT&CK T1214 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Credential Access // Sysmon | where EventID == 1 and (process_command_line contains "reg query HKLM \\/f password \\/t REG_SZ \\/s" or process_command_line contains "reg query HKCU \\/f password \\/t REG_SZ \\/s" or process_command_line contains "Get-UnattendedInstallFile" or process_command_line contains "Get-Webconfig" or process_command_line contains "Get-ApplicationHost" or process_command_line contains "Get-SiteListPassword" or process_command_line contains "Get-CachedGPPPassword" or process_command_line contains "Get-RegistryAutoLogon")```
## T1216_Signed_Script_Proxy_Execution
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1216_Signed_Script_Proxy_Execution.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1216_Signed_Script_Proxy_Execution

> Query:

```// Name: Signed Script Proxy Execution // Description: Checks for execution of MITRE ATT&CK T1216 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion, #Execution // Sysmon | where process_path contains "cscript" or process_path contains "wscript" or process_path contains "certutil" or process_path contains "jjs" and file_directory !contains " /nologo \"MonitorKnowledgeDiscovery.vbs\""```
## T1217_Browser_Bookmark_Discovery
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1217_Browser_Bookmark_Discovery.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1217_Browser_Bookmark_Discovery

> Query:

```// Name: Browser Bookmark Discovery // Description: Checks for execution of MITRE ATT&CK T1217 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Discovery // Sysmon | where EventID == 1 and (process_command_line contains "*firefox*places.sqlite*")```
## T1218_Signed_Binary_Proxy_Execution_Network
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1218_Signed_Binary_Proxy_Execution_Network.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1218_Signed_Binary_Proxy_Execution_Network

> Query:

```// Name: Signed Binary Proxy Execution - Network // Description: Checks for execution of MITRE ATT&CK T1218 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion, #Execution // Sysmon | where EventID == 3 and (process_path contains "certutil.exe" or process_command_line contains "*certutil*script\\:http\\[\\:\\]\\/\\/*" or process_path contains "*\\replace.exe")```
## T1218_Signed_Binary_Proxy_Execution_Process
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1218_Signed_Binary_Proxy_Execution_Process.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1218_Signed_Binary_Proxy_Execution_Process

> Query:

```// Name: Signed Binary Proxy Execution - Process // Description: Checks for execution of MITRE ATT&CK T1218 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion, #Execution // Sysmon | where EventID == 1 and (process_command_line contains "mavinject*\\/injectrunning" or process_command_line contains "mavinject32*\\/injectrunning*" or process_command_line contains "*certutil*script\\:http\\[\\:\\]\\/\\/*" or process_command_line contains "*certutil*script\\:https\\[\\:\\]\\/\\/*" or process_command_line contains "*msiexec*http\\[\\:\\]\\/\\/*" or process_command_line contains "*msiexec*https\\[\\:\\]\\/\\/*")```
## T1223_Compiled_HTML_File
### Hunt Tags

> Author: [blueteam](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/T1223_Compiled_HTML_File.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: T1223_Compiled_HTML_File

> Query:

```// Name: Compiled HTML File // Description: Checks for execution of MITRE ATT&CK T1223 // // Severity: High // // QueryFrequency: 1h // // QueryPeriod: 1h // // AlertTriggerThreshold: 1 // // DataSource: #Sysmon // // Tactics: #Defense Evasion #Execution // Sysmon | where EventID == 1 and process_path contains "hh.exe"```
