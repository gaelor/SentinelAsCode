![](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg "Metsys")
# Hunting Rules
## KQL_apt_apt29_thinktanks
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_apt29_thinktanks.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_apt29_thinktanks

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine contains "-noni -ep bypass $"```
## KQL_apt_babyshark
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_babyshark.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_babyshark

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine == "reg query "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default"" or CommandLine startswith "powershell.exe mshta.exe http" or CommandLine == "cmd.exe /c taskkill /im cmd.exe"```
## KQL_apt_bear_activity_gtr19
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_bear_activity_gtr19.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_bear_activity_gtr19

> Query:

```C#SecurityEvent | where EventID == "4688" | where ((Image endswith "\\xcopy.exe" and CommandLine contains " /S /E /C /Q /H \\") or (Image endswith "\\adexplorer.exe" and CommandLine contains " -snapshot \"\" c:\\users\\"))```
## KQL_apt_cloudhopper
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_cloudhopper.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_cloudhopper

> Query:

```C#SecurityEvent | where EventID == "4688" | where (Image endswith "\\cscript.exe" and CommandLine contains ".vbs /shell ")```
## KQL_apt_dragonfly
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_dragonfly.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_dragonfly

> Query:

```C#SecurityEvent | where EventID == "4688" | where Image endswith "\\crackmapexec.exe"```
## KQL_apt_elise
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_elise.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_elise

> Query:

```C#SecurityEvent | where EventID == "4688" | where ((Image == "C:\Windows\SysWOW64\cmd.exe" and CommandLine contains "\\Windows\\Caches\\NavShExt.dll ") or CommandLine endswith "\\AppData\\Roaming\\MICROS~1\\Windows\\Caches\\NavShExt.dll,Setting")```
## KQL_apt_empiremonkey
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_empiremonkey.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_empiremonkey

> Query:

```C#SecurityEvent | where EventID == "4688" | where (CommandLine endswith "/i:%APPDATA%\\logs.txt scrobj.dll" and (Image endswith "\\cutil.exe" or Description == "Microsoft(C) Registerserver"))```
## KQL_apt_equationgroup_dll_u_load
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_equationgroup_dll_u_load.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_equationgroup_dll_u_load

> Query:

```C#SecurityEvent | where EventID == "4688" | where ((Image endswith "\\rundll32.exe" and CommandLine endswith ",dll_u") or CommandLine contains " -export dll_u ")```
## KQL_apt_hurricane_panda
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_hurricane_panda.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_hurricane_panda

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine endswith " localgroup administrators admin /add" or CommandLine contains "\\Win64.exe"```
## KQL_apt_judgement_panda_gtr19
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_judgement_panda_gtr19.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_judgement_panda_gtr19

> Query:

```C#SecurityEvent | where EventID == "4688" | where (CommandLine contains "\\ldifde.exe -f -n " or CommandLine contains "\\7za.exe a 1.7z " or CommandLine endswith " eprod.ldf" or CommandLine contains "\\aaaa\\procdump64.exe" or CommandLine contains "\\aaaa\\netsess.exe" or CommandLine contains "\\aaaa\\7za.exe" or CommandLine contains "copy .\\1.7z \\" or CommandLine contains "copy \\client\\c$\\aaaa\\" or Image == "C:\Users\Public\7za.exe")```
## KQL_apt_pandemic
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_pandemic.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_pandemic

> Query:

```C#Event | where (EventID == "13" and TargetObject startswith "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\services\\null\\Instance" or TargetObject startswith "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\services\\null\\Instance" or TargetObject startswith "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\services\\null\\Instance") SecurityEvent | where EventID == "4688" | where Command startswith "loaddll -a "```
## KQL_apt_slingshot
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_slingshot.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_slingshot

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine matches regex ".*schtasks.* /delete .*Defrag\\ScheduledDefrag.*" SecurityEvent | where (EventID == "4701" and TaskName == "\Microsoft\Windows\Defrag\ScheduledDefrag")```
## KQL_apt_sofacy
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_sofacy.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_sofacy

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine matches regex "rundll32\.exe %APPDATA%\\\.*\.dat\",.*" or CommandLine matches regex "rundll32\.exe %APPDATA%\\\.*\.dll\",#1"```
## KQL_apt_sofacy_zebrocy
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_sofacy_zebrocy.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_sofacy_zebrocy

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine endswith "cmd.exe /c SYSTEMINFO & TASKLIST"```
## KQL_apt_ta17_293a_ps
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_ta17_293a_ps.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_ta17_293a_ps

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine == "ps.exe -accepteula"```
## KQL_apt_tropictrooper
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_tropictrooper.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_tropictrooper

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine contains "abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc"```
## KQL_apt_turla_namedpipes
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_turla_namedpipes.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_turla_namedpipes

> Query:

```C#Event | where (EventID == "17" or EventID == "18" and PipeName == "\atctl" or PipeName == "\userpipe" or PipeName == "\iehelper" or PipeName == "\sdlrpc" or PipeName == "\comnap")```
## KQL_apt_unidentified_nov_18
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_unidentified_nov_18.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_unidentified_nov_18

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine endswith "cyzfc.dat, PointFunctionCall" Event | where (EventID == "11" and TargetFilename contains "ds7002.lnk")```
## KQL_apt_zxshell
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_apt_zxshell.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_apt_zxshell

> Query:

```C#SecurityEvent | where EventID == "4688" | where Command matches regex "rundll32\.exe .*,zxFunction.*" or Command matches regex "rundll32\.exe .*,RemoteDiskXXXXX"```
## KQL_crime_fireball
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_crime_fireball.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_crime_fireball

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine matches regex ".*\\rundll32\.exe .*,InstallArcherSvc"```
## KQL_powershell_xor_commandline
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_powershell_xor_commandline.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_powershell_xor_commandline

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine contains " -bxor"```
## KQL_sysmon_susp_rdp
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_sysmon_susp_rdp.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_sysmon_susp_rdp

> Query:

```C#// title: Suspicious Outbound RDP Connections  // description: Detects Non-Standard Tools Connecting to TCP port 3389 indicating possible lateral movement // // reference: https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708 // // original author: Markus Neis (Swisscom) // KQL author: Maarten Goet (condicio) // // MITRE ATT&CK: lateral_movement, t1210   Event  | parse EventData with    * Data Name="RuleName"> RuleName <    * Data Name="UtcTime"> UtcTime <    * Data Name="ProcessGuid"> ProcessGuid <    * Data Name="ProcessId"> ProcessId <    * Data Name="Image"> Image <    * Data Name="User"> User <    * Data Name="Protocol"> Protocol <    * Data Name="Initiated"> Initiated <    * Data Name="SourceIsIpv6"> SourceIsIpv6 <    * Data Name="SourceIp"> SourceIp <    * Data Name="SourceHostname"> SourceHostname <    * Data Name="SourcePort"> SourcePort <    * Data Name="SourcePortName"> SourcePortName <    * Data Name="DestinationIsIpv6"> DestinationIsIpv6 <    * Data Name="DestinationIp"> DestinationIp <    * Data Name="DestinationHostname"> DestinationHostname <    * Data Name="DestinationPort"> DestinationPort <    * Data Name="DestinationPortName"> DestinationPortName <    *    | where ((EventID == "3" and DestinationPort == "3389") and not     (Image endswith "\\mstsc.exe"   or Image endswith "\\RTSApp.exe"   or Image endswith "\\RTS2App.exe"   or Image endswith "\\RDCMan.exe"   or Image endswith "\\ws_TunnelService.exe"   or Image endswith "\\RSSensor.exe"   or Image endswith "\\RemoteDesktopManagerFree.exe"   or Image endswith "\\RemoteDesktopManager.exe"   or Image endswith "\\RemoteDesktopManager64.exe"   or Image endswith "\\mRemoteNG.exe"   or Image endswith "\\mRemote.exe"   or Image endswith "\\Terminals.exe"   or Image endswith "\\spiceworks-finder.exe"   or Image endswith "\\FSDiscovery.exe"   or Image endswith "\\FSAssessment.exe"   or Image endswith "\\MobaRTE.exe"   or Image endswith "\\chrome.exe"))```
## KQL_win_account_backdoor_dcsync_rights
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_account_backdoor_dcsync_rights.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_account_backdoor_dcsync_rights

> Query:

```C#SecurityEvent | where (EventID == "5136" and LDAPDisplayName == "ntSecurityDescriptor" and Value contains "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" or Value contains "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")```
## KQL_win_account_discovery
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_account_discovery.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_account_discovery

> Query:

```C#SecurityEvent | where (EventID == "4661" and ObjectType == "SAM_USER" or ObjectType == "SAM_GROUP" and ObjectName endswith "-512" or ObjectName endswith "-502" or ObjectName endswith "-500" or ObjectName endswith "-505" or ObjectName endswith "-519" or ObjectName endswith "-520" or ObjectName endswith "-544" or ObjectName endswith "-551" or ObjectName endswith "-555" or ObjectName contains "admin")```
## KQL_win_admin_rdp_login
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_admin_rdp_login.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_admin_rdp_login

> Query:

```C#SecurityEvent | where (EventID == "4624" and LogonType == "10" and AuthenticationPackageName == "Negotiate" and AccountName startswith "Admin-")```
## KQL_win_admin_share_access
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_admin_share_access.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_admin_share_access

> Query:

```C#SecurityEvent | where ((EventID == "5140" and ShareName == "Admin$") and not (SubjectUserName endswith "$"))```
## KQL_win_alert_active_directory_user_control
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_alert_active_directory_user_control.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_alert_active_directory_user_control

> Query:

```C#SecurityEvent | where (EventID == "4704" and "SeEnableDelegationPrivilege")```
## KQL_win_alert_ad_user_backdoors
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_alert_ad_user_backdoors.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_alert_ad_user_backdoors

> Query:

```C#SecurityEvent | where ((((EventID == "4738" and not (isnull(AllowedToDelegateTo))) or (EventID == "5136" and AttributeLDAPDisplayName == "msDS-AllowedToDelegateTo")) or (EventID == "5136" and ObjectClass == "user" and AttributeLDAPDisplayName == "servicePrincipalName")) or (EventID == "5136" and AttributeLDAPDisplayName == "msDS-AllowedToActOnBehalfOfOtherIdentity"))```
## KQL_win_alert_enable_weak_encryption
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_alert_enable_weak_encryption.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_alert_enable_weak_encryption

> Query:

```C#SecurityEvent | where ((EventID == "4738" and ("DES" or "Preauth" or "Encrypted")) and "Enabled")```
## KQL_win_alert_hacktool_use
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_alert_hacktool_use.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_alert_hacktool_use

> Query:

```C#SecurityEvent | where (EventID == "4776" or EventID == "4624" or EventID == "4625" and WorkstationName == "RULER")```
## KQL_win_atsvc_task
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_atsvc_task.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_atsvc_task

> Query:

```C#SecurityEvent | where (EventID == "5145" and ShareName matches regex "\\\.*\\IPC\$" and RelativeTargetName == "atsvc" and Accesses contains "WriteData")```
## KQL_win_attrib_hiding_files
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_attrib_hiding_files.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_attrib_hiding_files

> Query:

```C#SecurityEvent | where EventID == "4688" | where ((Image endswith "\\attrib.exe" and CommandLine contains " +h ") and not ((CommandLine contains "\\desktop.ini " or (ParentImage endswith "\\cmd.exe" and CommandLine matches regex "+R +H +S +A \\\.*\.cui" and ParentCommandLine matches regex "C:\\WINDOWS\\system32\\\.*\.bat"))))```
## KQL_win_bypass_squiblytwo
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_bypass_squiblytwo.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_bypass_squiblytwo

> Query:

```C#SecurityEvent | where EventID == "4688" | where ((Image endswith "\\wmic.exe" and CommandLine matches regex "wmic .* .*format:\\\"http.*" or CommandLine matches regex "wmic .* /format:http" or CommandLine matches regex "wmic .* /format:http.*") or (Imphash == "1B1A3F43BF37B5BFE60751F2EE2F326E" or Imphash == "37777A96245A3C74EB217308F3546F4C" or Imphash == "9D87C9D67CE724033C0B40CC4CA1B206" and CommandLine matches regex ".* .*format:\\\"http.*" or CommandLine endswith " /format:http" or CommandLine contains " /format:http"))```
## KQL_win_cmdkey_recon
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_cmdkey_recon.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_cmdkey_recon

> Query:

```C#SecurityEvent | where EventID == "4688" | where (Image endswith "\\cmdkey.exe" and CommandLine contains " /list ")```
## KQL_win_cmstp_com_object_access
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_cmstp_com_object_access.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_cmstp_com_object_access

> Query:

```C#SecurityEvent | where EventID == "4688" | where (ParentCommandLine endswith "\\DllHost.exe" and ParentCommandLine endswith "\\{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" or ParentCommandLine endswith "\\{3E000D72-A845-4CD9-BD83-80C07C3B881F}")```
## KQL_win_dcsync
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_dcsync.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_dcsync

> Query:

```C#SecurityEvent | where (EventID == "4662" and Properties contains "Replicating Directory Changes All" or Properties contains "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")```
## KQL_win_disable_event_logging
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_disable_event_logging.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_disable_event_logging

> Query:

```C#SecurityEvent | where (EventID == "4719" and AuditPolicyChanges == "removed")```
## KQL_win_exploit_cve_2015_1641
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_exploit_cve_2015_1641.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_exploit_cve_2015_1641

> Query:

```C#SecurityEvent | where EventID == "4688" | where (ParentImage endswith "\\WINWORD.EXE" and Image endswith "\\MicroScMgmt.exe ")```
## KQL_win_exploit_cve_2017_0261
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_exploit_cve_2017_0261.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_exploit_cve_2017_0261

> Query:

```C#SecurityEvent | where EventID == "4688" | where (ParentImage endswith "\\WINWORD.EXE" and Image contains "\\FLTLDR.exe")```
## KQL_win_exploit_cve_2017_11882
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_exploit_cve_2017_11882.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_exploit_cve_2017_11882

> Query:

```C#SecurityEvent | where EventID == "4688" | where ParentImage endswith "\\EQNEDT32.EXE"```
## KQL_win_exploit_cve_2017_8759
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_exploit_cve_2017_8759.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_exploit_cve_2017_8759

> Query:

```C#SecurityEvent | where EventID == "4688" | where (ParentImage endswith "\\WINWORD.EXE" and Image endswith "\\csc.exe")```
## KQL_win_GPO_scheduledtasks
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_GPO_scheduledtasks.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_GPO_scheduledtasks

> Query:

```C#SecurityEvent | where (EventID == "5145" and ShareName matches regex "\\\.*\\SYSVOL" and RelativeTargetName endswith "ScheduledTasks.xml" and Accesses contains "WriteData")```
## KQL_win_hack_rubeus
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_hack_rubeus.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_hack_rubeus

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine contains " asreproast " or CommandLine contains " dump /service:krbtgt " or CommandLine contains " kerberoast " or CommandLine contains " createnetonly /program:" or CommandLine contains " ptt /ticket:" or CommandLine contains " /impersonateuser:" or CommandLine contains " renew /ticket:" or CommandLine contains " asktgt /user:" or CommandLine contains " harvest /interval:"```
## KQL_win_impacket_secretdump
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_impacket_secretdump.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_impacket_secretdump

> Query:

```C#SecurityEvent | where (EventID == "5145" and ShareName matches regex "\\\.*\\ADMIN\$" and RelativeTargetName matches regex "SYSTEM32\.*\.tmp")```
## KQL_win_lethalhta
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_lethalhta.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_lethalhta

> Query:

```C#SecurityEvent | where EventID == "4688" | where (ParentImage endswith "\\svchost.exe" and Image endswith "\\mshta.exe")```
## KQL_win_lm_namedpipe
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_lm_namedpipe.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_lm_namedpipe

> Query:

```C#SecurityEvent | where ((EventID == "5145" and ShareName matches regex "\\\.*\\IPC\$") and not (EventID == "5145" and ShareName matches regex "\\\.*\\IPC\$" and RelativeTargetName == "atsvc" or RelativeTargetName == "samr" or RelativeTargetName == "lsarpc" or RelativeTargetName == "winreg" or RelativeTargetName == "netlogon" or RelativeTargetName == "srvsvc" or RelativeTargetName == "protected_storage" or RelativeTargetName == "wkssvc" or RelativeTargetName == "browser" or RelativeTargetName == "netdfs"))```
## KQL_win_mal_adwind
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_mal_adwind.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_mal_adwind

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine matches regex ".*\\AppData\\Roaming\\Oracle.*\\java.*\.exe .*" or CommandLine matches regex ".*cscript\.exe .*Retrive.*\.vbs .*" Event | where (EventID == "11" and TargetFilename matches regex ".*\\AppData\\Roaming\\Oracle\\bin\\java.*\.exe" or TargetFilename matches regex ".*\\Retrive.*\.vbs") Event | where (EventID == "13" and TargetObject startswith "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" and Details startswith "%AppData%\\Roaming\\Oracle\\bin\\")```
## KQL_win_mal_lockergoga
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_mal_lockergoga.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_mal_lockergoga

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine endswith " cl Microsoft-Windows-WMI-Activity/Trace"```
## KQL_win_mal_ursnif
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_mal_ursnif.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_mal_ursnif

> Query:

```C#Event | where (EventID == "13" and TargetObject startswith "HKU\\Software\\AppDataLow\\Software\\Microsoft\\")```
## KQL_win_mal_wannacry
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_mal_wannacry.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_mal_wannacry

> Query:

```C#SecurityEvent | where EventID == "4688" | where (CommandLine contains "vssadmin delete shadows" or CommandLine matches regex ".*icacls .* /grant Everyone:F /T /C /Q.*" or CommandLine contains "bcdedit /set {default} recoveryenabled no" or CommandLine contains "wbadmin delete catalog -quiet" or Image endswith "\\tasksche.exe" or Image endswith "\\mssecsvc.exe" or Image endswith "\\taskdl.exe" or Image contains "\\WanaDecryptor" or Image endswith "\\taskhsvc.exe" or Image endswith "\\taskse.exe" or Image endswith "\\111.exe" or Image endswith "\\lhdfrgui.exe" or Image endswith "\\diskpart.exe" or Image endswith "\\linuxnew.exe" or Image endswith "\\wannacry.exe")```
## KQL_win_mal_wceaux_dll
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_mal_wceaux_dll.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_mal_wceaux_dll

> Query:

```C#SecurityEvent | where (EventID == "4656" or EventID == "4658" or EventID == "4660" or EventID == "4663" and ObjectName endswith "\\wceaux.dll")```
## KQL_win_malware_dridex
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_malware_dridex.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_malware_dridex

> Query:

```C#SecurityEvent | where EventID == "4688" | where (CommandLine matches regex ".*\\svchost\.exe C:\\Users\\\.*\\Desktop\\\.*" or (ParentImage contains "\\svchost.exe" and CommandLine endswith "whoami.exe /all" or CommandLine endswith "net.exe view"))```
## KQL_win_malware_notpetya
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_malware_notpetya.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_malware_notpetya

> Query:

```C#SecurityEvent | where EventID == "4688" | where ((Image endswith "\\fsutil.exe" and CommandLine contains " deletejournal ") or CommandLine matches regex ".*\\AppData\\Local\\Temp\.* \\\\\.\\pipe\\\.*" or (Image endswith "\\wevtutil.exe" and CommandLine contains " cl ") or (Image endswith "\\rundll32.exe" and CommandLine endswith ".dat,#1") or "*\\perfc.dat*")```
## KQL_win_malware_script_dropper
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_malware_script_dropper.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_malware_script_dropper

> Query:

```C#SecurityEvent | where EventID == "4688" | where ((Image endswith "\\wscript.exe" or Image endswith "\\cscript.exe" and CommandLine matches regex ".* C:\\Users\\\.*\.jse .*" or CommandLine matches regex ".* C:\\Users\\\.*\.vbe .*" or CommandLine matches regex ".* C:\\Users\\\.*\.js .*" or CommandLine matches regex ".* C:\\Users\\\.*\.vba .*" or CommandLine matches regex ".* C:\\Users\\\.*\.vbs .*" or CommandLine matches regex ".* C:\\ProgramData\\\.*\.jse .*" or CommandLine matches regex ".* C:\\ProgramData\\\.*\.vbe .*" or CommandLine matches regex ".* C:\\ProgramData\\\.*\.js .*" or CommandLine matches regex ".* C:\\ProgramData\\\.*\.vba .*" or CommandLine matches regex ".* C:\\ProgramData\\\.*\.vbs .*") and not (ParentImage contains "\\winzip"))```
## KQL_win_malware_wannacry
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_malware_wannacry.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_malware_wannacry

> Query:

```C#SecurityEvent | where EventID == "4688" | where (Image endswith "\\tasksche.exe" or Image endswith "\\mssecsvc.exe" or Image endswith "\\taskdl.exe" or Image contains "\\@WanaDecryptor@" or Image endswith "\\taskhsvc.exe" or Image endswith "\\taskse.exe" or Image endswith "\\111.exe" or Image endswith "\\lhdfrgui.exe" or Image endswith "\\diskpart.exe" or Image endswith "\\linuxnew.exe" or Image endswith "\\wannacry.exe" or CommandLine contains "vssadmin delete shadows" or CommandLine matches regex ".*icacls .* /grant Everyone:F /T /C /Q.*" or CommandLine contains "bcdedit /set {default} recoveryenabled no" or CommandLine contains "wbadmin delete catalog -quiet" or CommandLine contains "@Please_Read_Me@.txt")```
## KQL_win_mavinject_proc_inj
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_mavinject_proc_inj.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_mavinject_proc_inj

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine contains " /INJECTRUNNING "```
## KQL_win_mshta_spawn_shell
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_mshta_spawn_shell.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_mshta_spawn_shell

> Query:

```C#SecurityEvent | where EventID == "4688" | where ((ParentImage endswith "\\mshta.exe" and Image endswith "\\cmd.exe" or Image endswith "\\powershell.exe" or Image endswith "\\wscript.exe" or Image endswith "\\cscript.exe" or Image endswith "\\sh.exe" or Image endswith "\\bash.exe" or Image endswith "\\reg.exe" or Image endswith "\\regsvr32.exe" or Image contains "\\BITSADMIN") and not (CommandLine contains "/HP/HP" or CommandLine contains "\\HP\\HP"))```
## KQL_win_net_ntlm_downgrade
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_net_ntlm_downgrade.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_net_ntlm_downgrade

> Query:

```C#Event | where (EventID == "13" and TargetObject matches regex ".*SYSTEM\\\.*ControlSet.*\\Control\\Lsa\\lmcompatibilitylevel" or TargetObject matches regex ".*SYSTEM\\\.*ControlSet.*\\Control\\Lsa\\NtlmMinClientSec" or TargetObject matches regex ".*SYSTEM\\\.*ControlSet.*\\Control\\Lsa\\RestrictSendingNTLMTraffic") SecurityEvent | where (EventID == "4657" and ObjectName matches regex "\\REGISTRY\\MACHINE\\SYSTEM\\\.*ControlSet.*\\Control\\Lsa" and ObjectValueName == "LmCompatibilityLevel" or ObjectValueName == "NtlmMinClientSec" or ObjectValueName == "RestrictSendingNTLMTraffic")```
## KQL_win_netsh_fw_add
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_netsh_fw_add.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_netsh_fw_add

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine contains "netsh firewall add"```
## KQL_win_netsh_port_fwd
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_netsh_port_fwd.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_netsh_port_fwd

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine startswith "netsh interface portproxy add v4tov4 "```
## KQL_win_netsh_port_fwd_3389
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_netsh_port_fwd_3389.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_netsh_port_fwd_3389

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine matches regex "netsh i.* p.*=3389 c.*"```
## KQL_win_office_shell
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_office_shell.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_office_shell

> Query:

```C#SecurityEvent | where EventID == "4688" | where (ParentImage endswith "\\WINWORD.EXE" or ParentImage endswith "\\EXCEL.EXE" or ParentImage endswith "\\POWERPNT.exe" or ParentImage endswith "\\MSPUB.exe" or ParentImage endswith "\\VISIO.exe" or ParentImage endswith "\\OUTLOOK.EXE" and Image endswith "\\cmd.exe" or Image endswith "\\powershell.exe" or Image endswith "\\wscript.exe" or Image endswith "\\cscript.exe" or Image endswith "\\sh.exe" or Image endswith "\\bash.exe" or Image endswith "\\scrcons.exe" or Image endswith "\\schtasks.exe" or Image endswith "\\regsvr32.exe" or Image endswith "\\hh.exe" or Image endswith "\\wmic.exe" or Image endswith "\\mshta.exe" or Image endswith "\\rundll32.exe" or Image endswith "\\msiexec.exe" or Image endswith "\\forfiles.exe" or Image endswith "\\scriptrunner.exe" or Image endswith "\\mftrace.exe" or Image endswith "\\AppVLP.exe")```
## KQL_win_overpass_the_hash
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_overpass_the_hash.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_overpass_the_hash

> Query:

```C#SecurityEvent | where (EventID == "4624" and LogonType == "9" and LogonProcessName == "seclogo" and AuthenticationPackageName == "Negotiate")```
## KQL_win_pass_the_hash
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_pass_the_hash.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_pass_the_hash

> Query:

```C#SecurityEvent | where ((LogonType == "3" and LogonProcessName == "NtLmSsp" and WorkstationName == "%Workstations%" and ComputerName == "%Workstations%" and (EventID == "4624" or EventID == "4625")) and not (AccountName == "ANONYMOUS LOGON"))```
## KQL_win_plugx_susp_exe_locations
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_plugx_susp_exe_locations.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_plugx_susp_exe_locations

> Query:

```C#SecurityEvent | where EventID == "4688" | where ((((((((((((Image endswith "\\CamMute.exe" and not (Image contains "\\Lenovo\\Communication Utility\\")) or (Image endswith "\\chrome_frame_helper.exe" and not (Image contains "\\Google\\Chrome\\application\\"))) or (Image endswith "\\dvcemumanager.exe" and not (Image contains "\\Microsoft Device Emulator\\"))) or (Image endswith "\\Gadget.exe" and not (Image contains "\\Windows Media Player\\"))) or (Image endswith "\\hcc.exe" and not (Image contains "\\HTML Help Workshop\\"))) or (Image endswith "\\hkcmd.exe" and not (Image contains "\\System32\\" or Image contains "\\SysNative\\" or Image contains "\\SysWowo64\\"))) or (Image endswith "\\Mc.exe" and not (Image contains "\\Microsoft Visual Studio" or Image contains "\\Microsoft SDK" or Image contains "\\Windows Kit"))) or (Image endswith "\\MsMpEng.exe" and not (Image contains "\\Microsoft Security Client\\" or Image contains "\\Windows Defender\\" or Image contains "\\AntiMalware\\"))) or (Image endswith "\\msseces.exe" and not (Image contains "\\Microsoft Security Center\\" or Image contains "\\Microsoft Security Client\\" or Image contains "\\Microsoft Security Essentials\\"))) or (Image endswith "\\OInfoP11.exe" and not (Image contains "\\Common Files\\Microsoft Shared\\"))) or (Image endswith "\\OleView.exe" and not (Image contains "\\Microsoft Visual Studio" or Image contains "\\Microsoft SDK" or Image contains "\\Windows Kit" or Image contains "\\Windows Resource Kit\\"))) or (Image endswith "\\rc.exe" and not (Image contains "\\Microsoft Visual Studio" or Image contains "\\Microsoft SDK" or Image contains "\\Windows Kit" or Image contains "\\Windows Resource Kit\\" or Image contains "\\Microsoft.NET\\")))```
## KQL_win_possible_applocker_bypass
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_possible_applocker_bypass.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_possible_applocker_bypass

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine contains "\\msdt.exe" or CommandLine contains "\\installutil.exe" or CommandLine contains "\\regsvcs.exe" or CommandLine contains "\\regasm.exe" or CommandLine contains "\\regsvr32.exe" or CommandLine contains "\\msbuild.exe" or CommandLine contains "\\ieexec.exe" or CommandLine contains "\\mshta.exe"```
## KQL_win_powershell_amsi_bypass
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_powershell_amsi_bypass.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_powershell_amsi_bypass

> Query:

```C#SecurityEvent | where EventID == "4688" | where (CommandLine contains "System.Management.Automation.AmsiUtils" and CommandLine contains "amsiInitFailed")```
## KQL_win_powershell_b64_shellcode
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_powershell_b64_shellcode.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_powershell_b64_shellcode

> Query:

```C#SecurityEvent | where EventID == "4688" | where (CommandLine contains "AAAAYInlM" and CommandLine contains "OiCAAAAYInlM" or CommandLine contains "OiJAAAAYInlM")```
## KQL_win_powershell_dll_execution
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_powershell_dll_execution.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_powershell_dll_execution

> Query:

```C#SecurityEvent | where EventID == "4688" | where ((Image endswith "\\rundll32.exe" or Description contains "Windows-Hostprozess (Rundll32)") and CommandLine contains "Default.GetString" or CommandLine contains "FromBase64String")```
## KQL_win_powershell_download
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_powershell_download.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_powershell_download

> Query:

```C#SecurityEvent | where EventID == "4688" | where (Image endswith "\\powershell.exe" and CommandLine contains "new-object system.net.webclient).downloadstring(" or CommandLine contains "new-object system.net.webclient).downloadfile(" or CommandLine contains "new-object net.webclient).downloadstring(" or CommandLine contains "new-object net.webclient).downloadfile(")```
## KQL_win_powershell_renamed_ps
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_powershell_renamed_ps.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_powershell_renamed_ps

> Query:

```C#SecurityEvent | where EventID == "4688" | where (Description == "Windows PowerShell" and not ((Image endswith "\\powershell.exe" or Image endswith "\\powershell_ise.exe" or Description == "Windows PowerShell ISE")))```
## KQL_win_powershell_suspicious_parameter_variation
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_powershell_suspicious_parameter_variation.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_powershell_suspicious_parameter_variation

> Query:

```C#SecurityEvent | where EventID == "4688" | where (Image endswith "\\Powershell.exe" and CommandLine == " -windowstyle h " or CommandLine == " -windowstyl h" or CommandLine == " -windowsty h" or CommandLine == " -windowst h" or CommandLine == " -windows h" or CommandLine == " -windo h" or CommandLine == " -wind h" or CommandLine == " -win h" or CommandLine == " -wi h" or CommandLine == " -win h " or CommandLine == " -win hi " or CommandLine == " -win hid " or CommandLine == " -win hidd " or CommandLine == " -win hidde " or CommandLine == " -NoPr " or CommandLine == " -NoPro " or CommandLine == " -NoProf " or CommandLine == " -NoProfi " or CommandLine == " -NoProfil " or CommandLine == " -nonin " or CommandLine == " -nonint " or CommandLine == " -noninte " or CommandLine == " -noninter " or CommandLine == " -nonintera " or CommandLine == " -noninterac " or CommandLine == " -noninteract " or CommandLine == " -noninteracti " or CommandLine == " -noninteractiv " or CommandLine == " -ec " or CommandLine == " -encodedComman " or CommandLine == " -encodedComma " or CommandLine == " -encodedComm " or CommandLine == " -encodedCom " or CommandLine == " -encodedCo " or CommandLine == " -encodedC " or CommandLine == " -encoded " or CommandLine == " -encode " or CommandLine == " -encod " or CommandLine == " -enco " or CommandLine == " -en ")```
## KQL_win_process_creation_bitsadmin_download
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_process_creation_bitsadmin_download.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_process_creation_bitsadmin_download

> Query:

```C#SecurityEvent | where EventID == "4688" | where (Image endswith "\\bitsadmin.exe" and CommandLine == "/transfer")```
## KQL_win_psexesvc_start
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_psexesvc_start.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_psexesvc_start

> Query:

```C#SecurityEvent | where EventID == "4688" | where ProcessCommandLine == "C:\Windows\PSEXESVC.exe"```
## KQL_win_rdp_bluekeep_poc_scanner
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_rdp_bluekeep_poc_scanner.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_rdp_bluekeep_poc_scanner

> Query:

```C#// title: Scanner PoC for CVE-2019-0708 RDP RCE vuln // description: Detects the use of a scanner by zerosum0x0 that discovers targets vulnerable to  CVE-2019-0708 RDP RCE aka BlueKeep // // references: https://twitter.com/AdamTheAnalyst/status/1134394070045003776 & https://github.com/zerosum0x0/CVE-2019-0708 // // original authors: Florian Roth (sigma rule), Adam Bradbury (idea) // KQL author: Maarten Goet (Wortell) // // MITRE ATT&CK: lateral_movement, t1210   SecurityEvent  | where (EventID == "4625" and AccountName == "AAAAAAA")```
## KQL_win_rdp_localhost_login
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_rdp_localhost_login.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_rdp_localhost_login

> Query:

```C#SecurityEvent | where (EventID == "4624" and LogonType == "10" and SourceNetworkAddress == "::1" or SourceNetworkAddress == "127.0.0.1")```
## KQL_win_rdp_reverse_tunnel
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_rdp_reverse_tunnel.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_rdp_reverse_tunnel

> Query:

```C#SecurityEvent | where (EventID == "5156" and ((SourcePort == "3389" and DestinationAddress startswith "127." or DestinationAddress == "::1") or (DestinationPort == "3389" and SourceAddress startswith "127." or SourceAddress == "::1")))```
## KQL_win_shell_spawn_susp_program
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_shell_spawn_susp_program.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_shell_spawn_susp_program

> Query:

```C#SecurityEvent | where EventID == "4688" | where ((ParentImage endswith "\\mshta.exe" or ParentImage endswith "\\powershell.exe" or ParentImage endswith "\\cmd.exe" or ParentImage endswith "\\rundll32.exe" or ParentImage endswith "\\cscript.exe" or ParentImage endswith "\\wscript.exe" or ParentImage endswith "\\wmiprvse.exe" and Image endswith "\\schtasks.exe" or Image endswith "\\nslookup.exe" or Image endswith "\\certutil.exe" or Image endswith "\\bitsadmin.exe" or Image endswith "\\mshta.exe") and not (CurrentDirectory contains "\\ccmcache\\"))```
## KQL_win_spn_enum
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_spn_enum.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_spn_enum

> Query:

```C#SecurityEvent | where EventID == "4688" | where ((Image endswith "\\setspn.exe" or Description matches regex ".*Query or reset the computer.* SPN attribute.*") and CommandLine contains "-q")```
## KQL_win_susp_add_sid_history
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_add_sid_history.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_add_sid_history

> Query:

```C#SecurityEvent | where EventID == "4765" or EventID == "4766"```
## KQL_win_susp_bcdedit
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_bcdedit.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_bcdedit

> Query:

```C#SecurityEvent | where EventID == "4688" | where (NewProcessName endswith "\\fsutil.exe" and ProcessCommandLine contains "delete" or ProcessCommandLine contains "deletevalue" or ProcessCommandLine contains "import")```
## KQL_win_susp_certutil_command
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_certutil_command.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_certutil_command

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine contains " -decode " or CommandLine contains " /decode " or CommandLine contains " -decodehex " or CommandLine contains " /decodehex " or CommandLine contains " -urlcache " or CommandLine contains " /urlcache " or CommandLine contains " -verifyctl " or CommandLine contains " /verifyctl " or CommandLine contains " -encode " or CommandLine contains " /encode " or CommandLine matches regex ".*certutil.* -URL.*" or CommandLine matches regex ".*certutil.* /URL.*" or CommandLine matches regex ".*certutil.* -ping.*" or CommandLine matches regex ".*certutil.* /ping.*"```
## KQL_win_susp_certutil_encode
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_certutil_encode.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_certutil_encode

> Query:

```C#SecurityEvent | where EventID == "4688" | where CommandLine startswith "certutil -f -encode " or CommandLine startswith "certutil.exe -f -encode " or CommandLine startswith "certutil -encode -f " or CommandLine startswith "certutil.exe -encode -f "```
## KQL_win_susp_dsrm_password_change
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_dsrm_password_change.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_dsrm_password_change

> Query:

```C#SecurityEvent | where EventID == "4794"```
## KQL_win_susp_failed_logon_reasons
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_failed_logon_reasons.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_failed_logon_reasons

> Query:

```C#SecurityEvent | where (EventID == "4625" or EventID == "4776" and Status == "0xC0000072" or Status == "0xC000006F" or Status == "0xC0000070" or Status == "0xC0000413" or Status == "0xC000018C" or Status == "0xC000015B")```
## KQL_win_susp_interactive_logons
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_interactive_logons.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_interactive_logons

> Query:

```C#SecurityEvent | where ((EventID == "528" or EventID == "529" or EventID == "4624" or EventID == "4625" and LogonType == "2" and ComputerName == "%ServerSystems%" or ComputerName == "%DomainControllers%") and not (LogonProcessName == "Advapi" and ComputerName == "%Workstations%"))```
## KQL_win_susp_kerberos_manipulation
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_kerberos_manipulation.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_kerberos_manipulation

> Query:

```C#SecurityEvent | where (EventID == "675" or EventID == "4768" or EventID == "4769" or EventID == "4771" and FailureCode == "0x9" or FailureCode == "0xA" or FailureCode == "0xB" or FailureCode == "0xF" or FailureCode == "0x10" or FailureCode == "0x11" or FailureCode == "0x13" or FailureCode == "0x14" or FailureCode == "0x1A" or FailureCode == "0x1F" or FailureCode == "0x21" or FailureCode == "0x22" or FailureCode == "0x23" or FailureCode == "0x24" or FailureCode == "0x26" or FailureCode == "0x27" or FailureCode == "0x28" or FailureCode == "0x29" or FailureCode == "0x2C" or FailureCode == "0x2D" or FailureCode == "0x2E" or FailureCode == "0x2F" or FailureCode == "0x31" or FailureCode == "0x32" or FailureCode == "0x3E" or FailureCode == "0x3F" or FailureCode == "0x40" or FailureCode == "0x41" or FailureCode == "0x43" or FailureCode == "0x44")```
## KQL_win_susp_lsass_dump
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_lsass_dump.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_lsass_dump

> Query:

```C#SecurityEvent | where (EventID == "4656" and ProcessName == "C:\Windows\System32\lsass.exe" and AccessMask == "0x705" and ObjectType == "SAM_DOMAIN")```
## KQL_win_susp_mshta_execution
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_mshta_execution.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_mshta_execution

> Query:

```C#SecurityEvent | where EventID == "4688" | where (CommandLine contains "mshta vbscript:CreateObject(\"Wscript.Shell\")" or CommandLine contains "mshta vbscript:Execute(\"Execute" or CommandLine contains "mshta vbscript:CreateObject(\"Wscript.Shell\").Run(\"mshta.exe" or (Image == "C:\Windows\system32\mshta.exe" and CommandLine contains ".jpg" or CommandLine contains ".png" or CommandLine contains ".lnk" or CommandLine contains ".xls" or CommandLine contains ".doc" or CommandLine contains ".zip"))```
## KQL_win_susp_net_recon_activity
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_net_recon_activity.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_net_recon_activity

> Query:

```C#SecurityEvent | where (EventID == "4661" and AccessMask == "0x2d" and ((ObjectType == "SAM_USER" and ObjectName matches regex "S-1-5-21-.*-500") or (ObjectType == "SAM_GROUP" and ObjectName matches regex "S-1-5-21-.*-512")))```
## KQL_win_susp_psexec
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_psexec.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_psexec

> Query:

```C#SecurityEvent | where ((EventID == "5145" and ShareName matches regex "\\\.*\\IPC\$" and RelativeTargetName endswith "-stdin" or RelativeTargetName endswith "-stdout" or RelativeTargetName endswith "-stderr") and not (EventID == "5145" and ShareName matches regex "\\\.*\\IPC\$" and RelativeTargetName startswith "PSEXESVC"))```
## KQL_win_susp_raccess_sensitive_fext
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_raccess_sensitive_fext.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_raccess_sensitive_fext

> Query:

```C#SecurityEvent | where (EventID == "5145" and RelativeTargetName endswith ".pst" or RelativeTargetName endswith ".ost" or RelativeTargetName endswith ".msg" or RelativeTargetName endswith ".nst" or RelativeTargetName endswith ".oab" or RelativeTargetName endswith ".edb" or RelativeTargetName endswith ".nsf" or RelativeTargetName endswith ".bak" or RelativeTargetName endswith ".dmp" or RelativeTargetName endswith ".kirbi" or RelativeTargetName endswith "\\ntds.dit" or RelativeTargetName endswith "\\groups.xml" or RelativeTargetName endswith ".rdp")```
## KQL_win_susp_rc4_kerberos
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_rc4_kerberos.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_rc4_kerberos

> Query:

```C#SecurityEvent | where ((EventID == "4769" and TicketOptions == "0x40810000" and TicketEncryptionType == "0x17") and not (ServiceName startswith "$"))```
## KQL_win_susp_sdelete
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_sdelete.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_sdelete

> Query:

```C#SecurityEvent | where (EventID == "4656" or EventID == "4663" or EventID == "4658" and ObjectName endswith ".AAA" or ObjectName endswith ".ZZZ")```
## KQL_win_susp_security_eventlog_cleared
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_security_eventlog_cleared.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_security_eventlog_cleared

> Query:

```C#SecurityEvent | where EventID == "517" or EventID == "1102"```
## KQL_win_susp_time_modification
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_susp_time_modification.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_susp_time_modification

> Query:

```C#SecurityEvent | where (EventID == "4616" and not (((ProcessName == "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" or ProcessName == "C:\Windows\System32\VBoxService.exe") or (ProcessName == "C:\Windows\System32\svchost.exe" and SubjectUserSid == "S-1-5-19"))))```
## KQL_win_svcctl_remote_service
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_svcctl_remote_service.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_svcctl_remote_service

> Query:

```C#SecurityEvent | where (EventID == "5145" and ShareName matches regex "\\\.*\\IPC\$" and RelativeTargetName == "svcctl" and Accesses contains "WriteData")```
## KQL_win_user_added_to_local_administrators
### Hunt Tags

> Author: [wortell](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/wortell/KQL/master/KQL_win_user_added_to_local_administrators.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KQL_win_user_added_to_local_administrators

> Query:

```C#SecurityEvent | where ((EventID == "4732" and GroupName == "Administrators") and not (SubjectUserName endswith "$"))```
