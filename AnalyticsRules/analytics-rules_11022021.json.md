![](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg "Metsys")
# Analytics Rules
## (Preview) Anomalous SSH Login Detection

### Informations

> lastUpdatedDateUTC: 2020-07-16T00:00:00Z

> createdDateUTC: 2019-08-05T00:00:00Z

### Details

> Description: This detection uses machine learning (ML) to identify anomalous Secure Shell (SSH) login activity, based on syslog data. Scenarios include:

*	Unusual IP - This IP address has not or has rarely been seen in last 30 days.
*	Unusual Geo - The IP address, city, country and ASN have not (or rarely) been seen in last 30 days.
*	New user - A new user logs in from an IP address and geo location, both or either of which are not expected to be seen in the last 30 days.

Allow 7 days after this alert is enabled for Azure Sentinel to build a profile of normal activity for your environment.

This detection requires a specific configuration of the data source. [Learn more](https://docs.microsoft.com/en-us/azure/sentinel/connect-syslog#configure-the-syslog-connector-for-anomalous-ssh-login-detection)

## (Preview) Anomalous RDP Login Detections

### Informations

> lastUpdatedDateUTC: 2020-07-16T00:00:00Z

> createdDateUTC: 2020-04-02T00:00:00Z

### Details

> Description: This detection uses machine learning (ML) to identify anomalous Remote Desktop Protocol (RDP) login activity, based on Windows Security Event data. Scenarios include:

*	Unusual IP - This IP address has not or has rarely been seen in last 30 days.
*	Unusual Geo - The IP address, city, country and ASN have not (or rarely) been seen in last 30 days.
*	New user - A new user logs in from an IP address and geo location, both or either of which are not expected to be seen in the last 30 days.

Allow 7 days after this alert is enabled for Azure Sentinel to build a profile of normal activity for your environment.	

This detection requires a specific configuration of the data source. [Learn more](https://docs.microsoft.com/en-us/azure/sentinel/connect-windows-security-events)

## Interactive STS refresh token modifications

### Informations

> lastUpdatedDateUTC: 2020-12-04T00:00:00Z

> createdDateUTC: 2020-12-04T00:00:00Z

### Details

> Description: This will show Active Directory Security Token Service (STS) refresh token modifications by Service Principals and Applications other than DirectorySync. Refresh tokens are used to validate identification and obtain access tokens.
This event is most often generated when legitimate administrators troubleshoot frequent AAD user sign-ins but may also be generated as a result of malicious token extensions. Confirm that the activity is related to an administrator legitimately modifying STS refresh tokens and check the new token validation time period for high values.
For in-depth documentation of AAD Security Tokens, see https://docs.microsoft.com/azure/active-directory/develop/security-tokens.
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.

## (Preview) TI map IP entity to DnsEvents

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-27T00:00:00Z

### Details

> Description: Identifies a match in DnsEvents from any IP IOC from TI

## Login to AWS Management Console without MFA

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-27T00:00:00Z

### Details

> Description: Multi-Factor Authentication (MFA) helps you to prevent credential compromise. This alert identifies logins to the AWS Management Console without MFA.
You can limit this detection to trigger for adminsitrative accounts if you do not have MFA enabled on all accounts.
This is done by looking at the eventName ConsoleLogin and if the AdditionalEventData field indicates MFA was NOT used 
and the ResponseElements field indicates NOT a Failure. Thereby indicating that a non-MFA login was successful.

## Failed Logins from Unknown or Invalid User

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-07-08T00:00:00Z

### Details

> Description: This query searches for numerous login attempts to the management console with an unknown or invalid user name

## High count of failed logons by a user

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-03-19T00:00:00Z

### Details

> Description: Identifies when 100 or more failed attempts by a given user in 10 minutes occur on the IIS Server.
This could be indicative of attempted brute force based on known account information.
This could also simply indicate a misconfigured service or device. 
References:
IIS status code mapping - https://support.microsoft.com/help/943891/the-http-status-code-in-iis-7-0-iis-7-5-and-iis-8-0
Win32 Status code mapping - https://msdn.microsoft.com/library/cc231199.aspx

## Brute force attack against Azure Portal

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-04-02T00:00:00Z

### Details

> Description: Identifies evidence of brute force activity against Azure Portal by highlighting multiple authentication failures 
and by a successful authentication within a given time window. 
(The query does not enforce any sequence - eg requiring the successful authentication to occur last.)
Default Failure count is 5, Default Success count is 1 and default Time Window is 20 minutes.
References: https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes.

## AD user created password not set within 24-48 hours

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-01-28T00:00:00Z

### Details

> Description: Identifies whenever a new account is created with a default password and password is not changed within 24-48 hours.
Simple version, can be more precise with Windowing, but not necessary if run as an alert on a daily basis.
Effectively, there is an event 4722 indicating a user enabled and no event 4723 indicating a password was changed within in that day or the next day.

## Creation of expensive computes in Azure

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-08-28T00:00:00Z

### Details

> Description: Identifies the creation of large size/expensive VMs (GPU or with large no of virtual CPUs) in Azure.
Adversary may create new or update existing virtual machines sizes to evade defenses 
or use it for cryptomining purposes.
For Windows/Linux Vm Sizes - https://docs.microsoft.com/azure/virtual-machines/windows/sizes 
Azure VM Naming Conventions - https://docs.microsoft.com/azure/virtual-machines/vm-naming-conventions

## (Preview) TI map IP entity to OfficeActivity

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-27T00:00:00Z

### Details

> Description: Identifies a match in OfficeActivity from any IP IOC from TI

## (Preview) TI map Email entity to CommonSecurityLog

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-28T00:00:00Z

### Details

> Description: Identifies a match in CommonSecurityLog table from any Email IOC from TI

## ADFS DKM Master Key Export

### Informations

> lastUpdatedDateUTC: 2020-12-22T00:00:00Z

> createdDateUTC: 2020-12-17T00:00:00Z

### Details

> Description: Identifies an export of the ADFS DKM Master Key from Active Directory.
 References: https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/, 
 https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html?1

## MFA disabled for a user

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-12-16T00:00:00Z

### Details

> Description: Multi-Factor Authentication (MFA) helps prevent credential compromise. This alert identifies when an attempt has been made to diable MFA for a user 

## Squid proxy events related to mining pools

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-07-12T00:00:00Z

### Details

> Description: Checks for Squid proxy events in Syslog associated with common mining pools .This query presumes the default Squid log format is being used. 
 http://www.squid-cache.org/Doc/config/access_log/

## High Number of Urgent Vulnerabilities Detected

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-06-20T00:00:00Z

### Details

> Description: This Creates an incident when a host has a high number of Urgent, severity 5, vulnerabilities detected.

## Password spray attack against Azure AD application

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-03-26T00:00:00Z

### Details

> Description: Identifies evidence of password spray activity against Azure AD applications by looking for failures from multiple accounts from the same
IP address within a time window. If the number of accounts breaches the threshold just once, all failures from the IP address within the time range
are bought into the result. Details on whether there were successful authentications by the IP address within the time window are also included.
This can be an indicator that an attack was successful.
The default failure acccount threshold is 5, Default time window for failures is 20m and default look back window is 3 days
Note: Due to the number of possible accounts involved in a password spray it is not possible to map identities to a custom entity.
References: https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes.

## Rare application consent

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-07-04T00:00:00Z

### Details

> Description: This will alert when the "Consent to application" operation occurs by a user that has not done this operation before or rarely does this.
This could indicate that permissions to access the listed Azure App were provided to a malicious actor. 
Consent to application, Add service principal and Add OAuth2PermissionGrant should typically be rare events. 
This may help detect the Oauth2 attack that can be initiated by this publicly available tool - https://github.com/fireeye/PwnAuth
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.

## SSH - Potential Brute Force

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-20T00:00:00Z

### Details

> Description: Identifies an IP address that had 15 failed attempts to sign in via SSH in a 4 hour block during a 24 hour time period.

## Changes to Amazon VPC settings

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-27T00:00:00Z

### Details

> Description: Amazon Virtual Private Cloud (Amazon VPC) lets you provision a logically isolated section of the AWS Cloud where you can launch AWS resources
in a virtual network that you define.
This identifies changes to Amazon VPC (Virtual Private Cloud) settings such as new ACL entries,routes, routetable or Gateways.
More information: https://medium.com/@GorillaStack/the-most-important-aws-cloudtrail-security-events-to-track-a5b9873f8255 
and AWS VPC API Docs: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/OperationList-query-vpc.html

## (Preview) TI map Domain entity to PaloAlto

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-28T00:00:00Z

### Details

> Description: Identifies a match in Palo Alto data in CommonSecurityLog table from any Domain IOC from TI

## (Preview) TI map Domain entity to Syslog

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-28T00:00:00Z

### Details

> Description: Identifies a match in Syslog table from any Domain IOC from TI

## ClientDeniedAccess

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-06-06T00:00:00Z

### Details

> Description: Creates an incident in the event a Client has an excessive amounts of denied access requests.

## Time series anomaly for data size transferred to public internet

### Informations

> lastUpdatedDateUTC: 2020-12-11T00:00:00Z

> createdDateUTC: 2019-05-07T00:00:00Z

### Details

> Description: Identifies anomalous data transfer to public networks. The query leverages built-in KQL anomaly detection algorithms that detects large deviations from a baseline pattern.
A sudden increase in data transferred to unknown public networks is an indication of data exfiltration attempts and should be investigated.
The higher the score, the further it is from the baseline value.
The output is aggregated to provide summary view of unique source IP to destination IP address and port bytes sent traffic observed in the flagged anomaly hour.
The source IP addresses which were sending less than bytessentperhourthreshold have been exluded whose value can be adjusted as needed .
You may have to run queries for individual source IP addresses from SourceIPlist to determine if anything looks suspicious

## (Preview) TI map IP entity to WireData

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-27T00:00:00Z

### Details

> Description: Identifies a match in WireData from any IP IOC from TI

## Sensitive Azure Key Vault operations

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-07-01T00:00:00Z

### Details

> Description: Identifies when sensitive Azure Key Vault operations are used. This includes: VaultDelete, KeyDelete, KeyDecrypt, SecretDelete, SecretPurge, KeyPurge, SecretBackup, KeyBackup. 
Any Backup operations should match with expected scheduled backup activity.

## Possible STRONTIUM attempted credential harvesting

### Informations

> lastUpdatedDateUTC: 2020-11-05T00:00:00Z

> createdDateUTC: 2020-09-10T00:00:00Z

### Details

> Description: Surfaces potential STRONTIUM group Office365 credential harvesting attempts within OfficeActivity Logon events.
References: https://www.microsoft.com/security/blog/2020/09/10/strontium-detecting-new-patters-credential-harvesting/.

## Port Scan Detected

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-07-08T00:00:00Z

### Details

> Description: This alert creates an incident when a source IP addresses attempt to communicate with a large amount of distinct ports within a short period.

## User account enabled and disabled within 10 mins

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-14T00:00:00Z

### Details

> Description: Identifies when a user account is enabled and then disabled within 10 minutes. This can be an indication of compromise and
an adversary attempting to hide in the noise.

## Changes made to AWS CloudTrail logs

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-27T00:00:00Z

### Details

> Description: Attackers often try to hide their steps by deleting or stopping the collection of logs that could show their activity. 
This alert identifies any manipulation of AWS CloudTrail, Cloudwatch/EventBridge or VPC Flow logs.
More Information: AWS CloudTrail API: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_Operations.html
AWS Cloudwatch/Eventbridge API: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_Operations.html
AWS DelteteFlowLogs API : https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteFlowLogs.html 

## First access credential added to Application or Service Principal where no credential was present

### Informations

> lastUpdatedDateUTC: 2020-12-20T00:00:00Z

> createdDateUTC: 2020-11-30T00:00:00Z

### Details

> Description: This will alert when an admin or app owner account adds a new credential to an Application or Service Principal where there was no previous verify KeyCredential associated.
If a threat actor obtains access to an account with sufficient privileges and adds the alternate authentication material triggering this event, the threat actor can now authenticate as the Application or Service Principal using this credential.
Additional information on OAuth Credential Grants can be found in RFC 6749 Section 4.4 or https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.

## New executable via Office FileUploaded Operation

### Informations

> lastUpdatedDateUTC: 2020-03-02T00:00:00Z

> createdDateUTC: 2020-02-27T00:00:00Z

### Details

> Description: Identifies when executable file types are uploaded to Office services such as SharePoint and OneDrive.
List currently includes 'exe', 'inf', 'gzip', 'cmd', 'bat' file extensions.
Additionally, identifies when a given user is uploading these files to another users workspace.
This may be indication of a staging location for malware or other malicious activity.

## ADFS Key Export (Sysmon)

### Informations

> lastUpdatedDateUTC: 2020-12-22T00:00:00Z

> createdDateUTC: 2020-12-19T00:00:00Z

### Details

> Description: This detection uses Sysmon telemetry to detect potential ADFS certificate material export. 
In order to use this query you need to be collecting Sysmon EventIdD 17 and 18.
If you do not have Sysmon data in your workspace this query will raise an error stating:
Failed to resolve scalar expression named "[@Name]

## (Preview) TI map Email entity to SigninLogs

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-28T00:00:00Z

### Details

> Description: Identifies a match in SigninLogs table from any Email IOC from TI

## Malware in the recycle bin

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2018-09-14T00:00:00Z

### Details

> Description: Identifies malware that has been hidden in the recycle bin.
References: https://azure.microsoft.com/blog/how-azure-security-center-helps-reveal-a-cyberattack/.

## Malware attachment delivered

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-06-20T00:00:00Z

### Details

> Description: This query identifies a message containing a malware attachment that was delivered.

## (Preview) TI map IP entity to W3CIISLog

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-27T00:00:00Z

### Details

> Description: Identifies a match in W3CIISLog from any IP IOC from TI

## Group added to built in domain local or global group

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-27T00:00:00Z

### Details

> Description: Identifies when a recently created Group was added to a privileged built in domain local group or global group such as the 
Enterprise Admins, Cert Publishers or DnsAdmins.  Be sure to verify this is an expected addition.
References: For AD SID mappings - https://docs.microsoft.com/windows/security/identity-protection/access-control/active-directory-security-groups.

## Solorigate Network Beacon

### Informations

> lastUpdatedDateUTC: 2020-12-22T00:00:00Z

> createdDateUTC: 2020-12-17T00:00:00Z

### Details

> Description: Identifies a match across various data feeds for domains IOCs related to the Solorigate incident.
 References: https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/, 
 https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html?1

## (Preview) TI map Email entity to OfficeActivity

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-28T00:00:00Z

### Details

> Description: Identifies a match in OfficeActivity table from any Email IOC from TI

## Suspicious application consent similar to O365 Attack Toolkit

### Informations

> lastUpdatedDateUTC: 2020-06-29T00:00:00Z

> createdDateUTC: 2020-06-26T00:00:00Z

### Details

> Description: This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the MDSec O365 Attack Toolkit (https://github.com/mdsecactivebreach/o365-attack-toolkit).
The default permissions/scope for the MDSec O365 Attack toolkit are contacts.read, user.read, mail.read, notes.read.all, mailboxsettings.readwrite, and files.readwrite.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.

## Rare RDP Connections

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-01-14T00:00:00Z

### Details

> Description: Identifies when an RDP connection is new or rare related to any logon type by a given account today based on comparison with the previous 14 days.
RDP connections are indicated by the EventID 4624 with LogonType = 10

## New internet-exposed SSH endpoints

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-27T00:00:00Z

### Details

> Description: Looks for SSH endpoints with a history of sign-ins only from private IP addresses are accessed from a public IP address.

## Modified domain federation trust settings

### Informations

> lastUpdatedDateUTC: 2020-12-12T00:00:00Z

> createdDateUTC: 2020-12-11T00:00:00Z

### Details

> Description: This will alert when an user or application modifies the federation settings on the domain. For example, this alert will trigger when a new Active Directory Federated Service (ADFS) TrustedRealm object, such as a signing certificate, is added to the domain.
Modification to domain federation settings should be rare. Confirm the added or modified target domain/URL is legitimate administrator behavior.
To understand why an authorized user may update settings for a federated domain in Office 365, Azure, or Intune, see: https://docs.microsoft.com/office365/troubleshoot/active-directory/update-federated-domain-office-365.
For details on security realms that accept security tokens, see the ADFS Proxy Protocol (MS-ADFSPP) specification: https://docs.microsoft.com/openspecs/windows_protocols/ms-adfspp/e7b9ea73-1980-4318-96a6-da559486664b.
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.

## (Preview) TI map Domain entity to DnsEvent

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-28T00:00:00Z

### Details

> Description: Identifies a match in DnsEvent table from any Domain IOC from TI

## Excessive NXDOMAIN DNS Queries

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-06-06T00:00:00Z

### Details

> Description: This creates an incident in the event a client generates excessive amounts of DNS queries for non-existent domains.

## Palo Alto - potential beaconing detected

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-05-07T00:00:00Z

### Details

> Description: Identifies beaconing patterns from Palo Alto Network traffic logs based on recurrent timedelta patterns. 
The query leverages various KQL functions to calculate time deltas and then compares it with total events observed in a day to find percentage of beaconing. 
This outbound beaconing pattern to untrusted public networks should be investigated for any malware callbacks or data exfiltration attempts.
Reference Blog:
http://www.austintaylor.io/detect/beaconing/intrusion/detection/system/command/control/flare/elastic/stack/2017/06/10/detect-beaconing-with-flare-elasticsearch-and-intrusion-detection-systems/

## Threats detected by Eset

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-07-09T00:00:00Z

### Details

> Description: Escalates threats detected by Eset.

## (Preview) TI map URL entity to Syslog data

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-27T00:00:00Z

### Details

> Description: Identifies a match in Syslog data from any URL IOC from TI

## Known GALLIUM domains and hashes

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-12-06T00:00:00Z

### Details

> Description: GALLIUM command and control domains and hash values for tools and malware used by GALLIUM. 
 Matches domain name IOCs related to the GALLIUM activity group with CommonSecurityLog, DnsEvents, VMConnection and SecurityEvents dataTypes.
 References: https://www.microsoft.com/security/blog/2019/12/12/gallium-targeting-global-telecom/ 

## Mail.Read Permissions Granted to Application

### Informations

> lastUpdatedDateUTC: 2020-12-19T00:00:00Z

> createdDateUTC: 2020-12-19T00:00:00Z

### Details

> Description: This query look for applications that have been granted permissions to Read Mail (Permissions field has Mail.Read) and subsequently has been consented to. This can help identify applications that have been abused to gain access to mailboxes.

## Network endpoint to host executable correlation

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-07-08T00:00:00Z

### Details

> Description: Correlates blocked URLs hosting [malicious] executables with host endpoint data
to identify potential instances of executables of the same name having been recently run.

## Suspicious Resource deployment

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-05T00:00:00Z

### Details

> Description: Identifies when a rare Resource and ResourceGroup deployment occurs by a previously unseen Caller.

## New user created and added to the built-in administrators group

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-22T00:00:00Z

### Details

> Description: Identifies when a user account was created and then added to the builtin Administrators group in the same day.
This should be monitored closely and all additions reviewed.

## (Preview) TI map Domain entity to CommonSecurityLog

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-28T00:00:00Z

### Details

> Description: Identifies a match in CommonSecurityLog table from any Domain IOC from TI

## SharePointFileOperation via devices with previously unseen user agents

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-23T00:00:00Z

### Details

> Description: Identifies if the number of documents uploaded or downloaded from device(s) associated
with a previously unseen user agent exceeds a threshold (default is 5).

## New High Severity Vulnerability Detected Across Multiple Hosts

### Informations

> lastUpdatedDateUTC: 2020-06-20T00:00:00Z

> createdDateUTC: 2020-06-20T00:00:00Z

### Details

> Description: This creates an incident when a new high severity vulnerability is detected across multilple hosts

## Known IRIDIUM IP

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-12-16T00:00:00Z

### Details

> Description: IRIDIUM command and control IP. Identifies a match across various data feeds for IP IOCs related to the IRIDIUM activity group.

## Cisco - firewall block but success logon to Azure AD

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-07-08T00:00:00Z

### Details

> Description: Correlate IPs blocked by a Cisco firewall appliance with successful Azure Active Directory signins. 
Because the IP was blocked by the firewall, that same IP logging on successfully to AAD is potentially suspect
and could indicate credential compromise for the user account.

## Known Manganese IP and UserAgent activity

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-10-02T00:00:00Z

### Details

> Description: Matches IP plus UserAgent IOCs in OfficeActivity data, along with IP plus Connection string information in the CommonSecurityLog data related to Manganese group activity.
References: 
https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101/
https://fortiguard.com/psirt/FG-IR-18-384

## Successful logon from IP and failure from a different IP

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-19T00:00:00Z

### Details

> Description: Identifies when a user account successfully logs onto an Azure App from one IP and within 10 mins failed to logon to the same App via a different IP.
This may indicate a malicious attempt at password guessing based on knowledge of the users account.

## Squid proxy events for ToR proxies

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-07-12T00:00:00Z

### Details

> Description: Check for Squid proxy events associated with common ToR proxies. This query presumes the default squid log format is being used.
http://www.squid-cache.org/Doc/config/access_log/

## Exchange workflow MailItemsAccessed operation anomaly

### Informations

> lastUpdatedDateUTC: 2020-12-10T00:00:00Z

> createdDateUTC: 2020-12-10T00:00:00Z

### Details

> Description: Identifies anomalous increases in Exchange mail items accessed operations. 
The query leverages KQL built-in anomaly detection algorithms to find large deviations from baseline patterns. 
Sudden increases in execution frequency of sensitive actions should be further investigated for malicious activity.
Manually change scorethreshold from 1.5 to 3 or higher to reduce the noise based on outliers flagged from the query criteria.
Read more about MailItemsAccessed- https://docs.microsoft.com/microsoft-365/compliance/advanced-audit?view=o365-worldwide#mailitemsaccessed

## Changes to internet facing AWS RDS Database instances

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-27T00:00:00Z

### Details

> Description: Amazon Relational Database Service (RDS) is scalable relational database in the cloud. 
If your organization have one or more AWS RDS Databases running, monitoring changes to especially internet facing AWS RDS (Relational Database Service) 
Once alerts triggered, validate if changes observed are authorized and adhere to change control policy. 
More information: https://medium.com/@GorillaStack/the-most-important-aws-cloudtrail-security-events-to-track-a5b9873f8255
and RDS API Reference Docs: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_Operations.html

## (Preview) TI map File Hash to Security Event

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-27T00:00:00Z

### Details

> Description: Identifies a match in Security Event data from any File Hash IOC from TI

## Failed logon attempts in authpriv

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-14T00:00:00Z

### Details

> Description: Identifies failed logon attempts from unknown users in Syslog authpriv logs. The unknown user means the account that tried to log in 
isn't provisioned on the machine. A few hits could indicate someone attempting to access a machine they aren't authorized to access. 
If there are many of hits, especially from outside your network, it could indicate a brute force attack. 
Default threshold for logon attempts is 15.

## Explicit MFA Deny

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-10-14T00:00:00Z

### Details

> Description: User explicitly denies MFA push, indicating that login was not expected and the account's password may be compromised.

## Possible STRONTIUM attempted credential harvesting

### Informations

> lastUpdatedDateUTC: 2020-11-05T00:00:00Z

> createdDateUTC: 2020-09-10T00:00:00Z

### Details

> Description: Surfaces potential STRONTIUM group Office365 credential harvesting attempts within OfficeActivity Logon events.

## Failed AzureAD logons but success logon to host

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-20T00:00:00Z

### Details

> Description: Identifies a list of IP addresses with a minimum number (default of 5) of failed logon attempts to Azure Active Directory.
Uses that list to identify any successful remote logons to hosts from these IPs within the same timeframe.

## AD account with don't expire password - disabled

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-01-28T00:00:00Z

### Details

> Description: Identifies whenever a user account has the setting "Password Never Expires" in the user account properties selected.
This is indicated in Security event 4738 in the EventData item labeled UserAccountControl with an included value of %%2089 
%%2089 resolves to "Don't Expire Password - Disabled".

## Critical Threat Detected

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-06-20T00:00:00Z

### Details

> Description: This creates an incident in the event a critical threat was identified on a Carbon Black managed endpoint.

## Possible contact with a domain generated by a DGA

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-03-27T00:00:00Z

### Details

> Description: Identifies contacts with domains names in CommonSecurityLog that might have been generated by a Domain Generation Algorithm (DGA). DGAs can be used
by malware to generate rendezvous points that are difficult to predict in advance. This detection uses the Alexa Top 1 million domain names to build a model
of what normal domains look like. It uses this to identify domains that may have been randomly generated by an algorithm.
The triThreshold is set to 500 - increase this to report on domains that are less likely to have been randomly generated, decrease it for more likely.
The start time and end time look back over 6 hours of data and the dgaLengthThreshold is set to 8 - meaning domains whose length is 8 or more are reported.

## Multiple RDP connections from Single System

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-10-21T00:00:00Z

### Details

> Description: Identifies when an RDP connection is made to multiple systems and above the normal for the previous 7 days.  
Connections from the same system with the same account within the same day.
RDP connections are indicated by the EventID 4624 with LogonType = 10

## (Preview) TI map Email entity to SecurityAlert

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-28T00:00:00Z

### Details

> Description: Identifies a match in SecurityAlert table from any Email IOC from TI which will extend coverage to datatypes such as MCAS, StorageThreatProtection and many others

## (Preview) TI map File Hash to CommonSecurityLog Event

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-30T00:00:00Z

### Details

> Description: Identifies a match in CommonSecurityLog Event data from any FileHash IOC from TI

## Request for single resource on domain

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-03-17T00:00:00Z

### Details

> Description: This will look for connections to a domain where only a single file is requested, this is unusual as most modern web applications require additional recources. This type of activity is often assocaited with malware beaconing or tracking URL's delivered in emails. Developed for Zscaler but applicable to any outbound web logging.

## Known Phosphorus group domains/IP

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-10-20T00:00:00Z

### Details

> Description: Matches domain name IOCs related to Phosphorus group activity with CommonSecurityLog, DnsEvents, OfficeActivity and VMConnection dataTypes.
References: https://blogs.microsoft.com/on-the-issues/2019/03/27/new-steps-to-protect-customers-from-hacking/.

## Malware Link Clicked

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-06-20T00:00:00Z

### Details

> Description: This query identifies a user clicking on an email link whose threat category is classified as a malware

## Malicious web application requests linked with MDATP alerts

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-05-21T00:00:00Z

### Details

> Description: Takes MDATP alerts where web scripts are present in the evidence and correlates with requests made to those scripts
in the WCSIISLog to surface new alerts for potentially malicious web request activity.
The lookback for alerts is set to 1h and the lookback for W3CIISLogs is set to 7d. A sample set of popular web script extensions
has been provided in scriptExtensions that should be tailored to your environment.

## Exchange AuditLog disabled

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-04-15T00:00:00Z

### Details

> Description: Identifies when the exchange audit logging has been disabled which may be an adversary attempt
to evade detection or avoid other defenses.

## Account added and removed from privileged groups

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-04-03T00:00:00Z

### Details

> Description: Identifies accounts that are added to privileged group and then quickly removed, which could be a sign of compromise.' 

## Anomalous sign-in location by user account and authenticating application

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-05T00:00:00Z

### Details

> Description: This query over Azure Active Directory sign-in considers all user sign-ins for each Azure Active 
Directory application and picks out the most anomalous change in location profile for a user within an 
individual application. An alert is generated for recent sign-ins that have location counts that are anomalous
over last day but also over the last 7-day and 14-day periods.

## Cisco ASA - average attack detection rate increase

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-28T00:00:00Z

### Details

> Description: This will help you determine if Cisco ASA devices are under heavier attack than normal over the last hour versus the previous 6 hours based on DeviceEventClassID 733100
References: https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog/syslogs9.html
Details on how to further troubleshoot/investigate: https://www.cisco.com/c/en/us/support/docs/security/asa-5500-x-series-next-generation-firewalls/113685-asa-threat-detection.html

## Malicious Inbox Rule

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-03-02T00:00:00Z

### Details

> Description: Often times after the initial compromise the attackers create inbox rules to delete emails that contain certain keywords. 
 This is done so as to limit ability to warn compromised users that they've been compromised. Below is a sample query that tries to detect this.
Reference: https://www.reddit.com/r/sysadmin/comments/7kyp0a/recent_phishing_attempts_my_experience_and_what/

## SecurityEvent - Multiple authentication failures followed by a success

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-04-03T00:00:00Z

### Details

> Description: Identifies accounts who have failed to logon to the domain multiple times in a row, followed by a successful authentication
within a short time frame. Multiple failed attempts followed by a success can be an indication of a brute force attempt or
possible mis-configuration of a service account within an environment.
The lookback is set to 6h and the authentication window and threshold are set to 1h and 5, meaning we need to see a minimum
of 5 failures followed by a success for an account within 1 hour to surface an alert.

## Excessive Denied Proxy Traffic

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-06-06T00:00:00Z

### Details

> Description: This alert creates an incident when a client generates an excessive amounts of denied proxy traffic.

## Attempts to sign in to disabled accounts

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-11T00:00:00Z

### Details

> Description: Identifies failed attempts to sign in to disabled accounts across multiple Azure Applications.
Default threshold for Azure Applications attempted to sign in to is 3.
References: https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes
50057 - User account is disabled. The account has been disabled by an administrator.

## Monitor AWS Credential abuse or hijacking

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-27T00:00:00Z

### Details

> Description: Looking for GetCallerIdentity Events where the UserID Type is AssumedRole 
An attacker who has assumed the role of a legitimate account can call the GetCallerIdentity function to determine what account they are using.
A legitimate user using legitimate credentials would not need to call GetCallerIdentity since they should already know what account they are using.
More Information: https://duo.com/decipher/trailblazer-hunts-compromised-credentials-in-aws
AWS STS GetCallerIdentity API: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html 

## Failed AWS Console logons but success logon to AzureAD

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-20T00:00:00Z

### Details

> Description: Identifies a list of IP addresses with a minimum numbe(default of 5) of failed logon attempts to AWS Console.
Uses that list to identify any successful Azure Active Directory logons from these IPs within the same timeframe.

## User Accessed Suspicious URL Categories

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-06-06T00:00:00Z

### Details

> Description: Creates an incident in the event the requested URL accessed by the user has been identified as Suspicious, Phishing, or Hacking.

## Distributed Password cracking attempts in AzureAD

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-11T00:00:00Z

### Details

> Description: Identifies distributed password cracking attempts from the Azure Active Directory SigninLogs.
The query looks for unusually high number of failed password attempts coming from multiple locations for a user account.
References: https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes
50053   Account is locked because the user tried to sign in too many times with an incorrect user ID or password.
50055   Invalid password, entered expired password.
50056   Invalid or null password - Password does not exist in store for this user.
50126   Invalid username or password, or invalid on-premises username or password.

## Powershell Empire cmdlets seen in command line

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-01-25T00:00:00Z

### Details

> Description: Identifies instances of PowerShell Empire cmdlets in powershell process command line data.

## Potential DGA detected

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-07T00:00:00Z

### Details

> Description: Identifies clients with a high NXDomain count which could be indicative of a DGA (cycling through possible C2 domains
where most C2s are not live). Alert is generated when a new IP address is seen (based on not being seen associated with 
NXDomain records in prior 10-day baseline period).

## Anomalous login followed by Teams action

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-06-30T00:00:00Z

### Details

> Description: Detects anomalous IP address usage by user accounts and then checks to see if a suspicious Teams action is performed.
Query calculates IP usage Delta for each user account and selects accounts where a delta >= 90% is observed between the most and least used IP.
To further reduce results the query performs a prevalence check on the lowest used IP's country, only keeping IP's where the country is unusual for the tenant (dynamic ranges)
Finally the user accounts activity within Teams logs is checked for suspicious commands (modifying user privileges or admin actions) during the period the suspicious IP was active.

## Excessive Failed Authentication from Invalid Inputs

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-06-06T00:00:00Z

### Details

> Description: Creates an incident in the event that a user generates an excessive amount of failed authentications due to invalid inputs, indications of a potential brute force.

## (Preview) TI map URL entity to PaloAlto data

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-27T00:00:00Z

### Details

> Description: Identifies a match in PaloAlto data from any URL IOC from TI

## Brute Force Attack against GitHub Account

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-06-02T00:00:00Z

### Details

> Description: Attackers who are trying to guess your users' passwords or use brute-force methods to get in. If your organization is using SSO with Azure Active Directory, authentication logs to GitHub.com will be generated. Using the following query can help you identify a sudden increase in failed logon attempt of users.

## Failed AzureAD logons but success logon to AWS Console

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-20T00:00:00Z

### Details

> Description: Identifies a list of IP addresses with a minimum number(defualt of 5) of failed logon attempts to Azure Active Directory.
Uses that list to identify any successful AWS Console logons from these IPs within the same timeframe.

## (Preview) TI map Email entity to SecurityEvent

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-28T00:00:00Z

### Details

> Description: Identifies a match in SecurityEvent table from any Email IOC from TI

## GitHub Signin Burst from Multiple Locations

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-06-02T00:00:00Z

### Details

> Description: This alerts when there Signin burst from multiple locations in GitHub (AAD SSO).

## IP with multiple failed Azure AD logins successfully logs in to Palo Alto VPN

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-09-04T00:00:00Z

### Details

> Description: This query creates a list of IP addresses with a number failed login attempts to AAD 
above a set threshold.  It then looks for any successful Palo Alto VPN logins from any
of these IPs within the same timeframe.

## Known Malware Detected

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-06-20T00:00:00Z

### Details

> Description: This creates an incident when a known Malware is detected on a endpoint managed by a Carbon Black.

## Rare and potentially high-risk Office operations

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-13T00:00:00Z

### Details

> Description: Identifies Office operations that are typically rare and can provide capabilities useful to attackers.

## High count of connections by client IP on many ports

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-03-19T00:00:00Z

### Details

> Description: Identifies when 30 or more ports are used for a given client IP in 10 minutes occurring on the IIS server.
This could be indicative of attempted port scanning or exploit attempt at internet facing web applications.  
This could also simply indicate a misconfigured service or device.
References:
IIS status code mapping - https://support.microsoft.com/help/943891/the-http-status-code-in-iis-7-0-iis-7-5-and-iis-8-0
Win32 Status code mapping - https://msdn.microsoft.com/library/cc231199.aspx

## Office policy tampering

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-04-15T00:00:00Z

### Details

> Description: Identifies if any tampering is done to either auditlog, ATP Safelink, SafeAttachment, AntiPhish or Dlp policy. 
An adversary may use this technique to evade detection or avoid other policy based defenses.
References: https://docs.microsoft.com/powershell/module/exchange/advanced-threat-protection/remove-antiphishrule?view=exchange-ps.

## Changes to AWS Elastic Load Balancer security groups

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-27T00:00:00Z

### Details

> Description: Elastic Load Balancer distributes incoming traffic across multiple instances in multiple availability Zones. This increases the fault tolerance of your applications. 
 Unwanted changes to Elastic Load Balancer specific security groups could open your environment to attack and  hence needs monitoring.
 More information: https://medium.com/@GorillaStack/the-most-important-aws-cloudtrail-security-events-to-track-a5b9873f8255 
 and https://aws.amazon.com/elasticloadbalancing/.

## THALLIUM domains included in DCU takedown

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-01-06T00:00:00Z

### Details

> Description: THALLIUM spearphishing and command and control domains included in December 2019 DCU/MSTIC takedown. 
 Matches domain name IOCs related to the THALLIUM activity group with CommonSecurityLog, DnsEvents, VMConnection and SecurityEvents dataTypes.
 References: https://blogs.microsoft.com/on-the-issues/2019/12/30/microsoft-court-action-against-nation-state-cybercrime/ 

## Process executed from binary hidden in Base64 encoded file

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-01-24T00:00:00Z

### Details

> Description: Encoding malicious software is a technique used to obfuscate files from detection. 
The first CommandLine component is looking for Python decoding base64. 
The second CommandLine component is looking for Bash/sh command line base64 decoding.
The third one is looking for Ruby decoding base64.

## (Preview) TI map URL entity to AuditLogs

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-27T00:00:00Z

### Details

> Description: Identifies a match in AuditLogs from any URL IOC from TI

## User account created and deleted within 10 mins

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-14T00:00:00Z

### Details

> Description: Identifies when a user account is created and then deleted within 10 minutes. This can be an indication of compromise and
an adversary attempting to hide in the noise.

## Rare subscription-level operations in Azure

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-24T00:00:00Z

### Details

> Description: This query looks for a few sensitive subscription-level events based on Azure Activity Logs. 
 For example this monitors for the operation name 'Create or Update Snapshot' which is used for creating backups but could be misused by attackers 
 to dump hashes or extract sensitive information from the disk.

## Several deny actions registered

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-10-19T00:00:00Z

### Details

> Description: Identifies attack pattern when attacker tries to move, or scan, from resource to resource on the network and creates an incident when a source has more than 1 registered deny action in Azure Firewall.

## Potential DHCP Starvation Attack

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-06-06T00:00:00Z

### Details

> Description: This creates an incident in the event that an excessive amount of DHCPREQUEST have been recieved by a DHCP Server and could potentially be an indication of a DHCP Starvation Attack.

## Potential Password Spray Attack

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-07-08T00:00:00Z

### Details

> Description: This query searches for failed attempts to log into the Okta console from more than 15 various users within a 5 minute timeframe from the same source. This is a potential indication of a password spray attack

## Potential Kerberoasting

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-04-01T00:00:00Z

### Details

> Description: A service principal name (SPN) is used to uniquely identify a service instance in a Windows environment. 
Each SPN is usually associated with a service account. Organizations may have used service accounts with weak passwords in their environment. 
An attacker can try requesting Kerberos ticket-granting service (TGS) service tickets for any SPN from a domain controller (DC) which contains 
a hash of the Service account. This can then be used for offline cracking. This hunting query looks for accounts that are generating excessive 
requests to different resources within the last hour compared with the previous 24 hours.  Normal users would not make an unusually large number 
of request within a small time window. This is based on 4769 events which can be very noisy so environment based tweaking might be needed.

## Azure Key Vault access TimeSeries anomaly

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-07-01T00:00:00Z

### Details

> Description: Indentifies a sudden increase in count of Azure Key Vault secret or vault access operations by CallerIPAddress. The query leverages a built-in KQL anomaly detection algorithm 
to find large deviations from baseline Azure Key Vault access patterns. Any sudden increase in the count of Azure Key Vault accesses can be an 
indication of adversary dumping credentials via automated methods. If you are seeing any noise, try filtering known source(IP/Account) and user-agent combinations.
TimeSeries Reference Blog: https://techcommunity.microsoft.com/t5/azure-sentinel/looking-for-unknown-anomalies-what-is-normal-time-series/ba-p/555052

## Mail redirect via ExO transport rule

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-05-05T00:00:00Z

### Details

> Description: Identifies when Exchange Online transport rule configured to forward emails.
This could be an adversary mailbox configured to collect mail from multiple user accounts.

## Anomalous User Agent connection attempt

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-20T00:00:00Z

### Details

> Description: Identifies connection attempts (success or fail) from clients with very short or very long User Agent strings and with less than 100 connection attempts.

## (Preview) TI map Email entity to AzureActivity

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-28T00:00:00Z

### Details

> Description: Identifies a match in AzureActivity table from any Email IOC from TI

## User added to Azure Active Directory Privileged Groups

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-07-15T00:00:00Z

### Details

> Description: This will alert when a user is added to any of the Privileged Groups.
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.
For Administrator role permissions in Azure Active Directory please see https://docs.microsoft.com/azure/active-directory/users-groups-roles/directory-assign-admin-roles

## Sign-ins from IPs that attempt sign-ins to disabled accounts

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-11T00:00:00Z

### Details

> Description: Identifies IPs with failed attempts to sign in to one or more disabled accounts signed in successfully to another account.
References: https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes
50057 - User account is disabled. The account has been disabled by an administrator.

## PulseConnectSecure - Potential Brute Force Attempts

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-06-06T00:00:00Z

### Details

> Description: This query identifies evidence of potential brute force attack by looking at multiple failed attempts to log into the VPN server

## Rare client observed with high reverse DNS lookup count

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-07T00:00:00Z

### Details

> Description: Identifies clients with a high reverse DNS counts which could be carrying out reconnaissance or discovery activity.
Alert is generated if the IP performing such reverse DNS lookups was not seen doing so in the preceding 7-day period.

## Mass secret retrieval from Azure Key Vault

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-07-01T00:00:00Z

### Details

> Description: Identifies mass secret retrieval from Azure Key Vault observed by a single user. 
Mass secret retrival crossing a certain threshold is an indication of credential dump operations or mis-configured applications. 
You can tweak the EventCountThreshold based on average count seen in your environment 
and also filter any known sources (IP/Account) and useragent combinations based on historical analysis to further reduce noise

## Suspicious application consent similar to PwnAuth

### Informations

> lastUpdatedDateUTC: 2020-06-29T00:00:00Z

> createdDateUTC: 2020-06-26T00:00:00Z

### Details

> Description: This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the FireEye PwnAuth toolkit (https://github.com/fireeye/PwnAuth).
The default permissions/scope for the PwnAuth toolkit are user.read, offline_access, mail.readwrite, mail.send, and files.read.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.

## Correlate Unfamiliar sign-in properties and atypical travel alerts

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-09-19T00:00:00Z

### Details

> Description: When a user has both an Unfamiliar sign-in properties alert and an Atypical travel alert within 20 minutes, the alert should be handled with a higher severity

## Known ZINC related maldoc hash

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-10-30T00:00:00Z

### Details

> Description: Document hash used by ZINC in highly targeted spear phishing campaign.

## Suspicious application consent for offline access

### Informations

> lastUpdatedDateUTC: 2020-06-29T00:00:00Z

> createdDateUTC: 2020-06-26T00:00:00Z

### Details

> Description: This will alert when a user consents to provide a previously-unknown Azure application with offline access via OAuth.
Offline access will provide the Azure App with access to the listed resources without requiring two-factor authentication.
Consent to applications with offline access and read capabilities should be rare, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.

## Known CERIUM domains and hashes

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-10-30T00:00:00Z

### Details

> Description: CERIUM malicious webserver and hash values for maldocs and malware. 
 Matches domain name IOCs related to the CERIUM activity group with CommonSecurityLog, DnsEvents, and VMConnection dataTypes.

## (Preview) TI map URL entity to SecurityAlert data

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-27T00:00:00Z

### Details

> Description: Identifies a match in SecurityAlert data from any URL IOC from TI

## (Preview) TI map Domain entity to SecurityAlert

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-28T00:00:00Z

### Details

> Description: Identifies a match in SecurityAlert table from any Domain IOC from TI

## Palo Alto - possible internal to external port scanning

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-28T00:00:00Z

### Details

> Description: Identifies a list of internal Source IPs (10.x.x.x Hosts) that have triggered 10 or more non-graceful tcp server resets from one or more Destination IPs which 
results in an "ApplicationProtocol = incomplete" designation. The server resets coupled with an "Incomplete" ApplicationProtocol designation can be an indication 
of internal to external port scanning or probing attack. 
References: https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClUvCAK and
https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClTaCAK

## RDP Nesting

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-10-21T00:00:00Z

### Details

> Description: Identifies when an RDP connection is made to a first system and then an RDP connection is made from the first system 
to another system with the same account within the 60 minutes. Additionally, if historically daily  
RDP connections are indicated by the logged EventID 4624 with LogonType = 10

## Web sites blocked by Eset

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-07-09T00:00:00Z

### Details

> Description: Create alert on web sites blocked by Eset.

## Failed login attempts to Azure Portal

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-11T00:00:00Z

### Details

> Description: Identifies failed login attempts in the Azure Active Directory SigninLogs to the Azure Portal.  Many failed logon 
attempts or some failed logon attempts from multiple IPs could indicate a potential brute force attack.  
The following are excluded due to success and non-failure results:
References: https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes
0 - successful logon
50125 - Sign-in was interrupted due to a password reset or password registration entry.
50140 - This error occurred due to 'Keep me signed in' interrupt when the user was signing-in.

## Failed host logons but success logon to AzureAD

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-20T00:00:00Z

### Details

> Description: Identifies a list of IP addresses with a minimum number(default of 5) of failed logon attempts to remote hosts.
Uses that list to identify any successful logons to Azure Active Directory from these IPs within the same timeframe.

## (Preview) TI map IP entity to AWSCloudTrail

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-27T00:00:00Z

### Details

> Description: Identifies a match in AWSCloudTrail from any IP IOC from TI

## User Login from Different Countries within 3 hours

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-07-08T00:00:00Z

### Details

> Description: This query searches for successful user logins to the Okta Console from different countries within 3 hours

## (Preview) TI map IP entity to SigninLogs

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-27T00:00:00Z

### Details

> Description: Identifies a match in SigninLogs from any IP IOC from TI

## Known STRONTIUM group domains - July 2019

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-07-25T00:00:00Z

### Details

> Description: Matches domain name IOCs related to Strontium group activity published July 2019 with CommonSecurityLog, DnsEvents and VMConnection dataTypes.
References: https://blogs.microsoft.com/on-the-issues/2019/07/17/new-cyberthreats-require-new-ways-to-protect-democracy/.

## Multiple Teams deleted by a single user

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-09-13T00:00:00Z

### Details

> Description: This detection flags the occurrences of deleting multiple teams within an hour.
This data is a part of Office 365 Connector in Azure Sentinel.

## User account added to built in domain local or global group

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-14T00:00:00Z

### Details

> Description: Identifies when a user account has been added to a privileged built in domain local group or global group 
such as the Enterprise Admins, Cert Publishers or DnsAdmins. Be sure to verify this is an expected addition.

## Changes to AWS Security Group ingress and egress settings

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-27T00:00:00Z

### Details

> Description: A Security Group acts as a virtual firewall of an instance to control inbound and outbound traffic. 
 Hence, ingress and egress settings changes to AWS Security Group should be monitored as these can expose the enviornment to new attack vectors.
More information: https://medium.com/@GorillaStack/the-most-important-aws-cloudtrail-security-events-to-track-a5b9873f8255.

## (Preview) TI map IP entity to VMConnection

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-27T00:00:00Z

### Details

> Description: Identifies a match in VMConnection from any IP IOC from TI

## High count of failed attempts from same client IP

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-03-19T00:00:00Z

### Details

> Description: Identifies when 20 or more failed attempts from a given client IP in 1 minute occur on the IIS server.
This could be indicative of an attempted brute force. This could also simply indicate a misconfigured service or device.
Recommendations: Validate that these are expected connections from the given Client IP.  If the client IP is not recognized, 
potentially block these connections at the edge device.
If these are expected connections, verify the credentials are properly configured on the system, service, application or device 
that is associated with the client IP.
References:
IIS status code mapping: https://support.microsoft.com/help/943891/the-http-status-code-in-iis-7-0-iis-7-5-and-iis-8-0
Win32 Status code mapping: https://msdn.microsoft.com/library/cc231199.aspx

## Solorigate Defender Detections

### Informations

> lastUpdatedDateUTC: 2020-12-19T00:00:00Z

> createdDateUTC: 2020-12-17T00:00:00Z

### Details

> Description: Surfaces any Defender Alert for Solorigate Events. In Azure Sentinel the SecurityAlerts table includes only the Device Name of the affected device, this query joins the DeviceInfo table to clearly connect other information such as 
 Device group, ip, logged on users etc. This way, the Sentinel user can have all the pertinent device info in one view for all the the Solarigate Defender alerts.

## Known PHOSPHORUS group domains/IP - October 2020

### Informations

> lastUpdatedDateUTC: 2020-11-19T00:00:00Z

> createdDateUTC: 2020-10-20T00:00:00Z

### Details

> Description: Matches IOCs related to PHOSPHORUS group activity published October 2020 with CommonSecurityLog, DnsEvents, OfficeActivity and VMConnection dataTypes.
References: 

## Multiple Password Reset by user

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-09-03T00:00:00Z

### Details

> Description: This query will determine multiple password resets by user across multiple data sources. 
Account manipulation including password reset may aid adversaries in maintaining access to credentials 
and certain permission levels within an environment.

## DNS events related to ToR proxies

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-07T00:00:00Z

### Details

> Description: Identifies IP addresses performing DNS lookups associated with common ToR proxies.

## Fortinet - Beacon pattern detected

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-03-31T00:00:00Z

### Details

> Description: Identifies patterns in the time deltas of contacts between internal and external IPs in Fortinet network data that are consistent with beaconing.
 Accounts for randomness (jitter) and seasonality such as working hours that may have been introduced into the beacon pattern.
 The lookback is set to 1d, the minimum granularity in time deltas is set to 60 seconds and the minimum number of beacons required to emit a
 detection is set to 4.
 Increase the lookback period to capture beacons with larger periodicities.
 The jitter tolerance is set to 0.2 - This means we account for an overall 20% deviation from the infered beacon periodicity. Seasonality is dealt with
 automatically using series_outliers.
 Note: In large environments it may be necessary to reduce the lookback period to get fast query times.

## Full Admin policy created and then attached to Roles, Users or Groups

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-04-27T00:00:00Z

### Details

> Description: Identity and Access Management (IAM) securely manages access to AWS services and resources. 
Identifies when a policy is created with Full Administrators Access (Allow-Action:*,Resource:*). 
This policy can be attached to role,user or group and may be used by an adversary to escalate a normal user privileges to an adminsitrative level.
AWS IAM Policy Grammar: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
and AWS IAM API at https://docs.aws.amazon.com/IAM/latest/APIReference/API_Operations.html

## New access credential added to Application or Service Principal

### Informations

> lastUpdatedDateUTC: 2020-12-20T00:00:00Z

> createdDateUTC: 2020-11-30T00:00:00Z

### Details

> Description: This will alert when an admin or app owner account adds a new credential to an Application or Service Principal where a verify KeyCredential was already present for the app.
If a threat actor obtains access to an account with sufficient privileges and adds the alternate authentication material triggering this event, the threat actor can now authenticate as the Application or Service Principal using this credential.
Additional information on OAuth Credential Grants can be found in RFC 6749 Section 4.4 or https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.

## Excessive Amount of Denied Connections from a Single Source

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-07-08T00:00:00Z

### Details

> Description: This creates an incident in the event that a single source IP address generates a excessive amount of denied connections.

## Malformed user agent

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-01-25T00:00:00Z

### Details

> Description: Malware authors will sometimes hardcode user agent string values when writing the network communication component of their malware.
Malformed user agents can be an indication of such malware.

## Cisco ASA - threat detection message fired

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-28T00:00:00Z

### Details

> Description: Identifies when the Cisco ASA Threat Detection engine fired an alert based on malicious activity occurring on the network inicated by DeviceEventClassID 733101-733105
Resources: https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog/syslogs9.html
Details on how to further troubleshoot/investigate: https://www.cisco.com/c/en/us/support/docs/security/asa-5500-x-series-next-generation-firewalls/113685-asa-threat-detection.html

## (Preview) TI map IP entity to AzureActivity

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-27T00:00:00Z

### Details

> Description: Identifies a match in AzureActivity from any IP IOC from TI

## SharePointFileOperation via previously unseen IPs

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-23T00:00:00Z

### Details

> Description: Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses
exceeds a threshold (default is 50).

## Azure Active Directory PowerShell accessing non-AAD resources

### Informations

> lastUpdatedDateUTC: 2020-12-15T00:00:00Z

> createdDateUTC: 2020-12-11T00:00:00Z

### Details

> Description: This will alert when an user or application signs in using Azure Active Directory PowerShell to access non-Active Directory resources, such as the Azure Key Vault, which may be undesired or unauthorized behavior.
For capabilities and expected behavior of the Azure Active Directory PowerShell module, see: https://docs.microsoft.com/powershell/module/azuread/?view=azureadps-2.0.
For further information on Azure Active Directory Signin activity reports, see: https://docs.microsoft.com/azure/active-directory/reports-monitoring/concept-sign-ins.

## DNS events related to mining pools

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-07T00:00:00Z

### Details

> Description: Identifies IP addresses that may be performing DNS lookups associated with common currency mining pools.

## Attempt to bypass conditional access rule in Azure AD

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-11T00:00:00Z

### Details

> Description: Identifies an attempt to Bypass conditional access rule(s) in Azure Active Directory.
The ConditionalAccessStatus column value details if there was an attempt to bypass Conditional Access
or if the Conditional access rule was not satisfied (ConditionalAccessStatus == 1).
References: 
https://docs.microsoft.com/azure/active-directory/conditional-access/overview
https://docs.microsoft.com/azure/active-directory/reports-monitoring/concept-sign-ins
https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes
ConditionalAccessStatus == 0 // Success
ConditionalAccessStatus == 1 // Failure
ConditionalAccessStatus == 2 // Not Applied
ConditionalAccessStatus == 3 // unknown

## Process execution frequency anomaly

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-05-07T00:00:00Z

### Details

> Description: Identifies anomalous spike in frequency of executions of sensitive processes which are often leveraged as attack vectors. 
The query leverages KQL built-in anomaly detection algorithms to find large deviations from baseline patterns. 
Sudden increases in execution frequency of sensitive processes should be further investigated for malicious activity.
Tune the values from 1.5 to 3 in series_decompose_anomalies for further outliers or based on custom threshold values for score.

## Time series anomaly detection for total volume of traffic

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-05-07T00:00:00Z

### Details

> Description: Identifies anamalous spikes in network traffic logs as compared to baseline or normal historical patterns. 
The query leverages a KQL built-in anomaly detection algorithm to find large deviations from baseline patterns. 
Sudden increases in network traffic volume may be an indication of data exfiltration attempts and should be investigated.
The higher the score, the further it is from the baseline value.
The output is aggregated to provide summary view of unique source IP to destination IP address and port traffic observed in the flagged anomaly hour. 
The source IP addresses which were sending less than percentotalthreshold of the total traffic have been exluded whose value can be adjusted as needed .
You may have to run queries for individual source IP addresses from SourceIPlist to determine if anything looks suspicious

## Multiple users email forwarded to same destination

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-23T00:00:00Z

### Details

> Description: Identifies when multiple (more than one) users mailboxes are configured to forward to the same destination. 
This could be an attacker-controlled destination mailbox configured to collect mail from multiple compromised user accounts.

## (Preview) TI map URL entity to OfficeActivity data

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-27T00:00:00Z

### Details

> Description: Identifies a match in OfficeActivity data from any URL IOC from TI

## Security Event log cleared

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-22T00:00:00Z

### Details

> Description: Checks for event id 1102 which indicates the security event log was cleared. 
It uses Event Source Name "Microsoft-Windows-Eventlog" to avoid generating false positives from other sources, like AD FS servers for instance.

## PulseConnectSecure - Large Number of Distinct Failed User Logins

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-06-06T00:00:00Z

### Details

> Description: This query identifies evidence of failed login attempts from a large number of distinct users on a Pulse Connect Secure VPN server

## Failed logon attempts by valid accounts within 10 mins

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-14T00:00:00Z

### Details

> Description: Identifies when failed logon attempts are 20 or higher during a 10 minute period (2 failed logons per minute minimum) from valid account.

## Suspicious granting of permissions to an account

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-05T00:00:00Z

### Details

> Description: Identifies IPs from which users grant access to other users on azure resources and alerts when a previously unseen source IP address is used.

## Base64 encoded Windows process command-lines

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2018-09-14T00:00:00Z

### Details

> Description: Identifies instances of a base64 encoded PE file header seen in the process command line parameter.

## New UserAgent observed in last 24 hours

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-04-01T00:00:00Z

### Details

> Description: Identifies new UserAgents observed in the last 24 hours versus the previous 14 days. This detection 
extracts words from user agents to build the baseline and determine rareity rather than perform a 
direct comparison. This avoids FPs caused by version numbers and other high entropy user agent components.
These new UserAgents could be benign. However, in normally stable environments,
these new UserAgents could provide a starting point for investigating malicious activity.
Note: W3CIISLog can be noisy depending on the environment, however OfficeActivity and AWSCloudTrail are
usually stable with low numbers of detections.

## Suspicious number of resource creation or deployment activities

### Informations

> lastUpdatedDateUTC: 2020-11-18T00:00:00Z

> createdDateUTC: 2019-02-05T00:00:00Z

### Details

> Description: Indicates when an anomalous number of VM creations or deployment activities occur in Azure via the AzureActivity log.
The anomaly detection identifies activities that have occurred both since the start of the day 1 day ago and the start of the day 7 days ago.
The start of the day is considered 12am UTC time.

## Microsoft COVID-19 file hash indicator matches

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-30T00:00:00Z

### Details

> Description: Identifies a match in CommonSecurityLog Event data from any FileHash published in the Microsoft COVID-19 Threat Intel Feed - as described at https://www.microsoft.com/security/blog/2020/05/14/open-sourcing-covid-threat-intelligence/

## Excessive Windows logon failures

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-02-22T00:00:00Z

### Details

> Description: User has over 50 Windows logon failures today and at least 33% of the count of logon failures over the previous 7 days.

## TI map IP entity to GitHub_CL

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-08-27T00:00:00Z

### Details

> Description: Identifies a match in GitHub_CL table from any IP IOC from TI

## Advanced Multistage Attack Detection

### Informations

> lastUpdatedDateUTC: 2020-09-09T00:00:00Z

> createdDateUTC: 2019-07-25T00:00:00Z

### Details

> Description: Using Fusion technology based on machine learning, Azure Sentinel automatically detects multistage attacks by identifying combinations of anomalous behaviors and suspicious activities observed at various stages of the kill chain. On the basis of these discoveries, Azure Sentinel generates incidents that would otherwise be very difficult to catch. By design, these incidents are low-volume, high-fidelity, and high-severity, which is why this detection is turned ON by default.

There are a total of 70 Fusion incident types detected by Azure Sentinel.
- 65 of these show the combination of suspicious Azure Active Directory sign-in events followed by anomalous Office 365 activity. Out of these 65, 30 are in public preview. 
- The remaining five incident types show the combination of anomalous signals from Microsoft Defender for Endpoint and from Palo Alto Networks firewalls. These five types are all in public preview.

To detect these multistage attacks, the following data connectors must be configured:
- Azure Active Directory Identity Protection.
- Microsoft Cloud App Security.
- Microsoft Defender for Endpoint.
- Palo Alto Networks.

For a full list and description of each scenario that is supported for these multistage attacks, go to https://aka.ms/SentinelFusion.

## Create incidents based on Azure Active Directory Identity Protection alerts

### Informations

> productFilter: Azure Active Directory Identity Protection

> lastUpdatedDateUTC: 2019-07-16T00:00:00Z

> createdDateUTC: 2019-07-16T00:00:00Z

### Details

> Description: Create incidents based on all alerts generated in Azure Active Directory Identity Protection

## Create incidents based on Microsoft Defender Advanced Threat Protection alerts

### Informations

> productFilter: Microsoft Defender Advanced Threat Protection

> lastUpdatedDateUTC: 2019-10-24T00:00:00Z

> createdDateUTC: 2019-10-24T00:00:00Z

### Details

> Description: Create incidents based on all alerts generated in Microsoft Defender Advanced Threat Protection

## Create incidents based on Azure Security Center alerts

### Informations

> productFilter: Azure Security Center

> lastUpdatedDateUTC: 2019-07-16T00:00:00Z

> createdDateUTC: 2019-07-16T00:00:00Z

### Details

> Description: Create incidents based on all alerts generated in Azure Security Center

## Create incidents based on Azure Advanced Threat Protection alerts

### Informations

> productFilter: Azure Advanced Threat Protection

> lastUpdatedDateUTC: 2019-07-16T00:00:00Z

> createdDateUTC: 2019-07-16T00:00:00Z

### Details

> Description: Create incidents based on all alerts generated in Azure Advanced Threat Protection

## Create incidents based on Microsoft Cloud App Security alerts

### Informations

> productFilter: Microsoft Cloud App Security

> lastUpdatedDateUTC: 2019-07-16T00:00:00Z

> createdDateUTC: 2019-07-16T00:00:00Z

### Details

> Description: Create incidents based on all alerts generated in Microsoft Cloud App Security

## Create incidents based on Office 365 Advanced Threat Protection alerts

### Informations

> productFilter: Office 365 Advanced Threat Protection

> lastUpdatedDateUTC: 2020-09-01T00:00:00Z

> createdDateUTC: 2020-04-20T00:00:00Z

### Details

> Description: Create incidents based on all alerts generated in Office 365 Advanced Threat Protection

## Create incidents based on Azure Security Center for IoT alerts

### Informations

> productFilter: Azure Security Center for IoT

> lastUpdatedDateUTC: 2019-12-24T00:00:00Z

> createdDateUTC: 2019-12-24T00:00:00Z

### Details

> Description: Create incidents based on all alerts generated in Azure Security Center for IoT

