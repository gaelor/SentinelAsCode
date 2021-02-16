![](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg "Metsys")
# Analytics Rules
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

## Suspicious application consent similar to O365 Attack Toolkit

### Informations

> lastUpdatedDateUTC: 2020-06-29T00:00:00Z

> createdDateUTC: 2020-06-26T00:00:00Z

### Details

> Description: This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the MDSec O365 Attack Toolkit (https://github.com/mdsecactivebreach/o365-attack-toolkit).
The default permissions/scope for the MDSec O365 Attack toolkit are contacts.read, user.read, mail.read, notes.read.all, mailboxsettings.readwrite, and files.readwrite.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.

## Known Phosphorus group domains/IP

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-10-20T00:00:00Z

### Details

> Description: Matches domain name IOCs related to Phosphorus group activity with CommonSecurityLog, DnsEvents, OfficeActivity and VMConnection dataTypes.
References: https://blogs.microsoft.com/on-the-issues/2019/03/27/new-steps-to-protect-customers-from-hacking/.

## Known IRIDIUM IP

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-12-16T00:00:00Z

### Details

> Description: IRIDIUM command and control IP. Identifies a match across various data feeds for IP IOCs related to the IRIDIUM activity group.

## THALLIUM domains included in DCU takedown

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-01-06T00:00:00Z

### Details

> Description: THALLIUM spearphishing and command and control domains included in December 2019 DCU/MSTIC takedown. 
 Matches domain name IOCs related to the THALLIUM activity group with CommonSecurityLog, DnsEvents, VMConnection and SecurityEvents dataTypes.
 References: https://blogs.microsoft.com/on-the-issues/2019/12/30/microsoft-court-action-against-nation-state-cybercrime/ 

## Known PHOSPHORUS group domains/IP - October 2020

### Informations

> lastUpdatedDateUTC: 2020-11-19T00:00:00Z

> createdDateUTC: 2020-10-20T00:00:00Z

### Details

> Description: Matches IOCs related to PHOSPHORUS group activity published October 2020 with CommonSecurityLog, DnsEvents, OfficeActivity and VMConnection dataTypes.
References: 

## Known Manganese IP and UserAgent activity

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-10-02T00:00:00Z

### Details

> Description: Matches IP plus UserAgent IOCs in OfficeActivity data, along with IP plus Connection string information in the CommonSecurityLog data related to Manganese group activity.
References: 
https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101/
https://fortiguard.com/psirt/FG-IR-18-384

## Known GALLIUM domains and hashes

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-12-06T00:00:00Z

### Details

> Description: GALLIUM command and control domains and hash values for tools and malware used by GALLIUM. 
 Matches domain name IOCs related to the GALLIUM activity group with CommonSecurityLog, DnsEvents, VMConnection and SecurityEvents dataTypes.
 References: https://www.microsoft.com/security/blog/2019/12/12/gallium-targeting-global-telecom/ 

## Known STRONTIUM group domains - July 2019

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2019-07-25T00:00:00Z

### Details

> Description: Matches domain name IOCs related to Strontium group activity published July 2019 with CommonSecurityLog, DnsEvents and VMConnection dataTypes.
References: https://blogs.microsoft.com/on-the-issues/2019/07/17/new-cyberthreats-require-new-ways-to-protect-democracy/.

## Known CERIUM domains and hashes

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-10-30T00:00:00Z

### Details

> Description: CERIUM malicious webserver and hash values for maldocs and malware. 
 Matches domain name IOCs related to the CERIUM activity group with CommonSecurityLog, DnsEvents, and VMConnection dataTypes.

## Known ZINC related maldoc hash

### Informations

> lastUpdatedDateUTC: 2020-11-17T00:00:00Z

> createdDateUTC: 2020-10-30T00:00:00Z

### Details

> Description: Document hash used by ZINC in highly targeted spear phishing campaign.

## (Preview) Anomalous SSH Login Detection

### Informations

### Details

## Advanced Multistage Attack Detection

### Informations

### Details

## Create incidents based on Office 365 Advanced Threat Protection alerts

### Informations

> productFilter: Office 365 Advanced Threat Protection

> lastUpdatedDateUTC: 2020-09-01T00:00:00Z

> createdDateUTC: 2020-04-20T00:00:00Z

### Details

> Description: Create incidents based on all alerts generated in Office 365 Advanced Threat Protection

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

## Create incidents based on Microsoft Cloud App Security alerts

### Informations

> productFilter: Microsoft Cloud App Security

> lastUpdatedDateUTC: 2019-07-16T00:00:00Z

> createdDateUTC: 2019-07-16T00:00:00Z

### Details

> Description: Create incidents based on all alerts generated in Microsoft Cloud App Security

## Create incidents based on Azure Advanced Threat Protection alerts

### Informations

> productFilter: Azure Advanced Threat Protection

> lastUpdatedDateUTC: 2019-07-16T00:00:00Z

> createdDateUTC: 2019-07-16T00:00:00Z

### Details

> Description: Create incidents based on all alerts generated in Azure Advanced Threat Protection

