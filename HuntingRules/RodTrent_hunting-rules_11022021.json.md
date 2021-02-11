![](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg "Metsys")
# Hunting Rules
## acrossworkspaceforFunction
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/acrossworkspaceforFunction.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: acrossworkspaceforFunction

> Query:

```C#union Update, workspace("contosoretail-it").Update, workspace("b459b4u5-912x-46d5-9cb1-p43069212nb4").Update | where TimeGenerated >= ago(1h) | where UpdateState == "Needed" | summarize dcount(Computer) by Classification```
## ActiveIncidents
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/ActiveIncidents.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: ActiveIncidents

> Query:

```C#SecurityIncident | where TimeGenerated > ago(10d)  | where Status == "Active"```
## AddClientDataSource
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/AddClientDataSource.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: AddClientDataSource

> Query:

```C#//Identifies who added new Datasources to the client configuration for the Log Analytics workspace  AzureActivity | where OperationNameValue has "DATASOURCES/WRITE" | where ResourceProviderValue has "MICROSOFT.OPERATIONALINSIGHTS" | project TimeGenerated, Caller, CallerIpAddress```
## AddedorAssignedGlobalAdministratorroleperms
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/AddedorAssignedGlobalAdministratorroleperms.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: AddedorAssignedGlobalAdministratorroleperms

> Query:

```C#AuditLogs | where OperationName == "Add member to role" and AADOperationType == "Assign" and Result =="success" | mv-expand TargetResources | extend modifiedProperties = parse_json(TargetResources).modifiedProperties | mv-expand modifiedProperties | extend DisplayName = tostring(parse_json(modifiedProperties).displayName), GroupName = tostring(parse_json(modifiedProperties).newValue) | where GroupName == "\"TenantAdmins\""```
## AdminConsent
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/AdminConsent.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: AdminConsent

> Query:

```C#//The applications an administrator granted admin consent  AuditLogs | where OperationName == "Consent to application" | extend Iby=todynamic(InitiatedBy)  | extend IbyUser=(Iby.user) | extend TR=todynamic(tostring(TargetResources)) | mv-expand Targets = TR | project TimeGenerated,AADTenantId,UPN=IbyUser.userPrincipalName,APPName=Targets.displayName,APPID=Targets.id```
## adminskql
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/adminskql.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: adminskql

> Query:

```C#WindowsEvent | where TimeGenerated > ago(7d) | extend eventData-parse_json(Data) | project  TimeGenerated,  Computer,  EventID,  Data.MemberName,  Data.SubjectDomainName,  Data.SubjetUserName,  Data.TargetUserName | where Data_TargetUserName == "Domain Admins" or Data_TargetUserName == "Enterprise Admins"```
## AgentedDevicesnotADJoined
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/AgentedDevicesnotADJoined.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: AgentedDevicesnotADJoined

> Query:

```C#//Agented devices that are not AD-joined  SigninLogs | union Heartbeat | where Category == "Direct Agent" and DeviceDetail <> "Azure AD joined" | distinct Computer```
## AgentProblems
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/AgentProblems.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: AgentProblems

> Query:

```C#//Detecting Agent problems //Based on: https://docs.microsoft.com/en-us/azure/azure-monitor/platform/monitor-workspace#_logsoperation-function  _LogOperation | where Category == "Agent" | where Level == "Warning" | project TimeGenerated, Operation , Computer ```
## allreportingcomputers
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/allreportingcomputers.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: allreportingcomputers

> Query:

```C#union withsource = TableName * | distinct Computer | where isnotempty(Computer) | summarize  by Computer```
## AnalyticsRuleCreatedorModified
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/AnalyticsRuleCreatedorModified.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: AnalyticsRuleCreatedorModified

> Query:

```C#//Analytics Rule to report when someone creates or modifies an Analytics Rule //Entities: Caller, Caller IP, and Analytics Rule ID AzureActivity | where OperationNameValue has "MICROSOFT.SECURITYINSIGHTS/ALERTRULES/WRITE" | where ActivityStatusValue == "Success" | extend Analytics_Rule_ID = tostring(parse_json(Properties).resource) | extend AccountCustomEntity = Caller | extend IPCustomEntity = CallerIpAddress | extend URLCustomEntity = Analytics_Rule_ID```
## AnalyticsRuleDeleted
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/AnalyticsRuleDeleted.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: AnalyticsRuleDeleted

> Query:

```C#//When an Analytics Rule is Deleted; Alert when an Analytics Rule is deleted and who did it.  AzureActivity | where OperationNameValue contains "MICROSOFT.SECURITYINSIGHTS/ALERTRULES/DELETE" | where ActivityStatusValue == "Success" | extend Analytics_Rule_ID = tostring(parse_json(Properties).resource) | extend AccountCustomEntity = Caller | extend IPCustomEntity = CallerIpAddress | extend URLCustomEntity = Analytics_Rule_ID```
## AnalyticsRulesRunbyTimes
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/AnalyticsRulesRunbyTimes.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: AnalyticsRulesRunbyTimes

> Query:

```C#SecurityAlert | where ProviderName contains "ASI" | summarize count() by DisplayName```
## AR-BreakGlassAccount
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/AR-BreakGlassAccount.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: AR-BreakGlassAccount

> Query:

```C#//Monitor break-glass account usage  SigninLogs | where OperationName == "Sign-in activity" and UserPrincipalName == "youremergencyaccount@domain.com" | extend AccountCustomEntity = UserPrincipalName | extend IPCustomEntity = IPAddress```
## AR-BruteForce
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/AR-BruteForce.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: AR-BruteForce

> Query:

```C#//Monitor for Brute Force attach  SigninLogs | where ResultType == "50126" or ResultType == "50053" | extend IPCustomEntity = IPAddress | extend AccountCustomEntity = UserDisplayName```
## AR-CloudShellExecution
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/AR-CloudShellExecution.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: AR-CloudShellExecution

> Query:

```C#//KQL for Analytics Rule to track Cloud Shell Execution  AzureActivity | where ResourceGroup startswith "CLOUD-SHELL" | where ActivityStatusValue == "Start" | extend action_ = tostring(parse_json(Authorization).action)  | summarize count() by TimeGenerated , ResourceGroup  , Caller , CallerIpAddress , ActivityStatusValue | extend AccountCustomEntity = Caller | extend IPCustomEntity = CallerIpAddress```
## Azure Runbooks query with correlation
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Azure Runbooks query with correlation.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Azure Runbooks query with correlation

> Query:

```C#let RequestId = toguid("9A07544E-004A-4E14-895D-3348165D7DBD"); let UPN = "user@domain.com"; AzureDiagnostics | join kind= inner (    AzureDiagnostics     | where TimeGenerated > ago(180d)     | where resultDescription_RequestId_g == RequestId or resultDescription_UPN_s == UPN     | distinct CorrelationId  ) on CorrelationId  | project TimeGenerated,_TimeReceived,Latency=(_TimeReceived-TimeGenerated),RequestId=resultDescription_RequestId_g, RunbookName=RunbookName_s, Status=resultDescription_Status_s,ResultType,UPN=resultDescription_UPN_s,Attempt= resultDescription_AttemptCount_d,RequestExpectedSuccessCount= resultDescription_RequestExpectedSuccessCount_d, ExternalEmailAddress=resultDescription_ExternalEmailAddress_s  | summarize CountSuccess = dcountif(RunbookName, Status == "Success"),      CountFailure = dcountif(RunbookName, Status == "Failure"),     CountDistinct = dcountif(RunbookName, Status != "Success"),      RequestExpectedSuccessCount = max(RequestExpectedSuccessCount) by RunbookName | summarize requestExpectedSuccessCount = max(RequestExpectedSuccessCount),     totalFailed = sum(CountFailure),      totalSuccess = sum(CountSuccess),     totalStarted = sum(CountDistinct) | extend packedStatistics = pack_all() | project packedStatistics```
## AzurePortalLoginErrors
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/AzurePortalLoginErrors.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: AzurePortalLoginErrors

> Query:

```C#//Azure Portal login errors by User, IPAddr, City, State, code, and description  SigninLogs | where TimeGenerated > ago(30d) | where AppDisplayName == "Azure Portal" | extend errorCode_ = tostring(Status.errorCode) | where errorCode_ != "0" | extend city_ = tostring(LocationDetails.city), state_ = tostring(LocationDetails.state) | project UserDisplayName, IPAddress, city_, state_, errorCode_, ResultDescription```
## BillableDatabyDataType
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/BillableDatabyDataType.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: BillableDatabyDataType

> Query:

```C#Usage  | where TimeGenerated > ago(32d) | where StartTime >= startofday(ago(31d)) and EndTime < startofday(now()) //| where IsBillable == true | summarize BillableDataGB = sum(Quantity) / 1000. by bin(StartTime, 1d), DataType```
## Billabledatavolumebydatatype
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Billabledatavolumebydatatype.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Billabledatavolumebydatatype

> Query:

```C#//Billable data volume by data type Usage  | where TimeGenerated > ago(32d) | where StartTime >= startofday(ago(31d)) and EndTime < startofday(now()) | where IsBillable == true | summarize BillableDataGB = sum(Quantity) / 1000. by bin(StartTime, 1d), DataType | render barchart```
## Billabledatavolumebysolution
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Billabledatavolumebysolution.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Billabledatavolumebysolution

> Query:

```C#//Billable data volume by solution Usage  | where TimeGenerated > ago(32d) | where StartTime >= startofday(ago(31d)) and EndTime < startofday(now()) | where IsBillable == true | summarize BillableDataGB = sum(Quantity) / 1000. by bin(StartTime, 1d), Solution | render barchart```
## BookmarksCreatedBy
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/BookmarksCreatedBy.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: BookmarksCreatedBy

> Query:

```C#HuntingBookmark | sort by CreatedBy | project BookmarkName , CreatedBy ```
## BookmarkUpdate
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/BookmarkUpdate.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: BookmarkUpdate

> Query:

```C#AzureActivity | where OperationName == "Update Bookmarks" and ActivityStatusValue == "Succeeded"  | project Caller , EventSubmissionTimestamp```
## BookMarkUpdatedBy
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/BookMarkUpdatedBy.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: BookMarkUpdatedBy

> Query:

```C#HuntingBookmark | where isnotempty(CreatedBy) | project BookmarkName , UpdatedBy ```
## BrowserActivitybyGEO
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/BrowserActivitybyGEO.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: BrowserActivitybyGEO

> Query:

```C#SigninLogs  | where AppDisplayName == "Microsoft Cloud App Security"  | extend UserBrowser_ = tostring(DeviceDetail.browser)  | extend UserOperatingSystem_ = tostring(DeviceDetail.operatingSystem)  | extend UserCountryOrRegion_ = tostring(LocationDetails.countryOrRegion)  | extend UserCity_ = tostring(LocationDetails.city) ```
## CaseComments
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/CaseComments.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: CaseComments

> Query:

```C#//Who added case comments and to which case  AzureActivity | where OperationName == "Create Case Comments" | project Caller, CallerIpAddress, OperationName, _ResourceId```
## CEFDevices
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/CEFDevices.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: CEFDevices

> Query:

```C#union isfuzzy=true withsource = TableName // Microsoft  (AzureDiagnostics    | where ResourceType == "AZUREFIREWALLS" ),  (WindowsFirewall     | summarize count() by FirewallAction ),  // Barracuda GlodGen Syslog (CGFWFirewallActivity| summarize count() by DeviceName = Computer ),    // CEF section (CommonSecurityLog   | where DeviceVendor == "Barracuda" ),  (CommonSecurityLog   | where DeviceVendor == "Fortinet"              | summarize count() by DeviceVendor, DeviceName = DeviceExternalID),  (CommonSecurityLog   | where DeviceVendor == "TestCommonEventFormat" | summarize count() by DeviceVendor, DeviceName = DeviceExternalID),  (CommonSecurityLog   | where DeviceVendor == "Palo Alto Networks"    | where isnotempty(DeviceName) | summarize count() by DeviceVendor, DeviceName)  // show devices found | summarize count() by  DeviceName , DeviceVendor ```
## Check4LockedoutUser
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Check4LockedoutUser.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Check4LockedoutUser

> Query:

```C#SecurityEvent | where EventID == 4740 or EventID == 644 //A user account was locked out | extend LowerAccount=tolower(Account) | search "username"```
## CheckPointLogs
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/CheckPointLogs.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: CheckPointLogs

> Query:

```C#//Check Point logs  CommonSecurityLog | extend DeviceProduct = iif(DeviceEventClassID has "geo_protection","Check Point Geo Protection", iif(DeviceEventClassID has "Log","Check Point Firewall-1 Log","Check Point")) | sort by TimeGenerated desc```
## CloudShell
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/CloudShell.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: CloudShell

> Query:

```C#AzureActivity | where TimeGenerated > ago(1d) | where ResourceGroup contains "cloud-shell" and ActivityStatus == "Started" | project CallerIpAddress , Caller ```
## Cloudshell2
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Cloudshell2.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Cloudshell2

> Query:

```C#AzureActivity | where ResourceGroup startswith "CLOUD-SHELL" | extend action_ = tostring(parse_json(Authorization).action)  | summarize count() by ResourceGroup  , Caller , CallerIpAddress , ActivityStatusValue , ActivitySubstatusValue,  CategoryValue , action_    // List sucess vs. failure  AzureActivity | where ResourceGroup startswith "CLOUD-SHELL" | summarize count(ActivityStatus) by Caller, ActivityStatus```
## CloudShellPart2
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/CloudShellPart2.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: CloudShellPart2

> Query:

```C#//AzureActivity logs differently between certain instances of Azure. For those environments where the original CloudShell Analytics Rules //doesnt work. Use this.  //Still attempting to determine why the differences.  AzureActivity | where ResourceGroup startswith "CLOUD-SHELL" | where ResourceProviderValue == "MICROSOFT.STORAGE" | where ActivityStatusValue == "Start" | extend action_ = tostring(parse_json(Authorization).action)  | summarize count() by TimeGenerated , ResourceGroup  , Caller , CallerIpAddress , ActivityStatusValue | extend AccountCustomEntity = Caller | extend IPCustomEntity = CallerIpAddress```
## CompareTotalRecordswithValuebyPercentage
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/CompareTotalRecordswithValuebyPercentage.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: CompareTotalRecordswithValuebyPercentage

> Query:

```C#//Compare a count of total records in a table for the last 24h to the count of records in the same table with a specific property value to get a % //Myself and Brian Barrington were schooled by Clive Watson on this one :)  SigninLogs | summarize ErrorCount=countif(ResultType == 16000 or ResultType == 50140), TotalCount=countif(isnotempty(ResultType)) | extend percent = ((toreal(ErrorCount) / toreal(TotalCount))*100)```
## computersendingmostsecurityalerts
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/computersendingmostsecurityalerts.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: computersendingmostsecurityalerts

> Query:

```C#union withsource = tt * | where TimeGenerated > startofday(ago(7d)) and TimeGenerated < startofday(now()) | where _IsBillable == true | where tt == "SecurityEvent" | summarize GBytes=round(sum(_BilledSize/(1024*1024*1024)),2)  by  Solution=tt, Computer | sort by GBytes nulls last | render barchart kind=unstacked ```
## computersunhealthystate
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/computersunhealthystate.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: computersunhealthystate

> Query:

```C#let timeRangeQuery = 1h; let UnhealthyCriteria = 1m; Heartbeat | where TimeGenerated > startofday(ago(timeRangeQuery)) | summarize LastHeartbeat = max(TimeGenerated) by Computer, OSType, OSName | extend State = iff(LastHeartbeat < ago(UnhealthyCriteria), Unhealthy, Healthy) | extend TimeFromNow = now() - LastHeartbeat | extend ["TimeAgo"] = strcat(toint(TimeFromNow / 1s),  seconds) | project Computer, State, TimeAgo, TimeFromNow, OSType | order by TimeAgo desc, State desc```
## Conditional access changes new value and old value
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Conditional access changes new value and old value.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Conditional access changes new value and old value

> Query:

```C#let operatorUPN = "user@domain.com"; let lookback = 2d; AuditLogs | where TimeGenerated > ago(lookback) | where LoggedByService == "Core Directory" and OperationName == "Update policy" | where InitiatedBy has operatorUPN | extend initator = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)  | extend policyName = tostring(TargetResources[0].displayName) | extend changes = TargetResources[0].modifiedProperties | project TimeGenerated, initator, policyName, changes | mvexpand changes | evaluate bag_unpack(changes) | where newValue <> "\"\""  | sort by TimeGenerated, initator, policyName```
## CostperEventID
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/CostperEventID.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: CostperEventID

> Query:

```C#SecurityEvent | where TimeGenerated >= startofday(ago(1d)) and TimeGenerated < startofday(now()) | summarize sum(_BilledSize) by EventID | order by sum__BilledSize desc```
## CountriesWhereAgentedComputersReportFrom
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/CountriesWhereAgentedComputersReportFrom.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: CountriesWhereAgentedComputersReportFrom

> Query:

```C#//Countries where your agented computers are reporting from union isfuzzy=true    (Heartbeat | extend TrafficDirection = "InboundOrUnknown", Country=RemoteIPCountry, Latitude=RemoteIPLatitude, Longitude=RemoteIPLongitude) | where TimeGenerated > ago(7d)    | where isnotempty(Country) and isnotempty(Latitude) and isnotempty(Longitude) | distinct Country```
## Cross resource query
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Cross resource query.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Cross resource query

> Query:

```C#let AuditLogsDEV = workspace("9b5dc943-9550-4b95-ab2d-0f1c898956da").AuditLogs; let start = ago(24h);  AuditLogsDEV | where TimeGenerated > start | where OperationName == "Add group" | project flatten = tostring(TargetResources) | where flatten contains "Unified"```
## DataByProvider
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/DataByProvider.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: DataByProvider

> Query:

```C#SecurityAlert | where ProviderName == "MCAS"    SecurityAlert | where ProviderName == "Office 365 Security & Compliance"    SecurityAlert | where ProviderName == "MDATP" ```
## DataConnectorOpened
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/DataConnectorOpened.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: DataConnectorOpened

> Query:

```C#//Someone opened a Data Connector page  AzureActivity | where OperationNameValue contains "dataconnectorscheckrequirements" | where ActivityStatusValue == "Start"```
## DataConnectorReqsFailed
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/DataConnectorReqsFailed.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: DataConnectorReqsFailed

> Query:

```C#//Data Connector Requirements failed  AzureActivity | where OperationNameValue contains "dataconnectorscheckrequirements" | where ActivityStatusValue != "Success" and ActivityStatusValue != "Start"```
## DataConnectorReqsFailedbyCallerIPOperation
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/DataConnectorReqsFailedbyCallerIPOperation.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: DataConnectorReqsFailedbyCallerIPOperation

> Query:

```C#//Data Connector page access that failed authorization by caller, caller IP Address, and Operation name  AzureActivity | where OperationNameValue contains "dataconnectorscheckrequirements" | where ActivityStatusValue == "Failed" and ActivitySubstatusValue == "Unauthorized" | project Caller, CallerIpAddress, OperationName```
## DataIngestionNotHappening
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/DataIngestionNotHappening.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: DataIngestionNotHappening

> Query:

```C#//Replace the table name with the name you want to track. Create an Analytics Rule and be notified if a table has not received new data in the last 3 days. //Seconds calculation for last_log is 60 x 60 x 24 x 3 = 259200 //Make sure to set the Lookback to 14 days  HuntingBookmark | where TimeGenerated > ago(30d) | summarize last_log = datetime_diff("second",now(), max(TimeGenerated)) | where last_log >= 259200```
## dataingestionthresholdlimits
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/dataingestionthresholdlimits.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: dataingestionthresholdlimits

> Query:

```C#//Data ingestion crossed the limit Operation |where OperationCategory == "Ingestion" |where Detail startswith "The data ingestion volume rate crossed the threshold"  //Data ingestion crossed 80% of the limit Operation |where OperationCategory == "Ingestion" |where Detail startswith "The data ingestion volume rate crossed 80% of the threshold"```
## dataparser
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/dataparser.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: dataparser

> Query:

```C#MyCustomCSVLog_CL | extend CSVFields  = split(RawData, ,) | extend EventTime  = todatetime(CSVFields[0]) | extend Code       = toint(CSVFields[1])  | extend Status     = tostring(CSVFields[2])  | extend Message    = tostring(CSVFields[3])  | where getyear(EventTime) == 2018 | summarize count() by Status,Code```
## dataproviders
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/dataproviders.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: dataproviders

> Query:

```C#//Listing all Data providers SecurityAlert | where isnotempty(ProviderName) | distinct ProviderName```
## DataTypeUsagePieChart
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/DataTypeUsagePieChart.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: DataTypeUsagePieChart

> Query:

```C#// Usage by data types in a pie chart Usage | summarize count_per_type=count() by DataType | sort by count_per_type desc | render piechart```
## Debugging authentication sign-ins
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Debugging authentication sign-ins.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Debugging authentication sign-ins

> Query:

```C#SigninLogs | where UserPrincipalName == "kkilty@microsoft.com" | extend ClientAppUsed = iff(isempty(ClientAppUsed) == true, "Unknown", ClientAppUsed)  | extend IsLegacyAuth =  case(ClientAppUsed contains "Browser", "No",  ClientAppUsed contains "Mobile Apps and Desktop clients", "No", ClientAppUsed contains "Exchange ActiveSync", "No", ClientAppUsed contains "Other clients", "Yes", "Unknown")  | extend errorCode = toint(Status.errorCode)  | extend SigninStatus =  case(errorCode == 0, "Success",  errorCode == 50058, "Interrupt", errorCode == 50140, "Interrupt", errorCode == 51006, "Interrupt", errorCode == 50059, "Interrupt", errorCode == 65001, "Interrupt", errorCode == 52004, "Interrupt", errorCode == 50055, "Interrupt", errorCode == 50144, "Interrupt", errorCode == 50072, "Interrupt", errorCode == 50074, "Interrupt", errorCode == 16000, "Interrupt", errorCode == 16001, "Interrupt", errorCode == 16003, "Interrupt", errorCode == 50127, "Interrupt", errorCode == 50125, "Interrupt", errorCode == 50129, "Interrupt", errorCode == 50143, "Interrupt", errorCode == 81010, "Interrupt", errorCode == 81014, "Interrupt", errorCode == 81012 ,"Interrupt",  "Failure")  | extend StatusReason = tostring(Status.failureReason) | extend DeviceOS = DeviceDetail.operatingSystem | extend DeviceBrowser = extract("([a-zA-Z]+)", 1, tostring(DeviceDetail.browser)) | extend Country = tostring(LocationDetails.countryOrRegion) | extend State = tostring(LocationDetails.state) | extend City = tostring(LocationDetails.city) | extend conditionalAccessStatusDesc =  case(ConditionalAccessStatus == 0, "Success",  ConditionalAccessStatus == 1, "Failure", ConditionalAccessStatus == 2, "Not Applied", ConditionalAccessStatus == "", "Not Applied",  "Unknown") | project CreatedDateTime, IsLegacyAuth, Id, CorrelationId, ClientAppUsed, AppDisplayName, AppId, UserDisplayName,  UserPrincipalName, UserId, IPAddress, Country, State, City, SigninStatus, StatusReason,DeviceOS, DeviceBrowser, conditionalAccessStatusDesc, tostring(ConditionalAccessPolicies) | sort by CreatedDateTime desc```
## devices
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/devices.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: devices

> Query:

```C#// find Azure Firewalls   AzureDiagnostics  | where ResourceType == "AZUREFIREWALLS"    //Windows Firewall WindowsFirewall | summarize count() by FirewallAction   //Barracuda CGFWFirewallActivity   //Barracuda WAF  CommonSecurityLog? | where DeviceVendor == "Barracuda"   //CommonSecurityLog? | where DeviceVendor == "Check Point"   CommonSecurityLog? | where DeviceVendor == "Cisco" | where DeviceProduct == "ASA"```
## DirectAgent
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/DirectAgent.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: DirectAgent

> Query:

```C#Heartbeat | where Category == "Direct Agent" | distinct Computer , Category , OSType , OSMajorVersion , OSMinorVersion```
## DirectReport
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/DirectReport.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: DirectReport

> Query:

```C#Heartbeat | project Computer , Category  |where Category contains "Direct"  |distinct Computer```
## Does a table exist
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Does a table exist.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Does a table exist

> Query:

```C#let hasNonEmptyTable = (T:string)  {     toscalar( union isfuzzy=true ( table(T) | count as Count ), (print Count=0) | summarize sum(Count) ) > 0 }; let TableName = AzureDiagnostics; print Table=TableName, IsPresent=iif(hasNonEmptyTable(TableName), "Table present", "Table not preset")```
## DomainAdminsEnterpriseAdmins
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/DomainAdminsEnterpriseAdmins.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: DomainAdminsEnterpriseAdmins

> Query:

```C#WindowsEvent | where TimeGenerated > ago(7d) | extend eventData=parse_json(Data) | project TimeGenerated, Computer, EventID, Data.MemberName, Data.SubjectDomainName, Data.SubjectUserName, Data.TargetUserName | where Data_TargetUserName == "Domain Admins" or Data_TargetUserName == "Enterprise Admins"```
## Duration of session
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Duration of session.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Duration of session

> Query:

```C#let Events=datatable (SessionId:int, TimeGenerated:datetime, Event:string) [1, datetime(2018-01-01 12:30:00),"Start", 1, datetime(2018-01-01 13:30:00),"Stop", 2, datetime(2018-01-02 12:30:00),"Start", 2, datetime(2018-01-03 13:30:00),"Stop", 3, datetime(2018-01-01 12:30:00),"Start", 3, datetime(2018-01-02 12:45:00),"Stop", 4, datetime(2018-03-03 11:30:00),"Start", 4, datetime(2018-03-03 12:30:00),"Stop", 5, datetime(2018-03-03 13:30:00),"Start" ]; Events | where Event == "Start" | project Event, SessionId, StartTime=TimeGenerated | join kind=leftouter (Events          | where Event =="Stop"         | project EventRight=Event, SessionId, StopTime=iif(isempty(TimeGenerated),datetime(null),TimeGenerated))     on SessionId | project SessionId, StartTime, StopTime, Duration = StopTime - StartTime | where isnull(StopTime)```
## EventIDsinLastDay
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/EventIDsinLastDay.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: EventIDsinLastDay

> Query:

```C#//Switch to Stacked Display SecurityEvent | where TimeGenerated > ago(1d) | summarize count() by tostring(EventID), AccountType, bin(TimeGenerated, 1h)   ```
## EventIDStorageinBytes
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/EventIDStorageinBytes.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: EventIDStorageinBytes

> Query:

```C#//Show how much each storage each EventID is taking up in bytes SecurityEvent | summarize count() by Activity, EventID | extend size_in_bytes = count_ * 500 | order by count_ desc```
## EventLogSources
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/EventLogSources.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: EventLogSources

> Query:

```C#SecurityEvent | distinct EventSourceName```
## EventVolumePerTable
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/EventVolumePerTable.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: EventVolumePerTable

> Query:

```C#//Event volume per table. Change OfficeActivity to the table you want to query against.  let Now = now(); (range TimeGenerated from ago(14d) to Now-1d step 1d | extend Count = 0 | union isfuzzy=true( OfficeActivity | summarize Count = count() by bin_at(TimeGenerated, 1d, Now) ) | summarize Count=max(Count) by bin_at(TimeGenerated, 1d, Now) | sort by TimeGenerated | project Value = iff(isnull(Count), 0, Count), Time = TimeGenerated, Legend = "Events") | render timechart```
## excessivefailedlogins
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/excessivefailedlogins.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: excessivefailedlogins

> Query:

```C#SecurityEvent | where TimeGenerated < startofday(ago(1d)) | where EventID in (4625) and Status=="0xc000006d" | summarize min(TimeGenerated),  EventCount = count() by bin_at(TimeGenerated, 1h,now()) | order by TimeGenerated asc```
## ExistingConditionalAccessPolicies
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/ExistingConditionalAccessPolicies.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: ExistingConditionalAccessPolicies

> Query:

```C#//Display the existing Conditional Access Policies  SigninLogs | mv-expand ConditionalAccessPolicies | project DisplayName = tostring(ConditionalAccessPolicies.displayName),ID = tostring(ConditionalAccessPolicies.id) | distinct ID,DisplayName | order by DisplayName asc ```
## ExpiredPassword
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/ExpiredPassword.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: ExpiredPassword

> Query:

```C#SigninLogs | where ResultType == "50055" | project UserDisplayName, UserPrincipalName```
## ExternalAccess
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/ExternalAccess.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: ExternalAccess

> Query:

```C#//This is an example line of KQL query for external data retrieval. //This example queries IP-API with an IP address and returns country, region, regionName, and city.  //This is a way to do this while developing a KQL query in the Logs blade. //You can also do this (IP-API query) with a Playbook to add additional context to an Incident in the comments //See: https://secureinfra.blog/2020/09/03/how-to-add-geographical-data-for-ip-addresses-to-an-azure-sentinel-incident/  externaldata(status:string, country:string, region:string, regionName:string, city:string)[@"http://ip-api.com/json/174.98.173.42"] with(format="json")```
## ExternalGEOforSecurityEvents
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/ExternalGEOforSecurityEvents.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: ExternalGEOforSecurityEvents

> Query:

```C#//Get you geolocation for your SecurityEvents, using a publicly available IP geolocation file  let geoData = externaldata (network:string,geoname_id:string,continent_code:string,continent_name:string, country_iso_code:string,country_name:string,is_anonymous_proxy:string,is_satellite_provider:string) [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/master/data/geoip2-ipv4.csv"] with (ignoreFirstRecord=true, format="csv"); SecurityEvent | evaluate ipv4_lookup (geoData, IpAddress,  network, false)```
## GetTags
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/GetTags.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: GetTags

> Query:

```C#HuntingBookmark | where isnotempty(Tags) | project Tags ```
## heartbeatforscomagent
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/heartbeatforscomagent.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: heartbeatforscomagent

> Query:

```C#Heartbeat | project Computer , Category  |where Category contains "Scom agent"  |distinct Computer//```
## HowManyQueriesEachPersonRan
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/HowManyQueriesEachPersonRan.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: HowManyQueriesEachPersonRan

> Query:

```C#//How many queries each person ran in the last 7 days //Enabling the Diag Setting for the Audit log is required to expose the LAQueryLogs table  LAQueryLogs | where TimeGenerated > ago(7d) | summarize events_count=count() by AADEmail | extend UserPrincipalName = AADEmail, Queries = events_count | join kind= leftouter (     SigninLogs)     on UserPrincipalName | project UserDisplayName, UserPrincipalName, Queries | summarize arg_max(Queries, *) by UserPrincipalName | sort by Queries desc```
## HuntingQueriesAzureActivitySuccessandFailures
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/HuntingQueriesAzureActivitySuccessandFailures.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: HuntingQueriesAzureActivitySuccessandFailures

> Query:

```C#//Hunting query to detect Azure Activity successes and show who did it  AzureActivity | where TimeGenerated > ago(1d) | where OperationNameValue has "Action" | where ActivityStatusValue == "Success" | extend AccountCustomEntity = Caller | extend IPCustomEntity = CallerIpAddress | extend URLCustomEntity = OperationNameValue  //Hunting query to detect Azure Activity failures and show who did it  AzureActivity | where TimeGenerated > ago(1d) | where OperationNameValue has "Action" | where ActivityStatusValue == "Failure" | extend AccountCustomEntity = Caller | extend IPCustomEntity = CallerIpAddress | extend URLCustomEntity = OperationNameValue```
## ImpossibleTravelKQL
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/ImpossibleTravelKQL.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: ImpossibleTravelKQL

> Query:

```C#SecurityAlert | where AlertName == "Impossible travel activity" | project (parse_json(Entities)[1].Name), Entities | extend Name_ = tostring(parse_json(Entities)[3].Name)```
## Incidents
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Incidents.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Incidents

> Query:

```C#AzureActivity | where _ResourceId contains "SecurityInsights" and _ResourceId contains "incidents"```
## IntuneActivityTypes
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneActivityTypes.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneActivityTypes

> Query:

```C#//Activity Types IntuneAuditLogs | summarize OperationCount=count() by OperationName  | sort by OperationCount desc```
## IntuneAuditEvents
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneAuditEvents.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneAuditEvents

> Query:

```C#IntuneAuditLogs  |summarize Auditevents = count() by OperationName  | sort by Auditevents```
## IntuneAuditEventsTrend
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneAuditEventsTrend.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneAuditEventsTrend

> Query:

```C#//Audit Events Trend IntuneAuditLogs | summarize count() by bin(TimeGenerated, {TimeRange:grain})```
## Intune-AutoPilotFailedEnrollment1Day
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Intune-AutoPilotFailedEnrollment1Day.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Intune-AutoPilotFailedEnrollment1Day

> Query:

```C#//Autopilot devices that failed enrollment in the last day  IntuneOperationalLogs | where TimeGenerated > ago(24h) | extend IsAutopilot_ = tostring(parse_json(Properties).IsAutopilot) | extend DeviceName_ = tostring(parse_json(Properties).DeviceName) | where IsAutopilot_ == "True" | where OperationName == "Enrollment" and Result == "Failure"```
## IntuneComplianceFailuresbyOperatingSystem
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneComplianceFailuresbyOperatingSystem.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneComplianceFailuresbyOperatingSystem

> Query:

```C#//Compliance Failures by Operating System let ComplianceLogs= IntuneOperationalLogs  | where OperationName == "Compliance"  | project TimeGenerated, Properties; ComplianceLogs | sort by TimeGenerated desc | join ( ComplianceLogs | extend myJson = todynamic(Properties) | project-away Properties | extend IntuneDeviceId=tostring(myJson["IntuneDeviceId"])  | project TimeGenerated, IntuneDeviceId | summarize TimeGenerated=max(TimeGenerated) by IntuneDeviceId     ) on TimeGenerated | project-away TimeGenerated1, IntuneDeviceId   | extend myJson=todynamic(Properties) | project-away Properties | extend DeviceOperatingSystem=tostring(myJson["DeviceOperatingSystem"])  | summarize FailureCount=count() by DeviceOperatingSystem | sort by FailureCount desc```
## IntuneComplianceFailuresbyReason
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneComplianceFailuresbyReason.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneComplianceFailuresbyReason

> Query:

```C#//Compliance Failures by Failure Reason let ComplianceLogs= IntuneOperationalLogs  | where OperationName == "Compliance"  | project TimeGenerated, Properties; ComplianceLogs | sort by TimeGenerated desc | join ( ComplianceLogs | extend myJson = todynamic(Properties) | project-away Properties | extend IntuneDeviceId=tostring(myJson["IntuneDeviceId"])  | project TimeGenerated, IntuneDeviceId | summarize TimeGenerated=max(TimeGenerated) by IntuneDeviceId     ) on TimeGenerated | project-away TimeGenerated1, IntuneDeviceId   | extend myJson=todynamic(Properties) | project-away Properties | extend Description=tostring(myJson["Description"]) | extend Description=tostring(extract("(.*?)_IID_.*", 1, tostring(Description))) | extend Reason = tostring(extract("(.*?)\\.(.*)", 2, tostring(Description))) | summarize FailureCount=count() by Reason  | sort by FailureCount desc```
## Intunecomputershutdowns
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Intunecomputershutdowns.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Intunecomputershutdowns

> Query:

```C#// Computers restarts/shutdowns  // List restart and shutdowns events for all monitored computers.   Event | where  EventLog == "System" and Source == "User32" and EventID == 1074 | search "shutdown" | sort by TimeGenerated desc  | project TimeGenerated, Computer```
## IntuneCountofSuccessfulEnrollmentsbyOS
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneCountofSuccessfulEnrollmentsbyOS.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneCountofSuccessfulEnrollmentsbyOS

> Query:

```C#//Count of Successful Enrollments by OS IntuneOperationalLogs  | where OperationName == "Enrollment" and Result == "Success" | extend Os_ = tostring(parse_json(Properties).Os) | summarize count() by Os_```
## IntuneDevicesNotinCompliance
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneDevicesNotinCompliance.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneDevicesNotinCompliance

> Query:

```C#let ComplianceLogs= IntuneOperationalLogs  | where OperationName == "Compliance"  | project TimeGenerated, Properties; ComplianceLogs | sort by TimeGenerated desc | join ( ComplianceLogs | extend myJson = todynamic(Properties) | project-away Properties | extend IntuneDeviceId=tostring(myJson["IntuneDeviceId"])  | project TimeGenerated, IntuneDeviceId | summarize TimeGenerated=max(TimeGenerated) by IntuneDeviceId     ) on TimeGenerated | project-away TimeGenerated1, IntuneDeviceId   | summarize EventCount=count() by bin(TimeGenerated, {TimeRange:grain})```
## IntuneDevicesNotSupported
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneDevicesNotSupported.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneDevicesNotSupported

> Query:

```C#//Devices not supported by time, failure type, and operating system  IntuneOperationalLogs | extend FailureCategory_ = tostring(parse_json(Properties).FailureCategory) | where FailureCategory_ == "DeviceNotSupported" | extend Os_ = tostring(parse_json(Properties).Os) | project TimeGenerated , FailureCategory_ , Os_```
## Intune-DeviceThreatLevelnotSecured
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Intune-DeviceThreatLevelnotSecured.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Intune-DeviceThreatLevelnotSecured

> Query:

```C#//Intune Device Threat Level not Secured  IntuneDeviceComplianceOrg | where isnotempty(DeviceHealthThreatLevel) | where DeviceHealthThreatLevel != "Secured" | project TimeGenerated , DeviceName , DeviceId , OS , UserName , DeviceHealthThreatLevel```
## IntuneEnrollmentEventsTrend
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneEnrollmentEventsTrend.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneEnrollmentEventsTrend

> Query:

```C#//Enrollment Events Trend IntuneOperationalLogs | where OperationName=="Enrollment" | summarize OperationCount=count() by bin(TimeGenerated, {TimeRange:grain})```
## IntuneEnrollmentFailurereasons
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneEnrollmentFailurereasons.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneEnrollmentFailurereasons

> Query:

```C#//Enrollment Failure reasons IntuneOperationalLogs | where  OperationName == "Enrollment"  | where Result == "Fail" | extend myJson=todynamic(Properties) | extend FailureReason = tostring(myJson ["FailureReason"]) | summarize OperationCount=count() by FailureReason | sort by OperationCount desc```
## IntuneEnrollmentFailuresbyEnrollmentType
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneEnrollmentFailuresbyEnrollmentType.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneEnrollmentFailuresbyEnrollmentType

> Query:

```C#//Enrollment Failures by Enrollment Type IntuneOperationalLogs | where  OperationName == "Enrollment"  | where Result == "Fail"  | extend myJson=todynamic(Properties) | extend EnrollmentType = tostring(myJson ["EnrollmentType"]) | summarize OperationCount=count() by EnrollmentType  | sort by OperationCount desc```
## IntuneEnrollmentFailuresbyPlatform
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneEnrollmentFailuresbyPlatform.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneEnrollmentFailuresbyPlatform

> Query:

```C#//Enrollment Failures by Platform IntuneOperationalLogs | where  OperationName == "Enrollment"  | where Result == "Fail" | extend myJson=todynamic(Properties) | extend Platform = tostring(myJson ["Os"]) | summarize OperationCount=count() by Platform  | sort by OperationCount desc```
## Intune-Enrollmentsabandonedbytheuser
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Intune-Enrollmentsabandonedbytheuser.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Intune-Enrollmentsabandonedbytheuser

> Query:

```C#//Enrollments abandoned by the user //For details, see (https://docs.microsoft.com/en-us/mem/intune/enrollment/enrollment-report-company-portal-abandon)  IntuneOperationalLogs | where OperationName == "Enrollment"  | where Result == "Fail" | extend myJson=todynamic(Properties) | extend FailureReason = tostring(myJson ["FailureReason"]) | extend Os_ = tostring(parse_json(Properties).Os) | extend IntuneUserId_ = tostring(parse_json(Properties).IntuneUserId) | where FailureReason == "UserAbandonment"  | summarize OperationCount=count() by FailureReason , IntuneUserId_ , Os_ | sort by OperationCount desc```
## IntuneEnrollmentStatistics
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneEnrollmentStatistics.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneEnrollmentStatistics

> Query:

```C#//Enrollment Statistics IntuneOperationalLogs | where  OperationName == "Enrollment" | summarize count() by Result```
## IntuneEnrollmentSuccessbyEnrollmentType
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneEnrollmentSuccessbyEnrollmentType.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneEnrollmentSuccessbyEnrollmentType

> Query:

```C#//Enrollment Success by Enrollment Type IntuneOperationalLogs | where  OperationName == "Enrollment"  | where Result == "Success"  | extend myJson=todynamic(Properties) | extend EnrollmentType = tostring(myJson ["EnrollmentType"]) | summarize OperationCount=count() by EnrollmentType  | sort by OperationCount desc```
## IntuneisCompliantByOSandOSVersion
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneisCompliantByOSandOSVersion.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneisCompliantByOSandOSVersion

> Query:

```C#//Intune devices that are compliant with OS, OS Version, and number of existing IntuneDeviceComplianceOrg  | where isnotempty(DeviceName) | where ComplianceState == "Compliant" | summarize count() by OSDescription, OSVersion```
## IntuneNotCompliant
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneNotCompliant.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneNotCompliant

> Query:

```C#IntuneDeviceComplianceOrg | where ComplianceState <> "Not Compliant" and isnotempty(ComplianceState) | project TimeGenerated , ComplianceState , DeviceName , DeviceId , OS , UserName , UserEmail```
## IntuneNotCompliant2
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneNotCompliant2.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneNotCompliant2

> Query:

```C#//Intune Devices Not Compliant  IntuneDeviceComplianceOrg | where isnotempty(DeviceHealthThreatLevel) | where ComplianceState != "Compliant" | project TimeGenerated , ComplianceState , DeviceName , DeviceId , OS , UserName , UserEmail```
## IntuneRecentEventsbyAccounts
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneRecentEventsbyAccounts.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneRecentEventsbyAccounts

> Query:

```C#IntuneAuditLogs  | top 10 by TimeGenerated | project Identity, OperationName```
## IntuneRemoteactionsbyactiontype
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneRemoteactionsbyactiontype.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneRemoteactionsbyactiontype

> Query:

```C#//Remote actions by action type IntuneAuditLogs | where OperationName contains "ManagedDevice"  | summarize OperationCount=count() by OperationName | sort by OperationCount desc ```
## IntuneRemoteactionstopusers
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneRemoteactionstopusers.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneRemoteactionstopusers

> Query:

```C#//Remote actions top users IntuneAuditLogs | where OperationName contains "ManagedDevice"  | summarize OperationCount=count() by Identity | sort by OperationCount desc ```
## IntuneSuccessfulSynchedDevice
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneSuccessfulSynchedDevice.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneSuccessfulSynchedDevice

> Query:

```C#IntuneAuditLogs  | where OperationName == " syncDevice ManagedDevice" and ResultType == "Success"```
## IntuneSummarizebyOperation
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneSummarizebyOperation.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneSummarizebyOperation

> Query:

```C#IntuneAuditLogs  | summarize count() by OperationName```
## IntuneTopuserswithauditedactions
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/IntuneTopuserswithauditedactions.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: IntuneTopuserswithauditedactions

> Query:

```C#//Top users with audited actions IntuneAuditLogs | extend myJson=todynamic(Properties) | summarize OperationCount=count() by Identity  | sort by OperationCount desc```
## isempty
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/isempty.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: isempty

> Query:

```C#SecurityAlert | where isempty(ProviderName)  | project AlertName, SourceComputerId,  ProviderName ```
## KDCforKRBTGTPassword
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/KDCforKRBTGTPassword.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: KDCforKRBTGTPassword

> Query:

```C#name: KDC for KRBTGT Password description: |   KDC Changes Alert when KRBTGT was changed. severity: High requiredDataConnectors:       - Azure ATP       - Security Events     dataTypes:       - SecurityEvent       - Event queryFrequency: 1h queryPeriod: 1h triggerOperator: gt triggerThreshold: 0 tactics:   - Impact   - Persistence query: |  //KDC for KRBTGT Password // Details: https://www.eshlomo.us/azure-sentinel-and-krbtgt/   union SecurityEvent, Event | where TimeGenerated >= ago(5d) | where EventID in (10,14) //KDC Reset | where EventID == "4769" //TGT After Reset```
## LAG analysis example
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/LAG analysis example.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: LAG analysis example

> Query:

```C#requests | serialize  | extend RequestId = toguid(customDimensions.RequestId) | project-away resultCode, id, itemType, operation_Name, client_Type, client_IP, operation_SyntheticSource, appId, itemId, itemCount, source, url, performanceBucket  | sort by RequestId, timestamp desc | extend rn = row_number() | extend rncr = row_number(1, prev(RequestId,1,0) != RequestId)  | extend previousTimestamp = iif(prev(RequestId,1,0) != RequestId, timestamp, prev(timestamp,1,0))  | extend deltaInMin = datetime_diff(minute, previousTimestamp, timestamp) | project rncr, timestamp, RequestId, name, success, deltaInMin, duration, customDimensions, operation_Id, operation_ParentId, cloud_RoleInstance, appName   let SampleData = datatable (user:string, rowValue: int) ["A",5,"B",12,"B",15,"A",3,"A",9,"A",19,"B",7]; SampleData  | serialize | extend rowNumber = row_number() | extend rowNumberCurrentUser = row_number(1, prev(user,1,0) != user)  | extend previousValue = strcat("Previous value was ", prev(rowValue,1,0)) | extend nextValue = strcat("Next value was ", next(rowNumber,1,0)) | extend runningTotal = row_cumsum(rowValue) | project rowNumber, rowNumberCurrentUser, user, rowValue, previousValue, nextValue, runningTotal ```
## Language demo just for fun and demo pattern replace
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Language demo just for fun and demo pattern replace.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Language demo just for fun and demo pattern replace

> Query:

```C#print a= ????????????????????????????????????????  | extend a=extractall((.), a) | mvexpand a  | extend a=substring(base64_encodestring(strcat(abracadabra, a)), 19)  | summarize Message=replace(@[+],  , replace(@[[",\]], "", tostring(makelist(a))))```
## Latency for a Log Analytics example with rolling percentiles
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Latency for a Log Analytics example with rolling percentiles.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Latency for a Log Analytics example with rolling percentiles

> Query:

```C#let latencyCachedData = materialize(SigninLogs | where TimeGenerated > ago(24h) | project TimeGenerated, IngestionLatency = (_TimeReceived - TimeGenerated) | extend IngestionLatencyInMinutes = (IngestionLatency / 1m)); union  (latencyCachedData | evaluate rolling_percentile(IngestionLatencyInMinutes, 95, TimeGenerated, 15m, 5) | extend pcnt=95), (latencyCachedData | evaluate rolling_percentile(IngestionLatencyInMinutes, 99, TimeGenerated, 15m, 5) | extend pcnt=99)```
## LineNumbers-serialize
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/LineNumbers-serialize.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: LineNumbers-serialize

> Query:

```C#let timeframe = 1d; SecurityEvent | where TimeGenerated >= ago(timeframe) | where EventID in (4624, 4625) | where AccountType == User  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), Amount = count() by LogonTypeName | extend timestamp = StartTimeUtc | serialize Num = row_number() //using the serialize operator to generate line numbers```
## LoginFailureButPasswordChangeRequired
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/LoginFailureButPasswordChangeRequired.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: LoginFailureButPasswordChangeRequired

> Query:

```C#//Users with login failure due but required to change password at next logon  SecurityEvent | where EventID == 4624 and SubStatus == "0XC0000224"```
## LoginFailureUnknownUserNameorBadPassword
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/LoginFailureUnknownUserNameorBadPassword.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: LoginFailureUnknownUserNameorBadPassword

> Query:

```C#//Users with login failure due to Unknown user name or bad password  SecurityEvent | where EventID == 4625 and FailureReason == "%%2313" | distinct Account```
## LookingforInstalledKBIDs
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/LookingforInstalledKBIDs.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: LookingforInstalledKBIDs

> Query:

```C#//Looking for Installed KBIDs Update | where KBID == "4565511" or KBID == "4558998" or KBID == "4565483" or KBID == "4565503" | distinct Computer, Product, KBID```
## Make series to fill in gaps with default for bin by bucket
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Make series to fill in gaps with default for bin by bucket.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Make series to fill in gaps with default for bin by bucket

> Query:

```C#let window = 1d; let bucket = 1h; let min_t = toscalar(customMetrics | where timestamp > ago(window) | summarize min(timestamp)); let max_t = toscalar(customMetrics | where timestamp > ago(window) | summarize max(timestamp)); customMetrics | where timestamp > ago(window) | make-series totalHeartbeatCountByHour=count() default=0 on timestamp in range(min_t, max_t, bucket)  | mvexpand timestamp to typeof(datetime),     totalHeartbeatCountByHour to typeof(double) | sort by timestamp desc```
## Make-series for gaps
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Make-series for gaps.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Make-series for gaps

> Query:

```C#// Example to perform a aggregation by period where they may be no data for a given period. let startdate = todatetime("2016-11-01"); let enddate = todatetime("2018-11-15"); OfficeActivity | where TimeGenerated between (startdate .. enddate) | make-series count(Operation) default=0 on TimeGenerated in range(startdate, enddate, 1d) by OfficeWorkload | mvexpand TimeGenerated to typeof(datetime), count_Operation to typeof(double)   // Same as above however using a numbers table approach similar to the method used in SQL let startdate = todatetime("2018-11-01"); let startdate2 = todatetime("2018-11-07"); let enddate = todatetime("2018-11-15"); range Day from startdate to enddate step 1d | extend CountOfSomething = 0 | join kind=fullouter (range Day from startdate2 to enddate step 1d | extend CountOfActual = 1 ) on Day | project Day,Value=iff(isnull(CountOfActual), CountOfSomething, CountOfActual)```
## meraki_GROK
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/meraki_GROK.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: meraki_GROK

> Query:

```C#input { file {     path => "/var/log/meraki.log"   } } filter{ grok { #---urls--- match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:devicename} %{WORD:type} src=%{IP:src_ip}:%{INT:src_port} dst=%{IP:dst_ip}:%{INT:dst_port} mac=%{MAC:mac_address} request: %{WORD:request_type} %{URI:uri}"]   match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:devicename} %{WORD:type} src=%{IP:src_ip}:%{INT:src_port} dst=%{IP:dst_ip}:%{INT:dst_port} mac=%{MAC:mac_address} agent=%{WORD:agent} request: %{WORD:request_type} %{URI:uri}"]                  match => [ "message", "%%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host} %{BASE16FLOAT:epoch_time} %{WORD:devicename} %{WORD:type} src=%{IP:src_ip}:%{INT:src_port} dst=%{IP:dst_ip}:%{INT:dst_port} mac=%{MAC:mac_address} agent=%{GREEDYDATA:agent} request: %{WORD:request_type} %{URI:uri}"]  #--- match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:type} src=%{IP:src_ip} dst=%{IP:dst_ip} protocol=%{WORD:protocol} sport=%{INT:src_port} dport=%{INT:dst_port} translated_src_ip=%{IP:translated_src_ip} translated_port=%{INT:translated_port}"]   match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:type} src=%{IP:src_ip} dst=%{IP:dst_ip} protocol=%{WORD:protocol} sport=%{INT:src_port} dport=%{INT:dst_port} translated_dst_ip=%{IP:translated_dst_ip} translated_port=%{INT:translated_port}"]   match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:type} src=%{IP:src_ip} dst=%{IP:dst_ip} protocol=%{WORD:protocol} translated_dst_ip=%{IP:translated_dst_ip}"]  match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:type} src=%{IP:src_ip} dst=%{IP:dst_ip} protocol=%{WORD:protocol} translated_src_ip=%{IP:translated_src_ip}"]  match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:devicename} %{WORD:type} src=%{IP:src_ip} dst=%{IP:dst_ip} protocol=%{WORD:protocol} sport=%{INT:src_port} dport=%{INT:dst_port} pattern: %{GREEDYDATA:pattern}"]    match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:devicename} %{WORD:type} src=%{IP:src_ip} dst=%{IP:dst_ip} mac=%{MAC:mac_address} protocol=%{WORD:protocol} sport=%{INT:src_port} dport=%{INT:dst_port} pattern: %{GREEDYDATA:pattern}"]  match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:devicename} %{WORD:type} src=%{IP:src_ip} dst=%{IP:dst_ip} mac=%{MAC:mac_address} protocol=%{WORD:protocol} type=%{INT:protocol_type} pattern: %{GREEDYDATA:pattern}"]  match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:devicename} %{WORD:type} src=%{IP:src_ip} dst=%{IP:dst_ip} protocol=%{WORD:protocol} type=%{INT:protocol_type} pattern: %{GREEDYDATA:pattern}"]  match => ["message", "%{SYSLOGTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{NUMBER:epoch_time} %{WORD:hostname} (?<log_type>[a-zA-Z0-9\-]+)([ ])?%{GREEDYDATA:contents}"] overwrite => "host"     }     mutate {       add_field => { "device_type" => "cisco-meraki" }     } date {     match => [ "epoch_time","UNIX" ]     target => "@timestamp"     remove_field => [ "ciscotimestamp" ]     remove_field => [ "epoch_time" ] } } output { microsoft-logstash-output-azure-loganalytics {          workspace_id => "<yourworkspaceID>"         workspace_key => "<yourworkspacekey>"         custom_log_table_name => "CiscoMeraki" key_names => [host,devicename,type,hostname,src_ip,log_type,contents,dst_ip,src_port,dst_port,protocol,mac_address,request_type,uri,translated_src_ip,translated_dst_ip,pattern,translated_port,agent,message,@timestamp]     } stdout {}   }```
## MerakiConf2
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/MerakiConf2.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: MerakiConf2

> Query:

```C#input { file {     path => "/var/log/meraki.log"   } } filter{ grok { #---urls--- match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:devicename} %{WORD:type} src=%{IP:src_ip}:%{INT:src_port} dst=%{IP:dst_ip}:%{INT:dst_port} mac=%{MAC:mac_address} request: %{WORD:request_type} %{URI:uri}"]   match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:devicename} %{WORD:type} src=%{IP:src_ip}:%{INT:src_port} dst=%{IP:dst_ip}:%{INT:dst_port} mac=%{MAC:mac_address} agent=%{WORD:agent} request: %{WORD:request_type} %{URI:uri}"]                  match => [ "message", "%%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host} %{BASE16FLOAT:epoch_time} %{WORD:devicename} %{WORD:type} src=%{IP:src_ip}:%{INT:src_port} dst=%{IP:dst_ip}:%{INT:dst_port} mac=%{MAC:mac_address} agent=%{GREEDYDATA:agent} request: %{WORD:request_type} %{URI:uri}"]  #--- match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:type} src=%{IP:src_ip} dst=%{IP:dst_ip} protocol=%{WORD:protocol} sport=%{INT:src_port} dport=%{INT:dst_port} translated_src_ip=%{IP:translated_src_ip} translated_port=%{INT:translated_port}"]   match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:type} src=%{IP:src_ip} dst=%{IP:dst_ip} protocol=%{WORD:protocol} sport=%{INT:src_port} dport=%{INT:dst_port} translated_dst_ip=%{IP:translated_dst_ip} translated_port=%{INT:translated_port}"]   match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:type} src=%{IP:src_ip} dst=%{IP:dst_ip} protocol=%{WORD:protocol} translated_dst_ip=%{IP:translated_dst_ip}"]  match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:type} src=%{IP:src_ip} dst=%{IP:dst_ip} protocol=%{WORD:protocol} translated_src_ip=%{IP:translated_src_ip}"]  match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:devicename} %{WORD:type} src=%{IP:src_ip} dst=%{IP:dst_ip} protocol=%{WORD:protocol} sport=%{INT:src_port} dport=%{INT:dst_port} pattern: %{GREEDYDATA:pattern}"]    match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:devicename} %{WORD:type} src=%{IP:src_ip} dst=%{IP:dst_ip} mac=%{MAC:mac_address} protocol=%{WORD:protocol} sport=%{INT:src_port} dport=%{INT:dst_port} pattern: %{GREEDYDATA:pattern}"]  match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:devicename} %{WORD:type} src=%{IP:src_ip} dst=%{IP:dst_ip} mac=%{MAC:mac_address} protocol=%{WORD:protocol} type=%{INT:protocol_type} pattern: %{GREEDYDATA:pattern}"]  match => [ "message", "%{CISCOTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{BASE16FLOAT:epoch_time} %{WORD:devicename} %{WORD:type} src=%{IP:src_ip} dst=%{IP:dst_ip} protocol=%{WORD:protocol} type=%{INT:protocol_type} pattern: %{GREEDYDATA:pattern}"]  match => ["message", "%{SYSLOGTIMESTAMP:ciscotimestamp} %{SYSLOGHOST:host}  %{NUMBER:epoch_time} %{WORD:hostname} (?<log_type>[a-zA-Z0-9\-]+)([ ])?%{GREEDYDATA:contents}"] overwrite => "host"     }     mutate {       add_field => { "device_type" => "cisco-meraki" }     } date {     match => [ "epoch_time","UNIX" ]     target => "@timestamp"     remove_field => [ "ciscotimestamp" ]     remove_field => [ "epoch_time" ] } } output { microsoft-logstash-output-azure-loganalytics {          workspace_id => "<yourID>"         workspace_key => "<yourWorkspace"         custom_log_table_name => "CiscoMeraki" key_names => [host,devicename,type,hostname,src_ip,log_type,contents,dst_ip,src_port,dst_port,protocol,mac_address,request_type,uri,translated_src_ip,translated_dst_ip,pattern,translated_port,agent,message,@timestamp]     } stdout {}   }```
## MerakiDenialofService
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/MerakiDenialofService.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: MerakiDenialofService

> Query:

```C#//Looking for denial of service  Cisco_Meraki_CL | where (* contains "shutdown" or * contains "config-register 0x2100" or * contains "config-register 0x2142")```
## MerakiDeviceChanges
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/MerakiDeviceChanges.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: MerakiDeviceChanges

> Query:

```C#//Looking for config changes on Meraki MX devices  Cisco_Meraki_CL | where (* contains "ip http server" or * contains "ip https server" or * contains "kron policy-list" or * contains "kron occurrence" or * contains "policy-list" or * contains "access-list" or * contains "ip access-group" or * contains "archive maximum")```
## MerakiDeviceInformation
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/MerakiDeviceInformation.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: MerakiDeviceInformation

> Query:

```C#//Looking for additional device information for Meraki MX devices  Cisco_Meraki_CL | where (* contains "dir" or * contains "show processes" or * contains "show arp" or * contains "show cdp" or * contains "show version" or * contains "show ip route" or * contains "show ip interface" or * contains "show ip sockets" or * contains "show users" or * contains "show ssh" or * contains "show clock")```
## MerakiParser
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/MerakiParser.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: MerakiParser

> Query:

```C#//Available columns: [host,devicename,type,hostname,src_ip,log_type,contents,dst_ip,src_port,dst_port,protocol,mac_address,request_type,uri,translated_src_ip,translated_dst_ip,pattern,translated_port,agent,message,@timestamp]  Cisco_Meraki_CL | where TimeGenerated > ago(10d) | extend ParseFields  = split(RawData,  ) | extend EventMonth   = tostring(ParseFields[0]) | extend EventDay     = tostring(ParseFields[1])  | extend Time         = tostring(ParseFields[2])  | extend DeviceIP     = tostring(ParseFields[3])  | extend Fluff_1      = tostring(ParseFields[4])  | extend Addr         = tostring(ParseFields[5]) | extend Server       = tostring(ParseFields[6]) | extend Method       = tostring(ParseFields[7]) | extend Source       = tostring(ParseFields[8]) | extend Destination  = tostring(ParseFields[9]) | extend MAC          = tostring(ParseFields[10]) | extend Protocol     = tostring(ParseFields[11]) | extend S_Port       = tostring(ParseFields[12]) | extend D_Port       = tostring(ParseFields[13]) | extend Fluff_2      = tostring(ParseFields[14]) | extend Pattern      = tostring(ParseFields[15])```
## MerakiPKIActivity
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/MerakiPKIActivity.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: MerakiPKIActivity

> Query:

```C#//Looking for private key transaction or distribution of new certificates  Cisco_Meraki_CL | where (* contains "crypto pki export" or * contains "crypto pki import" or * contains "crypto pki trustpoint")```
## MerakiSIGRED
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/MerakiSIGRED.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: MerakiSIGRED

> Query:

```C#//Looking for SIGRED  Cisco_Meraki_CL | where ((record_type == "SIG" or record_type == "sig" or record_type == "RRSIG" or record_type == "rrsig") and network_protocol == "tcp")  | summarize dcount_query = dcount(query) by SourceIp | where dcount_query < 15```
## multipleLAworkspaces
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/multipleLAworkspaces.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: multipleLAworkspaces

> Query:

```C#union Update, workspace("1stLAWorkspace").Update, workspace("2ndLAWorkspace").Update | where TimeGenerated >= ago(1h) | where UpdateState == "Needed"```
## NetLogonPatchCompliance
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/NetLogonPatchCompliance.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: NetLogonPatchCompliance

> Query:

```C#//Choose which to track (compliance or non-compliance) and remove the comment //Based on https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc  SecurityEvent | join Heartbeat on Computer //| where EventID == "5829" //Tracking NetLogon Non-Compliance //| where EventID == "5827" or EventID == "5828" //Tracking NetLogon Compliance | distinct Computer, OSType, OSMajorVersion, Version```
## NewBruteForceAttacks
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/NewBruteForceAttacks.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: NewBruteForceAttacks

> Query:

```C#let ExcludedIP = dynamic ([ 172.24.1.4 ]); let PreviousFailures = SecurityEvent | where TimeGenerated between (ago(60m) .. ago(10m)) | where EventID == 4625 | where SubStatus != "0xc0000064" | where AccountType != Machine | where IpAddress !in (ExcludedIP) | summarize FailureCount=count() by TargetAccount, IpAddress, bin(TimeGenerated, 50m) | where FailureCount >= 50 | summarize make_set(strcat(TargetAccount,  , IpAddress)); SecurityEvent | where TimeGenerated > ago(10m) | where EventID == 4625 | where SubStatus != "0xc0000064" | where AccountType != Machine | where IpAddress !in (ExcludedIP) | summarize FailureCount=count() by TargetAccount, IpAddress, bin(TimeGenerated, 10m) | where FailureCount >= 10 | where strcat(TargetAccount,  , IpAddress) !in (PreviousFailures)```
## NotEqual
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/NotEqual.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: NotEqual

> Query:

```C#//Not Equal example SecurityAlert | where DisplayName == "An event log was cleared" | where EndTime != "7/15/2020, 5:55:31.000 PM" and ProviderName != "IPC" and SystemAlertId != "e3f60b59-3c5c-5b5d-8213-698a58fa39aa"```
## NSGChangesByUser
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/NSGChangesByUser.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: NSGChangesByUser

> Query:

```C#AzureActivity | where parse_json(Authorization).action == "Microsoft.Network/networkSecurityGroups/securityRules/write" and ActivityStatus == "Succeeded" | make-series count() default=0 on TimeGenerated in range(ago(7d), now(), 1d) by Caller |render barchart```
## NSGChangesbyUserandResource
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/NSGChangesbyUserandResource.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: NSGChangesbyUserandResource

> Query:

```C#//NSG Changes by Resource and Who did it  AzureActivity | where parse_json(Authorization).action == "Microsoft.Network/networkSecurityGroups/securityRules/write" and ActivityStatus == "Succeeded" | distinct Resource, Caller```
## NumberofEventsOveraSelectedTime
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/NumberofEventsOveraSelectedTime.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: NumberofEventsOveraSelectedTime

> Query:

```C#//Number of events over selected time  union withsource=TableName * | where All Tables == All Tables or TableName == All Tables | summarize count()  by bin(TimeGenerated, 3h), Type | project [Table name] = Type, [Time generated] = TimeGenerated, [Number of events] = count_```
## PowerShellExecution
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/PowerShellExecution.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: PowerShellExecution

> Query:

```C#SecurityEvent | where ProcessName has "powershell.exe" or ProcessName has "powershell_ise.exe" | project TimeGenerated, Computer, SubjectUserName, SubjectDomainName, Process, CommandLine, ParentProcessName```
## PowerShellExecutionwithDownload
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/PowerShellExecutionwithDownload.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: PowerShellExecutionwithDownload

> Query:

```C#//Requires the Microsoft 365 Defender Connector //Identify PowerShell executions that could have initiated a download request  //Query:  union DeviceProcessEvents, DeviceNetworkEvents | where Timestamp > ago(7d) | where FileName in~ ("powershell.exe", "powershell_ise.exe") | where ProcessCommandLine has_any("WebClient", "DownloadFile", "DownloadData", "DownloadString", "WebRequest", "Shellcode", "http", "https") | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, RemoteIPType  //For an Analytics Rule:  union DeviceProcessEvents, DeviceNetworkEvents, DeviceEvents | where Timestamp > ago(7d) | where FileName in~ ("powershell.exe", "powershell_ise.exe") | where ProcessCommandLine has_any("WebClient", "DownloadFile", "DownloadData", "DownloadString", "WebRequest", "Shellcode", "http", "https") | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, RemoteIPType | extend IPCustomEntity = RemoteIP | extend URLCustomEntity = RemoteUrl | extend HostCustomEntity = DeviceName```
## qualys
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/qualys.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: qualys

> Query:

```C#SecurityAlert | where ProviderName contains "asc" and ExtendedProperties contains "qualys" | project RemediationSteps```
## QueriesEachPersonRan
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/QueriesEachPersonRan.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: QueriesEachPersonRan

> Query:

```C#//The actual KQL queries that each person ran in the last 7 days //Enabling the Diag Setting for the Audit log is required to expose the LAQueryLogs table  LAQueryLogs | where TimeGenerated > ago(7d) | project AADEmail, QueryText```
## RemoteWorkspaceQuery
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/RemoteWorkspaceQuery.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: RemoteWorkspaceQuery

> Query:

```C#//Query a remote workspace for usage. Just enter your remote workspace.  workspace("yourremoteworkspace").Usage```
## RestartShutdownsLast7Days
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/RestartShutdownsLast7Days.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: RestartShutdownsLast7Days

> Query:

```C#// List restart and shutdowns events for the last 7 days for all agented computers. Event | where TimeGenerated > ago(7d) | where  EventLog == "System" and Source == "User32" and EventID == 1074 | search "shutdown" | sort by TimeGenerated desc  | project TimeGenerated, Computer```
## Running total aka cumulative sum
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Running total aka cumulative sum.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Running total aka cumulative sum

> Query:

```C#let SampleData = datatable (user:string, rowValue: int) ["A",5,"B",12,"B",15,"A",3,"A",9,"A",19,"B",7]; SampleData  | serialize | extend rowNumber = row_number() | extend rowNumberCurrentUser = row_number(1, prev(user,1,0) != user)  | extend previousValue = strcat("Previous value was ", prev(rowValue,1,0)) | extend nextValue = strcat("Next value was ", next(rowNumber,1,0)) | extend runningTotal = row_cumsum(rowValue) | project rowNumber, rowNumberCurrentUser, user, rowValue, previousValue, nextValue, runningTotal```
## scalarexpression
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/scalarexpression.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: scalarexpression

> Query:

```C#let numdays=3; let newnumdays=toscalar(numdays*3); SecurityAlert | where DisplayName contains "svchost"  | project AlertName , newnumdays```
## SecurityChangePasswordResets
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/SecurityChangePasswordResets.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: SecurityChangePasswordResets

> Query:

```C#// Security Change or Reset Passwords Attempts  // Counts change/reset paswords attempts per target account.  SecurityEvent | where EventID in (4723, 4724) | summarize count() by TargetAccount```
## SecurityIndicentsCreatedinLastDay
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/SecurityIndicentsCreatedinLastDay.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: SecurityIndicentsCreatedinLastDay

> Query:

```C#SecurityIncident | where TimeGenerated > ago(1d)  | where Status == "Active" | project TimeGenerated, Title, Description, Severity, IncidentUrl```
## SentinelIncidentURLs- ALL
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/SentinelIncidentURLs- ALL.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: SentinelIncidentURLs- ALL

> Query:

```C#let IncidentURL = "https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident";  AzureActivity | where _ResourceId has "Microsoft.SecurityInsights" and _ResourceId has "incidents" | summarize by _ResourceId | extend IncidentLINK = strcat(IncidentURL, _ResourceId) | distinct IncidentLINK```
## serversenrolledinWDATP
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/serversenrolledinWDATP.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: serversenrolledinWDATP

> Query:

```C#MachineInfo |where OSPlatform  contains "server"  |project ComputerName, OSPlatform  |distinct ComputerName, OSPlatform```
## SharePointDownloads
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/SharePointDownloads.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: SharePointDownloads

> Query:

```C#OfficeActivity | where  RecordType == "SharePointFileOperation" | where Operation == "FileDownloaded" or Operation == "FileSyncDownloadedFull" | join kind= inner (     Heartbeat     | summarize arg_max(TimeGenerated, *) by ComputerIP     | extend ClientIP = tostring(ComputerIP), Computer ) on ClientIP | project TimeGenerated, ClientIP, Computer, Operation, OfficeWorkload, UserId, SourceFileName, OfficeObjectId | sort by TimeGenerated desc```
## SignInbyLocation
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/SignInbyLocation.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: SignInbyLocation

> Query:

```C#SigninLogs | where TimeGenerated > ago(120d) | where UserDisplayName !="On-Premises Directory Synchronization Service Account" | extend city_  = tostring(LocationDetails.city)  | extend state_ = tostring(LocationDetails.state)  | extend countryOrRegion_ = tostring(LocationDetails.countryOrRegion)  | extend latitude_  = tostring(parse_json(tostring(LocationDetails.geoCoordinates)).latitude)  | extend longitude_ = tostring(parse_json(tostring(LocationDetails.geoCoordinates)).longitude)  | order by TimeGenerated asc , city_ asc | serialize  | extend pLat = prev(latitude_,1) | extend pLon = prev(longitude_,1) | extend distance_in_miles = iif(isnotempty(pLat),tostring(round(geo_distance_2points(todouble(longitude_), todouble(latitude_), todouble(pLon), todouble(pLat))/1609.344 ,2)),"FirstLocation") | where distance_in_miles !="0.0" | summarize count() by bin(TimeGenerated, 24h),                                            userNameLocation = strcat(UserDisplayName," ?? " ,city_ , " ??? ",                        countryOrRegion_),                        visit_order = strcat(row_number(), ".",city_),                        MilesTravelled=distance_in_miles                                         | project-away count_ | order by TimeGenerated asc, visit_order asc```
## SigninLogsByBrowserandLocation
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/SigninLogsByBrowserandLocation.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: SigninLogsByBrowserandLocation

> Query:

```C#SigninLogs  | where AppDisplayName == "Microsoft Cloud App Security"  | extend UserBrowser_ = tostring(DeviceDetail.browser)  | extend UserOperatingSystem_ = tostring(DeviceDetail.operatingSystem)  | extend UserCountryOrRegion_ = tostring(LocationDetails.countryOrRegion)  | extend UserCity_ = tostring(LocationDetails.city)```
## SigninLogsByDay - parsing UTC
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/SigninLogsByDay - parsing UTC.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: SigninLogsByDay - parsing UTC

> Query:

```C#//Sign-ins - how many per day - different ways to get the day split out  SigninLogs  | where AuthenticationRequirement == "multiFactorAuthentication" | summarize count() by bin(TimeGenerated, 1d) | extend myDAY = format_datetime(TimeGenerated, yyyy-MM-dd) //using datetime //| extend myDAY = format_datetime(TimeGenerated, dd) //using datetime, just the day //| extend myDAY = bin(TimeGenerated, 1d) //using bin, but still displays the time, too //| extend myDAY = split(TimeGenerated, "T", 0) //using split to parse | order by TimeGenerated asc | project myDAY, count_```
## SMA and EMA examples
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/SMA and EMA examples.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: SMA and EMA examples

> Query:

```C#// Simple moving average (SMA) version, curve smoothing. let window = 7d; let bucket = 1d; let min_t = toscalar(OfficeActivity | where TimeGenerated > ago(window) | summarize min(TimeGenerated)); let max_t = toscalar(OfficeActivity | where TimeGenerated > ago(window) | summarize max(TimeGenerated)); OfficeActivity | make-series totalAuditCountByDay=count() default=0 on TimeGenerated in range(min_t, max_t, bucket) | extend buckets=range(min_t, max_t, bucket) | extend 3d_SimpleMovingAvg=series_fir(totalAuditCountByDay, dynamic([1,1,1])), 3d_SimpleMovingAvg_centered=series_fir(totalAuditCountByDay, dynamic([1,1,1]), true, true), 5d_SimpleMovingAvg=series_fir(totalAuditCountByDay, dynamic([1,1,1,1,1])) | project buckets,3d_SimpleMovingAvg, 3d_SimpleMovingAvg_centered, 5d_SimpleMovingAvg | render timechart   // Exponential moving average (EMA) version over X days // l sub p is the estimate or smoothed value of the data, smoothing coefficient more aggressive towards 0 let window = 30d; let bucket = 1d; let min_t = toscalar(OfficeActivity | where TimeGenerated > ago(window) | summarize min(TimeGenerated)); let max_t = toscalar(OfficeActivity | where TimeGenerated > ago(window) | summarize max(TimeGenerated)); let series_exp_smooth = (series:dynamic, alpha:real) { series_iir(series, pack_array(alpha), pack_array(1, alpha-1)) }; OfficeActivity | make-series totalAuditCountByDay=count() default=0 on TimeGenerated in range(min_t, max_t, bucket) | extend lp_num1 = series_exp_smooth(totalAuditCountByDay, 0.6) | extend lp_num2 = series_exp_smooth(totalAuditCountByDay, 0.5) | extend lp_num3 = series_exp_smooth(totalAuditCountByDay, 0.4) | render timechart```
## SophosDisabled
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/SophosDisabled.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: SophosDisabled

> Query:

```C#CommonSecurityLog | where DeviceVendor == "sophos" and LogSeverity == 8 and Activity !in ("Real time protection disabled")  | sort by TimeGenerated | project TimeGenerated, Activity, DestinationHostName, SourceUserName, LogSeverity | extend HostCustomEntity = DestinationHostName | extend AccountCustomEntity = SourceUserName```
## SQLServerAuditLogs
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/SQLServerAuditLogs.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: SQLServerAuditLogs

> Query:

```C#//Azure SQL Server Audit Logs //Requires Azure SQL Server auditing enabled: https://azurecloudai.blog/2020/10/29/how-to-send-azure-sql-server-audit-logs-to-azure-sentinel/  AzureDiagnostics  | where TimeGenerated > ago(24h)  | where Category == "SQLSecurityAuditEvents"```
## SuccessfulRoleAssignments
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/SuccessfulRoleAssignments.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: SuccessfulRoleAssignments

> Query:

```C#AzureActivity | where TimeGenerated > ago(60d) and Authorization contains "Microsoft.Authorization/roleAssignments/write" and ActivityStatus == "Succeeded" | parse ResourceId with * "/providers/" TargetResourceAuthProvider "/" * | summarize count(), makeset(Caller) by TargetResourceAuthProvider```
## SysmonEventsStorageSize
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/SysmonEventsStorageSize.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: SysmonEventsStorageSize

> Query:

```C#//Sysmon Events by storage size by bytes  Event | where Source == "Microsoft-Windows-Sysmon" | summarize count() by EventID | extend size_in_bytes = count_ * 500 | order by size_in_bytes desc```
## SystemsReportingtoSentinel
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/SystemsReportingtoSentinel.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: SystemsReportingtoSentinel

> Query:

```C#//Agented systems reporting to Azure Sentinel  SigninLogs | union Heartbeat | where Category == "Direct Agent" | distinct Computer```
## SystemthatHaveUpdatedintheLast4Hours
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/SystemthatHaveUpdatedintheLast4Hours.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: SystemthatHaveUpdatedintheLast4Hours

> Query:

```C#//Systems that have updated in the last 4 hours Update | where TimeGenerated < ago(4h) | where UpdateState != Installed | extend Resource = Computer | summarize count() by Resource | sort by count_ desc```
## TableExistence
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/TableExistence.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: TableExistence

> Query:

```C#//Checking to see if a table (or tables) exist or not  let hasNonEmptyTable = (T:string, T2:string)  {     toscalar(     union isfuzzy=true     ( table(T) | take 1 | count as Count ),    ( table(T2) | take 1 | count as Count),    (print Count=0)     | summarize sum(Count)     ) > 1 }; let TableName = AzureActivity; let TableName2 = SecurityEvent; print  IsPresent=iif(hasNonEmptyTable(TableName,TableName2 ), "present", "not present")```
## TablesNotIngestingDatain3Days
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/TablesNotIngestingDatain3Days.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: TablesNotIngestingDatain3Days

> Query:

```C#//Check all Tables to see which ones have not ingested data in 3 days or more  union withsource=BadTable * | where TimeGenerated > ago(30d) | summarize Entries = count(), last_log = datetime_diff("second",now(), max(TimeGenerated)), estimate  = sumif(_BilledSize, _IsBillable==true)  by BadTable | where last_log >= 259200 | project BadTable```
## TableUsageandCost
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/TableUsageandCost.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: TableUsageandCost

> Query:

```C#//Shows Tables by Table size and how much it costs //For the 0.0 - Enter your price (tip. Use the Azure Pricing Calculator, enter a value of 1GB and divide by 30days)   union withsource=TableName1 * | where TimeGenerated > ago(30d) | summarize Entries = count(), Size = sum(_BilledSize), last_log = datetime_diff("second",now(), max(TimeGenerated)), estimate  = sumif(_BilledSize, _IsBillable==true)  by TableName1, _IsBillable | project [Table Name] = TableName1, [Table Entries] = Entries, [Table Size] = Size,           [Size per Entry] = 1.0 * Size / Entries, [IsBillable] = _IsBillable, [Last Record Received] =  last_log , [Estimated Table Price] =  (estimate/(1024*1024*1024)) * 0.0  | order by [Table Size]  desc ```
## TeamsAADSigninLogsRelatedtoTeamOwners
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/TeamsAADSigninLogsRelatedtoTeamOwners.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: TeamsAADSigninLogsRelatedtoTeamOwners

> Query:

```C#//Detection of suspicious patterns in Azure AD SigninLogs, and using that information while hunting for Team Owners.  let timeRange = 1d; let lookBack = 7d; let threshold_Failed = 5; let threshold_FailedwithSingleIP = 20; let threshold_IPAddressCount = 2; let isGUID = "[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}"; let azPortalSignins = SigninLogs | where TimeGenerated >= ago(timeRange) // Azure Portal only and exclude non-failure Result Types | where AppDisplayName has "Azure Portal" and ResultType !in ("0", "50125", "50140") // Tagging identities not resolved to friendly names | extend Unresolved = iff(Identity matches regex isGUID, true, false); // Lookup up resolved identities from last 7 days let identityLookup = SigninLogs | where TimeGenerated >= ago(lookBack) | where not(Identity matches regex isGUID) | summarize by UserId, lu_UserDisplayName = UserDisplayName, lu_UserPrincipalName = UserPrincipalName; // Join resolved names to unresolved list from portal signins let unresolvedNames = azPortalSignins | where Unresolved == true | join kind= inner (    identityLookup ) on UserId | extend UserDisplayName = lu_UserDisplayName, UserPrincipalName = lu_UserPrincipalName | project-away lu_UserDisplayName, lu_UserPrincipalName; // Join Signins that had resolved names with list of unresolved that now have a resolved name let u_azPortalSignins = azPortalSignins | where Unresolved == false | union unresolvedNames; let failed_signins = (u_azPortalSignins | extend Status = strcat(ResultType, ": ", ResultDescription), OS = tostring(DeviceDetail.operatingSystem), Browser = tostring(DeviceDetail.browser) | extend FullLocation = strcat(Location,|, LocationDetails.state, |, LocationDetails.city) | summarize TimeGenerated = makelist(TimeGenerated), Status = makelist(Status), IPAddresses = makelist(IPAddress), IPAddressCount = dcount(IPAddress), FailedLogonCount = count() by UserPrincipalName, UserId, UserDisplayName, AppDisplayName, Browser, OS, FullLocation | mvexpand TimeGenerated, IPAddresses, Status | extend TimeGenerated = todatetime(tostring(TimeGenerated)), IPAddress = tostring(IPAddresses), Status = tostring(Status) | project-away IPAddresses | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserPrincipalName, UserId, UserDisplayName, Status, FailedLogonCount, IPAddress, IPAddressCount, AppDisplayName, Browser, OS, FullLocation | where (IPAddressCount >= threshold_IPAddressCount and FailedLogonCount >= threshold_Failed) or FailedLogonCount >= threshold_FailedwithSingleIP | project UserPrincipalName); OfficeActivity | where TimeGenerated > ago(time_window) | where Operation =~ "MemberRoleChanged" | extend Member = tostring(parse_json(Members)[0].UPN)  | extend NewRole = toint(parse_json(Members)[0].Role)  | where NewRole == 2 | where Member in (failed_signins) | extend TeamGuid = tostring(Details.TeamGuid)```
## TeamsAADSigninsSuccessUnsuccess
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/TeamsAADSigninsSuccessUnsuccess.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: TeamsAADSigninsSuccessUnsuccess

> Query:

```C#//Tracking Teams sign-ins for successful/unsuccesful logins  let timeFrame = 1d; let logonDiff = 10m; SigninLogs    | where TimeGenerated >= ago(timeFrame)    | where ResultType == "0"    | where AppDisplayName startswith "Microsoft Teams"   | project SuccessLogonTime = TimeGenerated, UserPrincipalName, SuccessIPAddress = IPAddress, AppDisplayName, SuccessIPBlock = strcat(split(IPAddress, ".")[0], ".", split(IPAddress, ".")[1])   | join kind= inner (       SigninLogs        | where TimeGenerated >= ago(timeFrame)        | where ResultType !in ("0", "50140")        | where ResultDescription !~ "Other"         | where AppDisplayName startswith "Microsoft Teams"       | project FailedLogonTime = TimeGenerated, UserPrincipalName, FailedIPAddress = IPAddress, AppDisplayName, ResultType, ResultDescription   ) on UserPrincipalName, AppDisplayName    | where SuccessLogonTime < FailedLogonTime and FailedLogonTime - SuccessLogonTime <= logonDiff and FailedIPAddress !startswith SuccessIPBlock   | summarize FailedLogonTime = max(FailedLogonTime), SuccessLogonTime = max(SuccessLogonTime) by UserPrincipalName, SuccessIPAddress, AppDisplayName, FailedIPAddress, ResultType, ResultDescription    | extend timestamp = SuccessLogonTime, AccountCustomEntity = UserPrincipalName, IPCustomEntity = SuccessIPAddress```
## TeamsBotsorAppsAdded
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/TeamsBotsorAppsAdded.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: TeamsBotsorAppsAdded

> Query:

```C#//Hunt for apps or bots that are new to Teams  // If you have more than 14 days worth of Teams data change this value  let data_date = 14d;  let historical_bots = (  TeamsData  | where TimeGenerated > ago(data_date)  | where isnotempty(AddOnName)  | project AddOnName);  OfficeActivity  | where TimeGenerated > ago(1d)  // Look for add-ins we have never seen before  | where AddOnName in (historical_bots)  // Uncomment the following line to map query entities is you plan to use this as a detection query  //| extend timestamp = TimeGenerated, AccountCustomEntity = UserId```
## TeamsExternalRareUserAccess
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/TeamsExternalRareUserAccess.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: TeamsExternalRareUserAccess

> Query:

```C#//External users added to teams who come from organizations that havent been seen or added before  // If you have more than 14 days worth of Teams data change this value  let data_date = 14d;  // If you want to look at users further back than the last day change this value  let lookback_data = 1d;  let known_orgs = (  OfficeActivity   | where TimeGenerated > ago(data_date)  | where Operation =~ "MemberAdded" or Operation =~ "TeamsSessionStarted"  // Extract the correct UPN and parse our external organization domain  | extend UPN = iif(Operation == "MemberAdded", tostring(parse_json(Members)[0].UPN), UserId)  | extend Organization = tostring(split(split(UPN, "_")[1], "#")[0])  | where isnotempty(Organization)  | summarize by Organization);  OfficeActivity   | where TimeGenerated > ago(lookback_data)  | where Operation =~ "MemberAdded"  | extend UPN = tostring(parse_json(Members)[0].UPN)  | extend Organization = tostring(split(split(UPN, "_")[1], "#")[0])  | where isnotempty(Organization)  | where Organization !in (known_orgs)  // Uncomment the following line to map query entities is you plan to use this as a detection query  //| extend timestamp = TimeGenerated, AccountCustomEntity = UPN```
## TeamsExternalSuspiciousAccountsRevokedAccess
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/TeamsExternalSuspiciousAccountsRevokedAccess.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: TeamsExternalSuspiciousAccountsRevokedAccess

> Query:

```C#//Hunt for external accounts that are added to Teams and swiftly removed to help identify suspicious behavior  // If you want to look at user added further than 7 days ago adjust this value  let time_ago = 7d;  // If you want to change the timeframe of how quickly accounts need to be added and removed change this value  let time_delta = 1h;  OfficeActivity   | where TimeGenerated > ago(time_ago)  | where Operation =~ "MemberAdded"  | extend UPN = tostring(parse_json(Members)[0].UPN)  | project TimeAdded=TimeGenerated, Operation, UPN, UserWhoAdded = UserId, TeamName, TeamGuid = tostring(Details.TeamGuid)  | join (  OfficeActivity   | where TimeGenerated > ago(time_ago)  | where Operation =~ "MemberRemoved"  | extend UPN = tostring(parse_json(Members)[0].UPN)  | project TimeDeleted=TimeGenerated, Operation, UPN, UserWhoDeleted = UserId, TeamName, TeamGuid = tostring(Details.TeamGuid)) on UPN, TeamGuid  | where TimeDeleted < (TimeAdded + time_delta)  | project TimeAdded, TimeDeleted, UPN, UserWhoAdded, UserWhoDeleted, TeamName, TeamGuid  // Uncomment the following line to map query entities is you plan to use this as a detection query  //| extend timestamp = TimeAdded, AccountCustomEntity = UPN```
## TeamsListFederatedUsers
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/TeamsListFederatedUsers.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: TeamsListFederatedUsers

> Query:

```C#//List of Teams sites that have federated external users  OfficeActivity | where TimeGenerated > ago(7d) | where Operation =~ "MemberAdded" | extend UPN = tostring(parse_json(Members)[0].Upn) | where UPN !endswith "sixmilliondollarman.onmicrosoft.com" | where parse_json(Members)[0].Role == 3 | project TeamName, Operation, UserId, Members, UPN```
## TeamsSingleUsersDeleteMultipleTeams
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/TeamsSingleUsersDeleteMultipleTeams.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: TeamsSingleUsersDeleteMultipleTeams

> Query:

```C#//Single users who delete multiple teams  // Adjust this value to change how many Teams should be deleted before including  let max_delete = 3;  // Adjust this value to change the timewindow the query runs over  let time_window = 1d;  let deleting_users = ( OfficeActivity   | where TimeGenerated > ago(time_window)  | where Operation =~ "TeamDeleted"  | summarize count() by UserId  | where count_ > max_delete  | project UserId); OfficeActivity  | where TimeGenerated > ago(time_window)  | where Operation =~ "TeamDeleted"  | where UserId in (deleting_users)  | extend TeamGuid = tostring(Details.TeamGuid)  | project-away AddOnName, Members, Settings  // Uncomment the following line to map query entities is you plan to use this as a detection query  //| extend timestamp = TimeGenerated, AccountCustomEntity = UserId```
## TeamsSuspiciousElevationofPrivileges
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/TeamsSuspiciousElevationofPrivileges.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: TeamsSuspiciousElevationofPrivileges

> Query:

```C#//Suspicious behaviour related to elevation of Teams privileges  // Adjust this value to change how many teams a user is made owner of before detecting  let max_owner_count = 3;  // Change this value to adjust how larger timeframe the query is run over.  let time_window = 1d;  let high_owner_count = (OfficeActivity  | where TimeGenerated > ago(time_window)  | where Operation =~ "MemberRoleChanged"  | extend Member = tostring(parse_json(Members)[0].UPN)   | extend NewRole = toint(parse_json(Members)[0].Role)   | where NewRole == 2  | summarize dcount(TeamName) by Member  | where dcount_TeamName > max_owner_count  | project Member);  OfficeActivity  | where TimeGenerated > ago(time_window)  | where Operation =~ "MemberRoleChanged"  | extend Member = tostring(parse_json(Members)[0].UPN)   | extend NewRole = toint(parse_json(Members)[0].Role)   | where NewRole == 2  | where Member in (high_owner_count)  | extend TeamGuid = tostring(Details.TeamGuid)  // Uncomment the following line to map query entities is you plan to use this as a detection query  //| extend timestamp = TimeGenerated, AccountCustomEntity = Member```
## TeamsUserAddedtoTeamsChannel
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/TeamsUserAddedtoTeamsChannel.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: TeamsUserAddedtoTeamsChannel

> Query:

```C#//Query a specific user to check if they were added to a Teams channel in the last 7 days  OfficeActivity | where TimeGenerated > ago(7d) | where Operation =~ "MemberAdded" | where Members contains "UserName"```
## TeamsWasUserRoleChanged
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/TeamsWasUserRoleChanged.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: TeamsWasUserRoleChanged

> Query:

```C#//Was a users role changed for a Team in the last 7 days  OfficeActivity | where TimeGenerated > ago(7d) | where Operation =~ "MemberRoleChanged" | where Members contains "Role" and Members contains "1"```
## TimeBetweenDates
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/TimeBetweenDates.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: TimeBetweenDates

> Query:

```C#SecurityEvent | where TimeGenerated between(datetime("2020-04-01 22:46:42") .. datetime("2020-04-30 00:57:27"))```
## Top N by group example via LAG - option 1
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Top N by group example via LAG - option 1.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Top N by group example via LAG - option 1

> Query:

```C#let SampleUserData=datatable (UserId:int, OperationDate:datetime) [1, datetime(2018-01-01 12:30:00), 1, datetime(2018-01-01 13:30:00), 2, datetime(2018-01-02 12:30:00), 2, datetime(2018-01-03 13:30:00), 3, datetime(2018-01-02 12:30:00), 3, datetime(2018-01-01 12:30:00), 3, datetime(2018-02-02 13:30:00), 1, datetime(2018-02-02 12:30:00), 1, datetime(2018-02-03 12:30:00), 3, datetime(2018-03-01 12:30:00), 3, datetime(2018-03-02 12:30:00), 2, datetime(2018-03-02 12:30:00), 1, datetime(2018-03-03 11:30:00), 1, datetime(2018-03-03 12:30:00), 1, datetime(2018-03-03 13:30:00) ]; SampleUserData | extend MonthNum = datetime_part("Month", OperationDate)  | summarize CountByMonthNumUserId = count() by MonthNum,UserId | order by MonthNum asc, UserId asc, CountByMonthNumUserId desc | extend RowNum = row_number(1, prev(MonthNum) != MonthNum) | extend CountIsSameAsPrev = CountByMonthNumUserId == prev(CountByMonthNumUserId) | where RowNum in (1,2) or CountIsSameAsPrev | project-away RowNum, CountIsSameAsPrev ```
## Top N by Group example via top-nested - option 2
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Top N by Group example via top-nested - option 2.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Top N by Group example via top-nested - option 2

> Query:

```C#let SampleUserData=datatable (UserId:int, OperationDate:datetime) [1, datetime(2018-01-01 12:30:00), 1, datetime(2018-01-01 13:30:00), 2, datetime(2018-01-02 12:30:00), 2, datetime(2018-01-03 13:30:00), 3, datetime(2018-01-02 12:30:00), 3, datetime(2018-01-01 12:30:00), 3, datetime(2018-02-02 13:30:00), 1, datetime(2018-02-02 12:30:00), 1, datetime(2018-02-03 12:30:00), 3, datetime(2018-03-01 12:30:00), 3, datetime(2018-03-02 12:30:00), 2, datetime(2018-03-02 12:30:00), 1, datetime(2018-03-03 11:30:00), 1, datetime(2018-03-03 12:30:00), 1, datetime(2018-03-03 13:30:00) ]; let SampleUserData2 = SampleUserData | extend MonthNum = datetime_part("Month", OperationDate); SampleUserData2 | top-nested toscalar(SampleUserData2 | summarize dcount(MonthNum)) of MonthNum by max(1), top-nested 2 of UserId by count()```
## Tracking Privileged Account Rare Activity without AWS
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/Tracking Privileged Account Rare Activity without AWS.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Tracking Privileged Account Rare Activity without AWS

> Query:

```C#  let LocalSID = "S-1-5-32-5[0-9][0-9]$";   let GroupSID = "S-1-5-21-[0-9]*-[0-9]*-[0-9]*-5[0-9][0-9]$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-1102$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-1103$";   let timeframe = 8d;   let p_Accounts = SecurityEvent   | where TimeGenerated > ago(timeframe)   | where EventID in ("4728", "4732", "4756") and AccountType == "User" and MemberName == "-"   // Exclude Remote Desktop Users group: S-1-5-32-555 and IIS Users group S-1-5-32-568   | where TargetSid !in ("S-1-5-32-555", "S-1-5-32-568")   | where TargetSid matches regex LocalSID or TargetSid matches regex GroupSID   | summarize by DomainSlashAccount = tolower(SubjectAccount), NtDomain = SubjectDomainName,   AccountAtDomain = tolower(strcat(SubjectUserName,"@",SubjectDomainName)), AccountName = tolower(SubjectUserName);   // Build custom high value account list   let cust_Accounts = datatable(Account:string, NtDomain:string, Domain:string)[   "john", "Contoso", "contoso.com",  "greg", "Contoso", "contoso.com",  "larry", "Domain", "contoso.com"];   let c_Accounts = cust_Accounts   | extend AccountAtDomain = tolower(strcat(Account,"@",Domain)), AccountName = tolower(Account),   DomainSlashAccount = tolower(strcat(NtDomain,"\\",Account));   let AccountFormat = p_Accounts | union c_Accounts | project AccountName, AccountAtDomain, DomainSlashAccount;   // Normalize activity from diverse sources into common schema using a function   let activity = view (a_StartTime:datetime, a_EndTime:datetime) {   (union isfuzzy=true     (AccountFormat | join kind=inner   (SigninLogs   | where TimeGenerated >= a_StartTime and TimeGenerated <= a_EndTime   | extend AccountName = tolower(split(UserPrincipalName, "@")[0]), WinSecEventDomain = "-"   | project-rename EventType = strcat(OperationName, "-", ResultType, "-", ResultDescription), ServiceOrSystem = AppDisplayName, ClientIP = IPAddress)   on AccountName),   (AccountFormat | join kind=inner   (OfficeActivity   | where TimeGenerated >= a_StartTime and TimeGenerated <= a_EndTime   | extend AccountName = tolower(split(UserId, "@")[0]), WinSecEventDomain = "-"   | project-rename EventType = strcat(Operation, "-", ResultStatus), ServiceOrSystem = OfficeWorkload)   on AccountName),   (AccountFormat | join kind=inner   (SecurityEvent   | where TimeGenerated >= a_StartTime and TimeGenerated <= a_EndTime   | where EventID in (4624, 4625)    | extend ClientIP = "-"   | extend AccountName = tolower(split(Account,"\\")[1]), Domain = tolower(split(Account,"\\")[0])   | project-rename EventType = Activity, ServiceOrSystem = Computer, WinSecEventDomain = Domain)   on AccountName),   (AccountFormat | join kind=inner   (W3CIISLog   | where TimeGenerated >= a_StartTime and TimeGenerated <= a_EndTime   | where csUserName != "-" and isnotempty(csUserName)   | extend AccountName = tolower(csUserName), WinSecEventDomain = "-"   | project-rename EventType = csMethod, ServiceOrSystem = sSiteName, ClientIP = cIP)   on AccountName),   (AccountFormat | join kind=inner   (W3CIISLog   | where TimeGenerated >= a_StartTime and TimeGenerated <= a_EndTime   | where csUserName != "-" and isnotempty(csUserName)   | extend AccountAtDomain = tolower(csUserName), WinSecEventDomain = "-"   | project-rename EventType = csMethod, ServiceOrSystem = sSiteName, ClientIP = cIP)   on AccountAtDomain));   };   // Rare activity today versus prior week   let LastDay = startofday(ago(1d));   let PrevDay = endofday(ago(2d));   let Prev7Day = startofday(ago(8d));   let ra_LastDay = activity(LastDay, now())   | summarize ra_StartTime = min(TimeGenerated), ra_EndTime = max(TimeGenerated),   ra_Count = count() by Type, AccountName, EventType, ClientIP, ServiceOrSystem, WinSecEventDomain;   let a_7day = activity(Prev7Day, PrevDay)   | summarize ha_Count = count() by Type, AccountName, EventType, ClientIP, ServiceOrSystem, WinSecEventDomain;   let ra_Today = ra_LastDay | join kind=leftanti (a_7day) on Type, AccountName, ServiceOrSystem   | extend RareServiceOrSystem = ServiceOrSystem;   // Retrieve related activity as context   let a_Related =   (union isfuzzy=true   (// Make sure we at least publish the unusual activity we identified above - even if no related context activity is found in the subsequent union   ra_Today),   // Remaining elements of the union look for related activity   (ra_Today | join kind=inner   (OfficeActivity   | where TimeGenerated > LastDay   | summarize rel_StartTime = min(TimeGenerated), rel_EndTime = max(TimeGenerated), rel_ServiceOrSystemCount = dcount(OfficeWorkload),   rel_ServiceOrSystemSet = makeset(OfficeWorkload), rel_ClientIPSet = makeset(ClientIP),   rel_Count = count() by AccountName = tolower(UserId), rel_EventType = Operation, Type   ) on AccountName),   (ra_Today | join kind=inner   (SecurityEvent | where TimeGenerated > LastDay   | where EventID in (4624, 4625)   | where AccountType == "User"   | summarize rel_StartTime = min(TimeGenerated), rel_EndTime = max(TimeGenerated), rel_ServiceOrSystemCount = dcount(Computer),   rel_ServiceOrSystemSet = makeset(Computer), rel_ClientIPSet = makeset("-"),   rel_Count = count() by DomainSlashAccount = tolower(Account), rel_EventType = Activity, Type   ) on DomainSlashAccount),   (ra_Today | join kind=inner   (Event | where TimeGenerated > LastDay   // 7045: A service was installed in the system   | where EventID == 7045   | summarize rel_StartTime = min(TimeGenerated), rel_EndTime = max(TimeGenerated), rel_ServiceOrSystemCount = dcount(Computer),   rel_ServiceOrSystemSet = makeset(Computer), rel_ClientIPSet = makeset("-"),   rel_Count = count() by DomainSlashAccount = tolower(UserName), rel_EventType = strcat(EventID, "-", tostring(split(RenderedDescription,".")[0])), Type   ) on DomainSlashAccount),   (ra_Today | join kind=inner   (SecurityEvent | where TimeGenerated > LastDay   // 4720: Account created, 4726: Account deleted   | where EventID in (4720,4726)   | summarize rel_StartTime = min(TimeGenerated), rel_EndTime = max(TimeGenerated), rel_ServiceOrSystemCount = dcount(UserPrincipalName),   rel_ServiceOrSystemSet = makeset(UserPrincipalName), rel_ClientIPSet = makeset("-"),   rel_Count = count() by DomainSlashAccount = tolower(Account), rel_EventType = Activity, Type   ) on DomainSlashAccount),   (ra_Today | join kind=inner   (SigninLogs | where TimeGenerated > LastDay   | extend RemoteHost = tolower(tostring(parsejson(DeviceDetail.["displayName"])))   | extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser, StatusCode = tostring(Status.errorCode),   StatusDetails = tostring(Status.additionalDetails), State = tostring(LocationDetails.state)   | summarize rel_StartTime = min(TimeGenerated), rel_EndTime = max(TimeGenerated), a_RelatedRemoteHostSet = makeset(RemoteHost),   rel_ServiceOrSystemSet = makeset(AppDisplayName), rel_ServiceOrSystemCount = dcount(AppDisplayName), rel_ClientIPSet = makeset(IPAddress),   rel_StateSet = makeset(State),   rel_Count = count() by AccountAtDomain = tolower(UserPrincipalName), rel_EventType = iff(isnotempty(ResultDescription), ResultDescription, StatusDetails), Type   ) on AccountAtDomain),   (ra_Today | join kind=inner   (SecurityAlert | where TimeGenerated > LastDay   | extend ExtProps=parsejson(ExtendedProperties)   | extend AccountName = tostring(ExtProps.["user name"])   | summarize rel_StartTime = min(TimeGenerated), rel_EndTime = max(TimeGenerated), rel_ServiceOrSystemCount = dcount(AlertType),   rel_ServiceOrSystemSet = makeset(AlertType),    rel_Count = count() by DomainSlashAccount = tolower(AccountName), rel_EventType = ProductName, Type   ) on DomainSlashAccount)   );   a_Related   | project Type, RareActivtyStartTimeUtc = ra_StartTime, RareActivityEndTimeUtc = ra_EndTime, RareActivityCount = ra_Count,   AccountName, WinSecEventDomain, EventType, RareServiceOrSystem, RelatedActivityStartTimeUtc = rel_StartTime,   RelatedActivityEndTimeUtc = rel_EndTime, RelatedActivityEventType = rel_EventType, RelatedActivityClientIPSet = rel_ClientIPSet,   RelatedActivityServiceOrSystemCount = rel_ServiceOrSystemCount, RelatedActivityServiceOrSystemSet = rel_ServiceOrSystemSet, RelatedActivityCount = rel_Count   | extend timestamp = RareActivtyStartTimeUtc, AccountCustomEntity = AccountName```
## UpdateComplianceBarChart
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/UpdateComplianceBarChart.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: UpdateComplianceBarChart

> Query:

```C#//Update Compliance with Barchart  Update | join UpdateSummary on Computer | where UpdateState != Installed | extend Resource = Computer | extend IsUpdateNeeded = UpdateState | extend UpdateTitle = Title | extend UpdateType = Classification | extend KB = KBID | distinct Computer, OsVersion, UpdateState, Title, Classification, KBID | sort by Computer asc  | summarize count() by Computer | render barchart ```
## UpdateDataConnectors
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/UpdateDataConnectors.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: UpdateDataConnectors

> Query:

```C#AzureActivity | where OperationName == "Update Data Connectors" and ActivityStatus == "Succeeded" | project Caller , CallerIpAddress, EventSubmissionTimestamp```
## UserAccountLockedAAD
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/UserAccountLockedAAD.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: UserAccountLockedAAD

> Query:

```C#SigninLogs  | where TimeGenerated > ago(4h)  | where ResultType == "50053" | project UserDisplayName```
## WatchlistNOTin
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/WatchlistNOTin.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: WatchlistNOTin

> Query:

```C#//Just a simple KQL query to use as a template to use a Watchlist to show where something is NOT in the Watchlist  let watchlist = _GetWatchlist("Your Watchlist Alias") | project IP; let timeframe = 1d; let threshold = 15; TableName | where TimeGenerated >= ago(timeframe) | where ip !in (watchlist) | project user, ip, port, SyslogMessage, EventTime```
## WhenUEBAwasEnabledByWho
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/WhenUEBAwasEnabledByWho.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: WhenUEBAwasEnabledByWho

> Query:

```C#//When UEBA was enabled and by who  AzureActivity | where Properties_d has "microsoft.securityinsights/ueba" | extend WhoDidIt = Caller | project WhoDidIt, CallerIpAddress, EventSubmissionTimestamp```
## WhiteList-FindWhoAccessedAzureSentinelthatShouldNot
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/WhiteList-FindWhoAccessedAzureSentinelthatShouldNot.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: WhiteList-FindWhoAccessedAzureSentinelthatShouldNot

> Query:

```C#//Create a whitelist of users who should be able to access Azure Sentinel, then check to see if unauthorized users have performed activities. //Replace the users in the variable for AuthorizedUser with authorized accounts. Authorized account format is gleaned from AzureActivity/Caller let List = datatable(AuthorizedUser: string)["user1@domain.com", "user2@domain.com", "user3@domain.com"]; let timeframe = 1d; AzureActivity | where OperationNameValue has "MICROSOFT.SECURITYINSIGHTS" | where ActivityStatusValue == "Success" | where CategoryValue == "Administrative" | join kind= leftanti (     List     | project Caller = tolower(AuthorizedUser)     )     on Caller | extend AccountCustomEntity = Caller | extend IPCustomEntity = CallerIpAddress```
## WhoChangedConditionalAccessPolicy
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/WhoChangedConditionalAccessPolicy.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: WhoChangedConditionalAccessPolicy

> Query:

```C#//Reporting when a Conditional Access Policy is updated and who did it  AuditLogs | where OperationName == "Update policy" | extend Person = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName) | project Person```
## WhoChangedTheirAADPassword
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/WhoChangedTheirAADPassword.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: WhoChangedTheirAADPassword

> Query:

```C#AuditLogs | where OperationName contains "self-service" | where Result == "success" | extend userPrincipalName_ = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName) | project userPrincipalName_```
## WhoDeletedAlertRule
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/WhoDeletedAlertRule.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: WhoDeletedAlertRule

> Query:

```C#AzureActivity | where OperationName == "Delete Alert Rules" and ActivityStatusValue == "Succeeded"  | project Caller , EventSubmissionTimestamp```
## WhoModifiedAnalyticsRule
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/WhoModifiedAnalyticsRule.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: WhoModifiedAnalyticsRule

> Query:

```C#//Standard query  AzureActivity | where OperationNameValue contains "MICROSOFT.SECURITYINSIGHTS/ALERTRULES/WRITE" | where ActivityStatusValue == "Success" | extend Analytics_Rule_ID = tostring(parse_json(Properties).resource) | project TimeGenerated , CallerIpAddress , Caller , Analytics_Rule_ID  //Analytics Rule  AzureActivity | where OperationNameValue contains "MICROSOFT.SECURITYINSIGHTS/ALERTRULES/WRITE" | where ActivityStatusValue == "Success" | extend Analytics_Rule_ID = tostring(parse_json(Properties).resource) | extend AccountCustomEntity = Caller | extend IPCustomEntity = CallerIpAddress```
## WiresharkRSSTraffic
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/WiresharkRSSTraffic.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: WiresharkRSSTraffic

> Query:

```C#//RSS traffic  Wireshark_CL  | where TimeGenerated > ago(1d) | where RawData contains "rss.channel.item.link" | distinct RawData```
## ZeroLogon_Ports
### Hunt Tags

> Author: [rod trent](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/ZeroLogon_Ports.txt)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: ZeroLogon_Ports

> Query:

```C#//Ports accessed by Zerologon  DeviceNetworkEvents | where RemotePort == 135 or RemotePort between (49670 .. 49680) | summarize (Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountSid)=arg_min(ReportId, Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountSid), TargetDevicePorts=make_set(RemotePort) by DeviceId, DeviceName, RemoteIP, RemoteUrl | project-rename SourceComputerName=DeviceName, SourceDeviceId=DeviceId, TargetDeviceIP=RemoteIP, TargetComputerName=RemoteUrl```
