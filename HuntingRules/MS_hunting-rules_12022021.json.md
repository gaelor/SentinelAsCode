![](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg "Metsys")
# Hunting Rules
## Consent to Application discovery
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AuditLogs/ConsentToApplicationDiscovery.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence']

### Hunt details

> Description: This query looks at the last 14 days for any "Consent to application" operationoccurs by a user or app. This could indicate that permissions to access the listed AzureAppwas provided to a malicious actor. Consent to appliction, Add service principal and Add OAuth2PermissionGrant events should be rare. If available, additional context is added from the AuditLogs based on CorrleationId from the same account that performed "Consent to application".For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activitiesThis may help detect the Oauth2 attack that can be initiated by this publicly available toolhttps://github.com/fireeye/PwnAuth

> Query:

## Rare Audit activity initiated by App
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AuditLogs/RareAuditActivityByApp.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'LateralMovement']

### Hunt details

> Description: Compares the current day to the last 14 days of audits to identify new audit activities by OperationName, InitiatedByApp, UserPrincipalName, PropertyName, newValueThis can be useful when attempting to track down malicious activity related to additions of new users,additions to groups, removal from groups by Azure Apps and automated approvals.

> Query:

```let current = 1d;
let auditLookback = 14d;
let propertyIgnoreList = dynamic(["TargetId.UserType", "StsRefreshTokensValidFrom", "LastDirSyncTime", "DeviceOSVersion", "CloudDeviceOSVersion", "DeviceObjectVersion"]);
let appIgnoreList = dynamic(["Microsoft Azure AD Group-Based Licensing"]);
let AuditTrail = AuditLogs 
| where TimeGenerated >= ago(auditLookback) and TimeGenerated < ago(current)
| where isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend InitiatedByApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
| extend ModProps = TargetResources.[0].modifiedProperties
| extend InitiatedByIpAddress = tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)
| extend TargetUserPrincipalName = tolower(tostring(TargetResources.[0].userPrincipalName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| mv-expand ModProps
| where isnotempty(tostring(parse_json(tostring(ModProps.newValue))[0]))
| extend PropertyName = tostring(ModProps.displayName), newValue = tostring(parse_json(tostring(ModProps.newValue))[0])
| where PropertyName !in~ (propertyIgnoreList) and (PropertyName !~ "Action Client Name" and newValue !~ "DirectorySync") and (PropertyName !~ "Included Updated Properties" and newValue !~ "LastDirSyncTime")
| where InitiatedByApp !in~ (appIgnoreList) and OperationName !~ "Change user license"
| summarize by OperationName, InitiatedByApp, TargetUserPrincipalName, InitiatedByIpAddress, TargetResourceName, PropertyName;
let AccountMods = AuditLogs
| where TimeGenerated >= ago(current)
| where isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend InitiatedByApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
| extend ModProps = TargetResources.[0].modifiedProperties
| extend InitiatedByIpAddress = tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)
| extend TargetUserPrincipalName = tolower(tostring(TargetResources.[0].userPrincipalName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| mv-expand ModProps
| where isnotempty(tostring(parse_json(tostring(ModProps.newValue))[0]))
| extend PropertyName = tostring(ModProps.displayName), newValue = tostring(parse_json(tostring(ModProps.newValue))[0])
| where PropertyName !in~ (propertyIgnoreList) and (PropertyName !~ "Action Client Name" and newValue !~ "DirectorySync") and (PropertyName !~ "Included Updated Properties" and newValue !~ "LastDirSyncTime")
| where InitiatedByApp !in~ (appIgnoreList) and OperationName !~ "Change user license"
| extend ModifiedProps = pack("PropertyName",PropertyName,"newValue",newValue, "Id", Id, "CorrelationId", CorrelationId) 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), Activity = make_bag(ModifiedProps) by Type, InitiatedByApp, TargetUserPrincipalName, InitiatedByIpAddress, TargetResourceName, Category, OperationName, PropertyName;
let RareAudits = AccountMods | join kind= leftanti (
   AuditTrail 
) on OperationName, InitiatedByApp, InitiatedByIpAddress, TargetUserPrincipalName;//, PropertyName; //uncomment if you want to see Rare Property changes.
RareAudits
| summarize StartTime = min(StartTimeUtc), EndTime = max(EndTimeUtc), make_set(Activity), make_set(PropertyName) by InitiatedByApp, OperationName, TargetUserPrincipalName, InitiatedByIpAddress, TargetResourceName
| order by TargetUserPrincipalName asc, StartTime asc
| extend timestamp = StartTime, AccountCustomEntity = TargetUserPrincipalName, HostCustomEntity = iff(set_PropertyName has_any (DeviceOSType, CloudDeviceOSType), TargetResourceName, ), IPCustomEntity = InitiatedByIpAddress```
## Rare Audit activity initiated by User
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AuditLogs/RareAuditActivityByUser.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'LateralMovement']

### Hunt details

> Description: Compares the current day to the last 14 days of audits to identify new audit activities by OperationName, InitiatedByUser, UserPrincipalName, PropertyName, newValueThis can be useful when attempting to track down malicious activity related to additions of new users, additions to groups, removal from groups by specific users.

> Query:

```let current = 1d;
let auditLookback = 14d;
let propertyIgnoreList = dynamic(["TargetId.UserType", "StsRefreshTokensValidFrom", "LastDirSyncTime", "DeviceOSVersion", "CloudDeviceOSVersion", "DeviceObjectVersion"]);
let AuditTrail = AuditLogs 
| where TimeGenerated >= ago(auditLookback) and TimeGenerated < ago(current)
| where isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName))
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend InitiatedByIPAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend ModProps = TargetResources.[0].modifiedProperties
| extend TargetUserPrincipalName = tolower(tostring(TargetResources.[0].userPrincipalName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| mv-expand ModProps
| extend PropertyName = tostring(ModProps.displayName), newValue = tostring(parse_json(tostring(ModProps.newValue))[0])
| where PropertyName !in~ (propertyIgnoreList) and (PropertyName !~ "Action Client Name" and newValue !~ "DirectorySync") and (PropertyName !~ "Included Updated Properties" and newValue !~ "LastDirSyncTime")
| summarize count() by OperationName, InitiatedByUser, InitiatedByIPAddress, TargetUserPrincipalName, PropertyName, TargetResourceName;
let AccountMods = AuditLogs 
| where TimeGenerated >= ago(current)
| where isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName))
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend InitiatedByIPAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend ModProps = TargetResources.[0].modifiedProperties
| extend TargetUserPrincipalName = tolower(tostring(TargetResources.[0].userPrincipalName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| mv-expand ModProps
| extend PropertyName = tostring(ModProps.displayName), newValue = tostring(parse_json(tostring(ModProps.newValue))[0])
| where PropertyName !in~ (propertyIgnoreList) and (PropertyName !~ "Action Client Name" and newValue !~ "DirectorySync") and (PropertyName !~ "Included Updated Properties" and newValue !~ "LastDirSyncTime")
| extend ModifiedProps = pack("PropertyName",PropertyName,"newValue",newValue, "Id", Id, "CorrelationId", CorrelationId) 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), Activity = make_bag(ModifiedProps) by Type, InitiatedByUser, InitiatedByIPAddress, TargetUserPrincipalName, Category, OperationName, PropertyName, TargetResourceName;
let RareAudits = AccountMods | join kind= leftanti (
   AuditTrail 
) on OperationName, InitiatedByUser, InitiatedByIPAddress;//, TargetUserPrincipalName, PropertyName; //uncomment if you want to see Rare Property changes to a given TargetUserPrincipalName.
RareAudits 
| summarize StartTime = min(StartTimeUtc), EndTime = max(EndTimeUtc), make_set(Activity), make_set(PropertyName) by Type, InitiatedByUser, InitiatedByIPAddress, OperationName, TargetUserPrincipalName, TargetResourceName
| order by InitiatedByUser asc, StartTime asc
| extend timestamp = StartTime, AccountCustomEntity = InitiatedByUser, HostCustomEntity = iff(set_PropertyName has_any (DeviceOSType, CloudDeviceOSType), TargetResourceName, ), IPCustomEntity = InitiatedByIPAddress```
## Interactive STS refresh token modifications
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AuditLogs/StsRefreshTokenModification.yaml)

### ATT&CK Tags

> Tactics: [u'CredentialAccess']

### Hunt details

> Description: This will show Active Directory Security Token Service (STS) refresh token modifications by Service Principals and Applications other than DirectorySync. Refresh tokens are used to validate identification and obtain access tokens.This event is not necessarily an indication of malicious activity but can also be generated when legitimate administrators manually expire token validation or keep longer refresh tokens for better login experience with less prompts.Also an allowlist has been included to filter known accounts which can be customized after careful review of past historical activity.Analyze the results for unusual operations performed by administrators to extend a refresh token of a compromised account in order to extend the time they can use it without the need to re-authenticate (and thus potentially lose access).For in-depth documentation of AAD Security Tokens, see https://docs.microsoft.com/azure/active-directory/develop/security-tokens.For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.For valid use cases of altering token lifetime values, refer https://docs.microsoft.com/azure/active-directory/develop/access-tokens#token-timeoutsMore information about risky use-cases ,refer https://docs.microsoft.com/azure/active-directory/develop/active-directory-configurable-token-lifetimes#token-lifetimes-with-public-client-refresh-tokens

> Query:

```let auditLookback = 1d;
// Include your additions to the allow list below as needed
let AllowedUserList = dynamic(["Microsoft Cloud App Security","ADConnectSyncAccount1","SyncAccount2"]);
AuditLogs
| where TimeGenerated > ago(auditLookback)
| where OperationName has StsRefreshTokenValidFrom
| where TargetResources[0].modifiedProperties != []
| where TargetResources[0].modifiedProperties !has DirectorySync
| extend TargetResourcesModProps = TargetResources[0].modifiedProperties
| mv-expand TargetResourcesModProps
| where tostring(TargetResourcesModProps.displayName) =~ StsRefreshTokensValidFrom
| extend InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| where InitiatingUserOrApp !in (AllowedUserList)
| extend targetUserOrApp = TargetResources[0].userPrincipalName
| extend eventName = tostring(TargetResourcesModProps.displayName)
| extend oldStsRefreshValidFrom = todatetime(parse_json(tostring(TargetResourcesModProps.oldValue))[0])
| extend newStsRefreshValidFrom = todatetime(parse_json(tostring(TargetResourcesModProps.newValue))[0])
| extend tokenMinutesAdded = datetime_diff(minute,newStsRefreshValidFrom,oldStsRefreshValidFrom)
| extend tokenMinutesRemaining = datetime_diff(minute,TimeGenerated,newStsRefreshValidFrom)
| project-reorder Result, AADOperationType
| extend InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatingUserOrApp, IPCustomEntity = InitiatingIpAddress```
## User Granted Access and associated audit activity
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AuditLogs/UserGrantedAccess_AllAuditActivity.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'PrivilegeEscalation', u'Impact']

### Hunt details

> Description: Identifies when a new user is granted access and any subsequent audit related activity.  This can help you identify rogue or malicious user behavior.

> Query:

```let auditLookback = 14d;
let opName = dynamic(["Add user", "Invite external user"]);
// Setting threshold to 3 as a default, change as needed.  Any operation that has been initiated by a user or app more than 3 times in the past 14 days will be excluded
let threshold = 3;
// Helper function to extract relevant fields from AuditLog events
let auditLogEvents = view (startTimeSpan:timespan)  {
    AuditLogs | where TimeGenerated >= ago(auditLookback)
    | extend ModProps = iff(TargetResources.[0].modifiedProperties != "[]", TargetResources.[0].modifiedProperties, todynamic("NoValues"))
    | extend IpAddress = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)), 
    tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), tostring(parse_json(tostring(InitiatedBy.app)).ipAddress))
    | extend InitiatedByFull = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
    tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
    | extend InitiatedBy = replace("_","@",tostring(split(InitiatedByFull, "#")[0]))
    | extend TargetUserPrincipalName = tostring(TargetResources[0].userPrincipalName)
    | extend TargetUserName = replace("_","@",tostring(split(TargetUserPrincipalName, "#")[0]))
    | extend TargetResourceName = case(
    isempty(tostring(TargetResources.[0].displayName)), TargetUserPrincipalName,
    isnotempty(tostring(TargetResources.[0].displayName)) and tostring(TargetResources.[0].displayName) startswith "upn:", tolower(tostring(TargetResources.[0].displayName)),
    tolower(tostring(TargetResources.[0].displayName))
    )
    | extend TargetUserName = replace("_","@",tostring(split(TargetUserPrincipalName, "#")[0]))
    | extend TargetUserName = iff(isempty(TargetUserName), tostring(split(split(TargetResourceName, ",")[0], " ")[1]), TargetUserName ) 
    | mvexpand ModProps
    | extend PropertyName = tostring(ModProps.displayName), newValue = replace("\"","",tostring(ModProps.newValue));
};
let HistoricalAdd = auditLogEvents(auditLookback)
| where OperationName in~ (opName)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), OperationCount = count() 
by Type, InitiatedBy, IpAddress, TargetUserName, TargetResourceName, Category, OperationName, PropertyName, newValue, CorrelationId, Id
// Remove comment below to only include operations initiated by a user or app that is above the threshold for the last 14 days
| where OperationCount > threshold
;
// Get list of new added users to correlate with all other events
let Correlate = HistoricalAdd 
| summarize by InitiatedBy, TargetUserName, CorrelationId;
// Get all other events related to list of newly added users
let allOtherEvents = auditLogEvents(auditLookback);
// Join the new added user list to get the list of associated events
let CorrelatedEvents = Correlate 
| join allOtherEvents on InitiatedBy, TargetUserName
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) 
by Type, InitiatedBy, IpAddress, TargetUserName, TargetResourceName, Category, OperationName, PropertyName, newValue, CorrelationId, Id
;
// Union the results so we can see when the user was added and any associated events that occurred during the same time.
let Results = union isfuzzy=true HistoricalAdd,CorrelatedEvents;
// newValues that are simple semi-colon separated, make those dynamic for easy viewing and Aggregate into the PropertyUpdate set based on CorrelationId and Id(DirectoryId)
Results
| extend newValue = split(newValue, ";")
| extend PropertyUpdate = pack(PropertyName, newValue, "Id", Id)
| summarize StartTimeUtc = min(StartTimeUtc), EndTimeUtc = max(EndTimeUtc), PropertyUpdateSet = make_bag(PropertyUpdate) 
by InitiatedBy, IpAddress, TargetUserName, TargetResourceName, OperationName, CorrelationId
| extend timestamp = StartTimeUtc, AccountCustomEntity = InitiatedBy, HostCustomEntity = TargetResourceName, IPCustomEntity = IpAddress```
## User Granted Access and Grants others Access
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AuditLogs/UserGrantedAccess_GrantsOthersAccess.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'PrivilegeEscalation']

### Hunt details

> Description: Identifies when a new user is granted access and starts granting access to other users.  This can help you identify rogue or malicious user behavior.

> Query:

```let auditLookback = 14d;
let opName = dynamic(["Add user", "Invite external user"]);
// Helper function to extract relevant fields from AuditLog events
let auditLogEvents = view (startTimeSpan:timespan, operation:dynamic)  {
    AuditLogs | where TimeGenerated >= ago(auditLookback)
    | where OperationName in~ (operation)
    | extend ModProps = iff(TargetResources.[0].modifiedProperties != "[]", TargetResources.[0].modifiedProperties, todynamic("NoValues"))
    | extend IpAddress = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)), 
    tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), tostring(parse_json(tostring(InitiatedBy.app)).ipAddress))
    | extend InitiatedByFull = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
    tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
    | extend InitiatedBy = replace("_","@",tostring(split(InitiatedByFull, "#")[0]))
    | extend TargetUserPrincipalName = tostring(TargetResources[0].userPrincipalName)
    | extend TargetUserName = replace("_","@",tostring(split(TargetUserPrincipalName, "#")[0]))
    | extend TargetResourceName = case(
    isempty(tostring(TargetResources.[0].displayName)), TargetUserPrincipalName,
    isnotempty(tostring(TargetResources.[0].displayName)) and tostring(TargetResources.[0].displayName) startswith "upn:", tolower(tostring(TargetResources.[0].displayName)),
    tolower(tostring(TargetResources.[0].displayName))
    )
    | extend TargetUserName = replace("_","@",tostring(split(TargetUserPrincipalName, "#")[0]))
    | extend TargetUserName = iff(isempty(TargetUserName), tostring(split(split(TargetResourceName, ",")[0], " ")[1]), TargetUserName ) 
    | mvexpand ModProps
    | extend PropertyName = tostring(ModProps.displayName), newValue = replace("\"","",tostring(ModProps.newValue));
};
// Assigning time for First TargetUserName that was added
let FirstAdd = auditLogEvents(auditLookback, opName)  
| project FirstAddTimeUtc = TimeGenerated, Type, FirstInitiatedBy = InitiatedBy, IpAddress, FirstTargetUserName = TargetUserName, FirstTargetResourceName = TargetResourceName, 
FirstOperationName = OperationName, FirstPropertyName = PropertyName, FirstnewValue = newValue, FirstCorrelationId = CorrelationId, FirstId = Id;
// Assigning time for second TargetUserName that was added, which will allow us to see if a first TargetUserName added in is the Initiated by on the second in the later join
let SecondAdd = auditLogEvents(auditLookback, opName)  
| project SecondAddTimeUtc = TimeGenerated, Type, SecondInitiatedBy = InitiatedBy, IpAddress, SecondTargetUserName = TargetUserName, SecondTargetResourceName = TargetResourceName, 
SecondOperationName = OperationName, SecondPropertyName = PropertyName, SecondnewValue = newValue, SecondCorrelationId = CorrelationId, SecondId = Id;
//  Joining the FirstAdd with SecondAdd where the FirstAdd TargetUserName value matches the SecondAdd InitiatedBy.  This shows the new user adding a user.
let NewUserAddsUser = FirstAdd | join SecondAdd on $left.FirstTargetUserName == $right.SecondInitiatedBy
// we only want items where the FirstAddTimeUtc is before the SecondAddTimeUtc
| where FirstAddTimeUtc < SecondAddTimeUtc
;
// Build out some of the properties for context
NewUserAddsUser
| extend FirstnewValue = split(FirstnewValue, ";"), SecondnewValue = split(SecondnewValue, ";")
| extend PropertyUpdate = pack(FirstPropertyName, FirstnewValue, SecondPropertyName, SecondnewValue, "FirstCorrelationId", FirstCorrelationId, "FirstId", FirstId, "SecondCorrelationId", SecondCorrelationId, "SecondId", SecondId)
| summarize PropertyUpdateSet = make_bag(PropertyUpdate) by FirstAddTimeUtc, FirstInitiatedBy, FirstTargetUserName, SecondAddTimeUtc, SecondInitiatedBy, SecondTargetUserName, 
IpAddress, FirstTargetResourceName, SecondTargetResourceName, FirstOperationName, SecondOperationName
| extend timestamp = FirstAddTimeUtc, AccountCustomEntity = FirstInitiatedBy, HostCustomEntity = FirstTargetResourceName, IPCustomEntity = IpAddress```
## Changes made to AWS IAM policy
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AWSCloudTrail/AWS_IAM_PolicyChange.yaml)

### ATT&CK Tags

> Tactics: [u'PrivilegeEscalation', u'DefenseEvasion']

### Hunt details

> Description: Identity and Access Management (IAM) securely manages access to AWS services and resources. This query looks for when an API call is made to change an IAM, particularly those related to new policies being attached to users and roles, as well as changes to access methods and changes to account level policies. If these turn out to be noisy filter out the most common for your environment.

> Query:

```let timeframe = 7d;
AWSCloudTrail
| where TimeGenerated >= ago(timeframe)
| where  EventName in~ ("AttachGroupPolicy", "AttachRolePolicy", "AttachUserPolicy", "CreatePolicy",
"DeleteGroupPolicy", "DeletePolicy", "DeleteRolePolicy", "DeleteUserPolicy", "DetachGroupPolicy",
"PutUserPolicy", "PutGroupPolicy", "CreatePolicyVersion", "DeletePolicyVersion", "DetachRolePolicy", "CreatePolicy")
| project TimeGenerated, EventName, EventTypeName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, 
UserIdentityUserName, SessionMfaAuthenticated, SourceIpAddress, AWSRegion, EventSource, AdditionalEventData, ResponseElements
| extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityAccountId```
## IAM Privilege Escalation by Instance Profile attachment
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AWSCloudTrail/AWS_IAM_PrivilegeEscalationbyAttachment.yaml)

### ATT&CK Tags

> Tactics: [u'PrivilegeEscalation']

### Hunt details

> Description: An instance profile is a container for an IAM role that you can use to pass role information to an EC2 instance when the instance start.Identifies when existing role is removed and new/existing high privileged role is added to instance profile. Any instance with this instance profile attached is able to perform privileged operations.AWS Instance Profile: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.htmland CloudGoat - IAM PrivilegeEscalation by Attachment: https://github.com/RhinoSecurityLabs/cloudgoat/tree/master/scenarios/iam_privesc_by_attachment

> Query:

```let timeframe = 1d;
// Creating separate table for RemoveRoleToInstanceProfile
let RemoveRole=AWSCloudTrail
| where TimeGenerated >= ago(timeframe)
| where  EventName in~ ("RemoveRoleFromInstanceProfile") and isempty(ErrorMessage)
| extend RoleRemoved = tostring(parse_json(RequestParameters).roleName), InstanceProfileName = tostring(parse_json(RequestParameters).instanceProfileName), TimeRemoved=TimeGenerated
| extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,/)[-1]))
| summarize RoleRemovedCount= dcount(TimeRemoved) by TimeRemoved, EventName, EventTypeName, UserIdentityArn, UserIdentityUserName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, 
SourceIpAddress, AWSRegion, EventSource, RoleRemoved, InstanceProfileName;
// Creating separate table for AddRoleToInstanceProfile
let AddRole=AWSCloudTrail
| where TimeGenerated >= ago(timeframe)
| where  EventName in~ ("AddRoleToInstanceProfile") and isempty(ErrorMessage)
| extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,/)[-1]))
| extend RoleAdded = tostring(parse_json(RequestParameters).roleName), InstanceProfileName = tostring(parse_json(RequestParameters).instanceProfileName), TimeAdded=TimeGenerated
| summarize RoleAddedCount= dcount(TimeAdded) by TimeAdded, EventName, EventTypeName, UserIdentityArn, UserIdentityUserName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, 
SourceIpAddress, AWSRegion, EventSource, RoleAdded, InstanceProfileName;
//Joining both operations from the same source IP, user and instance profile name
RemoveRole
| join kind= inner (
   AddRole 
) on AWSRegion,SourceIpAddress, InstanceProfileName, UserIdentityUserName
| where TimeAdded  > TimeRemoved // Checking if RoleAdd operation was performed after removal
| summarize TotalCount=count() by TimeAdded, TimeRemoved, RoleAdded, RoleRemoved, UserIdentityUserName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent,
SourceIpAddress, AWSRegion, EventSource, RoleRemovedCount, RoleAddedCount
| extend timestamp = iff(TimeAdded > TimeRemoved,TimeAdded, TimeRemoved), IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityUserName```
## Privileged role attached to Instance
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AWSCloudTrail/AWS_PrivilegedRoleAttachedToInstance.yaml)

### ATT&CK Tags

> Tactics: [u'PrivilegeEscalation']

### Hunt details

> Description: Identity and Access Management (IAM) securely manages access to AWS services and resources. Identifies when a Privileged role is attached to an existing instance or new instance at deployment. This instance may be used by an adversary to escalate a normal user privileges to an adminsitrative level.and AWS API AddRoleToInstanceProfile at https://docs.aws.amazon.com/IAM/latest/APIReference/API_AddRoleToInstanceProfile.html

> Query:

```let EventNameList = dynamic(["AttachUserPolicy","AttachRolePolicy","AttachGroupPolicy"]);
let PolicyArnList = dynamic(["arn:aws:iam::aws:policy/AdministratorAccess","arn:aws:iam::aws:policy/DatabaseAdministrator","arn:aws:iam::aws:policy/NetworkAdministrator","arn:aws:iam::aws:policy/SystemAdministrator","arn:aws:iam::aws:policy/AmazonS3FullAccess"]);
let timeframe = 1d;
let lookback = 14d;
//Creating a temp table of events creating privileged role or users which can later be correlated with suspicious operations.
let PrivilegedRoleorUsers = AWSCloudTrail
| where TimeGenerated >= ago(lookback) 
| where EventName in (EventNameList)
| extend PolicyArn = tostring(parse_json(RequestParameters).policyArn), RoleName = tostring(parse_json(RequestParameters).roleName)
| where PolicyArn in (PolicyArnList)
| distinct PolicyArn, UserIdentityType, UserIdentityUserName,RoleName;
// Joining the list of identities having Privileged roles with the API call AddRoleToInstanceProfile to indentify the instances which may be used by adversaries as pivot point for privilege escalation.
PrivilegedRoleorUsers
| join (
AWSCloudTrail
| where TimeGenerated >= ago(timeframe)
| where EventName in ("AddRoleToInstanceProfile") 
| extend InstanceProfileName = tostring(parse_json(RequestParameters).InstanceProfileName), RoleName = tostring(parse_json(RequestParameters).roleName)
| summarize EventCount=count(), StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by EventSource, EventName, UserIdentityType , UserIdentityArn , UserIdentityUserName, SourceIpAddress, RoleName
) on RoleName 
| extend timestamp = StartTimeUtc, IPCustomEntity = SourceIpAddress, AccountCustomEntity = RoleName```
## Suspicious credential token access of valid IAM Roles
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AWSCloudTrail/AWS_SuspiciousCredentialTokenAccessOfValid_IAM_Roles.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess', u'DefenseEvasion']

### Hunt details

> Description: Adversaries may generate temporary credentials of existing privileged IAM roles to access AWS resources that were not previously accessible to perform malicious actions. The credentials may be generated by trusted IAM user or via AWS Cloud Instance Metadata API.This query will look for AWS STS API Assume Role operations for RoleArn (Role Amazon Resource Names) which was not historically seen.You can also limit the query to only sensitive IAM Roles which needs to be monitored.Read more about ingest custom logs using Logstash at https://github.com/Azure/Azure-Sentinel/wiki/Ingest-Custom-Logs-LogStash AWS API AssumeRole at https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html and AWS Instance Metadata API at https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html 

> Query:

```let starttime = 14d;
let midtime = 2d;
let endtime = 1d;
// Generating historical table of AssumeRole operations for IAM Roles to be compared with last 24 hour
AWSCloudTrail
| where TimeGenerated >= ago(endtime)
| where EventName == "AssumeRole" | extend RoleArn = tostring(parse_json(RequestParameters).roleArn)
| project TimeGenerated, EventSource, EventName, UserIdentityType, UserIdentityInvokedBy , SourceIpAddress, RoleArn
// Doing Leftanti join to find new AssumeRole operation for IAM role which was not seen historically generated from previous table.
| join kind= leftanti
(
  AWSCloudTrail
  | where TimeGenerated  between (ago(starttime)..ago(midtime))
  | where EventName == "AssumeRole" | extend RoleArn = tostring(parse_json(RequestParameters).roleArn)
  | project TimeGenerated, EventSource, EventName, UserIdentityType, UserIdentityInvokedBy , SourceIpAddress, RoleArn
) on RoleArn, UserIdentityInvokedBy
| summarize EventCount = count(), StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by RoleArn, EventSource, EventName, UserIdentityType, UserIdentityInvokedBy, SourceIpAddress
| extend timestamp = StartTimeUtc, IPCustomEntity = SourceIpAddress, AccountCustomEntity = tostring(split(RoleArn, "/")[1])```
## Unused or Unsupported Cloud Regions
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AWSCloudTrail/AWS_Unused_UnsupportedCloudRegions.yaml)

### ATT&CK Tags

> Tactics: [u'DefenseEvasion']

### Hunt details

> Description: Adversaries may create cloud instances in unused geographic service regions in order to evade detection. Access is usually obtained through compromising accounts used to manage cloud infrastructure.Refer: https://attack.mitre.org/techniques/T1535/

> Query:

```let starttime = 14d;
let midtime = 2d;
let endtime = 1d;
// Generating historical table of all events per AccountId and Region
let EventInfo_CurrentDay =  materialize (AWSCloudTrail | where TimeGenerated >= ago(endtime));
let EventInfo_historical = AWSCloudTrail  | where TimeGenerated  between (ago(starttime)..ago(midtime)) | summarize max(TimeGenerated) by AWSRegion, UserIdentityAccountId; 
// Doing Leftanti join to find new regions historically not seen for the same account.
let EventInfo_Unseen = materialize (
EventInfo_CurrentDay
| summarize max(TimeGenerated) by AWSRegion, UserIdentityAccountId
| join kind= leftanti
(
  EventInfo_historical
) on AWSRegion, UserIdentityAccountId
);
EventInfo_Unseen
// Join Ununsed region seen with current data to gather context about API events seen
| join kind= inner (
   EventInfo_CurrentDay
) on AWSRegion, UserIdentityAccountId
| extend UnusedRegion = AWSRegion
| extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,/)[-1]))
| summarize EventCount = count(), StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), EventNameList=make_set(EventName), IPList=make_set(SourceIpAddress) by UserIdentityAccountId, UnusedRegion, UserIdentityUserName
| extend timestamp = StartTime , AccountCustomEntity = UserIdentityUserName```
## S3 Bucket outbound Data transfer anomaly
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AWSS3/AWSBucketAPILogs-S3BucketDataTransferTimeSeriesAnomaly.yaml)

### ATT&CK Tags

> Tactics: [u'Exfiltration']

### Hunt details

> Description: Identifies when an anomalous spike occur in data transfer from an S3 bucket based on GetObject API call and the BytesTransferredOut field. The query leverages KQL built-in anomaly detection algorithms to find large deviations from baseline patterns. Sudden increases in execution frequency of sensitive actions should be further investigated for malicious activity.Manually change scorethreshold from 1.5 to 3 or higher to reduce the noise based on outliers flagged from the query criteria.Read more about ingest custom logs using Logstash at https://github.com/Azure/Azure-Sentinel/wiki/Ingest-Custom-Logs-LogStash AWS S3 API GetObject at https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.htmlS3 LogStash Config: https://github.com/Azure/Azure-Sentinel/blob/master/Parsers/Logstash/input-aws_s3-output-loganalytics.confS3 KQL Parser: https://github.com/Azure/Azure-Sentinel/blob/master/Parsers/AwsS3BucketAPILogsParser.txt

> Query:

```let starttime = 14d;
let endtime = 1d;
let timeframe = 1h;
let scorethreshold = 1.5;
// Preparing the time series data aggregated on BytesTransferredOut column in the form of multi-value array so that it can be used with time series anomaly function.
let TimeSeriesData=
AwsBucketAPILogs_CL 
| where EventTime between (startofday(ago(starttime))..startofday(ago(endtime)))
| where EventName == "GetObject"
| make-series Total=sum(BytesTransferredOut) on EventTime from startofday(ago(starttime)) to startofday(ago(endtime)) step timeframe;
// Use the time series data prepared in previous step with time series aomaly function to generate baseline pattern and flag the outlier based on scorethreshold value.
let TimeSeriesAlerts = TimeSeriesData
| extend (anomalies, score, baseline) = series_decompose_anomalies(Total, scorethreshold, -1, linefit)
| mv-expand Total to typeof(double), EventTime to typeof(datetime), anomalies to typeof(double), score to typeof(double), baseline to typeof(long)
| where anomalies > 0
| project EventTime, Total, baseline, anomalies, score;
// Joining the flagged outlier from the previous step with the original dataset to present contextual information during the anomalyhour to analysts to conduct investigation or informed decistions.
TimeSeriesAlerts
| join 
(
  AWSS3BucketAPILogParsed 
  | where EventTime between (startofday(ago(starttime))..startofday(ago(endtime)))
  | where EventName == "GetObject"
  | summarize Total = sum(BytesTransferredOut), Files= makeset(Key) , max(EventTime) by bin(EventTime, 1h), EventSource,EventName, SourceIPAddress, UserIdentityType, UserIdentityArn, UserIdentityUserName, BucketName, Host, AuthenticationMethod, SessionMfaAuthenticated, SessionUserName
) on EventTime
| project AnomalyTime = max_EventTime, SourceIPAddress, UserIdentityType,UserIdentityUserName,SessionUserName, BucketName, Host, AuthenticationMethod, Files, Total, baseline, anomalies, score 
| extend timestamp = AnomalyTime, AccountCustomEntity = SessionUserName , HostCustomEntity = Host, IPCustomEntity = SourceIPAddress```
## Suspicious Data Access to S3 Bucket from Unknown IP
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AWSS3/AWSBucketAPILogs-SuspiciousDataAccessToS3BucketsfromUnknownIP.yaml)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Adversaries may access data objects from improperly secured cloud storage. This query will identify any access originating from a Source IP which was not seen historically accessing the bucket or downloading files from it.You can also limit the query to only private buckets with sensitive files by setting the value or list of values to BucketName column.Read more about ingest custom logs using Logstash at https://github.com/Azure/Azure-Sentinel/wiki/Ingest-Custom-Logs-LogStash and AWS S3 API GetObject at https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html and ListObject at https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjects.htmland ListBucket at https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.htmlS3 LogStash Config: https://github.com/Azure/Azure-Sentinel/blob/master/Parsers/Logstash/input-aws_s3-output-loganalytics.confS3 KQL Parser: https://github.com/Azure/Azure-Sentinel/blob/master/Parsers/AwsS3BucketAPILogsParser.txt

> Query:

```let EventNameList = dynamic(["ListBucket","ListObjects","GetObject"]);
let starttime = 14d;
let midtime = 2d;
let endtime = 1d;
AwsBucketAPILogs_CL 
| where EventTime >= ago(endtime)
| where EventName in (EventNameList)
| project EventTime, EventSource,EventName, SourceIPAddress, UserIdentityType, UserIdentityArn, UserIdentityUserName, BucketName, Host, AuthenticationMethod, SessionMfaAuthenticated, SessionUserName, Key
| join kind=leftanti
(
  AWSS3BucketAPILogParsed 
  | where EventTime between (ago(starttime)..ago(midtime))
  | where EventName in (EventNameList)
) on SourceIPAddress
| summarize EventCount=count(), StartTimeUtc = min(EventTime), EndTimeUtc = max(EventTime), Files= makeset(Key), EventNames = makeset(EventName) by EventSource, SourceIPAddress, UserIdentityType, UserIdentityArn, UserIdentityUserName, BucketName, Host, AuthenticationMethod, SessionMfaAuthenticated, SessionUserName
| project StartTimeUtc, EndTimeUtc, EventSource, Host, SourceIPAddress, UserIdentityType, BucketName, EventNames, Files, AuthenticationMethod, SessionMfaAuthenticated, SessionUserName, EventCount
| extend timestamp = StartTimeUtc, HostCustomEntity = Host, AccountCustomEntity = SessionUserName, IPCustomEntity = SourceIPAddress```
## Azure Sentinel Analytics Rules Administrative Operations
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureActivity/AnalyticsRulesAdministrativeOperations.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: Identifies set of Azure Sentinel Analytics Rules administrative operational detection queries for hunting activites

> Query:

```let timeframe = 1d;
let opValues = dynamic(["Microsoft.SecurityInsights/alertRules/write", "Microsoft.SecurityInsights/alertRules/delete"]);
// Azure Sentinel Analytics - Rule Create / Update / Delete
AzureActivity
| where TimeGenerated >= ago(timeframe)
| where Category == "Administrative"
| where OperationNameValue in (opValues)
| where ActivitySubstatusValue in ("Created", "OK")
| sort by TimeGenerated desc
| extend AccountCustomEntity = Caller
| extend IPCustomEntity = CallerIpAddress```
## Azure storage key enumeration
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureActivity/Anomalous_Listing_Of_Storage_Keys.yaml)

### ATT&CK Tags

> Tactics: [u'Discovery']

### Hunt details

> Description: Listing of storage keys is an interesting operation in Azure which might expose additional secrets and PII to callers as well as granting access to VMs. While there are many benign operations of thistype, it would be interesting to see if the account performing this activity or the source IP address from which it is being done is anomalous. The query below generates known clusters of ip address per caller, notice that users which only had singleoperations do not appear in this list as we cannot learn from it their normal activity (only based on a singleevent). The activities for listing storage account keys is correlated with this learned clusters of expected activities and activity which is not expected is returned.

> Query:

```let timeframe = 7d;
AzureActivity
| where TimeGenerated >= ago(timeframe)
| where OperationName == "List Storage Account Keys"
| where ActivityStatus == "Succeeded" 
| join kind= inner (
    AzureActivity
    | where TimeGenerated >= ago(timeframe)
    | where OperationName == "List Storage Account Keys"
    | where ActivityStatus == "Succeeded" 
    | project ExpectedIpAddress=CallerIpAddress, Caller 
    | evaluate autocluster()
) on Caller 
| where CallerIpAddress != ExpectedIpAddress
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ResourceIds = makeset(ResourceId), ResourceIdCount = dcount(ResourceId) by OperationName, Caller, CallerIpAddress
| extend timestamp = StartTimeUtc, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress```
## Azure CloudShell Usage
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureActivity/Azure-CloudShell-Usage.yaml)

### ATT&CK Tags

> Tactics: [u'Execution']

### Hunt details

> Description: This query look for users starting an Azure CloudShell session and summarizes the Azure Activity from thatuser account during that timeframe (by default 1 hour). This can be used to help identify abuse of the CloudShellto modify Azure resources.

> Query:

```AzureActivity
   | where ActivityStatusValue == "Succeeded"
   | where ResourceGroup contains "cloud-shell-storage"
   | where OperationNameValue == "Microsoft.Storage/storageAccounts/listKeys/action"
   // Change the timekey scope below to get activity for a longer window 
   | summarize by Caller, timekey= bin(TimeGenerated, 1h)
   | join (AzureActivity
   | where OperationNameValue != "Microsoft.Storage/storageAccounts/listKeys/action"
   | where isnotempty(OperationName)
    // Change the timekey scope below to get activity for a longer window 
   | summarize make_set(OperationName) by Caller, timekey=bin(TimeGenerated, 1h)) on Caller, timekey
   | extend timestamp = timekey, AccountCustomEntity = Caller```
## Azure Network Security Group NSG Administrative Operations
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureActivity/AzureNSG_AdministrativeOperations.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: Identifies set of Azure NSG administrative operational detection queries for hunting activites

> Query:

```let timeframe = 1d;
let opValues = dynamic(["Microsoft.Network/networkSecurityGroups/write", "Microsoft.Network/networkSecurityGroups/delete"]);
// Azure NSG Create / Update / Delete
AzureActivity
| where TimeGenerated >= ago(timeframe)
| where Category == "Administrative"
| where OperationNameValue in (opValues)
| where ActivitySubstatusValue in ("Created", "OK")
| sort by TimeGenerated desc
| extend AccountCustomEntity = Caller
| extend IPCustomEntity = CallerIpAddress```
## Azure Sentinel Connectors Administrative Operations
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureActivity/AzureSentinelConnectors_AdministrativeOperations.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: Identifies set of Azure Sentinel Data Connectors administrative operational detection queries for hunting activites

> Query:

```let timeframe = 1d;
let opValues = dynamic(["Microsoft.SecurityInsights/dataConnectors/write", "Microsoft.SecurityInsights/dataConnectors/delete"]);
// Azure Sentinel Data Connectors Update / Delete
AzureActivity
| where TimeGenerated >= ago(timeframe)
| where Category == "Administrative"
| where OperationNameValue in (opValues)
| where ActivitySubstatusValue in ("Created", "OK")
| sort by TimeGenerated desc
| extend AccountCustomEntity = Caller
| extend IPCustomEntity = CallerIpAddress```
## Azure Sentinel Workbooks Administrative Operations
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureActivity/AzureSentinelWorkbooks_AdministrativeOperation.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: Identifies set of Azure Sentinel Workbooks administrative operational detection queries for hunting activites

> Query:

```let timeframe = 1d;
let opValues = dynamic(["microsoft.insights/workbooks/write", "microsoft.insights/workbooks/delete"]);
// Azure Sentinel Workbook Create / Update / Delete
AzureActivity
| where TimeGenerated >= ago(timeframe)
| where Category == "Administrative"
| where OperationNameValue in (opValues)
| where ActivitySubstatusValue in ("Created", "OK")
| sort by TimeGenerated desc
| extend AccountCustomEntity = Caller
| extend IPCustomEntity = CallerIpAddress```
## Azure Virtual Network Subnets Administrative Operations
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureActivity/AzureVirtualNetworkSubnets_AdministrativeOperationset.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: Identifies set of Azure Virtual Network Subnets administrative operational detection queries for hunting activites

> Query:

```let timeframe = 1d;
let opValues = dynamic(["Microsoft.Network/virtualNetworks/subnets/write"]);
// Creating Virtual Network Subnets
AzureActivity
| where TimeGenerated >= ago(timeframe)
| where Category == "Administrative"
| where OperationNameValue in (opValues)
| where ActivitySubstatusValue == "Created"
| sort by TimeGenerated desc
| extend AccountCustomEntity = Caller
| extend IPCustomEntity = CallerIpAddress```
## Common deployed resources
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureActivity/Common_Deployed_Resources.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: This query looks for common deployed resources (resource name and resource groups) and can be usedin combination with other signals that show suspicious deployment to evaluate if the resource is onethat is commonly being deployed/created or unique.

> Query:

```let timeframe = 7d;
AzureActivity
| where TimeGenerated >= ago(timeframe)
| where OperationName == "Create or Update Virtual Machine" or OperationName == "Create Deployment" 
| where ActivityStatus == "Succeeded" 
| project Resource, ResourceGroup 
| evaluate basket()```
## Creation of an anomalous number of resources
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureActivity/Creating_Anomalous_Number_Of_Resources.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: Looks for anomalous number of resources creation or deployment activities in azure activity log.It is best to run this query on a look back period which is at least 7 days.

> Query:

```let timeframe = 7d;
AzureActivity
| where TimeGenerated >= ago(timeframe)
| where OperationName == "Create or Update Virtual Machine" or OperationName == "Create Deployment" 
| where ActivityStatus == "Succeeded" 
| make-series dcount(ResourceId)  default=0 on EventSubmissionTimestamp in range(ago(7d), now(), 1d) by Caller
| extend AccountCustomEntity = Caller
| render timechart```
## Granting permissions to account
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureActivity/Granting_Permissions_to_Account.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'PrivilegeEscalation']

### Hunt details

> Description: Shows the most prevalent users who grant access to others on azure resources and for each account their common source ip address. If an operation is not from this IP address it may be worthy of investigation.

> Query:

```let timeframe = 7d;
AzureActivity
| where TimeGenerated >= ago(timeframe)
| where OperationName == "Create role assignment"
| where ActivityStatus == "Succeeded" 
| project Caller, CallerIpAddress
| evaluate basket()
| extend AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress```
## Port opened for an Azure Resource
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureActivity/PortOpenedForAzureResource.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl', u'Impact']

### Hunt details

> Description: Identifies what ports may have been opened for a given Azure Resource over the last 7 days

> Query:

```let timeframe = 7d;
AzureActivity
| where TimeGenerated >= ago(timeframe)
| where OperationName has_any ("Create", "Update") and OperationName has_any ("Ip", "Security Rule")
// Choosing Accepted here because it has the Rule Attributes included
| where ActivityStatus == "Accepted" 
// If there is publicIP info, include it
| extend publicIPAddress_ = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).ipAddress) 
| extend publicIPAddressVersion_ = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).publicIPAddressVersion) 
| extend publicIPAllocationMethod_ = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).publicIPAllocationMethod) 
// Include rule attributes for context
| extend access = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).access) 
| extend description = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).description) 
| extend destinationPortRange = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).destinationPortRange) 
| extend direction = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).direction) 
| extend protocol = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).protocol) 
| extend sourcePortRange = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).sourcePortRange) 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ResourceIds = makeset(ResourceId) by Caller, CallerIpAddress, Resource, ResourceGroup, 
ActivityStatus, ActivitySubstatus, SubscriptionId, access, description, destinationPortRange, direction, protocol, sourcePortRange  
| extend timestamp = StartTimeUtc, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress```
## Rare Custom Script Extension
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureActivity/Rare_Custom_Script_Extension.yaml)

### ATT&CK Tags

> Tactics: [u'Execution']

### Hunt details

> Description: The Custom Script Extension downloads and executes scripts on Azure virtual machines. This extension is useful for post deployment configuration, software installation, or any other configuration or management tasks.  Scripts could be downloaded from external links, Azure storage, GitHub, or provided to the Azure portal at extension run time. This could also be used maliciously by an attacker.  The query tries to identify rare custom script extensions that have been executed in your envioenment

> Query:

```let current = 1d;
let Lookback = 14d;
let CustomScriptExecution = AzureActivity 
| where TimeGenerated >= ago(Lookback) 
| where OperationName =~ "Create or Update Virtual Machine Extension"
| extend Settings = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).settings)))
| parse Settings with * fileUris":[ FileURI "]" *
| parse Settings with * commandToExecute": commandToExecute } *
| extend message_ = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).statusMessage)).error)).message);
let LookbackCustomScriptExecution = CustomScriptExecution
| where TimeGenerated >= ago(Lookback) and TimeGenerated < ago(current)
| where isnotempty(FileURI) and isnotempty(commandToExecute)
| summarize max(TimeGenerated), OperationCount = count() by Caller, Resource, CallerIpAddress, FileURI, commandToExecute;
let CurrentCustomScriptExecution = CustomScriptExecution
| where TimeGenerated >= ago(current)
| where isnotempty(FileURI) and isnotempty(commandToExecute)
| project TimeGenerated, ActivityStatus, OperationId, CorrelationId, ResourceId, CallerIpAddress, Caller, OperationName, Resource, ResourceGroup, FileURI, commandToExecute, FailureMessage = message_, HTTPRequest, Settings;
let RareCustomScriptExecution =  CurrentCustomScriptExecution
| join kind= leftanti (LookbackCustomScriptExecution) on Caller, CallerIpAddress, FileURI, commandToExecute;
let IPCheck = RareCustomScriptExecution 
| summarize arg_max(TimeGenerated, OperationName), OperationIds = makeset(OperationId), CallerIpAddresses = makeset(CallerIpAddress) by ActivityStatus, CorrelationId, ResourceId, Caller, Resource, ResourceGroup, FileURI, commandToExecute, FailureMessage
| extend IPArray = arraylength(CallerIpAddresses);
//Get IPs for later summarization so all associated CorrelationIds and Caller actions have an IP.  Success and Fails do not always have IP
let multiIP = IPCheck | where IPArray > 1
| mvexpand CallerIpAddresses | extend CallerIpAddress = tostring(CallerIpAddresses)
| where isnotempty(CallerIpAddresses);
let singleIP = IPCheck | where IPArray <= 1
| mvexpand CallerIpAddresses | extend CallerIpAddress = tostring(CallerIpAddresses);
let FullDetails = singleIP | union multiIP;
//Get IP address associated with successes and fails with no IP listed
let IPList = FullDetails | where isnotempty(CallerIpAddress) | summarize by CorrelationId, Caller, CallerIpAddress;
let EmptyIP = FullDetails | where isempty(CallerIpAddress) | project-away CallerIpAddress;
let IpJoin = EmptyIP | join kind= leftouter (IPList) on CorrelationId, Caller | project-away CorrelationId1, Caller1;
let nonEmptyIP = FullDetails | where isnotempty(CallerIpAddress);
nonEmptyIP | union IpJoin
// summarize all activities with a given CorrelationId and Caller together so we can provide a singular result
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), ActivityStatusSet = makeset(ActivityStatus), OperationIds = makeset(OperationIds), FailureMessages = makeset(FailureMessage) by CorrelationId, ResourceId, CallerIpAddress, Caller, Resource, ResourceGroup, FileURI, commandToExecute
| extend timestamp = StartTime, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress```
## Azure DevOps- AAD Conditional Access Disabled
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureDevOpsAuditing/AAD%20Conditional%20Access%20Disabled.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'DefenseEvasion']

### Hunt details

> Description: This hunting query identifies Azure DevOps activities where organization AADConditionalAccess policy disable by the admin

> Query:

```let timeframe = 7d;
AzureDevOpsAuditing
| where TimeGenerated >= ago(timeframe)
| where OperationName =="OrganizationPolicy.PolicyValueUpdated"
| where Data.PolicyName == "Policy.EnforceAADConditionalAccess"
| where Data.PolicyValue == "OFF"
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress```
## Azure DevOps- Addtional Org Admin added
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureDevOpsAuditing/Addtional%20Org%20Admin%20Added.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'DefenseEvasion']

### Hunt details

> Description: This hunting query identifies Azure DevOps activities where additional organization admin is added

> Query:

```let timeframe = 7d;
AzureDevOpsAuditing
| where TimeGenerated >= ago(timeframe)
| where OperationName == "Group.UpdateGroupMembership.Add"
| where Category == "Modify"
| where Area == "Group"
| where Details contains ("Project Collection Administrators")
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress```
## Azure DevOps Display Name Changes
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureDevOpsAuditing/AzDODisplayNameSwapping.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'DefenseEvasion']

### Hunt details

> Description: Shows all users with more than 1 display name in recent history.  This is to hunt for users maliciously changing their display name as a masquerading technique

> Query:

```let timeframe = 14d;
AzureDevOpsAuditing
| where TimeGenerated > ago(timeframe)
| where ActorCUID != 00000000-0000-0000-0000-000000000000 and ActorDisplayName != "Azure DevOps User"
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), DisplayNameCount = dcount(ActorDisplayName), ActorDisplayNames = make_set(ActorDisplayName), make_set(IpAddress), make_set(ProjectName) by ActorCUID, ActorUPN
| where DisplayNameCount > 1
| extend timestamp = StartTime, AccountCustomEntity = ActorUPN```
## Azure DevOps Pull Request Policy Bypassing
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureDevOpsAuditing/AzDOPrPolicyBypassers.yaml)

### ATT&CK Tags

> Tactics: [u'Execution']

### Hunt details

> Description: Looks for users bypassing Update Policies in repos

> Query:

```let timeframe = 7d;
AzureDevOpsAuditing
| where TimeGenerated >= ago(timeframe)
| where OperationName == Git.RefUpdatePoliciesBypassed
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress```
## Azure DevOps- Guest users access enabled
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureDevOpsAuditing/Guest%20users%20access%20enabled.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'DefenseEvasion']

### Hunt details

> Description: This hunting query identifies Azure DevOps activities where organization Guest Access policy is enabled by the admin

> Query:

```let timeframe = 7d;
AzureDevOpsAuditing
| where TimeGenerated >= ago(timeframe)
| where OperationName =="OrganizationPolicy.PolicyValueUpdated"
| where Data.PolicyName == "Policy.DisallowAadGuestUserAccess"
| where Data.PolicyValue == "OFF"
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress```
## Azure DevOps- Project visibility changed to public
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureDevOpsAuditing/Project%20visibility%20changed%20to%20public.yaml)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: This hunting query identifies Azure DevOps activities where organization project visibility changed to public project

> Query:

```let timeframe = 7d;
AzureDevOpsAuditing
| where TimeGenerated >= ago(timeframe)
| where Area == "Project"
| where OperationName == "Project.UpdateVisibilityCompleted"
| where Data.PreviousProjectVisibility == "private"
| where Data.ProjectVisibility == "public"
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress```
## Azure DevOps- Public project created
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureDevOpsAuditing/Public%20project%20created.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'DefenseEvasion']

### Hunt details

> Description: This hunting query identifies Azure DevOps activities where a public project is created

> Query:

```let timeframe = 7d;
AzureDevOpsAuditing
| where TimeGenerated >= ago(timeframe)
| where Data.ProjectVisibility == "Public"
| where OperationName == "Project.CreateCompleted"
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress```
## Azure DevOps- Public project enabled by admin
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureDevOpsAuditing/Public%20Projects%20enabled.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'DefenseEvasion']

### Hunt details

> Description: This hunting query identifies Azure DevOps activities where organization public projects policy enabled by the admin

> Query:

```let timeframe = 7d;
AzureDevOpsAuditing
| where TimeGenerated >= ago(timeframe)
| where OperationName == "OrganizationPolicy.PolicyValueUpdated"
| where Data.PolicyName == "Policy.AllowAnonymousAccess"
| where Data.PolicyValue == "ON"
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress```
## Check critical ports opened to the entire internet
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/AzureDiagnostics/CriticalPortsOpened.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: Discover all critical ports from a list having rules like Any for sourceIp, which means that they are opened to everyone. Critial ports should not be opened to everyone, and should be filtered.

> Query:

```//Check critical ports opened to the entire internet
AzureDiagnostics
| where Category == "NetworkSecurityGroupEvent" 
| where direction_s == "In" 
| where conditions_destinationPortRange_s in (
"22","22-22"          //SSH
,"3389","3389-3389"   //RDP
,"137","137-137"      //NetBIOS
,"138","138-138"      //NetBIOS
,"139","139-139"      //SMB
,"53","53-53"         //DNS
,"3020","3020-3020"   //CIFS
,"3306","3306-3306"   //MySQL
,"1521","1521-1521"   //Oracle Database
,"2483","2483-2483"   //Oracle Database
,"5432","5432-5432"   //PostgreSQL
,"389","389-389"      //LDAP
,"27017","27017-27017"//MongoDB
,"20","20-20"         //FTP
,"21","21-21"         //FTP
,"445","445-445"      //Active Directory
,"161","161-161"      //SNMP
,"25","25-25"         //SMTP
)
 or (conditions_destinationPortRange_s == "0-65535" and conditions_sourcePortRange_s == "0-65535")
| where priority_d < 65000    //Not to check the Azure defaults
| where conditions_sourceIP_s == "0.0.0.0/0,0.0.0.0/0" or conditions_sourceIP_s == "0.0.0.0/0" //With rules Any/Any
| where type_s !~ "block"
| order by TimeGenerated desc
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count() by OperationName, systemId_g, vnetResourceGuid_g, subnetPrefix_s, macAddress_s, primaryIPv4Address_s, ruleName_s,
 direction_s, priority_d, type_s, conditions_destinationIP_s, conditions_destinationPortRange_s, conditions_sourceIP_s, conditions_sourcePortRange_s, ResourceId```
## Anomalous AAD Account Manipulation
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/BehaviorAnalytics/Anomalous%20AAD%20Account%20Manipulation.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence']

### Hunt details

> Description: Adversaries may manipulate accounts to maintain access to victim systems. These actions include adding new accounts to high privilleged groups. Dragonfly 2.0, for example, added newly created accounts to the administrators group to maintain elevated access. The query below generates an output of all high Blast Radius users performing "Update user" (name change) to priveleged role, or where one or more features of the activitiy deviates from the user, his peers or the tenant profile.

> Query:

```//Critical Roles: can impersonate  any user or app, can update passwords for users or service principals (if the role can let a user update passwords for privileged users, if an attacker compromises this user then attacker can update passwords for privileged users hence gaining more privileges so users with this role are equally critical)
//High Roles: Administrators that can manage all aspects or permissions of important products but cant update credentials and impersonate another user/app
let critical = dynamic([9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3,c4e39bd9-1100-46d3-8c65-fb160da0071f,158c047a-c907-4556-b7ef-446551a6b5f7,62e90394-69f5-4237-9190-012177145e10,d29b2b05-8046-44ba-8758-1e26182fcf32,729827e3-9c14-49f7-bb1b-9608f156bbb8,966707d0-3269-4727-9be2-8c3a10f19b9d,194ae4cb-b126-40b2-bd5b-6091b380977d,fe930be7-5e62-47db-91af-98c3a49a38b1]);
let high = dynamic([cf1c38e5-3621-4004-a7cb-879624dced7c,7495fdc4-34c4-4d15-a289-98788ce399fd,aaf43236-0c0d-4d5f-883a-6955382ac081,3edaf663-341e-4475-9f94-5c398ef6c070,7698a772-787b-4ac8-901f-60d6b08affd2,b1be1c3e-b65d-4f19-8427-f6fa0d97feb9,9f06204d-73c1-4d4c-880a-6edb90606fd8,29232cdf-9323-42fd-ade2-1d097af3e4de,be2f45a1-457d-42af-a067-6ec1fa63bc45,7be44c8a-adaf-4e2a-84d6-ab2649e08a13,e8611ab8-c189-46e8-94e1-60213ab1f814]);
AuditLogs
| where OperationName == "Update user"
| mv-expand AdditionalDetails
| mv-expand TargetResources
| where AdditionalDetails.key == "UserPrincipalName"
| mv-expand TargetResources
| extend RoleId = tostring(TargetResources.modifiedProperties[0].newValue)
| extend RoleName = tostring(TargetResources.modifiedProperties[1].newValue)
| where RoleId in (critical,high)
| where isnotempty(RoleId) or isnotempty(RoleName)
| extend TargetId = tostring(TargetResources.id)
| extend Target =  iff(tostring(TargetResources.userPrincipalName) has "#EXT#",replace("_","@",tostring(split(TargetResources.userPrincipalName, "#")[0])),TargetResources.userPrincipalName),tostring(TargetResources.userPrincipalName)
| join kind=inner ( BehaviorAnalytics
) on $left._ItemId == $right.SourceRecordId
| where UsersInsights.BlastRadius == "High" or ActivityInsights has "True"
|  extend UserPrincipalName = iff(UserPrincipalName has "#EXT#",replace("_","@",tostring(split(UserPrincipalName, "#")[0])),UserPrincipalName),
UserName = iff(UserName has "#EXT#",replace("_","@",tostring(split(UserPrincipalName, "#")[0])),UserName) 
| project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, ["TargetUser"]=Target,RoleName,ActivityInsights ,SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights```
## Anomalous AAD Account Creation
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/BehaviorAnalytics/Anomalous%20Account%20Creation.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence']

### Hunt details

> Description: Adversaries may create a cloud account to maintain access to victim systems. With a sufficient level of access, such accounts may be used to establish secondary credentialed access that does not require persistent remote access tools to be deployed on the system. The query below generates an output of all the users performing user creation where one or more features of the activitiy deviates from the user, his peers or the tenant profile.

> Query:

```BehaviorAnalytics
| where ActionType == "Add user"
| where ActivityInsights has "True"
| join(
AuditLogs
) on $left.SourceRecordId == $right._ItemId
| mv-expand TargetResources
| extend Target =  iff(tostring(TargetResources.userPrincipalName) has "#EXT#",replace("_","@",tostring(split(TargetResources.userPrincipalName, "#")[0])),TargetResources.userPrincipalName),tostring(TargetResources.userPrincipalName)
| extend DisplayName = tostring(UsersInsights.AccountDisplayName),
UserPrincipalName = iff(UserPrincipalName has "#EXT#",replace("_","@",tostring(split(UserPrincipalName, "#")[0])),UserPrincipalName),
UserName = iff(UserName has "#EXT#",replace("_","@",tostring(split(UserPrincipalName, "#")[0])),UserName)
| sort by TimeGenerated desc	
| project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, ["TargetUser"]=Target,ActivityInsights ,SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights```
## Anomalous Activity Role Assignment
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/BehaviorAnalytics/Anomalous%20Activity%20Role%20Assignment.yaml)

### ATT&CK Tags

> Tactics: [u'PrivilegeEscalation']

### Hunt details

> Description: Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. The query below generates an output of all users performing an "action" operation regarding a access elevation, where one or more features of the activitiy deviates from the user, his peers or the tenant profile.

> Query:

```let operations = dynamic([Create role assignment]);
BehaviorAnalytics
| where ActionType in(operations)
| where ActivityInsights contains "True"
| project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType,ActivityInsights ,SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights```
## Anomalous Code Execution
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/BehaviorAnalytics/Anomalous%20Code%20Execution.yaml)

### ATT&CK Tags

> Tactics: [u'Execution']

### Hunt details

> Description: Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. APT19, for example, used PowerShell commands to execute payloads. The query below generates an output of all users performing an "action" operation regarding "runCommand" in virtual machines, where one or more features of the activitiy deviates from the user, his peers or the tenant profile.

> Query:

```let operations = dynamic([Run Command on Virtual Machine]);
BehaviorAnalytics
| where ActionType in(operations)
| where ActivityInsights has "True"
| project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType,ActivityInsights ,SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights```
## Anomalous Data Access
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/BehaviorAnalytics/Anomalous%20Data%20Access.yaml)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Adversaries may access data objects from cloud storage.  The query below generates an output of all users performing a "read" operation regarding data or files, where one or more features of the activitiy deviates from the user, his peers or the tenant profile.

> Query:

```let operations = dynamic([Export an existing database]);
BehaviorAnalytics
| where ActionType in(operations)
| where ActivityInsights has "True"
| project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType,ActivityInsights ,SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights```
## Anomalous Defensive Mechanism Modification
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/BehaviorAnalytics/Anomalous%20Defensive%20Mechanism%20Modification.yaml)

### ATT&CK Tags

> Tactics: [u'DefenseEvasion']

### Hunt details

> Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. DarkComet, for example, can disable Security Center functions like anti-virus. The query below generates an output of all users performing a "delete" operation regarding a security policy, where one or more features of the activitiy deviates from the user, his peers or the tenant profile.

> Query:

```let operations = dynamic([Remove database vulnerability assessment rule baseline]);
BehaviorAnalytics
| where ActionType in(operations)
| where ActivityInsights has "True"
| project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType,ActivityInsights ,SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights```
## Anomalous Failed Logon
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/BehaviorAnalytics/Anomalous%20Failed%20Logon.yaml)

### ATT&CK Tags

> Tactics: [u'CredentialAccess']

### Hunt details

> Description: Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Emotet, for example, has been observed using a hard coded list of passwords to brute force user accounts. The query below generates an output of all users with High BlastRadius that perform failed Sign-in:Invalid username or password.

> Query:

```BehaviorAnalytics
| where ActivityType == "LogOn"
| where UsersInsights.BlastRadius == "High"
| join (
SigninLogs  | where Status.errorCode == 50126
) on $left.SourceRecordId == $right._ItemId
| extend UserPrincipalName = iff(UserPrincipalName contains "#EXT#",replace("_","@",tostring(split(UserPrincipalName, "#")[0])),UserPrincipalName),
UserName = iff(UserName contains "#EXT#",replace("_","@",tostring(split(UserPrincipalName, "#")[0])),UserName)
| project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType,["Evidence"]=ActivityInsights, ResourceDisplayName,AppDisplayName ,SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights```
## Anomalous Geo Location Logon
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/BehaviorAnalytics/Anomalous%20Geo%20Location%20Logon.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: Adversaries may steal the credentials of a specific user or service account using Credential Access techniques or capture credentials earlier in their reconnaissance process through social engineering for means of gaining Initial Access. APT33, for example, has used valid accounts for initial access. The query below generates an output of successful Sign-in performed by a user from a new geo location he has never connected from before, and none of his peers as well.

> Query:

```BehaviorAnalytics
| where ActionType == "Sign-in"
| where ActivityInsights.FirstTimeConnectionFromCountryObservedInTenant == True and ActivityInsights.CountryUncommonlyConnectedFromAmongPeers == True
    | join (
SigninLogs
) on $left.SourceRecordId == $right._ItemId
| extend UserPrincipalName = iff(UserPrincipalName contains "#EXT#",replace("_","@",tostring(split(UserPrincipalName, "#")[0])),UserPrincipalName),
UserName = iff(UserName contains "#EXT#",replace("_","@",tostring(split(UserPrincipalName, "#")[0])),UserName)
| project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType,["Evidence"]=ActivityInsights, ResourceDisplayName,AppDisplayName ,SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights```
## Anomalous Login to Devices
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/BehaviorAnalytics/Anomalous%20Login%20to%20Devices.yaml)

### ATT&CK Tags

> Tactics: [u'PrivilegeEscalation']

### Hunt details

> Description: Adversaries may steal the credentials of a specific user or service account using Credential Access techniques or capture credentials earlier in their reconnaissance process through social engineering for means of gaining Initial Access. APT33, for example, has used valid accounts for initial access and privilege escalation. The query below generates an output of all administator users performing an interactive logon (4624:2) where one or more features of the activitiy deviates from the user, his peers or the tenant profile.

> Query:

```BehaviorAnalytics
| where UsersInsights.IsDormantAccount == true
| where DevicesInsights.IsLocalAdmin == true
| where ActivityType == "LogOn"
| where ActionType == "InteractiveLogon"
| where ActivityInsights contains "True"
| project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType,ActivityInsights ,SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights```
## Anomalous Password Reset
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/BehaviorAnalytics/Anomalous%20Password%20Reset.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts. LockerGoga, for example, has been observed changing account passwords and logging off current users. The query below generates an output of all users performing Reset user password where one or more features of the activitiy deviates from the user, his peers or the tenant profile.

> Query:

```BehaviorAnalytics
| where ActionType == "Reset user password"
| where ActivityInsights has "True"
| join (
AuditLogs
) on $left.SourceRecordId == $right._ItemId
| mv-expand TargetResources
| extend Target =  iff(tostring(TargetResources.userPrincipalName) has "#EXT#",replace("_","@",tostring(split(TargetResources.userPrincipalName, "#")[0])),TargetResources.userPrincipalName),tostring(TargetResources.userPrincipalName)
| extend UserPrincipalName = iff(UserPrincipalName has "#EXT#",replace("_","@",tostring(split(UserPrincipalName, "#")[0])),UserPrincipalName),
UserName = iff(UserName has "#EXT#",replace("_","@",tostring(split(UserPrincipalName, "#")[0])),UserName)
| sort by TimeGenerated desc
| project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, ["TargetUser"]=Target,ActivityInsights ,SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights```
## Anomalous RDP Activity
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/BehaviorAnalytics/Anomalous%20RDP%20Activity.yaml)

### ATT&CK Tags

> Tactics: [u'LateralMovement']

### Hunt details

> Description: Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user. FIN10, for example, has used RDP to move laterally to systems in the victim environment.

> Query:

```BehaviorAnalytics
| where ActivityType == "LogOn"
| where ActionType == "RemoteInteractiveLogon"
| where ActivityInsights has "True"
| project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType,ActivityInsights ,SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights```
## Anomalous Resource Access
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/BehaviorAnalytics/Anomalous%20Resource%20Access.yaml)

### ATT&CK Tags

> Tactics: [u'LateralMovement']

### Hunt details

> Description: Adversary may be trying to move through the environment. APT29 and APT32, for example, has used PtH & PtT techniques to lateral move around the network. The query below generates an output of all users performing an resource access (4624:3) to devices for the first time.

> Query:

```BehaviorAnalytics
| where ActivityType == "LogOn"
| where ActionType == "ResourceAccess"
| where ActivityInsights has "True"
| project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType,ActivityInsights ,SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights```
## Anomalous Role Assignment
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/BehaviorAnalytics/Anomalous%20Role%20Assignment.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence']

### Hunt details

> Description: Adversaries may manipulate accounts to maintain access to victim systems. These actions include adding new accounts to high privilleged groups. Dragonfly 2.0, for example, added newly created accounts to the administrators group to maintain elevated access.  The query below generates an output of all high Blast Radius users performing Add member to priveleged role, or where one or more features of the activitiy deviates from the user, his peers or the tenant profile.

> Query:

```let critical = dynamic([9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3,c4e39bd9-1100-46d3-8c65-fb160da0071f,158c047a-c907-4556-b7ef-446551a6b5f7,62e90394-69f5-4237-9190-012177145e10,d29b2b05-8046-44ba-8758-1e26182fcf32,729827e3-9c14-49f7-bb1b-9608f156bbb8,966707d0-3269-4727-9be2-8c3a10f19b9d,194ae4cb-b126-40b2-bd5b-6091b380977d,fe930be7-5e62-47db-91af-98c3a49a38b1]);
let high = dynamic([cf1c38e5-3621-4004-a7cb-879624dced7c,7495fdc4-34c4-4d15-a289-98788ce399fd,aaf43236-0c0d-4d5f-883a-6955382ac081,3edaf663-341e-4475-9f94-5c398ef6c070,7698a772-787b-4ac8-901f-60d6b08affd2,b1be1c3e-b65d-4f19-8427-f6fa0d97feb9,9f06204d-73c1-4d4c-880a-6edb90606fd8,29232cdf-9323-42fd-ade2-1d097af3e4de,be2f45a1-457d-42af-a067-6ec1fa63bc45,7be44c8a-adaf-4e2a-84d6-ab2649e08a13,e8611ab8-c189-46e8-94e1-60213ab1f814]);
AuditLogs
| where OperationName == "Add member to role"
| mv-expand TargetResources
| extend RoleId = tostring(TargetResources.modifiedProperties[0].newValue)
| extend RoleName = tostring(TargetResources.modifiedProperties[1].newValue)
| where RoleId in (critical,high)
| extend TargetId = tostring(TargetResources.id)
| extend Target = tostring(TargetResources.userPrincipalName)
| where isnotempty(RoleId) or isnotempty(RoleName)
| join kind=inner ( BehaviorAnalytics
) on $left._ItemId == $right.SourceRecordId
| where UsersInsights.BlasrRadius == "High" or ActivityInsights has "True"
| project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, ["TargetUser"]=Target,RoleName,ActivityInsights ,SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights```
## Anomalous Sign-in Activity
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/BehaviorAnalytics/Anomalous%20Sign-in%20Activity.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence']

### Hunt details

> Description: Adversaries may steal the credentials of a specific user or service account using Credential Access techniques or capture credentials earlier in their reconnaissance process through social engineering for means of gaining Persistence. Umbreon, for example, creates valid users to provide access to the system.The query below generates an output of successful Sign-in with one or more of the following indications:- performed by new or recently dormant accounts- where one or more features of the activitiy deviates from the user, his peers or the tenant profile- performed by a user with Risk indicaiton from AAD

> Query:

```BehaviorAnalytics
| where ActionType == "Sign-in"
| where UsersInsights.IsNewAccount == True or UsersInsights.IsDormantAccount == True or ActivityInsights has "True"
| join (
SigninLogs | where Status.errorCode == 0 or Status.errorCode == 0 and RiskDetail != "none"
) on $left.SourceRecordId == $right._ItemId
| extend UserPrincipalName = iff(UserPrincipalName has "#EXT#",replace("_","@",tostring(split(UserPrincipalName, "#")[0])),UserPrincipalName),
UserName = iff(UserName has "#EXT#",replace("_","@",tostring(split(UserPrincipalName, "#")[0])),UserName)
| project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType,["Evidence"]=ActivityInsights, ResourceDisplayName,AppDisplayName,SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights```
## DNS lookups for commonly abused TLDs
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/DnsEvents/DNS_CommonlyAbusedTLDs.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl', u'Exfiltration']

### Hunt details

> Description: Some top level domains (TLDs) are more commonly associated with malware for a range of reasons - including how easy domains on these TLDs are to obtain. Many of these may be undesirable from an enterprise policy perspective. You can update and extend the list of TLDs  you wish to search for.The NameCount column provides an initial insight into how widespread the domain usage is across the environment.

> Query:

```let timeframe = 7d;
// Add additional TLDs to this list are reuqired.
let abusedTLD = dynamic(["click", "club", "download",  "xxx", "xyz"]);
DnsEvents
| where TimeGenerated >= ago(timeframe) 
| where Name has "." 
| extend tld = tostring(split(Name, ".")[-1])
| where tld in~ (abusedTLD)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), NameCount = count() by Name, ClientIP, tld
| order by NameCount desc
| extend timestamp = StartTimeUtc, IPCustomEntity = ClientIP```
## DNS - domain anomalous lookup increase
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/DnsEvents/DNS_DomainAnomalousLookupIncrease.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl', u'Exfiltration']

### Hunt details

> Description: Checking for a threefold increase or more of domain lookups per client IP address for the current day vs daily average for the previous week. This can potentially identify excessive traffic to a given location that could be indicative of data transfer out of your network to a group of systems based on the same second level domain.  For example, if one client is sending requests for test1.badguy.com and another client is sending requests for test2.badguy.com, you may not see a high enough count to be interesting. However, a combination of the requests to badguy.com could have a high enough count to be interesting. This is only Name lookups, so it would be recommended to review the Firewall\Webproxy logs in relation to the client IP address making the interesting requests.

> Query:

```let startTime = 8d;
let endTime = 1d;
//example of excluding Saturday and Sunday in Average as those are potentially low volume and decrease the average, feel free to change
let excludedDays = dynamic(["Saturday", "Sunday"]);
// average is across 5 days as we are dropping weekends, change as needed
let numDays = 5;
// limit to over 1000 lookups somewhat random but helps focus in on higher lookups, change as needed
let avglookupThreshold = 3;
let lookupThreshold = 1000;
DnsEvents
//Setting to startofday so we get 7 days prior to today
| where TimeGenerated >= startofday(ago(startTime)) and TimeGenerated <= startofday(ago(endTime))
| where SubType =~ "LookupQuery"
//getting the associated number of the day of the week so we can map to a given day for later parsing if needed
| extend DayNumberofWeek = tostring(dayofweek(TimeGenerated))
//Setting the Day of the week value so that certain days could be excluded if needed
| extend DayofWeek = iff(DayNumberofWeek == "00:00:00", "Sunday", 
(iff(DayNumberofWeek == "1.00:00:00", "Monday", 
(iff(DayNumberofWeek == "2.00:00:00", "Tuesday", 
(iff(DayNumberofWeek == "3.00:00:00", "Wednesday", 
(iff(DayNumberofWeek == "4.00:00:00", "Thursday", 
(iff(DayNumberofWeek == "5.00:00:00", "Friday", 
(iff(DayNumberofWeek == "6.00:00:00", "Saturday", DayNumberofWeek)))))))))))))
| where DayofWeek !in~ (excludedDays) 
| extend Domain = iff(countof(Name,.) >= 2, strcat(split(Name,.)[-2], .,split(Name,.)[-1]), Name)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count() by ClientIP, Domain, IPAddresses
| project StartTimeUtc, EndTimeUtc, ClientIP, Domain, IPAddresses, DailyAvgLookupCountOverLastWeek = count_/numDays 
| join ( DnsEvents 
| where TimeGenerated >= startofday(ago(endTime)) 
| where SubType =~ "LookupQuery"
| extend Domain = iff(countof(Name,.) >= 2, strcat(split(Name,.)[-2], .,split(Name,.)[-1]), Name)
| summarize count() by ClientIP, Domain, IPAddresses 
| project ClientIP, LookupCountToday = count_, Domain, IPAddresses 
)
on ClientIP, Domain, IPAddresses 
| where LookupCountToday > ( DailyAvgLookupCountOverLastWeek * avglookupThreshold) and LookupCountToday > lookupThreshold 
| project StartTimeUtc, EndTimeUtc, ClientIP, SecondLevelDomain = Domain , LookupCountToday , DailyAvgLookupCountOverLastWeek, IPAddresses 
| order by LookupCountToday desc nulls last 
| extend timestamp = StartTimeUtc, IPCustomEntity = ClientIP```
## DNS Full Name anomalous lookup increase
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/DnsEvents/DNS_FullNameAnomalousLookupIncrease.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl', u'Exfiltration']

### Hunt details

> Description: Checking for a threefold increase or more of Full Name lookup per Client IP for the current day for today vs the daily average for the previous week.  This can potentially identify excessive traffic to a given location that could be indicative of data transfer out of your network.  This is only Name lookups, so it would be recommended to review the Firewall\Webproxy logs in relation to the ClientIP making the interesting requests.

> Query:

```let startTime = 8d;
let endTime = 1d;
//example of excluding Saturday and Sunday in Average as those are potentially low volume and decrease the average, feel free to change
let excludedDays = dynamic(["Saturday", "Sunday"]);
// average is across 5 days as we are dropping weekends, change as needed
let numDays = 5;
// limit to over 1000 lookups somewhat random but helps focus in on higher lookups, change as needed
let avglookupThreshold = 3;
let lookupThreshold = 1000;
DnsEvents
//Setting to startofday so we get 7 days prior to today
| where TimeGenerated >= startofday(ago(startTime)) and TimeGenerated <= startofday(ago(endTime))
| where SubType =~ "LookupQuery"
//getting the associated number of the day of the week so we can map to a given day for later parsing if needed
| extend DayNumberofWeek = tostring(dayofweek(TimeGenerated)) 
//Setting the Day of the week value so that certain days could be excluded if needed
| extend DayofWeek = iff(DayNumberofWeek == "00:00:00", "Sunday", 
(iff(DayNumberofWeek == "1.00:00:00", "Monday", 
(iff(DayNumberofWeek == "2.00:00:00", "Tuesday", 
(iff(DayNumberofWeek == "3.00:00:00", "Wednesday", 
(iff(DayNumberofWeek == "4.00:00:00", "Thursday", 
(iff(DayNumberofWeek == "5.00:00:00", "Friday", 
(iff(DayNumberofWeek == "6.00:00:00", "Saturday", DayNumberofWeek)))))))))))))
| where DayofWeek !in~ (excludedDays) 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count() by ClientIP, Name, IPAddresses
| project StartTimeUtc, EndTimeUtc, ClientIP, FullNameLookup = Name, IPAddresses, DailyAvgLookupCountOverLastWeek = count_/numDays
| join ( DnsEvents 
| where TimeGenerated >= startofday(ago(endTime))
| where SubType =~ "LookupQuery"
| summarize count() by ClientIP, FullNameLookup = Name, IPAddresses
| project ClientIP, LookupCountToday = count_, FullNameLookup, IPAddresses
)
on ClientIP, FullNameLookup, IPAddresses
| where LookupCountToday > (DailyAvgLookupCountOverLastWeek * avglookupThreshold) and LookupCountToday >= lookupThreshold 
| project StartTimeUtc, EndTimeUtc, ClientIP, LookupCountToday, DailyAvgLookupCountOverLastWeek, FullNameLookup, IPAddresses
| order by LookupCountToday desc nulls last 
| extend timestamp = StartTimeUtc, IPCustomEntity = ClientIP```
## Potential DGA detected
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/DnsEvents/DNS_HighPercentNXDomainCount.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl']

### Hunt details

> Description: Clients with a high NXDomain count could be indicative of a DGA (cycling through possible C2 domainswhere most C2s are not live). Based on quartile precent analysis aglorithm.

> Query:

```let timeframe = 1d;
let excludeTLD = dynamic(["arris","ati","virtusa","unknowndomain","onion","corp","domain","local","localdomain","host","home","gateway","lan",
"services","hub","domain.name","WirelessAP","Digicom-ADSL","OpenDNS","dlinkrouter","Dlink","ASUS","device","router","Belkin","DHCP","Cisco"]);
let nxDomainDnsEvents = DnsEvents
| where ResultCode == 3 
| where QueryType in ("A", "AAAA")
| where ipv4_is_match("127.0.0.1", ClientIP) == False
| where Name !contains "/"
| where Name contains "."
| extend mytld = tostring(split(Name, .)[-1])
| where mytld !in~ (excludeTLD)
| extend truncatedDomain = iff((strlen(Name) - indexof(Name, tostring(split(Name, ".")[-2])) ) >= 7, 
strcat(tostring(split(Name, ".")[-2]), ".", tostring(split(Name, ".")[-1])) , 
strcat(tostring(split(Name, ".")[-3]), ".", tostring(split(Name, ".")[-2]), ".", tostring(split(Name, ".")[-1])));
let quartileFunctionForIPThreshold = view (mypercentile:long, startTimeSpan:timespan, endTimeSpan:timespan) {
(nxDomainDnsEvents
| where TimeGenerated between (ago(startTimeSpan)..ago(endTimeSpan))
| summarize domainCount = dcount(truncatedDomain) by ClientIP, bin(TimeGenerated, 1d)
| project SearchList = (domainCount), ClientIP
| summarize qPercentiles = percentiles(SearchList, mypercentile) by ClientIP);
};
let firstQT = quartileFunctionForIPThreshold(25, 7d, 2d) | project-rename percentile_SearchList_25 = qPercentiles;
let thirdQT = quartileFunctionForIPThreshold(75, 7d, 2d) | project-rename percentile_SearchList_75 = qPercentiles;
// The IP threshold could be adjusted for based on the skewness of the IPthreshold distribution per IP - https://wis.kuleuven.be/stat/robust/papers/2008/outlierdetectionskeweddata-revision.pdf
let threshold = (firstQT
| join thirdQT on ClientIP
| extend IPthreshold = percentile_SearchList_75 + (1.5*exp(3)*(percentile_SearchList_75 - percentile_SearchList_25))
| project ClientIP, IPthreshold);
let FilterOnIPThreshold_MainTable = (
nxDomainDnsEvents
| where TimeGenerated > ago(timeframe)
| summarize TotalNXLookups=dcount(truncatedDomain) by ClientIP
| sort by TotalNXLookups desc
| join [threshold] on ClientIP
// Comment the line below in order to view results filtered by Global Threshold only. 
| where TotalNXLookups > IPthreshold 
| join kind = leftouter (nxDomainDnsEvents
    | where TimeGenerated > ago(timeframe)
    | summarize domainCount = dcount(Name) by truncatedDomain, ClientIP
    | project SearchList = strcat(truncatedDomain," (",tostring(domainCount),")"), ClientIP
    ) on ClientIP
| summarize SLDs_DistinctLookups = make_list(SearchList) by ClientIP, TotalNXLookups, IPthreshold
| sort by TotalNXLookups desc);
//
let quartileFunctionForGlobalThreshold = view (mypercentile:long, startTimeSpan:timespan) {
(nxDomainDnsEvents
| where TimeGenerated > ago(startTimeSpan)
| summarize domainCount = dcount(truncatedDomain) by ClientIP
| summarize event_count = count() by domainCount
| summarize perc2 = percentilesw(domainCount, event_count, mypercentile));
};
let firstQ = toscalar(quartileFunctionForGlobalThreshold(25, 1d));
let thirdQ = toscalar(quartileFunctionForGlobalThreshold(75, 1d));
// The Global threshold could be adjusted for based on the skewness of the GlobalThreshold distribution per IP - https://wis.kuleuven.be/stat/robust/papers/2008/outlierdetectionskeweddata-revision.pdf
let GlobalThreshold = toscalar(thirdQ + (1.5*exp(3)*(thirdQ - firstQ)));
let FilterOnGlobalThreshold_MainTable = (
nxDomainDnsEvents
| where TimeGenerated > ago(timeframe)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), TotalNXLookups = dcount(truncatedDomain) by ClientIP
| sort by TotalNXLookups desc
// Comment the line below in order to view results filtered by IPThreshold only. 
| where TotalNXLookups > GlobalThreshold 
| join kind = leftouter (nxDomainDnsEvents
    | where TimeGenerated > ago(timeframe)
    | summarize domainCount = dcount(Name) by truncatedDomain, ClientIP
    | project truncatedDomain = strcat(truncatedDomain," (",tostring(domainCount),")"), ClientIP
    ) on ClientIP
| summarize StartTimeUtc = min(StartTimeUtc), EndTimeUtc = max(EndTimeUtc), SLDs_DistinctLookups = make_list(truncatedDomain), UniqueSLDsCount=count(truncatedDomain) by ClientIP, TotalNXLookups, GlobalThreshold
| sort by TotalNXLookups desc);
FilterOnIPThreshold_MainTable
| join FilterOnGlobalThreshold_MainTable on ClientIP
| project StartTimeUtc, EndTimeUtc, ClientIP, TotalNXLookups, IPthreshold, GlobalThreshold, SLDs_DistinctLookups, UniqueSLDsCount
| extend timestamp = StartTimeUtc, IPCustomEntity = ClientIP```
## High reverse DNS count by host
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/DnsEvents/DNS_HighReverseDNSCount.yaml)

### ATT&CK Tags

> Tactics: [u'Discovery']

### Hunt details

> Description: Clients with a high reverse DNS count could be carrying out reconnaissance or discovery activity.

> Query:

```let timeframe = 1d;
let threshold = 10;
DnsEvents 
| where TimeGenerated >= ago(timeframe)
| where Name contains "in-addr.arpa" 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), NameCount = dcount(Name), Names = make_set(Name), ClientIPCount = count() by ClientIP
| where NameCount > threshold
| extend timestamp = StartTimeUtc, IPCustomEntity = ClientIP```
## Abnormally long DNS URI queries
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/DnsEvents/DNS_LongURILookup.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl', u'Exfiltration']

### Hunt details

> Description: Length of DNS query can often be an indicator of suspicious activity. Typical domain name lengths are short whereas domain name query used for data exfiltration or tunneling can often be very large in size. This is because they could be encoded using base 64/32 etc. The hunting query looks for Names that are more than 150 characters in length. Due to a lot of services using long DNS to communicate via prcodurally generated long domain namesthis can be prone, so a number of known services are excluded from this query. Additional items might need to be added to this exclusion dependent on yourenvironment.

> Query:

```let timeframe = 1d;
// Setting URI length threshold count, shorter URIs may cause noise, change as needed
let uriThreshold = 150;
let LocalDomains = 
(
DnsEvents | where TimeGenerated >= ago(1d)
| summarize count() by Computer 
| extend SubDomain = tolower(strcat(tostring(split(Computer, ".")[-2]),".", tostring(split(Computer, ".")[-1])))
| distinct SubDomain
);
let DomainLookups =
(
DnsEvents | where TimeGenerated >= ago(1d)
| where SubType =~ "LookupQuery"
| where ipv4_is_match("127.0.0.1", ClientIP) == False 
| where Name !endswith ".local" and Name !startswith "_" and Name !startswith "#"
| where Name !contains "::1"
| where Name !has "cnr.io" and Name !has "kr0.io" and Name !has "arcticwolf.net" and Name !has "webcfs00.com" and Name !has "barracudabrts.com"and Name !has "trendmicro.com" 
and Name !has "sophosxl.net" and Name !has "spotify.com" and Name !has "e5.sk" and Name !has "mcafee.com" and Name !has "opendns.com"  and Name !has "spameatingmonkey.net" 
and Name !has "_ldap" and Name !has "_kerberos" and Name !has "modsecurity.org" and Name !has "fdmarc.net" and Name !has "ipass.com" and Name !has "wpad"
and Name !has "cnr.io" and Name !has "trendmicro.com" and Name !has "sophosxl.net" and Name !has "spotify.com" and Name !has "e5.sk" and Name !has "mcafee.com" 
and Name !has "opendns.com"  and Name !has "spameatingmonkey.net" and Name !has "_ldap" and Name !has "_kerberos" and Name !has "modsecurity.org" and Name !has "fdmarc.net" 
and Name !has "ipass.com" and Name !has "wpad"
| extend Name = tolower(Name), Urilength = strlen(Name) 
| where Urilength >= uriThreshold
| extend SubDomain = case(
isempty(Name), Name,
array_length(split(Name, ".")) <= 2, Name,
tostring(split(Name, ".")[-2]) == "corp", strcat(tostring(split(Name, ".")[-3]),".",tostring(split(Name, ".")[-2]),".", tostring(split(Name, ".")[-1])),
strlen(tostring(split(Name, ".")[-1])) == 2, strcat(tostring(split(Name, ".")[-3]),".",tostring(split(Name, ".")[-2]),".", tostring(split(Name, ".")[-1])),
strlen(tostring(split(Name, ".")[-2])) != "corp", strcat(tostring(split(Name, ".")[-2]),".", tostring(split(Name, ".")[-1])),
Name))
;
DomainLookups
| join kind= leftanti (
    LocalDomains
) on SubDomain 
| summarize by TimeGenerated, Computer, ClientIP , Name, Urilength
| extend timestamp = TimeGenerated, IPCustomEntity = ClientIP, HostCustomEntity = Computer```
## DNS Domains linked to WannaCry ransomware campaign
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/DnsEvents/DNS_WannaCry.yaml)

### ATT&CK Tags

> Tactics: [u'Execution', u'Impact']

### Hunt details

> Description: Displays client DNS request for any of the known domains linked to WannaCry.These results may indicate Wannacry/Wannacrypt ransomware infection.Reference: Domain listing from https://pastebin.com/cRUii32E

> Query:

```let timeframe = 1d;
let badDomains = dynamic(["agrdwrtj.us", "bctxawdt.us", "cokfqwjmferc.us", "cxbenjiikmhjcerbj.us", "depuisgef.us", "edoknehyvbl.us", 
"enyeikruptiukjorq.com", "frullndjtkojlu.us", "gcidpiuvamynj.us", "gxrytjoclpvv.us", "hanoluexjqcf.us", "iarirjjrnuornts.us", 
"ifbjoosjqhaeqjjwaerri.us", "iouenviwrc.us", "kuuelejkfwk.us", "lkbsxkitgxttgaobxu.us", "nnnlafqfnrbynwor.us", "ns768.com", 
"ofdwcjnko.us", "peuwdchnvn.us", "pvbeqjbqrslnkmashlsxb.us", "pxyhybnyv.us", "qkkftmpy.us", "rkhlkmpfpoqxmlqmkf.us", 
"ryitsfeogisr.us", "srwcjdfrtnhnjekjerl.us", "thstlufnunxaksr.us", "udrgtaxgdyv.us", "w5q7spejg96n.com", "xmqlcikldft.us", 
"yobvyjmjbsgdfqnh.us", "yrwgugricfklb.us", "ywpvqhlqnssecpdemq.us"]);
DnsEvents
| where TimeGenerated >= ago(timeframe) 
| where Name in~ (badDomains)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count() by Computer, ClientIP, WannaCrypt_Related_Domain = Name
| extend timestamp = StartTimeUtc, HostCustomEntity = Computer, IPCustomEntity = ClientIP```
## Solorigate DNS Pattern
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/DnsEvents/Solorigate-DNS-Pattern.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl']

### Hunt details

> Description: Looks for DGA pattern of the domain associated with Solorigate in order to find other domains with the same activity pattern.

> Query:

```let cloudApiTerms = dynamic(["api", "east", "west"]);
DnsEvents
| where IPAddresses != "" and IPAddresses != "127.0.0.1"
| where Name endswith ".com" or Name endswith ".org" or Name endswith ".net"
| extend domain_split = split(Name, ".")
| where tostring(domain_split[-5]) != "" and tostring(domain_split[-6]) == ""
| extend sub_domain = tostring(domain_split[0])
| where sub_domain !contains "-"
| extend sub_directories = strcat(domain_split[-3], " ", domain_split[-4])
| where sub_directories has_any(cloudApiTerms)
//Based on sample communications the subdomain is always between 20 and 30 bytes
| where strlen(sub_domain) < 32 and strlen(sub_domain) > 20
| extend domain = strcat(tostring(domain_split[-2]), ".", tostring(domain_split[-1])) 
| extend subdomain_no = countof(sub_domain, @"(\d)", "regex")
| extend subdomain_ch = countof(sub_domain, @"([a-z])", "regex")
| where subdomain_no > 1
| extend percentage_numerical = toreal(subdomain_no) / toreal(strlen(sub_domain)) * 100
| where percentage_numerical < 50 and percentage_numerical > 5
| summarize count(), make_set(Name), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Name
| order by count_ asc```
## Solorigate Encoded Domain in URL
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/DnsEvents/Solorigate-Encoded-Domain-URL.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl']

### Hunt details

> Description: Looks for a logon domain seen in Azure AD logs appearing in a DNS query encoded with the DGA encoding used in the Solorigate incident.Reference: https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/

> Query:

```let dictionary = dynamic(["r","q","3","g","s","a","l","t","6","u","1","i","y","f","z","o","p","5","7","2","d","4","9","b","n","x","8","c","v","m","k","e","w","h","j"]);
let regex_bad_domains = SigninLogs
//Collect domains from tenant from signin logs
| where TimeGenerated > ago(1d)
| extend domain = tostring(split(UserPrincipalName, "@", 1)[0])
| where domain != ""
| summarize by domain
| extend split_domain = split(domain, ".")
//This cuts back on domains such as na.contoso.com by electing not to match on the "na" portion
| extend target_string = iff(strlen(split_domain[0]) <= 2, split_domain[1], split_domain[0])
| extend target_string = split(target_string, "-")
| mv-expand target_string
//Rip all of the alphanumeric out of the domain name
| extend string_chars = extract_all(@"([a-z0-9])", tostring(target_string))
//Guid for tracking our data
| extend guid = new_guid()
//Expand to get all of the individual chars from the domain
| mv-expand string_chars
| extend chars = tostring(string_chars)
//Conduct computation to encode the domain as per actor spec
| extend computed_char = array_index_of(dictionary, chars)
| extend computed_char = dictionary[(computed_char + 4) % array_length(dictionary)] 
| summarize make_list(computed_char) by guid, domain
| extend target_encoded = tostring(strcat_array(list_computed_char, ""))
//These are probably too small, but can be edited (expect FPs when going too small)
| where strlen(target_encoded) > 5
| distinct target_encoded
| summarize make_set(target_encoded)
//Key to join to DNS
| extend key = 1;
DnsEvents
| where TimeGenerated > ago(1d)
| summarize by Name
| extend key = 1
//For each DNS query join the malicious domain list
| join kind=inner ( 
    regex_bad_domains
) on key
| project-away key
//Expand each malicious key for each DNS query observed
| mv-expand set_target_encoded
//IndexOf allows us to fuzzy match on the substring
| extend match = indexof(Name, set_target_encoded)
| where match > -1```
## GitHub First Time Invite Member and Add Member to Repo
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/GitHub/First%20Time%20User%20Invite%20and%20Add%20Member%20to%20Org.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence']

### Hunt details

> Description: This hunting query identifies a user that add/invite a member to the organization for the first time. This technique can be leveraged by attackers to add stealth account access to the organization.

> Query:

```let LearningPeriod = 7d;
let RunTime = 1h;
let StartTime = 1h;
let EndRunTime = StartTime - RunTime;
let EndLearningTime = StartTime + LearningPeriod;
let GitHubOrgMemberLogs = (GitHubAudit
| where Action == "org.invite_member" or Action == "org.update_member" or Action == "org.add_member" or Action == "repo.add_member" or Action == "team.add_member");
GitHubOrgMemberLogs
| where TimeGenerated between (ago(EndLearningTime) .. ago(StartTime))
| distinct Actor
| join kind=rightanti (
  GitHubOrgMemberLogs
  | where TimeGenerated between (ago(StartTime) .. ago(EndRunTime))
  | distinct Actor
) on Actor```
## GitHub Inactive or New Account Access or Usage
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/GitHub/Inactive%20or%20New%20Account%20Usage.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence']

### Hunt details

> Description: This hunting query identifies Accounts that are new or inactive and have accessed or used GitHub that may be a sign of compromise.

> Query:

```let LearningPeriod = 7d;
let RunTime = 1h;
let StartTime = 1h;
let EndRunTime = StartTime - RunTime;
let EndLearningTime = StartTime + LearningPeriod;
let GitHubActorLogin = (GitHubAudit
| where Actor != "");
let GitHubUser = (GitHubAudit
| where ImpactedUser != "");
let GitHubNewActorLogin = (GitHubActorLogin
| where TimeGenerated between (ago(EndLearningTime) .. ago(StartTime))
| summarize makeset(Actor)
| extend Dummy = 1
| join kind=innerunique (
  GitHubActorLogin
  | where TimeGenerated between (ago(StartTime) .. ago(EndRunTime))
  | distinct Actor
  | extend Dummy = 1
) on Dummy
| project-away Dummy
| where set_Actor  !contains Actor);
let GitHubNewUser = ( GitHubUser
| where TimeGenerated between (ago(EndLearningTime) .. ago(StartTime))
| summarize makeset(ImpactedUser)
| extend Dummy = 1
| join kind=innerunique (
  GitHubUser
  | where TimeGenerated between (ago(StartTime) .. ago(EndRunTime))
  | distinct ImpactedUser
  | extend Dummy = 1
) on Dummy
| project-away Dummy
| where set_ImpactedUser !contains ImpactedUser);
union GitHubNewActorLogin, GitHubNewUser```
## GitHub Mass Deletion of repos or projects
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/GitHub/Mass%20Deletion%20of%20Repositories%20.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: This hunting query identifies GitHub activites where there are a large number of deletions that may be a sign of compromise.

> Query:

```let LearningPeriod = 7d;
let BinTime = 1h;
let RunTime = 1h;
let StartTime = 1h;
let NumberOfStds = 3;
let MinThreshold = 10.0;
let EndRunTime = StartTime - RunTime;
let EndLearningTime = StartTime + LearningPeriod;
let GitHubRepositoryDestroyEvents = (GitHubAudit
| where Action == "repo.destroy");
GitHubRepositoryDestroyEvents
| where TimeGenerated between (ago(EndLearningTime) .. ago(StartTime))
| summarize count() by bin(TimeGenerated, BinTime)
| summarize AvgInLearning = avg(count_), StdInLearning = stdev(count_)
| extend LearningThreshold = max_of(AvgInLearning + StdInLearning * NumberOfStds, MinThreshold)
| extend Dummy = 1
| join kind=innerunique (
  GitHubRepositoryDestroyEvents
  | where TimeGenerated between (ago(StartTime) .. ago(EndRunTime))
  | summarize CountInRunTime = count() by bin(TimeGenerated, BinTime)
  | extend Dummy = 1
) on Dummy
| project-away Dummy
| where CountInRunTime > LearningThreshold```
## GitHub OAuth App Restrictions Disabled
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/GitHub/Oauth%20App%20Restrictions%20Disabled.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'DefenseEvasion']

### Hunt details

> Description: This hunting query identifies GitHub OAuth Apps that have restrictions disabled that may be a sign of compromise. Attacker will want to disable such security tools in order to go undetected. 

> Query:

```let timeframe = 14d;
GitHubAudit
| where TimeGenerated > ago(timeframe)
| where Action == "org.disable_oauth_app_restrictions"
| project TimeGenerated, Action, Actor, Country```
## GitHub Update Permissions
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/GitHub/Org%20Repositories%20Default%20Permissions%20Change.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'DefenseEvasion']

### Hunt details

> Description: This hunting query identifies GitHub activites where permissions are updated that may be a sign of compromise.

> Query:

```GitHubAudit
| where Action == "org.update_default_repository_permission"
| project TimeGenerated, Action, Actor, Country, Repository, PreviousPermission, CurrentPermission```
## GitHub Repo switched from private to public
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/GitHub/Repository%20Permission%20Switched%20to%20Public.yaml)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: This hunting query identifies GitHub activites where a repo was changed from private to public that may be a sign of compromise.

> Query:

```let timeframe = 14d;
GitHubAudit
| where TimeGenerated > ago(timeframe)
| where Action == "repo.access"
| where OperationType == "MODIFY"
| where Visibility == "PUBLIC" 
| project TimeGenerated, Action, Actor, Country, Repository, Visibility```
## GitHub OAuth App Restrictions Disabled
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/GitHub/Suspicious%20Fork%20Activity.yaml)

### ATT&CK Tags

> Tactics: [u'Exfiltration']

### Hunt details

> Description: This hunting query identifies a fork activity against a repository done by a user who is not the owner of the repo nor a contributes.

> Query:

```let RunTime = 1h; 
let CollaboratorsUserToRepoMapping = (
GitHubRepo
| where TimeGenerated < ago(RunTime)
| where Action == "Collaborators"
| distinct Repository , Actor, Organization);
let UserCommitsInRepoMapping = (
GitHubRepo
| where Action == "Commits"
| where TimeGenerated < ago(RunTime)
| distinct  Repository ,Actor, Organization);
union CollaboratorsUserToRepoMapping, UserCommitsInRepoMapping
| summarize ContributedToRepos = make_set(Repository) by Actor, Organization
| join kind=innerunique (
GitHubRepo
| where TimeGenerated > ago(RunTime)
| where Action == "Forks"
| distinct Repository , Actor, Organization
) on Actor, Organization
| project-away Actor1, Organization1
| where ContributedToRepos !contains Repository```
## GitHub Repo Clone - Time Series Anomly
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/GitHub/Unusual%20Number%20of%20Repository%20Clones.yaml)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Attacker can exfiltrate data from you GitHub repository after gaining access to it by performing clone action. This hunting queries allows you to track the clones activities for each of your repositories. The visualization allow you to quickly identify anomalies/excessive clone, to further investigate repo access & permissions

> Query:

```let min_t = toscalar(GitHubRepo
| summarize min(timestamp_t));
let max_t = toscalar(GitHubRepo
| summarize max(timestamp_t));
GitHubRepo
| where Action == "Clones"
| distinct TimeGenerated, Repository, Count
| make-series num=sum(tolong(Count)) default=0 on TimeGenerated in range(min_t, max_t, 1h) by Repository 
| extend (anomalies, score, baseline) = series_decompose_anomalies(num, 1.5, -1, linefit)
| render timechart```
## GitHub First Time Repo Delete
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/GitHub/User%20First%20Time%20Repository%20Delete%20Activity.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: This hunting query identifies GitHub activites its the first time a user deleted a repo that may be a sign of compromise.

> Query:

```let LearningPeriod = 7d;
let RunTime = 1h;
let StartTime = 1h;
let EndRunTime = StartTime - RunTime;
let EndLearningTime = StartTime + LearningPeriod;
let GitHubRepositoryDestroyEvents = (GitHubAudit
| where Action == "repo.destroy");
GitHubRepositoryDestroyEvents
| where TimeGenerated between (ago(EndLearningTime) .. ago(StartTime))
| distinct Actor
| join kind=rightanti (
  GitHubRepositoryDestroyEvents
  | where TimeGenerated between (ago(StartTime) .. ago(EndRunTime))
  | distinct Actor
) on Actor```
## GitHub User Grants Access and Other User Grants Access
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/GitHub/User%20Grant%20Access%20and%20Grants%20Other%20Access.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'PrivilegeEscalation']

### Hunt details

> Description: This hunting query identifies Accounts in GitHub that have granted access to another account which then grants access to yet another account that may be a sign of compromise.

> Query:

```GitHubAudit
| where ImpactedUser != ""
| where Action == "org.invite_member" or Action == "org.add_member" or Action == "team.add_member" or Action == "repo.add_member"
| distinct ImpactedUser, TimeGenerated, Actor
| project-rename firstUserAdded = ImpactedUser, firstEventTime = TimeGenerated, firstAdderUser = Actor
| join kind= innerunique (
  GitHubAudit
  | where ImpactedUser != ""
  | where Action == "org.invite_member" or Action == "org.add_member" or Action == "team.add_member" or Action == "repo.add_member"
  | distinct ImpactedUser, TimeGenerated, Actor
  | project-rename secondUserAdded = ImpactedUser, secondEventTime = TimeGenerated, secondAdderUser = Actor
) on $right.secondAdderUser == $left.firstUserAdded
| where secondEventTime between (firstEventTime .. (firstEventTime + 1h))```
## Cross workspace query anomolies
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/LAQueryLogs/CrossWorkspaceQueryAnomolies.yaml)

### ATT&CK Tags

> Tactics: [u'Collection', u'Exfiltration']

### Hunt details

> Description: This hunting query looks for increases in the number of workspaces queried by a user.

> Query:

```let lookback = 30d;
let timeframe = 1d;
let threshold = 0;
LAQueryLogs
| where TimeGenerated between (ago(lookback)..ago(timeframe))
| mv-expand(RequestContext)
| extend RequestContextExtended = split(RequestTarget, "/")
| extend Subscription = tostring(RequestContextExtended[2]), ResourceGroups = tostring(RequestContextExtended[4]), Workspace = tostring(RequestContextExtended[8])
| summarize count(), HistWorkspaceCount=dcount(Workspace) by AADEmail
| join (
LAQueryLogs
| where TimeGenerated > ago(timeframe)
| mv-expand(RequestContext)
| extend RequestContextExtended = split(RequestTarget, "/")
| extend Subscription = tostring(RequestContextExtended[2]), ResourceGroups = tostring(RequestContextExtended[4]), Workspace = tostring(RequestContextExtended[8])
| summarize make_set(Workspace), count(), CurrWorkspaceCount=dcount(Workspace) by AADEmail
) on AADEmail
| where CurrWorkspaceCount > HistWorkspaceCount
// Uncomment follow rows to see queries made by these users
//| join (
//LAQueryLogs
//| where TimeGenerated > ago(timeframe))
//on AADEmail
//| extend timestamp = TimeGenerated, AccountCustomEntity = AADEmail```
## Multiple large queries made by user
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/LAQueryLogs/MultipleLargeQueriesByUser.yaml)

### ATT&CK Tags

> Tactics: [u'Exfiltration']

### Hunt details

> Description: This hunting query looks for users who are running multiple queries that return either a very largeamount of data or the maximum amount allowed by the query method.

> Query:

```let UI_apps = dynamic([ASI_Portal,AzureMonitorLogsConnector,AppAnalytics]);
let threshold = 3;
let timeframe = 1d;
LAQueryLogs
| where TimeGenerated > ago(timeframe)
| where (ResponseRowCount == 10001 and RequestClientApp in(UI_apps)) or (ResponseRowCount > 10001 and RequestClientApp !in(UI_apps))
| summarize count() by AADEmail
| where count_ > threshold
| join kind=rightsemi (
LAQueryLogs
| where TimeGenerated > ago(timeframe)
| where (ResponseRowCount == 10001 and RequestClientApp in(UI_apps)) or (ResponseRowCount > 10001 and RequestClientApp !in(UI_apps)))
on AADEmail
| extend timestamp = TimeGenerated, AccountCustomEntity = AADEmail```
## New client running queries
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/LAQueryLogs/NewClientRunningQueries.yaml)

### ATT&CK Tags

> Tactics: [u'Collection', u'Exfiltration']

### Hunt details

> Description: This hunting query looks for clients running queries that have not previously been seen running queries.

> Query:

```let lookback = 7d;
let timeframe = 1d;
LAQueryLogs
| where TimeGenerated between (ago(lookback)..ago(timeframe))
| where ResponseCode == 200
| join kind= rightanti(
LAQueryLogs
| where TimeGenerated > ago(timeframe)
)
on RequestClientApp
| extend timestamp = TimeGenerated, AccountCustomEntity = AADEmail```
## New ServicePrincipal running queries
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/LAQueryLogs/NewServicePrincipalRunningQueries.yaml)

### ATT&CK Tags

> Tactics: [u'Collection', u'Exfiltration']

### Hunt details

> Description: This hunting query looks for new Service Principals running queries that have not previously been seen running queries.

> Query:

```let lookback = 7d;
let timeframe = 1d;
LAQueryLogs
| where TimeGenerated between (ago(lookback)..ago(timeframe))
| where ResponseCode == 200 and RequestClientApp != "AppAnalytics" and AADEmail !contains "@"
| distinct AADClientId
| join kind=rightanti(
LAQueryLogs
| where TimeGenerated > ago(timeframe)
| where ResponseCode == 200 and RequestClientApp != "AppAnalytics" and AADEmail !contains "@"
)
on AADClientId
| extend timestamp = TimeGenerated, AccountCustomEntity = AADEmail```
## New users running queries
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/LAQueryLogs/NewUserRunningQueries.yaml)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: This hunting query looks for users who have run queries that have not previously been seen running queries.

> Query:

```let lookback = 7d;
let timeframe = 1d;
LAQueryLogs
| where TimeGenerated between(startofday(ago(lookback))..startofday(ago(timeframe)))
| summarize by AADEmail
| join kind = rightanti (LAQueryLogs
| where TimeGenerated > ago(timeframe))
on AADEmail
| project TimeGenerated, AADEmail, QueryText, RequestClientApp, RequestTarget
| extend timestamp = TimeGenerated, AccountCustomEntity = AADEmail```
## Query data volume anomolies
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/LAQueryLogs/QueryDataVolumeAnomolies.yaml)

### ATT&CK Tags

> Tactics: [u'Exfiltration']

### Hunt details

> Description: This hunting query looks for anomalously large LA queries by users.

> Query:

```let lookback = 7d;
let threshold = 0;
LAQueryLogs
| make-series rows = sum(ResponseRowCount) on TimeGenerated in range(startofday(ago(lookback)), now(), 1h)
| extend (anomalies, score, baseline) = series_decompose_anomalies(rows,3, -1, linefit)
| mv-expand anomalies to typeof(int), score to typeof(double), TimeGenerated to typeof(datetime)
| where anomalies > threshold
| sort by score desc
| join kind=rightsemi (
LAQueryLogs
| summarize make_set(QueryText) by AADEmail, RequestTarget, TimeGenerated = bin(TimeGenerated, 1h))
on TimeGenerated
| project TimeGenerated, AADEmail, RequestTarget, set_QueryText
| extend timestamp = TimeGenerated, AccountCustomEntity = AADEmail```
## Query looking for secrets
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/LAQueryLogs/QueryLookingForSecrets.yaml)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: This hunting query looks for queries that appear to be looking for secrets or passwords in tables.

> Query:

```// Extend this list with items to search for
let keywords = dynamic(["password", "pwd", "creds", "credentials", "secret"]);
// To exclude key phrases or tables to exclude add to these lists
let table_exclusions = dynamic(["AuditLogs","SigninLogs", "LAQueryLogs", "SecurityEvent"]);
let keyword_exclusion = dynamic(["reset user password", "change user password"]);
let timeframe = 7d;
LAQueryLogs
| where TimeGenerated > ago(timeframe)
| where RequestClientApp != Sentinel-General
| extend querytext_lower = tolower(QueryText)
| where querytext_lower has_any(keywords)
| project TimeGenerated, AADEmail, QueryText, RequestClientApp, RequestTarget, ResponseCode, ResponseRowCount, ResponseDurationMs, CorrelationId
| extend timestamp = TimeGenerated, AccountCustomEntity = AADEmail
| join kind=leftanti ( LAQueryLogs
| where TimeGenerated > ago(timeframe)
| where RequestClientApp != Sentinel-General
| extend querytext_lower = tolower(QueryText)
| where QueryText has_any(table_exclusions) or querytext_lower has_any(keyword_exclusion))
on CorrelationId```
## User returning more data than daily average
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/LAQueryLogs/UserReturningMoreDataThanDailyAverage.yaml)

### ATT&CK Tags

> Tactics: [u'Exfiltration']

### Hunt details

> Description: This hunting query looks for users whose total returned data for a day is significantly above their monthly average.

> Query:

```let threshold = 10;
let lookback = 7d;
let timeframe = 1d;
let baseline = 10000;
let diff = 5;
let anomolous_users = (
LAQueryLogs
| where TimeGenerated between(startofday(ago(lookback))..startofday(ago(timeframe)))
| summarize score=sum(ResponseRowCount) by AADEmail
| join kind = fullouter (LAQueryLogs
| where TimeGenerated > startofday(ago(timeframe))
| summarize score_now=sum(ResponseRowCount) by AADEmail)
on AADEmail
| extend hist_score = iif((score/29)*threshold > baseline, (score/29)*threshold, baseline)
| where isnotempty(score)
| where score_now > hist_score*diff
| project AADEmail);
LAQueryLogs
| where TimeGenerated > ago(timeframe)
| where AADEmail in(anomolous_users)
| extend timestamp = TimeGenerated, AccountCustomEntity = AADEmail
// Comment out the line below to see the queries run by users.
| summarize total_rows = sum(ResponseRowCount), NoQueries = count(), AvgQuerySize = sum(ResponseRowCount)/count() by AADEmail```
## User running multiple queries that fail
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/LAQueryLogs/UserRunningMultipleQueriesThatFail.yaml)

### ATT&CK Tags

> Tactics: [u'Exfiltration']

### Hunt details

> Description: This hunting query looks for users who have multiple failed queries in a short space of time.

> Query:

```let lookback = 7d;
let timeframe = 1h;
let threshold = 10;
LAQueryLogs
| where TimeGenerated > ago(lookback)
| where ResponseCode != 200
| summarize count() by AADEmail, bin(TimeGenerated, timeframe)
| where count_ > threshold
| join kind=rightsemi (
LAQueryLogs
| where TimeGenerated > ago(lookback)
| summarize make_set(QueryText) by AADEmail, bin(TimeGenerated, timeframe))
on AADEmail, TimeGenerated
| extend timestamp = TimeGenerated, AccountCustomEntity = AADEmail```
## Azure Resources assigned Public IP Addresses
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/MultipleDataSources/AzureResourceAssignedPublicIP.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: Identifies when public IP addresses are assigned to Azure Resources.  Additionally, shows connections to those resources.Resources: https://docs.microsoft.com/azure/azure-monitor/insights/azure-networking-analyticshttps://docs.microsoft.com/azure/network-watcher/traffic-analytics-schema

> Query:

```let timeframe = 7d;
AzureActivity
| where TimeGenerated >= ago(timeframe)
// We look for any Operation that modified and then was accepted or succeeded where a publicipaddress component is referenced
| where OperationName has_any ("Create", "Update", "Delete")// Virtual Machine" or OperationName == "Create Deployment" 
| where ActivityStatus has_any ("Succeeded", "Accepted")
| where Properties contains "publicipaddress"
//| extend frontendIPConfigurations = Properties.responseBody.properties.frontendIPConfigurations
// parsing the publicIPAddress from Properties. It is only available if the allocation method is Static.
| parse Properties with * "publicIPAddress\\" PublicIPAddressParse
| extend publicIPAddress_ = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).ipAddress) 
| extend publicIPAddressVersion_ = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).publicIPAddressVersion) 
| extend publicIPAllocationMethod_ = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).publicIPAllocationMethod) 
| extend scope_ = tostring(parse_json(Authorization).scope) 
| project TimeGenerated, OperationName, publicIPAllocationMethod_ , publicIPAddressVersion_, scope_ , Caller, CallerIpAddress, ActivityStatus, Resource 
// Join in the AzureNetworkAnalytics so that we can determine if any connections were made via the public ip address and get the currently assigned ip address when allocation method is Dynamic
| join kind= inner (
union isfuzzy=true
(AzureNetworkAnalytics_CL
| where TimeGenerated >= ago(timeframe) 
// Controlling for Schema Version and later parsing - This is Version 2 and Public IPs only
| where isnotempty(FASchemaVersion_s) and isnotempty(DestPublicIPs_s)
| extend SchemaVersion = FASchemaVersion_s
| extend PublicIPs = tostring(split(DestPublicIPs_s,"|")[0])
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), FirstProcessedTimeUTC = min(FlowStartTime_t), LastProcessedTimeUtc = max(FlowEndTime_t), 
Regions = makeset(Region_s), AzureRegions = makeset(AzureRegion_s), VMs = makeset(VM_s), MACAddresses = makeset(MACAddress_s), PublicIPs = makeset(PublicIPs), DestPort = makeset(DestPort_d), SrcIP = makeset(SrcIP_s), 
ActivityCount = count() by NSGRule_s, NSGList_s, SubNet = Subnet1_s, FlowDirection_s, Subscription = Subscription1_g, Tags_s, SchemaVersion
//NSGList_s contains the subscription ID, remove that as we already have a field for this and now it will match what we get for SchemaVersion 1
| extend NSG = case(isnotempty(NSGList_s), strcat(split(NSGList_s, "/")[-2],"/",split(NSGList_s, "/")[-1]), "NotAvailable")
// Depending on the SchemaVersion, we will need to provide the NSG_Name for matching against the resource identified in AzureActivity
| extend NSG_Name = tostring(split(NSG, "/")[-1])
),
(
AzureNetworkAnalytics_CL
| where TimeGenerated >= ago(timeframe) 
// Controlling for Schema Version and later parsing - This is Version 1
| where isempty(FASchemaVersion_s)
// Controlling for public IPs only
| where isnotempty(PublicFrontendIPs_s) or isnotempty(PublicIPAddresses_s)
| where PublicFrontendIPs_s != "null" or PublicIPAddresses_s != "null"
| extend SchemaVersion = SchemaVersion_s
// The Public IP can be indicated in one of 2 locations, assigning here for easy union results
| extend PublicIPs = case(isnotempty(PublicFrontendIPs_s), PublicFrontendIPs_s,
PublicIPAddresses_s) 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), FirstProcessedTimeUTC = min(TimeProcessed_t), LastProcessedTimeUtc = max(TimeProcessed_t), 
Regions = makeset(Region_s), AzureRegions = makeset(DiscoveryRegion_s), VMs = makeset(VirtualMachine_s), MACAddresses = makeset(MACAddress_s), PublicIPs = makeset(PublicIPs), 
SrcIP = makeset(PrivateIPAddresses_s), Name = makeset(Name_s), DestPort = makeset(DestinationPortRange_s),
ActivityCount = count() by NSG = NSG_s, SubNet = Subnetwork_s, Subscription = Subscription_g, Tags_s, SchemaVersion
// Some events dont have an NSG listed, populating so it is clear it is not available in the datatype
| extend NSG = case(isnotempty(NSG), NSG, "NotAvailable")
// Depending on the SchemaVersion, we will need to provide the NSG_Name for matching against the resource identified in AzureActivity
| extend NSG_Name = tostring(split(NSG, "/")[-1])
)
| project StartTimeUtc, EndTimeUtc, FirstProcessedTimeUTC, LastProcessedTimeUtc, PublicIPs, NSG, NSG_Name, SrcIP, DestPort, SubNet, Name, VMs, MACAddresses, ActivityCount, Regions, AzureRegions, Subscription, Tags_s, SchemaVersion
) on $left.Resource == $right.NSG_Name
| extend timestamp = StartTimeUtc, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress```
## Anomalous Resource Creation and related Network Activity
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/MultipleDataSources/AzureResourceCreationWithNetworkActivity.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: Indicates when an anomalous number of resources are created successfully in Azure via the AzureActivity log.This is then joined with the AzureNetworkAnalytics_CL data to identify any network related activity for the created resource.The anomaly detection identifies activities that have occured both since the start of the day 1 day ago and the start of the day 7 days ago.The start of the day is considered 12am UTC time.Resource creation could indicated malicious or spurious use of your Azure Resource allocation.  Resources can be abused in relation to digital currency mining, command and control, exfiltration, distributed attacks and propagation of malware, among others. Verify that this resource creationis expected.Resources: https://docs.microsoft.com/azure/azure-monitor/insights/azure-networking-analyticshttps://docs.microsoft.com/azure/network-watcher/traffic-analytics-schema

> Query:

```let starttime = 7d;
let endtime = 1d;
let Activity = AzureActivity
| where TimeGenerated >= startofday(ago(starttime))
// We look for any Operation that created and then succeeded where ActivitySubStatus has a value so that we can provide context
| where OperationName has "Create"
| where ActivityStatus has "Succeeded"
| make-series dResourceCount=dcount(ResourceId) default=0 on EventSubmissionTimestamp in range(startofday(ago(7d)), now(), 1d) by Caller, Resource, OperationName
| extend (RSquare,Slope,Variance,RVariance,Interception,LineFit)=series_fit_line(dResourceCount)
// Comment slope reference below to see all returns
| where Slope > 0.2
| join kind=leftsemi (
// Last days activity is anomalous
AzureActivity
| where TimeGenerated >= startofday(ago(endtime))
// We look for any Operation that created and then succeeded where ActivitySubStatus has a value so that we can provide context
| where OperationName has "Create"
| where ActivityStatus has "Succeeded"
| make-series dResourceCount=dcount(ResourceId) default=0 on EventSubmissionTimestamp in range(startofday(ago(1d)), now(), 1d) by Caller, Resource, OperationName
| extend (RSquare,Slope,Variance,RVariance,Interception,LineFit)=series_fit_line(dResourceCount)
// Comment slope reference below to see all returns
| where Slope > 0.2
) on Caller, Resource, OperationName
// Expanding the fields that were grouped so we can match on a time window when we join the details later
| mvexpand EventSubmissionTimestamp, dResourceCount
// Making sure the fields are the right type or the join fails
| extend todatetime(EventSubmissionTimestamp), tostring(dResourceCount)
| join kind= inner (
  AzureActivity
  | where TimeGenerated >= ago(endtime)
  // We look for any Operation that created and then succeeded where ActivitySubStatus has a value so that we can provide context
  | where OperationName has "Create"
  | where ActivityStatus has "Succeeded" and isnotempty(ActivitySubstatus) 
  | summarize by EventSubmissionTimestamp = bin(EventSubmissionTimestamp, 1d), Caller, CallerIpAddress, OperationName, OperationNameValue, ActivityStatusValue, Resource, ResourceGroup, ResourceId, SubscriptionId
) on EventSubmissionTimestamp, Caller, Resource, OperationName;
let NetworkAnalytics = 
  union isfuzzy=true
  (AzureNetworkAnalytics_CL
  | where TimeGenerated >= ago(endtime) 
  // Controlling for Schema Version and later parsing - This is Version 2 and Public IPs only
  | where (isnotempty(FASchemaVersion_s) and isnotempty(DestPublicIPs_s))
  | extend SchemaVersion = FASchemaVersion_s
  | extend PublicIPs = tostring(split(DestPublicIPs_s,"|")[0])
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), FirstProcessedTimeUTC = min(FlowStartTime_t), LastProcessedTimeUtc = max(FlowEndTime_t), 
  Regions = makeset(Region_s), AzureRegions = makeset(AzureRegion_s), VMs = makeset(VM_s), MACAddresses = makeset(MACAddress_s), PublicIPs = makeset(PublicIPs), DestPort = makeset(DestPort_d), SrcIP = makeset(SrcIP_s), 
  ActivityCount = count() by NSGRule_s, NSGList_s, SubNet = Subnet1_s, FlowDirection_s, Subscription = Subscription1_g, Tags_s, SchemaVersion
  //NSGList_s contains the subscription ID, remove that as we already have a field for this and now it will match what we get for SchemaVersion 1
  | extend NSG = case(isnotempty(NSGList_s), strcat(split(NSGList_s, "/")[-2],"/",split(NSGList_s, "/")[-1]), "NotAvailable")
  // Depending on the SchemaVersion, we will need to provide the NSG_Name for matching against the resource identified in AzureActivity
  | extend NSG_Name = tostring(split(NSG, "/")[-1])
  ),
  (
  AzureNetworkAnalytics_CL
  | where TimeGenerated >= ago(endtime) 
  // Controlling for Schema Version and later parsing - This is Version 1
  | where isempty(FASchemaVersion_s)
  // Controlling for public IPs only
  | where isnotempty(PublicFrontendIPs_s) or isnotempty(PublicIPAddresses_s)
  | where PublicFrontendIPs_s != "null" or PublicIPAddresses_s != "null"
  | extend SchemaVersion = SchemaVersion_s
  // The Public IP can be indicated in one of 2 locations, assigning here for easy union results
  | extend PublicIPs = case(isnotempty(PublicFrontendIPs_s), PublicFrontendIPs_s,
  PublicIPAddresses_s) 
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), FirstProcessedTimeUTC = min(TimeProcessed_t), LastProcessedTimeUtc = max(TimeProcessed_t),  
  Regions = makeset(Region_s), AzureRegions = makeset(DiscoveryRegion_s), VMs = makeset(VirtualMachine_s), MACAddresses = makeset(MACAddress_s), PublicIPs = makeset(PublicIPs), 
  SrcIP = makeset(PrivateIPAddresses_s), Name = makeset(Name_s), DestPort = makeset(DestinationPortRange_s),
  ActivityCount = count() by NSG = NSG_s, SubNet = Subnetwork_s, Subscription = Subscription_g, Tags_s, SchemaVersion
  // Some events dont have an NSG listed, populating so it is clear it is not available in th datatype
  | extend NSG = case(isnotempty(NSG), NSG, "NotAvailable")
  // Depending on the SchemaVersion, we will need to provide the NSG_Name for matching against the resource identified in AzureActivity
  | extend NSG_Name = tostring(split(NSG, "/")[-1])
  )
  | project StartTimeUtc, EndTimeUtc, FirstProcessedTimeUTC, LastProcessedTimeUtc, PublicIPs, NSG, NSG_Name, SrcIP, DestPort, SubNet, Name, VMs, MACAddresses, ActivityCount, Regions, AzureRegions, Subscription, Tags_s, SchemaVersion
  ;
  Activity | join kind= leftouter (NetworkAnalytics
  ) on $left.Resource == $right.NSG_Name
  | extend timestamp = StartTimeUtc, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress```
## Cobalt Strike DNS Beaconing
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/MultipleDataSources/CobaltDNSBeacon.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl']

### Hunt details

> Description: Cobalt Strike is a famous Pen Test tool that is used by pen testers as well as attackers alike To compromise an environment. The query tries to detect suspicious DNS queries known from Cobalt Strike beacons.This is based out of sigma rules described here: https://github.com/Neo23x0/sigma/blob/master/rules/network/net_mal_dns_cobaltstrike.yml

> Query:

```let timeframe = 1d;
let badNames = dynamic(["aaa.stage.", "post.1"]);
(union isfuzzy=true
(DnsEvents
| where TimeGenerated >= ago(timeframe) 
| where Name has_any (badNames)
| extend Domain = Name, SourceIp = ClientIP, RemoteIP = todynamic(IPAddresses)
| mvexpand RemoteIP
| extend RemoteIP = tostring(RemoteIP)),
(VMConnection
| where TimeGenerated >= ago(timeframe)
| where isnotempty(RemoteDnsCanonicalNames) 
| parse RemoteDnsCanonicalNames with * [" DNSName "] *
| where DNSName has_any (badNames)
| extend Domain = DNSName, RemoteIP = RemoteIp
))
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by Domain, SourceIp, RemoteIP, Computer
| extend timestamp = StartTimeUtc, HostCustomEntity = Computer, IPCustomEntity = RemoteIP```
## Failed service logon attempt by user account with available AuditData
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/MultipleDataSources/FailedSigninsWithAuditDetails.yaml)

### ATT&CK Tags

> Tactics: [u'CredentialAccess']

### Hunt details

> Description: User account failed to logon in current period (default last 1 day). Excludes Windows Sign in attempts due to noise and limits to only more than 10 failed logons or 3 different IPs used.Additionally, Azure Audit Log data from the last several days(default 7 days) related to the given UserPrincipalName will be joined if available.This can help to understand any events for this same user related to User or Group Management.Results may indicate a potential malicious use of an account that is rarely used. It is possible this is an account that is new or newly enabled.The associated Azure Audit data should help determine any recent changes to this account and may help you understand why the logons are failing.Receiving no results indicates that there were no less than 10 failed logons or that the Auditlogs related to this UserPrincipalName in the default 7 days.

> Query:

```let current = 1d;
let failLimit = 10;
let ipLimit = 3;
let auditLookback = 7d;
let FailedSignins = SigninLogs 
| where TimeGenerated >= ago(current)
| where ResultType != "0" and AppDisplayName != "Windows Sign In"
| extend UserPrincipalName = tolower(UserPrincipalName)
| extend CityState = strcat(tostring(LocationDetails.city),"|", tostring(LocationDetails.state))
| extend Result = strcat(ResultType,"-",ResultDescription) 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), DistinctIPAddressCount = dcount(IPAddress), IPAddresses = makeset(IPAddress), 
CityStates = makeset(CityState), DistinctResultCount = dcount(Result), Results = makeset(Result), AppDisplayNames = makeset(AppDisplayName), 
FailedLogonCount = count() by Type, OperationName, Category, UserPrincipalName = tolower(UserPrincipalName), ClientAppUsed, Location, CorrelationId
| project Type, StartTimeUtc, EndTimeUtc, OperationName, Category, UserPrincipalName, AppDisplayNames, DistinctIPAddressCount, IPAddresses, DistinctResultCount, 
Results, FailedLogonCount, Location, CityStates 
| where FailedLogonCount >= failLimit or DistinctIPAddressCount >= ipLimit
| extend Activity = pack("IPAddresses", IPAddresses, "AppDisplayNames", AppDisplayNames, "Results", Results, "Location", Location, "CityStates", CityStates)
| project Type, StartTimeUtc, EndTimeUtc, OperationName, Category, UserPrincipalName, FailedLogonCount, DistinctIPAddressCount, DistinctResultCount, Activity
| extend AccountCustomEntity = UserPrincipalName;
let AccountMods = AuditLogs | where TimeGenerated >= ago(current+auditLookback)
| where Category == "UserManagement" or Category == "GroupManagement"
| extend ModProps = TargetResources.[0].modifiedProperties
| extend InitiatedBy = case(
isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName),
isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).displayName)), tostring(parse_json(tostring(InitiatedBy.app)).displayName),
"")
| extend UserPrincipalName = tolower(tostring(TargetResources.[0].userPrincipalName))
| mvexpand ModProps
| extend PropertyName = tostring(ModProps.displayName), oldValue = tostring(ModProps.oldValue), newValue = tostring(ModProps.newValue)
| extend ModifiedProps = pack("PropertyName",PropertyName,"oldValue",oldValue,"newValue",newValue) 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), Activity = make_bag(ModifiedProps) by Type, InitiatedBy, UserPrincipalName, Category, OperationName, CorrelationId, Id
| extend AccountCustomEntity = UserPrincipalName;
// Gather only Audit data for UserPrincipalNames that we have Audit data for
let AccountNameOnly = FailedSignins | project UserPrincipalName;
let AuditMods = AccountNameOnly
| join kind= innerunique (
AccountMods
) on UserPrincipalName;
let AvailableAudits = AuditMods | project UserPrincipalName;
let SigninsWithAudit = AvailableAudits
| join kind= innerunique (
FailedSignins
) on UserPrincipalName;
// Union the Current Signin failures so we do not lose them with the Auditing data we do have
let Activity = (union isfuzzy=true
SigninsWithAudit, AuditMods)
| order by StartTimeUtc, UserPrincipalName;
Activity
| project StartTimeUtc, EndTimeUtc, DataType = Type, Category, OperationName, UserPrincipalName, InitiatedBy, Activity, FailedLogonCount, DistinctIPAddressCount, DistinctResultCount, CorrelationId, Id
| order by UserPrincipalName, StartTimeUtc
| extend timestamp = StartTimeUtc, AccountCustomEntity = UserPrincipalName```
## FireEye stolen red teaming tools communications
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/MultipleDataSources/FireEyeRedTeamComms.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl']

### Hunt details

> Description: This composite hunting query will highlight any HTTP traffic in CommonSecurityLog web proxies (such as ZScaler) that match known patterns used by red teaming tools potentially stolen from FireEye. Most FireEye red teaming tools are designed to mimiclegitimate API activity, false positives are common. This query includes a basic check to determine how common a hostname is in you environment, and allows you to modify this threshold to remove legitimate traffic from the query results.This query contains only a subset of potential FireEye red team tool communications, and therefore should not be relied upon alone :) .

> Query:

```let lookback = 7d;
let domainLookback = 7d;
let domainCountThreshold = 100; //Maxiumum number of times a domain ahs been visited
//Backdoor.HTTP.BEACON.[Yelp GET]
let FEQuery1 = CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where RequestMethod == "GET"
| where RequestURL contains "&parent_request_id="
| where RequestURL matches regex @"&parent_request_id=(?:[A-Za-z0-9_\/\+\-\%]{128,1000})={0,2}[^\r\n]{0,256}"
| extend Quality = "high"
| extend RuleName = "Backdoor.HTTP.BEACON.[Yelp GET]"
| project TimeGenerated, Quality, RuleName, DeviceVendor, DeviceProduct, TenantId, SourceIP, DestinationIP, DestinationHostName, RequestMethod, RequestURL;
//Backdoor.HTTP.BEACON.[CSBundle CDN GET]
let FEQuery2 = CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where RequestMethod == "GET"
| where FileType =~ "GZIP"
| where RequestURL matches regex @"(?:\/v1\/queue|\/v1\/profile|\/v1\/docs\/wsdl|\/v1\/pull)"
| extend Quality = "low"
| extend RuleName = "Backdoor.HTTP.BEACON.[CSBundle CDN GET]"
| project TimeGenerated, Quality, RuleName, DeviceVendor, DeviceProduct, TenantId, SourceIP, DestinationIP, DestinationHostName, RequestMethod, RequestURL;
//Backdoor.HTTP.BEACON.[CSBundle USAToday GET]
let FEQuery3 = CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where RequestMethod == "GET"
| where isempty(RequestContext)
| where RequestURL matches regex @"(?:\/USAT-GUP\/user\/|\/entertainment\/|\/entertainment\/navdd-q1a2z3Z6TET4gv2PNfXpaJAniOzOajK7M\.min\.json|\/global-q1a2z3C4M2nNlQYzWhCC0oMSEFjQbW1KA\.min\.json|\/life\/|\/news\/weather\/|\/opinion\/|\/sports\/|\/sports\/navdd-q1a2z3JHa8KzCRLOQAnDoVywVWF7UwxJs\.min\.json|\/tangstatic\/js\/main-q1a2z3b37df2b1\.min\.js|\/tangstatic\/js\/pbjsandwich-q1a2z300ab4198\.min\.js|\/tangstatic\/js\/pg-q1a2z3bbc110a4\.min\.js|\/tangsvc\/pg\/3221104001\/|\/ta`ngsvc\/pg\/5059005002\/|\/tangsvc\/pg\/5066496002\/|\/tech\/|\/travel\/)"
| where DestinationHostName !endswith "usatoday.com"
| extend Quality = "medium"
| extend RuleName = "Backdoor.HTTP.BEACON.[CSBundle USAToday GET]"
| project TimeGenerated, Quality, RuleName, DeviceVendor, DeviceProduct, TenantId, SourceIP, DestinationIP, DestinationHostName, RequestMethod, RequestURL;
//Backdoor.HTTP.BEACON.[CSBundle Original POST]
let FEQuery4 = CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where RequestMethod == "POST"
| where isempty(RequestContext)
| where RequestURL matches regex @"(?:\/v4\/links\/check-activity\/check|\/v1\/stats|\/gql|\/api2\/json\/check\/ticket|\/1.5\/95648064\/storage\/history|\/1.5\/95648064\/storage\/tabs|\/u\/0\/_\/og\/botguard\/get|\/ev\/prd001001|\/ev\/ext001001|\/gp\/aw\/ybh\/handlers|\/v3\/links\/ping-beat\/check)"
| extend Quality = "low"
| extend RuleName = "Backdoor.HTTP.BEACON.[CSBundle Original POST]"
| project TimeGenerated, Quality, RuleName, DeviceVendor, DeviceProduct, TenantId, SourceIP, DestinationIP, DestinationHostName, RequestMethod, RequestURL;
//Backdoor.HTTP.BEACON.[CSBundle MSOffice POST
let FEQuery5 = CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where RequestMethod == "POST"
| where isempty(RequestContext)
| where RequestURL contains "/v1/push"
| extend Quality = "low"
| extend RuleName = "Backdoor.HTTP.BEACON.[CSBundle MSOffice POST]"
| project TimeGenerated, Quality, RuleName, DeviceVendor, DeviceProduct, TenantId, SourceIP, DestinationIP, DestinationHostName, RequestMethod, RequestURL;
//Backdoor.HTTP.BEACON.[CSBundle NYTIMES POST]
let FEQuery6 = CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where RequestMethod == "POST"
| where isempty(RequestContext)
| where RequestURL matches regex @"(?:\/track|\/api\/v1\/survey\/embed|\/svc\/weather\/v2)"
| extend Quality = "low"
| extend RuleName = "Backdoor.HTTP.BEACON.[CSBundle NYTIMES POST]"
| project TimeGenerated, Quality, RuleName, DeviceVendor, DeviceProduct, TenantId, SourceIP, DestinationIP, DestinationHostName, RequestMethod, RequestURL;
//Backdoor.HTTP.BEACON.[CSBundle MSOffice GET]
let FEQuery7 = CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where RequestMethod == "GET"
| where isempty(RequestContext)
| where RequestURL matches regex @"(?:\/updates|\/license\/eula|\/docs\/office|\/software-activation)"
| extend Quality = "low"
| extend RuleName = "Backdoor.HTTP.BEACON.[CSBundle MSOffice GET]"
| project TimeGenerated, Quality, RuleName, DeviceVendor, DeviceProduct, TenantId, SourceIP, DestinationIP, DestinationHostName, RequestMethod, RequestURL;
//Backdoor.HTTP.BEACON.[CSBundle MSOffice POST]
let FEQuery8 = CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where RequestMethod == "POST"
| where isempty(RequestContext)
| where RequestURL contains "/notification"
| extend Quality = "low"
| extend RuleName = "Backdoor.HTTP.BEACON.[CSBundle MSOffice POST]"
| project TimeGenerated, Quality, RuleName, DeviceVendor, DeviceProduct, TenantId, SourceIP, DestinationIP, DestinationHostName, RequestMethod, RequestURL;
//Backdoor.HTTP.BEACON.[CSBundle Original GET]
let FEQuery9 = CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where RequestMethod == "GET"
| where isempty(RequestContext)
| where RequestURL matches regex @"(?:\/api2\/json\/access\/ticket|\/api2\/json\/cluster\/resources|\/api2\/json\/cluster\/tasks|\/en-us\/p\/onerf\/MeSilentPassport|\/en-us\/p\/book-2\/8MCPZJJCC98C|\/en-us\/store\/api\/checkproductinwishlist|\/gp\/cerberus\/gv|\/gp\/aj\/private\/reviewsGallery\/get-application-resources|\/gp\/aj\/private\/reviewsGallery\/get-image-gallery-assets|\/v1\/buckets\/default\/ext-5dkJ19tFufpMZjVJbsWCiqDcclDw\/records|\/v3\/links\/ping-centre|\/v4\/links\/activity-stream|\/wp-content\/themes\/am43-6\/dist\/records|\/wp-content\/themes\/am43-6\/dist\/records|\/wp-includes\/js\/script\/indigo-migrate)"
| extend Quality = "medium"
| extend RuleName = "Backdoor.HTTP.BEACON.[CSBundle Original GET]"
| project TimeGenerated, Quality, RuleName, DeviceVendor, DeviceProduct, TenantId, SourceIP, DestinationIP, DestinationHostName, RequestMethod, RequestURL;
let Results = union FEQuery1, FEQuery3, FEQuery4, FEQuery5, FEQuery6, FEQuery7, FEQuery8, FEQuery9;
//Check to see if the destination host name is low hitting in data, defeats a lot of legit API traffic
Results
| join (
    CommonSecurityLog
    | where TimeGenerated > ago(domainLookback)
    | where DestinationHostName != ""
  | summarize DomainCount=count() by DestinationHostName)
on $left.DestinationHostName == $right.DestinationHostName
| project TimeGenerated, Quality, DeviceVendor, DeviceProduct, TenantId, SourceIP, DestinationIP, DestinationHostName, RequestMethod, RequestURL, DomainCount
| where DomainCount <= domainCountThreshold```
## Failed Login Attempt by Expired account
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/MultipleDataSources/LogonwithExpiredAccount.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: This query looks at Account Logon events found through Windows Event Ids as well as SigninLogs to discover login attempts by accounts that have expired.

> Query:

```let timeframe = 1d;
(union isfuzzy=true
(SecurityEvent
| where TimeGenerated >= ago(timeframe) 
| where EventID == 4625
//4625: An account failed to log on
| where AccountType == User 
| where SubStatus == 0xc0000193 
| extend Reason = 
case
( SubStatus == 0xc0000193, Windows EventID (4625) - Account has expired, "Unknown")
| project Computer, Account,  Reason , TimeGenerated
),
(
SecurityEvent
| where TimeGenerated >= ago(timeframe) 
| where EventID == 4769
//4769: A Kerberos service ticket was requested ( Kerberos Auth)
| parse EventData with * Status"> Status "<" *
| parse EventData with * TargetUserName"> TargetUserName "<" *
| where Status == 0x12
| where TargetUserName !has "$" and isnotempty(TargetUserName)
| extend Reason = 
case(
Status == 0x12, Windows EventID (4769) - Account disabled, expired, locked out,
Unknown), Account = TargetUserName 
| project Computer, Account, Reason , TimeGenerated
),
(
SecurityEvent
| where TimeGenerated >= ago(timeframe) 
| where EventID == 4776 
// 4776: The domain controller attempted to validate the credentials for an account ( NTLM Auth)
| where Status == "0xc0000193"
| extend Reason = 
case(
ErrorCode == 0xc0000193, Windows EventID (4776) - Account has expired,
Unknown), Account = TargetAccount 
| parse EventData with * Workstation"> Workstation "<" *
| extend Workstation = trim_start(@"[\\]*", Workstation)
| extend Computer = iff(isnotempty(Workstation), Workstation, Computer ) 
| project Computer, Account, Reason , TimeGenerated
) ,
(
SigninLogs
| where TimeGenerated >= ago(timeframe) 
| where ResultType == "50057" 
| extend Reason = 
case(
ResultType == 50057, SigninLogs( Result Code- 50057) - User account is disabled. The account has been disabled by an administrator.,
Unknown), Account = UserPrincipalName 
| project Computer, Account, Reason , TimeGenerated
) )
| summarize StartTimeUtc = min(TimeGenerated), EndTImeUtc = max(TimeGenerated), EventCount = count() by Computer, Account, Reason
| extend timestamp = StartTimeUtc, AccountCustomEntity = Account, HostCustomEntity = Computer
| order by EventCount desc```
## Permutations on logon attempts by UserPrincipalNames indicating potential brute force
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/MultipleDataSources/PermutationsOnLogonNames.yaml)

### ATT&CK Tags

> Tactics: [u'CredentialAccess']

### Hunt details

> Description: Attackers sometimes try variations on account logon names, this will identify failed attempts on logging in using permutations based on known first and last name within 10m time windows, for UserPrincipalNames that separated by hyphen(-), underscore(_) and dot(.).If there is iteration through these separators or order changes in the logon name it may indicate potential Brute Force logon attempts.For example, attempts with first.last@example.com, last.first@example.com, first_last@example.com and so on.

> Query:

```let lookback = 1d;
let fl_Min = 3;
let un_MatchMin = 2;
let upnFunc = (startTimeSpan:timespan, tableName:string){
table(tableName) | where TimeGenerated >= ago(lookback)
| extend Operation = columnifexists("Operation", "Sign-in activity")
| where Operation == "UserLoginFailed" or Operation == "Sign-in activity"
| extend Result = columnifexists("ResultType", "tempValue")
| extend Result = iff(Result == "tempValue", columnifexists("ResultStatus", Result), Result)
| extend ResultValue = case(Result == "0", "Success", Result == "Success" or Result == "Succeeded", "Success", Result)
| where ResultValue != "Success"
| extend UserPrincipalName = columnifexists("UserPrincipalName", "tempValue") 
| extend UserPrincipalName = iff(tableName == "OfficeActivity", tolower(UserId), tolower(UserPrincipalName))
| extend UPN = split(UserPrincipalName, "@")
| extend UserNameOnly = tostring(UPN[0]), DomainOnly = tostring(UPN[1])
| where UserNameOnly contains "." or UserPrincipalName contains "-" or UserPrincipalName contains "_"
// Verify we only get accounts without other separators, it would be difficult to identify multi-level separators
// Count of any that are not alphanumeric
| extend charcount = countof(UserNameOnly, [^0-9A-Za-z], "regex")
// Drop any that have non-alphanumeric characters still included
| where charcount < 2
// Creating array of name pairs that include the separators we are interested in, this can be added to if needed.
| extend unoArray = case(
UserNameOnly contains ".", split(UserNameOnly, "."),
UserNameOnly contains "-", split(UserNameOnly, "-"),
UserNameOnly contains "_", split(UserNameOnly, "_"),
UserNameOnly)
| extend First = iff(isnotempty(tostring(parsejson(unoArray)[0])), tostring(parsejson(unoArray)[0]),tostring(unoArray))
| extend Last = tostring(parsejson(unoArray)[1])
| extend First4char = iff(countof(substring(First, 0,4), [0-9A-Za-z], "regex") >= 4, substring(First, 0,4), "LessThan4"),
First6char = iff(countof(substring(First, 0,6), [0-9A-Za-z], "regex") >= 6, substring(First, 0,6), "LessThan6"),
First8char = iff(countof(substring(First, 0,8), [0-9A-Za-z], "regex") >= 8, substring(First, 0,8), "LessThan8"),
Last4char = iff(countof(substring(Last, 0,4), [0-9A-Za-z], "regex") >= 4, substring(Last, 0,4), "LessThan4"),
Last6char = iff(countof(substring(Last, 0,6), [0-9A-Za-z], "regex") >= 6, substring(Last, 0,6), "LessThan6"),
Last8char = iff(countof(substring(Last, 0,8), [0-9A-Za-z], "regex") >= 8, substring(Last, 0,8), "LessThan8")
| where First != Last
| summarize UserNames = makeset(UserNameOnly),
fl_Count = count() by bin(TimeGenerated, 10m), First4char, First6char, First8char, Last4char, Last6char, Last8char, Type
};
let SigninList = upnFunc(lookback,"SigninLogs");
let OffActList = upnFunc(lookback,"OfficeActivity");
let UserNameList = (union isfuzzy=true SigninList, OffActList);
let Char4List = UserNameList
| project TimeGenerated, First4char, Last4char, UserNames, fl_Count, Type
| where First4char != "LessThan4" and Last4char != "LessThan4";
// Break out first and last so we can then join and see where a first and last match.
let First4charList = Char4List | where isnotempty(First4char)
| summarize un_MatchOnFirst = makeset(UserNames),
fl_CountForFirst = sum(fl_Count) by TimeGenerated, CharSet = First4char, Type
| project TimeGenerated, CharSet, un_MatchOnFirst, un_MatchOnFirstCount = array_length(un_MatchOnFirst), fl_CountForFirst, Type;
let Last4charList = Char4List | where isnotempty(Last4char) 
| summarize un_MatchOnLast = makeset(UserNames), fl_CountForLast = sum(fl_Count) by TimeGenerated, CharSet = Last4char, Type
| project TimeGenerated, CharSet, un_MatchOnLast, un_MatchOnLastCount = array_length(un_MatchOnLast), fl_CountForLast, Type;
let char4 = First4charList | join Last4charList on CharSet and TimeGenerated
| project-away TimeGenerated1, CharSet1
// Make sure that we get more than a single match for First or Last
| where un_MatchOnFirstCount >= un_MatchMin or un_MatchOnLastCount >= un_MatchMin
| where fl_CountForFirst >= fl_Min or fl_CountForLast >= fl_Min;
let Char6List = UserNameList
| project TimeGenerated, First6char, Last6char, UserNames, fl_Count, Type
| where First6char != "LessThan6" and Last6char != "LessThan6";
// Break out first and last so we can then join and see where a first and last match.
let First6charList = Char6List | where isnotempty(First6char)
| summarize un_MatchOnFirst = makeset(UserNames), fl_CountForFirst = sum(fl_Count) by TimeGenerated, CharSet = First6char, Type
| project TimeGenerated, CharSet, un_MatchOnFirst, un_MatchOnFirstCount = array_length(un_MatchOnFirst), fl_CountForFirst, Type;
let Last6charList = Char6List | where isnotempty(Last6char)
| summarize un_MatchOnLast = makeset(UserNames), fl_CountForLast = sum(fl_Count) by TimeGenerated, CharSet = Last6char, Type
| project TimeGenerated, CharSet, un_MatchOnLast, un_MatchOnLastCount = array_length(un_MatchOnLast), fl_CountForLast, Type;
let char6 = First6charList | join Last6charList on CharSet and TimeGenerated
| project-away TimeGenerated1, CharSet1
// Make sure that we get more than a single match for First or Last
| where un_MatchOnFirstCount >= un_MatchMin or un_MatchOnLastCount >= un_MatchMin
| where fl_CountForFirst >= fl_Min or fl_CountForLast >= fl_Min;
let Char8List = UserNameList
| project TimeGenerated, First8char, Last8char, UserNames, fl_Count, Type
| where First8char != "LessThan8" and Last8char != "LessThan8";
// Break out first and last so we can then join and see where a first and last match.
let First8charList = Char8List | where isnotempty(First8char)
| summarize un_MatchOnFirst = makeset(UserNames), fl_CountForFirst = sum(fl_Count) by TimeGenerated, CharSet = First8char, Type
| project TimeGenerated, CharSet, un_MatchOnFirst, un_MatchOnFirstCount = array_length(un_MatchOnFirst), fl_CountForFirst, Type; 
let Last8charList = Char8List | where isnotempty(Last8char)
| summarize un_MatchOnLast = makeset(UserNames), fl_CountForLast = sum(fl_Count) by TimeGenerated, CharSet = Last8char, Type
| project TimeGenerated, CharSet, un_MatchOnLast, un_MatchOnLastCount = array_length(un_MatchOnLast), fl_CountForLast, Type;
let char8 = First8charList | join Last8charList on CharSet and TimeGenerated
| project-away TimeGenerated1, CharSet1
// Make sure that we get more than a single match for First or Last
| where un_MatchOnFirstCount >= un_MatchMin or un_MatchOnLastCount >= un_MatchMin
| where fl_CountForFirst >= fl_Min or fl_CountForLast >= fl_Min;
(union isfuzzy=true char4, char6, char8)
| project Type, TimeGenerated, CharSet, UserNameMatchOnFirst = un_MatchOnFirst, UserNameMatchOnFirstCount = un_MatchOnFirstCount,
FailedLogonCountForFirst = fl_CountForFirst, UserNameMatchOnLast = un_MatchOnLast, UserNameMatchOnLastCount = un_MatchOnLastCount,
FailedLogonCountForLast = fl_CountForLast
| sort by UserNameMatchOnFirstCount desc, UserNameMatchOnLastCount desc
| extend timestamp = TimeGenerated```
## Potential Microsoft security services tampering
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/MultipleDataSources/PotentialMicrosoftSecurityServicesTampering.yaml)

### ATT&CK Tags

> Tactics: [u'DefenseEvasion']

### Hunt details

> Description: Identifies potential tampering related to Microsoft security related products and services.

> Query:

```let includeProc = dynamic(["sc.exe","net1.exe","net.exe", "taskkill.exe", "cmd.exe", "powershell.exe"]);
let action = dynamic(["stop","disable", "delete"]);
let service1 = dynamic([sense, windefend, mssecflt]);
let service2 = dynamic([sense, windefend, mssecflt, healthservice]);
let params1 = dynamic(["-DisableRealtimeMonitoring", "-DisableBehaviorMonitoring" ,"-DisableIOAVProtection"]);
let params2 = dynamic(["sgrmbroker.exe", "mssense.exe"]);
let regparams1 = dynamic([reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender", reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection"]);
let regparams2 = dynamic([ForceDefenderPassiveMode, DisableAntiSpyware]);
let regparams3 = dynamic([sense, windefend]);
let regparams4 = dynamic([demand, disabled]);
let regparams5 = dynamic([reg add "HKLM\\SYSTEM\\CurrentControlSet\\services\\HealthService", reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Sense", reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend", reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MsSecFlt", reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\DiagTrack", reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SgrmBroker", reg add "HKLMSYSTEM\\CurrentControlSet\\Services\\SgrmAgent", reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\AATPSensorUpdater" , reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\AATPSensor", reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\mpssvc"]);
let regparams6 = dynamic([/d 4,/d "4",/d 0x00000004]);
let regparams7 = dynamic([/d 1,/d "1",/d 0x00000001]);
let timeframe = 1d;
(union isfuzzy=true
(
SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID == 4688
| extend ProcessName = tostring(split(NewProcessName, \\)[-1])
| where ProcessName in~ (includeProc)
| where (CommandLine has_any (action) and CommandLine has_any (service1)) 
or (CommandLine has_any (params1) and CommandLine has Set-MpPreference and CommandLine has $true)
or (CommandLine has_any (params2) and CommandLine has "/IM") 
or (CommandLine has_any (regparams5) and CommandLine has Start and CommandLine has_any (regparams6))
or (CommandLine has_any (regparams1) and CommandLine has_any (regparams2) and CommandLine has_any (regparams7)) 
or (CommandLine has "start" and CommandLine has "config" and CommandLine has_any (regparams3) and CommandLine has_any (regparams4))
| project TimeGenerated, Computer, Account, AccountDomain, ProcessName, ProcessNameFullPath = NewProcessName, EventID, Activity, CommandLine, EventSourceName, Type
),
(
Event
| where TimeGenerated >= ago(timeframe)
| where Source =~ "Microsoft-Windows-SENSE"
| where EventID == 87 and ParameterXml in ("<Param>sgrmbroker</Param>", "<Param>WinDefend</Param>")
| project TimeGenerated, Computer, Account = UserName, EventID, Activity = RenderedDescription, EventSourceName = Source, Type
),
(
DeviceProcessEvents
| where TimeGenerated >= ago(timeframe)
| where InitiatingProcessFileName in~ (includeProc)
| where (InitiatingProcessCommandLine has_any(action) and InitiatingProcessCommandLine has_any (service2) and InitiatingProcessParentFileName != cscript.exe)
or (InitiatingProcessCommandLine has_any (params1) and InitiatingProcessCommandLine has Set-MpPreference and InitiatingProcessCommandLine has $true) 
or (InitiatingProcessCommandLine has_any (params2) and InitiatingProcessCommandLine has "/IM") 
or ( InitiatingProcessCommandLine has_any (regparams5) and  InitiatingProcessCommandLine has Start and  InitiatingProcessCommandLine has_any (regparams6))
or (InitiatingProcessCommandLine has_any (regparams1) and InitiatingProcessCommandLine has_any (regparams2) and InitiatingProcessCommandLine has_any (regparams7)) 
or (InitiatingProcessCommandLine has_any("start") and InitiatingProcessCommandLine has "config" and InitiatingProcessCommandLine has_any (regparams3) and InitiatingProcessCommandLine has_any (regparams4))
| extend Account = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName), Computer = DeviceName
| project TimeGenerated, Computer, Account, AccountDomain, ProcessName = InitiatingProcessFileName, ProcessNameFullPath = FolderPath, Activity = ActionType, CommandLine = InitiatingProcessCommandLine, Type, InitiatingProcessParentFileName
)
)
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer```
## RareDNSLookupWithDataTransfer
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/MultipleDataSources/RareDNSLookupWithDataTransfer.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl', u'Exfiltration']

### Hunt details

> Description: This query is designed to help identify rare DNS connections and resulting data transfer to/from the associated domain.This can help identify unexpected large data transfers to or from internal systems which may indicate data exfil or malicious tool download.Feel free to add additional data sources to connect DNS results too various network data that has byte transfer information included.

> Query:

```let lookbackint = 7;
let lookupThreshold = lookbackint*3;
let lookbackstring = strcat(tostring(lookbackint),".00:00:00");
let lookbacktime = totimespan(lookbackstring)+1d;
//startofday is setting to 00:00:00 for the given days ago
let starttime = startofday(ago(lookbacktime)); 
let endtime = startofday(now(-1d)); 
let binvalue = 1;
let bintime = make_timespan(binvalue,0);
let avgCalc = starttime/1h;
let PrivateIPregex = @^127\.|^10\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.|^192\.168\.; 
// Identify all domain lookups after starttime variable and prior to endtime variable
let DomainLookups = DnsEvents 
| where TimeGenerated >= starttime and TimeGenerated <= endtime 
| where SubType == "LookupQuery"
| where isnotempty(IPAddresses)
| extend Domain = iff(countof(Name,.) >= 2, strcat(split(Name,.)[-2], .,split(Name,.)[-1]), Name)
| summarize DomainCount = count() by Domain
| project Domain, DailyAvgLookupCountOverLookback = DomainCount/lookbackint;
// Common lookups should not include items that occurred more rarely over the lookback period.
let CommonLookups = DomainLookups
| where DailyAvgLookupCountOverLookback > lookupThreshold;
// Get todays lookups to compare against the lookback period
let TodayLookups = DnsEvents 
| where TimeGenerated >= endtime
| where SubType == "LookupQuery"
| where isnotempty(IPAddresses)
| extend Domain = iff(countof(Name,.) >= 2, strcat(split(Name,.)[-2], .,split(Name,.)[-1]), Name)
| summarize LookupStartTime = min(TimeGenerated), LookupEndTime = max(TimeGenerated), LookupCountToday = count() by ClientIP, Domain, IPAddresses 
| project LookupStartTime, LookupEndTime, ClientIP, LookupCountToday, Domain, IPAddresses;
// Remove Common Lookups from lookback period from Todays lookups
let UncommonLookupsToday = TodayLookups
| join kind=leftanti ( 
CommonLookups
)
on Domain;
// Join back the Daily Average Lookup Count to add context to rarity over lookback period
let RareLookups = UncommonLookupsToday | join kind= innerunique (
DomainLookups 
) on Domain 
| project LookupStartTime, LookupEndTime, ClientIP, Domain, IPAddresses, LookupCountToday, DailyAvgLookupCountOverLookback;
let DNSIPBreakout = RareLookups
| extend DnsIPAddress = iff(IPAddresses has ",", split(IPAddresses, ","), todynamic(IPAddresses)) 
| mvexpand DnsIPAddress
| extend DnsIPAddress = tostring(DnsIPAddress)
| distinct LookupStartTime, LookupEndTime, ClientIP, Domain, DnsIPAddress, LookupCountToday, DailyAvgLookupCountOverLookback
| extend IPCustomEntity = DnsIPAddress
| extend DnsIPType = iff(DnsIPAddress matches regex PrivateIPregex,"private" ,"public" )
| where DnsIPType =="public"
;
let DataMovement = ( union isfuzzy=true 
(CommonSecurityLog
| where TimeGenerated >= endtime
| where DeviceVendor =="Palo Alto Networks" and Activity == "TRAFFIC"
| extend DestinationIPType = iff(DestinationIP matches regex PrivateIPregex,"private" ,"public" )
| where DestinationIPType =="public"
| project DataType = DeviceVendor, TimeGenerated, SourceIP , SourcePort , DestinationIP, DestinationPort, ReceivedBytes, SentBytes
| sort by SourceIP asc, SourcePort asc,TimeGenerated asc, DestinationIP asc, DestinationPort asc
| summarize sum(ReceivedBytes), sum(SentBytes), ConnectionCount = count() by DataType, SourceIP, SourcePort, DestinationIP, DestinationPort
| extend IPCustomEntity = DestinationIP
| sort by sum_SentBytes desc
),
(WireData
| where TimeGenerated >= endtime
| where Direction == "Outbound"
| extend RemoteIPType = iff(RemoteIP matches regex PrivateIPregex,"private" ,"public" ) 
| where RemoteIPType =="public" 
| project DataType = Type, TimeGenerated , SourceIP = LocalIP , SourcePort = LocalPortNumber , DestinationIP = RemoteIP, DestinationPort = RemotePortNumber, ReceivedBytes, SentBytes 
| summarize sum(ReceivedBytes), sum(SentBytes), ConnectionCount = count() by DataType, SourceIP, SourcePort, DestinationIP, DestinationPort
| extend IPCustomEntity = DestinationIP
| extend DataType = Type
| sort by sum_SentBytes desc
),
(VMConnection 
| where TimeGenerated >= endtime
| where Direction == "outbound"
| extend DestinationIPType = iff(DestinationIp matches regex PrivateIPregex,"private" ,"public" )
| where DestinationIPType =="public"
| project DataType = Type, TimeGenerated, SourceIP = SourceIp , DestinationIP = DestinationIp, DestinationPort, ReceivedBytes = BytesReceived, SentBytes = BytesSent 
| summarize sum(ReceivedBytes), sum(SentBytes), ConnectionCount = count() by DataType, SourceIP, DestinationIP, DestinationPort
| sort by sum_SentBytes desc
| extend IPCustomEntity = DestinationIP
)
);
DNSIPBreakout | join kind = leftouter (
DataMovement
) on $left.DnsIPAddress == $right.DestinationIP and $left.ClientIP == $right.SourceIP
| project-away DnsIPAddress, ClientIP
// The below condition can be removed to see all DNS results.
// This is used here as the goal of the query is to connect rare DNS lookups to a data type that can show byte transfers to that given DestinationIP
| where isnotempty(DataType)
| extend timestamp = LookupStartTime, IPCustomEntity = DestinationIP```
## Rare domains seen in Cloud Logs
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/MultipleDataSources/RareDomainsInCloudLogs.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess', u'Discovery', u'Collection']

### Hunt details

> Description: This will identify rare domain accounts accessing or attempting to access cloud resources by examining the AuditLogs, OfficeActivity and SigninLogsRare does not mean malicious, but it may be something you would be interested in investigating furtherAdditionally, it is possible that there may be many domains if you have allowed access by 3rd party domain accounts.Lower the domainLimit value as needed.  For example, if you only want to see domains that have an access attempt count of 2 or less,then set domainLimit = 2 below.  If you need to set it lower only for a given log, then use customLimit in the same way and uncomment that line in the script.

> Query:

```// Provide customLimit value with default above domainLimit value so it will not block unless changed
let customLimit = 11;
let domainLimit = 10;
let lookback = 14d;
let domainLookback = union isfuzzy=true
(AuditLogs
| where TimeGenerated >= ago(lookback)
| extend UserPrincipalName = tolower(tostring(TargetResources.[0].userPrincipalName))
// parse out AuditLog values for various locations where UPN could be
| extend UserPrincipalName = iff(isnotempty(UserPrincipalName),
UserPrincipalName, 
iif((tostring(InitiatedBy.user.userPrincipalName)==unknown), 
extract("Email: ([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+)", 1, tostring(parse_json(TargetResources)[0].displayName)), 
InitiatedBy.user.userPrincipalName))
| where UserPrincipalName has "@" or UserPrincipalName startswith "NT AUTHORITY"
| extend RareDomain = toupper(tostring(split(UserPrincipalName, "@")[-1]))
| where isnotempty(RareDomain) 
| summarize RareDomainCount = count() by Type, RareDomain
| where RareDomainCount <= domainLimit
| extend AccountCustomEntity = UserPrincipalName
// remove comment from below if you would like to have a lower limit for RareDomainCount specific to AuditLog
//| where RareDomainCount <= customLimit
),
(OfficeActivity
| where TimeGenerated >= ago(lookback)
| extend UserPrincipalName = tolower(UserId)
| where UserPrincipalName has "@" or UserPrincipalName startswith "NT AUTHORITY"
| extend RareDomain = toupper(tostring(split(UserPrincipalName, "@")[-1]))
| summarize RareDomainCount = count() by Type, RareDomain
| where RareDomainCount <= domainLimit
| extend AccountCustomEntity = UserPrincipalName
// remove comment from below if you would like to have a lower limit for RareDomainCount specific to OfficeActivity
//| where RareDomainCount <= customLimit
),
(SigninLogs
| where TimeGenerated >= ago(lookback)
| where UserPrincipalName has "@" or UserPrincipalName startswith "NT AUTHORITY"
| extend RareDomain = toupper(tostring(split(UserPrincipalName, "@")[-1]))
| summarize RareDomainCount = count() by Type, RareDomain
| where RareDomainCount <= domainLimit
// remove comment from below if you would like to have a lower limit for RareDomainCount specific to SigninLogs
//| where RareDomainCount <= customLimit
);
let AuditLogsRef = domainLookback | join (
   AuditLogs
   | where TimeGenerated >= ago(lookback)
   | extend UserPrincipalName = tolower(tostring(TargetResources.[0].userPrincipalName))
   | extend UserPrincipalName = iff(isempty(UserPrincipalName), tostring(InitiatedBy.user.userPrincipalName), UserPrincipalName)
   | extend RareDomain = toupper(tostring(split(UserPrincipalName, "@")[-1]))
   | where isnotempty(RareDomain) 
   | summarize UPNRefCount = count() by TimeGenerated, Type, RareDomain, UserPrincipalName, OperationName, Category, Result
   | extend AccountCustomEntity = UserPrincipalName
) on Type, RareDomain;
let OfficeActivityRef = domainLookback | join (
    OfficeActivity
    | where TimeGenerated >= ago(lookback)
    | extend UserPrincipalName = tolower(UserId)
    | where UserPrincipalName has "@" or UserPrincipalName startswith "NT AUTHORITY"
    | extend RareDomain = toupper(tostring(split(UserPrincipalName, "@")[-1]))
    | summarize UPNRefCount = count() by TimeGenerated, Type, RareDomain, UserPrincipalName, OperationName = Operation, Category = OfficeWorkload, Result = ResultStatus
    | extend AccountCustomEntity = UserPrincipalName
) on Type, RareDomain;
let SigninLogsRef = domainLookback | join (
    SigninLogs
    | where TimeGenerated >= ago(lookback)
    | extend UserPrincipalName = tolower(UserId)
    | where UserPrincipalName has "@" or UserPrincipalName startswith "NT AUTHORITY"
    | extend RareDomain = toupper(tostring(split(UserPrincipalName, "@")[-1]))
    | summarize UPNRefCount = count() by TimeGenerated, Type, RareDomain, UserPrincipalName, OperationName, Category = AppDisplayName, Result = ResultType
    | extend AccountCustomEntity = UserPrincipalName
) on Type, RareDomain;
let Results = union isfuzzy=true
AuditLogsRef,OfficeActivityRef,SigninLogsRef;
Results | project TimeGenerated, Type, RareDomain, UserPrincipalName, OperationName, Category, Result, UPNRefCount 
| order by TimeGenerated asc 
| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName```
## SolarWinds Inventory
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/MultipleDataSources/SolarWindsInventory.yaml)

### ATT&CK Tags

> Tactics: [u'Execution']

### Hunt details

> Description: Beyond your internal software management systems, it is possible you may not have visibility into your entire footprint of SolarWinds installations.  This is intended to help use process exection information to discovery any systems that have SolarWinds processes

> Query:

```let timeframe = 30d; 
(union isfuzzy=true 
( 
SecurityEvent 
| where TimeGenerated >= ago(timeframe) 
| where EventID == 4688 
| where tolower(NewProcessName) has solarwinds 
| extend MachineName = Computer , Process = NewProcessName
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), MachineCount = dcount(MachineName), AccountCount = dcount(Account), MachineNames = make_set(MachineName), Accounts = make_set(Account) by Process, Type
), 
( 
DeviceProcessEvents 
| where TimeGenerated >= ago(timeframe) 
| where tolower(InitiatingProcessFolderPath) has solarwinds 
| extend MachineName = DeviceName , Process = InitiatingProcessFolderPath, Account = AccountName
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), MachineCount = dcount(MachineName), AccountCount = dcount(Account), MachineNames = make_set(MachineName), Accounts = make_set(Account)  by Process, Type
), 
( 
Event 
| where TimeGenerated >= ago(timeframe) 
| where Source == "Microsoft-Windows-Sysmon" 
| where EventID == 1 
| extend Image = EventDetail.[4].["#text"] 
| where tolower(Image) has solarwinds 
| extend MachineName = Computer , Process = Image, Account = UserName
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), MachineCount = dcount(MachineName), AccountCount = dcount(Account), MachineNames = make_set(MachineName), Accounts = make_set(Account)  by Process, Type
) 
)```
## Retrospective hunt for STRONTIUM IP IOCs
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/MultipleDataSources/STRONTIUM_IOC_RetroHunt.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl']

### Hunt details

> Description: Matches domain name IOCs related to Strontium group activity with CommonSecurityLog and SecurityAlert dataTypes.The query is scoped in the time window that these IOCs were active.References: https://blogs.microsoft.com/on-the-issues/2019/07/17/new-cyberthreats-require-new-ways-to-protect-democracy.

> Query:

```let STRONTIUM_IPS = dynamic(["82.118.242.171" , "167.114.153.55" , "94.237.37.28", "31.220.61.251" , "128.199.199.187" ]);
(union isfuzzy=true
(CommonSecurityLog
| where TimeGenerated between (startofday(datetime(2019-02-01)) .. endofday(datetime(2019-08-05)))
| where SourceIP in (STRONTIUM_IPS) or DestinationIP in (STRONTIUM_IPS)
| extend IPCustomEntity = SourceIP
),
(SecurityAlert
| where TimeGenerated between (startofday(datetime(2019-02-01)) .. endofday(datetime(2019-08-05)))
| extend RemoteAddress = iff(ExtendedProperties has "RemoteAddress", tostring(parse_json(ExtendedProperties)["RemoteAddress"]), "None")
| where RemoteAddress != "None"
| where RemoteAddress in (STRONTIUM_IPS)
| extend IPCustomEntity = RemoteAddress
) 
)
| extend timestamp = TimeGenerated```
## Tracking Password Changes
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/MultipleDataSources/TrackingPasswordChanges.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess', u'CredentialAccess']

### Hunt details

> Description: Identifies when a password change or reset occurs across multiple host and cloud based sources. Account manipulation including password changes and resets may aid adversaries in maintaining access to credentials and certain permission levels within an environment.

> Query:

```let timeframe = 7d;
let action = dynamic(["change ", "changed ", "reset "]);
let pWord = dynamic(["password ", "credentials "]);
(union isfuzzy=true
  (SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID in (4723,4724)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ResultDescriptions = makeset(Activity), ActionCount = count() by Resource = Computer, OperationName = strcat("TargetAccount: ", TargetUserName), UserId = Account, Type
),
(AuditLogs
| where TimeGenerated >= ago(timeframe)
| where OperationName has_any (pWord) and OperationName has_any (action)
| extend InitiatedBy = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName) 
| extend TargetUserPrincipalName = tostring(TargetResources[0].userPrincipalName) 
| where ResultDescription != "None" 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ResultDescriptions = makeset(ResultDescription), CorrelationIds = makeset(CorrelationId), ActionCount = count() by OperationName = strcat(Category, " - ", OperationName, " - ", Result), Resource, UserId = TargetUserPrincipalName, Type
| extend ResultDescriptions = tostring(ResultDescriptions)
),
(OfficeActivity
| where TimeGenerated >= ago(timeframe)
| where (ExtendedProperties has_any (pWord) or ModifiedProperties has_any (pWord)) and (ExtendedProperties has_any (action) or ModifiedProperties has_any (action))
| extend ResultDescriptions = case(
OfficeWorkload =~ "AzureActiveDirectory", tostring(ExtendedProperties),
OfficeWorkload has_any ("Exchange","OneDrive"), OfficeObjectId,
RecordType) 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ResultDescriptions = makeset(ResultDescriptions), ActionCount = count() by Resource = OfficeWorkload, OperationName = strcat(Operation, " - ", ResultStatus), IPAddress = ClientIP, UserId, Type
),
(Syslog
| where TimeGenerated >= ago(timeframe)
| where SyslogMessage has_any (pWord) and SyslogMessage has_any (action)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ResultDescriptions = makeset(SyslogMessage), ActionCount = count() by Resource = HostName, OperationName = Facility , IPAddress = HostIP, ProcessName, Type
),
(SigninLogs
| where TimeGenerated >= ago(timeframe)
| where OperationName =~ "Sign-in activity" and ResultType has_any ("50125", "50133")
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ResultDescriptions = makeset(ResultDescription), CorrelationIds = makeset(CorrelationId), ActionCount = count() by Resource, OperationName = strcat(OperationName, " - ", ResultType), IPAddress, UserId = UserPrincipalName, Type
)
)
| extend timestamp = StartTimeUtc, AccountCustomEntity = UserId, IPCustomEntity = IPAddress```
## Tracking Privileged Account Rare Activity
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/MultipleDataSources/TrackingPrivAccounts.yaml)

### ATT&CK Tags

> Tactics: [u'PrivilegeEscalation', u'Discovery']

### Hunt details

> Description: This query will determine rare activity by a high-value account carried out on a system or service.High Value accounts are determined by Group Membership to High Value groups via events listed below.Rare here means an activity type seen in the last day which has not been seen in the previous 7 days.If any account with such rare activity is found, the query will attempt to retrieve related activityfrom that account on that same day and summarize the information.4728 - A member was added to a security-enabled global group4732 - A member was added to a security-enabled local group4756 - A member was added to a security-enabled universal group

> Query:

```let LocalSID = "S-1-5-32-5[0-9][0-9]$";
let GroupSID = "S-1-5-21-[0-9]*-[0-9]*-[0-9]*-5[0-9][0-9]$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-1102$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-1103$";
let timeframe = 8d;
let p_Accounts = SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID in ("4728", "4732", "4756") and AccountType == "User" and MemberName == "-"
// Exclude Remote Desktop Users group: S-1-5-32-555 and IIS Users group S-1-5-32-568
| where TargetSid !in ("S-1-5-32-555", "S-1-5-32-568")
| where TargetSid matches regex LocalSID or TargetSid matches regex GroupSID
| summarize by DomainSlashAccount = tolower(SubjectAccount), NtDomain = SubjectDomainName,
AccountAtDomain = tolower(strcat(SubjectUserName,"@",SubjectDomainName)), AccountName = tolower(SubjectUserName);
// Build custom high value account list
let cust_Accounts = datatable(Account:string, NtDomain:string, Domain:string)[
"john", "Contoso", "contoso.com",  "greg", "Contoso", "contoso.com",  "larry", "Domain", "contoso.com"];
let c_Accounts = cust_Accounts
| extend AccountAtDomain = tolower(strcat(Account,"@",Domain)), AccountName = tolower(Account),
DomainSlashAccount = tolower(strcat(NtDomain,"\\",Account));
let AccountFormat = p_Accounts | union c_Accounts | project AccountName, AccountAtDomain, DomainSlashAccount;
// Normalize activity from diverse sources into common schema using a function
let activity = view (a_StartTime:datetime, a_EndTime:datetime) {
(union isfuzzy=true
(AccountFormat | join kind=inner 
(AWSCloudTrail
| where TimeGenerated >= a_StartTime and TimeGenerated <= a_EndTime
| extend ClientIP = "-", AccountName = tolower(UserIdentityUserName), WinSecEventDomain = "-"
| project-rename EventType = EventName, ServiceOrSystem = EventSource)
on AccountName),
(AccountFormat | join kind=inner
(SigninLogs
| where TimeGenerated >= a_StartTime and TimeGenerated <= a_EndTime
| extend AccountName = tolower(split(UserPrincipalName, "@")[0]), WinSecEventDomain = "-"
| project-rename EventType = strcat(OperationName, "-", ResultType, "-", ResultDescription), ServiceOrSystem = AppDisplayName, ClientIP = IPAddress)
on AccountName),
(AccountFormat | join kind=inner
(OfficeActivity
| where TimeGenerated >= a_StartTime and TimeGenerated <= a_EndTime
| extend AccountName = tolower(split(UserId, "@")[0]), WinSecEventDomain = "-"
| project-rename EventType = strcat(Operation, "-", ResultStatus), ServiceOrSystem = OfficeWorkload)
on AccountName),
(AccountFormat | join kind=inner
(SecurityEvent
| where TimeGenerated >= a_StartTime and TimeGenerated <= a_EndTime
| where EventID in (4624, 4625) 
| extend ClientIP = "-"
| extend AccountName = tolower(split(Account,"\\")[1]), Domain = tolower(split(Account,"\\")[0])
| project-rename EventType = Activity, ServiceOrSystem = Computer, WinSecEventDomain = Domain)
on AccountName),
(AccountFormat | join kind=inner
(W3CIISLog
| where TimeGenerated >= a_StartTime and TimeGenerated <= a_EndTime
| where csUserName != "-" and isnotempty(csUserName)
| extend AccountName = tolower(csUserName), WinSecEventDomain = "-"
| project-rename EventType = csMethod, ServiceOrSystem = sSiteName, ClientIP = cIP)
on AccountName),
(AccountFormat | join kind=inner
(W3CIISLog
| where TimeGenerated >= a_StartTime and TimeGenerated <= a_EndTime
| where csUserName != "-" and isnotempty(csUserName)
| extend AccountAtDomain = tolower(csUserName), WinSecEventDomain = "-"
| project-rename EventType = csMethod, ServiceOrSystem = sSiteName, ClientIP = cIP)
on AccountAtDomain));
};
// Rare activity today versus prior week
let LastDay = startofday(ago(1d));
let PrevDay = endofday(ago(2d));
let Prev7Day = startofday(ago(8d));
let ra_LastDay = activity(LastDay, now())
| summarize ra_StartTime = min(TimeGenerated), ra_EndTime = max(TimeGenerated),
ra_Count = count() by Type, AccountName, EventType, ClientIP, ServiceOrSystem, WinSecEventDomain;
let a_7day = activity(Prev7Day, PrevDay)
| summarize ha_Count = count() by Type, AccountName, EventType, ClientIP, ServiceOrSystem, WinSecEventDomain;
let ra_Today = ra_LastDay | join kind=leftanti (a_7day) on Type, AccountName, ServiceOrSystem
| extend RareServiceOrSystem = ServiceOrSystem;
// Retrieve related activity as context
let a_Related =
(union isfuzzy=true
(// Make sure we at least publish the unusual activity we identified above - even if no related context activity is found in the subsequent union
ra_Today),
// Remaining elements of the union look for related activity
(ra_Today | join kind=inner
(OfficeActivity
| where TimeGenerated > LastDay
| summarize rel_StartTime = min(TimeGenerated), rel_EndTime = max(TimeGenerated), rel_ServiceOrSystemCount = dcount(OfficeWorkload),
rel_ServiceOrSystemSet = makeset(OfficeWorkload), rel_ClientIPSet = makeset(ClientIP),
rel_Count = count() by AccountName = tolower(UserId), rel_EventType = Operation, Type
) on AccountName),
(ra_Today | join kind=inner
(SecurityEvent | where TimeGenerated > LastDay
| where EventID in (4624, 4625)
| where AccountType == "User"
| summarize rel_StartTime = min(TimeGenerated), rel_EndTime = max(TimeGenerated), rel_ServiceOrSystemCount = dcount(Computer),
rel_ServiceOrSystemSet = makeset(Computer), rel_ClientIPSet = makeset("-"),
rel_Count = count() by DomainSlashAccount = tolower(Account), rel_EventType = Activity, Type
) on DomainSlashAccount),
(ra_Today | join kind=inner
(Event | where TimeGenerated > LastDay
// 7045: A service was installed in the system
| where EventID == 7045
| summarize rel_StartTime = min(TimeGenerated), rel_EndTime = max(TimeGenerated), rel_ServiceOrSystemCount = dcount(Computer),
rel_ServiceOrSystemSet = makeset(Computer), rel_ClientIPSet = makeset("-"),
rel_Count = count() by DomainSlashAccount = tolower(UserName), rel_EventType = strcat(EventID, "-", tostring(split(RenderedDescription,".")[0])), Type
) on DomainSlashAccount),
(ra_Today | join kind=inner
(SecurityEvent | where TimeGenerated > LastDay
// 4720: Account created, 4726: Account deleted
| where EventID in (4720,4726)
| summarize rel_StartTime = min(TimeGenerated), rel_EndTime = max(TimeGenerated), rel_ServiceOrSystemCount = dcount(UserPrincipalName),
rel_ServiceOrSystemSet = makeset(UserPrincipalName), rel_ClientIPSet = makeset("-"),
rel_Count = count() by DomainSlashAccount = tolower(Account), rel_EventType = Activity, Type
) on DomainSlashAccount),
(ra_Today | join kind=inner
(SigninLogs | where TimeGenerated > LastDay
| extend RemoteHost = tolower(tostring(parsejson(DeviceDetail.["displayName"])))
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser, StatusCode = tostring(Status.errorCode),
StatusDetails = tostring(Status.additionalDetails), State = tostring(LocationDetails.state)
| summarize rel_StartTime = min(TimeGenerated), rel_EndTime = max(TimeGenerated), a_RelatedRemoteHostSet = makeset(RemoteHost),
rel_ServiceOrSystemSet = makeset(AppDisplayName), rel_ServiceOrSystemCount = dcount(AppDisplayName), rel_ClientIPSet = makeset(IPAddress),
rel_StateSet = makeset(State),
rel_Count = count() by AccountAtDomain = tolower(UserPrincipalName), rel_EventType = iff(isnotempty(ResultDescription), ResultDescription, StatusDetails), Type
) on AccountAtDomain),
(ra_Today | join kind=inner
(AWSCloudTrail | where TimeGenerated > LastDay
| summarize rel_StartTime = min(TimeGenerated),rel_EndTime = max(TimeGenerated), rel_ServiceOrSystemSet = makeset(EventSource),
rel_ServiceOrSystemCount = dcount(EventSource), rel_ClientIPSet = makeset("-"),
rel_Count= count() by AccountName = tolower(UserIdentityUserName), rel_EventType = EventName, Type
) on AccountName),
(ra_Today | join kind=inner
(SecurityAlert | where TimeGenerated > LastDay
| extend ExtProps=parsejson(ExtendedProperties)
| extend AccountName = tostring(ExtProps.["user name"])
| summarize rel_StartTime = min(TimeGenerated), rel_EndTime = max(TimeGenerated), rel_ServiceOrSystemCount = dcount(AlertType),
rel_ServiceOrSystemSet = makeset(AlertType), 
rel_Count = count() by DomainSlashAccount = tolower(AccountName), rel_EventType = ProductName, Type
) on DomainSlashAccount)
);
a_Related
| project Type, RareActivtyStartTimeUtc = ra_StartTime, RareActivityEndTimeUtc = ra_EndTime, RareActivityCount = ra_Count,
AccountName, WinSecEventDomain, EventType, RareServiceOrSystem, RelatedActivityStartTimeUtc = rel_StartTime,
RelatedActivityEndTimeUtc = rel_EndTime, RelatedActivityEventType = rel_EventType, RelatedActivityClientIPSet = rel_ClientIPSet,
RelatedActivityServiceOrSystemCount = rel_ServiceOrSystemCount, RelatedActivityServiceOrSystemSet = rel_ServiceOrSystemSet, RelatedActivityCount = rel_Count
| extend timestamp = RareActivtyStartTimeUtc, AccountCustomEntity = AccountName```
## Exploit and Pentest Framework User Agent
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/MultipleDataSources/UseragentExploitPentest.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess', u'CommandAndControl', u'Execution']

### Hunt details

> Description: There are several exploit and pen test frameworks that are being used by pen testers as well as attackers to compromise an environment and achieve their objective. The query tries to detect suspicious user agent strings used by these frameworks in some of the data sources that contain UserAgent field. This is based out of sigma rules described in references.References: https://github.com/Neo23x0/sigma/blob/master/rules/proxy/proxy_ua_frameworks.yml

> Query:

```let timeframe = 14d;
let UserAgentList = "Internet Explorer |Mozilla/4\\.0 \\(compatible; MSIE 6\\.0; Windows NT 5\\.1; SV1; InfoPath\\.2\\)|Mozilla/5\\.0 \\(Windows NT 10\\.0; Win32; x32; rv:60\\.0\\)|Mozilla/4\\.0 \\(compatible; Metasploit RSPEC\\)|Mozilla/4\\.0 \\(compatible; MSIE 6\\.1; Windows NT\\)|Mozilla/4\\.0 \\(compatible; MSIE 6\\.0; Windows NT 5\\.1\\)|Mozilla/4\\.0 \\(compatible; MSIE 8\\.0; Windows NT 6\\.0; Trident/4\\.0\\)|Mozilla/4\\.0 \\(compatible; MSIE 7\\.0; Windows NT 6\\.0; Trident/4\\.0; SIMBAR={7DB0F6DE-8DE7-4841-9084-28FA914B0F2E}; SLCC1; \\.N|Mozilla/5\\.0 \\(Windows; U; Windows NT 5\\.1; en-US\\) AppleWebKit/525\\.13 \\(KHTML, like Gecko\\) Chrome/4\\.0\\.221\\.6 Safari/525\\.13|Mozilla/5\\.0 \\(compatible; MSIE 9\\.0; Windows NT 6\\.1; WOW64; Trident/5\\.0; MAAU\\)|Mozilla/5\\.0[^\\s]|Mozilla/4\\.0 \\(compatible; SPIPE/1\\.0|Mozilla/5\\.0 \\(Windows NT 6\\.3; rv:39\\.0\\) Gecko/20100101 Firefox/35\\.0|Sametime Community Agent|X-FORWARDED-FOR|DotDotPwn v2\\.1|SIPDROID|wordpress hash grabber|exploit|okhttp/";
// Excluding for IIS, as the main malicious usage for okhttp that we have seen was in the OfficeActivity logs and this can create noise for IIS.
let ExcludeIIS = "okhttp/";
(union isfuzzy=true
(OfficeActivity
| where TimeGenerated >= ago(timeframe) 
| where ExtendedProperties has "UserAgent"
| extend UserAgent = extractjson("$[0].Value", ExtendedProperties, typeof(string))
| where UserAgent matches regex UserAgentList
| project TimeGenerated, Type, UserAgent, SourceIP
| extend IPCustomEntity = SourceIP
),
(
W3CIISLog
| where TimeGenerated >= ago(timeframe)
| extend UserAgent = replace(\\+,  , csUserAgent) 
| where UserAgent matches regex UserAgentList
| where UserAgent !startswith ExcludeIIS
| extend SourceIP = cIP
| project TimeGenerated, Type, UserAgent, SourceIP
| extend IPCustomEntity = SourceIP
),
(
AWSCloudTrail
| where TimeGenerated >= ago(timeframe) 
| where UserAgent matches regex UserAgentList
| extend SourceIP = SourceIpAddress
| project TimeGenerated, Type, UserAgent, SourceIP
))
| summarize min(TimeGenerated), max(TimeGenerated), count() by Type, UserAgent, SourceIP
| extend timestamp = min_TimeGenerated, IPCustomEntity = SourceIP```
## User Granted Access and created resources
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/MultipleDataSources/UserGrantedAccess_CreatesResources.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'PrivilegeEscalation', u'Impact']

### Hunt details

> Description: Identifies when a new user is granted access and starts creating resources in Azure.  This can help you identify rogue or malicious user behavior.

> Query:

```let auditLookback = 14d;
let opName = dynamic(["Add user", "Invite external user"]);
// Helper function to extract relevant fields from AuditLog events
let auditLogEvents = view (startTimeSpan:timespan, operation:dynamic)  {
    AuditLogs | where TimeGenerated >= ago(auditLookback)
    | where OperationName in~ (operation)
    | extend ModProps = iff(TargetResources.[0].modifiedProperties != "[]", TargetResources.[0].modifiedProperties, todynamic("NoValues"))
    | extend IpAddress = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)), 
    tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), tostring(parse_json(tostring(InitiatedBy.app)).ipAddress))
    | extend InitiatedByFull = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
    tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
    | extend InitiatedBy = replace("_","@",tostring(split(InitiatedByFull, "#")[0]))
    | extend TargetUserPrincipalName = tostring(TargetResources[0].userPrincipalName)
    | extend TargetUserName = replace("_","@",tostring(split(TargetUserPrincipalName, "#")[0]))
    | extend TargetResourceName = case(
    isempty(tostring(TargetResources.[0].displayName)), TargetUserPrincipalName,
    isnotempty(tostring(TargetResources.[0].displayName)) and tostring(TargetResources.[0].displayName) startswith "upn:", tolower(tostring(TargetResources.[0].displayName)),
    tolower(tostring(TargetResources.[0].displayName))
    )
    | extend TargetUserName = replace("_","@",tostring(split(TargetUserPrincipalName, "#")[0]))
    | extend TargetUserName = iff(isempty(TargetUserName), tostring(split(split(TargetResourceName, ",")[0], " ")[1]), TargetUserName ) 
    | mvexpand ModProps
    | extend PropertyName = tostring(ModProps.displayName), newValue = replace("\"","",tostring(ModProps.newValue));
};
let UserAdd = auditLogEvents(auditLookback, opName) 
| project Action = "User Added", TimeGenerated, Type, InitiatedBy_Caller = InitiatedBy, IpAddress, TargetUserName = tolower(TargetUserName), OperationName, PropertyName_ResourceId = PropertyName, Value = newValue;
// Get the simple list of creatd users so we can use later to get just the associated resource creation events
let SimpleUserList = UserAdd | project TimeGenerated, TargetUserName;
let ResourceCreation = AzureActivity
| where TimeGenerated >= ago(auditLookback)
// We look for any Operation that created and then succeeded where ActivityStatus has a value so that we can provide context
| where OperationName has "Create"
| where ActivityStatus has "Succeeded"
| project Action = "Resource Created", ResourceCreationTimeGenerated = TimeGenerated, Type, InitiatedBy_Caller = tolower(Caller), IpAddress = CallerIpAddress, OperationName, Value = OperationNameValue, PropertyName_ResourceId = ResourceId;
// Get just the Resources added by the new user
let ResourceMatch = SimpleUserList | join kind= innerunique (
   ResourceCreation
) on $left.TargetUserName == $right.InitiatedBy_Caller
// where the resource creation is after (greater than) the user addition
| where TimeGenerated < ResourceCreationTimeGenerated
| project-away TimeGenerated 
| project-rename TimeGenerated = ResourceCreationTimeGenerated
;
let SimpleResourceMatch = ResourceMatch | project InitiatedBy_Caller;
// Get only resource add, remove, change by the new user
let UserAddWithResource = SimpleResourceMatch | join kind= rightsemi (
   UserAdd 
) on $left.InitiatedBy_Caller == $right.TargetUserName;
// union the user addition events and resource addition events and provide common column names, additionally pack the value, property and resource info to reduce result set.
UserAddWithResource 
| union isfuzzy=true ResourceMatch
| extend PropertySet = pack("Value", Value, "PropertyName_ResourceId", PropertyName_ResourceId) 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), makeset(PropertySet)  by Action, Type, TargetUserName, InitiatedBy_Caller, IpAddress, OperationName
| order by StartTimeUtc asc 
| extend timestamp = StartTimeUtc, AccountCustomEntity = TargetUserName, IPCustomEntity = IpAddress```
## Anomalous access to other user's mailboxes
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/AnomolousUserAccessingOtherUsersMailbox.yaml)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: Looks for users accessing multiple other users mailboxes or accessing multiple folders in another users mailbox

> Query:

```//Adjust this value to exclude historical activity as known good
let lookback = 30d;
//Adjust this value to change hunting timeframe
let timeframe = 14d;
//Adjust this value to alter how many mailbox (other than their own) a user needs to access before being included in results
let user_threshold = 1;
//Adjust this value to alter how many mailbox folders in others email accounts a users needs to access before being included in results.
let folder_threshold = 5;
//Exclude historical as known good (set lookback and timeframe to same value to skip this)
OfficeActivity
| where TimeGenerated between(ago(lookback)..ago(timeframe))
| where Operation =~ "MailItemsAccessed"
| where ResultStatus =~ "Succeeded"
| where tolower(MailboxOwnerUPN) != tolower(UserId)
| join kind=rightanti(
OfficeActivity
| where TimeGenerated > ago(timeframe)
| where Operation =~ "MailItemsAccessed"
| where ResultStatus =~ "Succeeded"
| where tolower(MailboxOwnerUPN) != tolower(UserId)) on MailboxOwnerUPN, UserId
| where isnotempty(Folders)
| mv-expand parse_json(Folders)
| extend folders = tostring(Folders.Path)
| extend ClientIP = iif(Client_IPAddress startswith "[", extract("\\[([^\\]]*)", 1, Client_IPAddress), Client_IPAddress)
| summarize make_set(folders), make_set(ClientInfoString), make_set(ClientIP), make_set(MailboxGuid), make_set(MailboxOwnerUPN)  by UserId
| extend folder_count = array_length(set_folders)
| extend user_count = array_length(set_MailboxGuid)
| where user_count > user_threshold or folder_count > folder_threshold
| extend Reason = case(user_count > user_threshold and folder_count > folder_threshold, "Both User and Folder Threshold Exceeded", folder_count > folder_threshold and user_count < user_threshold, "Folder Count Threshold Exceeded","User Threshold Exceeded")
| sort by user_count desc
| project-reorder UserId, user_count, folder_count, set_MailboxOwnerUPN, set_ClientIP, set_ClientInfoString, set_folders```
## Exes with double file extension and access summary
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/double_file_ext_exes.yaml)

### ATT&CK Tags

> Tactics: [u'DefenseEvasion']

### Hunt details

> Description: Provides a summary of executable files with double file extensions in SharePoint  and the users and IP addresses that have accessed them.

> Query:

```let timeframe = 14d;
let known_ext = dynamic(["lnk","log","option","config", "manifest", "partial"]);
let excluded_users = dynamic(["app@sharepoint"]);
OfficeActivity
| where TimeGenerated > ago(timeframe)
| where RecordType =~ "SharePointFileOperation" and isnotempty(SourceFileName)
| where OfficeObjectId has ".exe." and SourceFileExtension !in~ (known_ext)
| extend Extension = extract("[^.]*.[^.]*$",0, OfficeObjectId)
| join kind= leftouter ( 
  OfficeActivity
    | where TimeGenerated > ago(timeframe)
    | where RecordType =~ "SharePointFileOperation" and (Operation =~ "FileDownloaded" or Operation =~ "FileAccessed") 
    | where SourceFileExtension !in~ (known_ext)
) on OfficeObjectId 
| where UserId1 !in~ (excluded_users)
| extend userBag = pack(UserId1, ClientIP1) 
| summarize makeset(UserId1), make_bag(userBag), Start=max(TimeGenerated), End=min(TimeGenerated) by UserId, OfficeObjectId, SourceFileName, Extension 
| extend NumberOfUsers = array_length(bag_keys(bag_userBag))
| project UploadTime=Start, Uploader=UserId, FileLocation=OfficeObjectId, FileName=SourceFileName, AccessedBy=bag_userBag, Extension, NumberOfUsers
| extend timestamp = UploadTime, AccountCustomEntity = Uploader```
## External user added and removed in short timeframe
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/ExternalUserAddedRemoved.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence']

### Hunt details

> Description: This hunting query identifies external user accounts that are added to a Team and then removed within one hour.

> Query:

```// If you want to look at user added further than 7 days ago adjust this value
let time_ago = 7d;
// If you want to change the timeframe of how quickly accounts need to be added and removed change this value
let time_delta = 1h;
OfficeActivity
| where TimeGenerated > ago(time_ago)
| where OfficeWorkload =~ "MicrosoftTeams" 
| where Operation =~ "MemberAdded"
| extend UPN = tostring(parse_json(Members)[0].UPN)
| where UPN contains ("#EXT#")
| project TimeAdded=TimeGenerated, Operation, UPN, UserWhoAdded = UserId, TeamName, TeamGuid
| join (
OfficeActivity
| where TimeGenerated > ago(time_ago)
| where OfficeWorkload =~ "MicrosoftTeams" 
| where Operation =~ "MemberRemoved"
| extend UPN = tostring(parse_json(Members)[0].UPN)
| where UPN contains ("#EXT#")
| project TimeDeleted=TimeGenerated, Operation, UPN, UserWhoDeleted = UserId, TeamName, TeamGuid) on UPN, TeamGuid
| where TimeDeleted < (TimeAdded + time_delta)
| project TimeAdded, TimeDeleted, UPN, UserWhoAdded, UserWhoDeleted, TeamName, TeamGuid
| extend timestamp = TimeAdded, AccountCustomEntity = UPN```
## Mail redirect via ExO transport rule
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/Mail_redirect_via_ExO_transport_rule_hunting.yaml)

### ATT&CK Tags

> Tactics: [u'Collection', u'Exfiltration']

### Hunt details

> Description: Identifies when Exchange Online transport rule configured to forward emails.This could be an adversary mailbox configured to collect mail from multiple user accounts.

> Query:

```let timeframe = 14d;
OfficeActivity
| where TimeGenerated >= ago(timeframe)
| where OfficeWorkload == "Exchange"
| where Operation in~ ("New-TransportRule", "Set-TransportRule")
| extend p = parse_json(Parameters)
| extend RuleName = case(
  Operation =~ "Set-TransportRule", tostring(OfficeObjectId),
  Operation =~ "New-TransportRule", tostring(p[1].Value),
  "Unknown"
  ) 
| mvexpand p
| where (p.Name =~ "BlindCopyTo" or p.Name =~ "RedirectMessageTo") and isnotempty(p.Value)
| extend RedirectTo = p.Value
| extend ClientIPOnly = case( 
  ClientIP has "." and ClientIP has ":", tostring(split(ClientIP,":")[0]), 
  ClientIP has "." and ClientIP has "-", tostring(split(ClientIP,"-")[0]), 
  ClientIP has "[", tostring(trim_start(@[[],tostring(split(ClientIP,"]")[0]))),
  ClientIP
  )  
| extend Port = case(
  ClientIP has "." and ClientIP has ":", (split(ClientIP,":")[1]),
  ClientIP has "." and ClientIP has "-", (split(ClientIP,"-")[1]),
  ClientIP has "[" and ClientIP has ":", tostring(split(ClientIP,"]:")[1]),
  ClientIP has "[" and ClientIP has "-", tostring(split(ClientIP,"]-")[1]),
  ClientIP
  )
| extend ClientIP = ClientIPOnly
| project TimeGenerated, RedirectTo, ClientIP, Port, UserId, Operation, RuleName
| extend timestamp = TimeGenerated, AccountCustomEntity = UserId, IPCustomEntity = ClientIP```
## User made Owner of multiple teams
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/MultiTeamOwner.yaml)

### ATT&CK Tags

> Tactics: [u'PrivilegeEscalation']

### Hunt details

> Description: This hunting query identifies users who have been made Owner of multiple Teams.

> Query:

```// Adjust this value to change how many teams a user is made owner of before detecting
let max_owner_count = 3;
// Change this value to adjust how larger timeframe the query is run over.
let time_window = 1d;
let high_owner_count = (OfficeActivity
| where TimeGenerated > ago(time_window)
| where OfficeWorkload =~ "MicrosoftTeams"
| where Operation =~ "MemberRoleChanged"
| extend Member = tostring(parse_json(Members)[0].UPN) 
| extend NewRole = toint(parse_json(Members)[0].Role) 
| where NewRole == 2
| summarize dcount(TeamName) by Member
| where dcount_TeamName > max_owner_count
| project Member);
OfficeActivity
| where TimeGenerated > ago(time_window)
| where OfficeWorkload =~ "MicrosoftTeams"
| where Operation =~ "MemberRoleChanged"
| extend Member = tostring(parse_json(Members)[0].UPN) 
| extend NewRole = toint(parse_json(Members)[0].Role) 
| where NewRole == 2
| where Member in (high_owner_count)
| extend timestamp = TimeGenerated, AccountCustomEntity = Member```
## New Admin account activity seen which was not seen historically
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/new_adminaccountactivity.yaml)

### ATT&CK Tags

> Tactics: [u'PrivilegeEscalation', u'Collection']

### Hunt details

> Description: This will help you discover any new admin account activity which was seen and were not seen historically. Any new accounts seen in the results can be validated and investigated for any suspicious activities.

> Query:

```let starttime = 14d;
let endtime = 1d;
let historicalActivity=
OfficeActivity
| where TimeGenerated between(ago(starttime)..ago(endtime))
| where RecordType=="ExchangeAdmin" and UserType in ("Admin","DcAdmin")
| summarize historicalCount=count() by UserId;
let recentActivity = OfficeActivity
| where TimeGenerated > ago(endtime)
| where UserType in ("Admin","DcAdmin")
| summarize recentCount=count() by UserId;
recentActivity | join kind = leftanti (
   historicalActivity
) on UserId
| project UserId,recentCount
| order by recentCount asc, UserId
| join kind = rightsemi 
(OfficeActivity 
| where TimeGenerated >= ago(endtime) 
| where RecordType == "ExchangeAdmin" | where UserType in ("Admin","DcAdmin")) 
on UserId
| summarize count(), min(TimeGenerated), max(TimeGenerated) by RecordType, Operation, UserType, UserId, OriginatingServer, ResultStatus
| extend timestamp = min_TimeGenerated, AccountCustomEntity = UserId```
## SharePointFileOperation via previously unseen IPs
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/new_sharepoint_downloads_by_IP.yaml)

### ATT&CK Tags

> Tactics: [u'Exfiltration']

### Hunt details

> Description: Shows volume of documents uploaded to or downloaded from Sharepoint by new IP addresses. In stable environments such connections by new IPs may be unauthorized, especially if associated with spikes in volume which could be associated with large-scale document exfiltration.

> Query:

```let starttime = 14d;
let endtime = 1d;
let historicalActivity=
OfficeActivity
| where  RecordType == "SharePointFileOperation"
| where Operation in ("FileDownloaded", "FileUploaded")
| where TimeGenerated between(ago(starttime)..ago(endtime))
| summarize historicalCount=count() by ClientIP;
let recentActivity = OfficeActivity
| where  RecordType == "SharePointFileOperation"
| where Operation in ("FileDownloaded", "FileUploaded")
| where TimeGenerated > ago(endtime) 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), recentCount=count() by ClientIP;
recentActivity | join kind= leftanti (
   historicalActivity 
) on ClientIP 
| extend timestamp = StartTimeUtc, IPCustomEntity = ClientIP```
## SharePointFileOperation via devices with previously unseen user agents
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/new_sharepoint_downloads_by_UserAgent.yaml)

### ATT&CK Tags

> Tactics: [u'Exfiltration']

### Hunt details

> Description: Tracking via user agent is one way to differentiate between types of connecting device. In homogeneous enterprise environments the user agent associated with an attacker device may stand out as unusual.

> Query:

```let starttime = 14d;
let endtime = 1d;
let historicalActivity=
OfficeActivity
| where  RecordType == "SharePointFileOperation"
| where Operation in ("FileDownloaded", "FileUploaded")
| where TimeGenerated between(ago(starttime)..ago(endtime))
| summarize historicalCount=count() by UserAgent, RecordType;
let recentActivity = OfficeActivity
| where  RecordType == "SharePointFileOperation"
| where Operation in ("FileDownloaded", "FileUploaded")
| where TimeGenerated > ago(endtime) 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), recentCount=count() by UserAgent, RecordType;
recentActivity | join kind = leftanti (
   historicalActivity 
) on UserAgent, RecordType
| order by recentCount asc, UserAgent
| extend timestamp = StartTimeUtc```
## New Windows Reserved Filenames staged on Office file services
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/New_WindowsReservedFileNamesOnOfficeFileServices.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl']

### Hunt details

> Description: Identifies when new Windows Reserved Filenames show up on Office services such as SharePoint and OneDrive in relation to the previous 7 days.List currently includes CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9, LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, LPT9 file extensions.Additionally, identifies when a given user is uploading these files to another users workspace.This may be indication of a staging location for malware or other malicious activity.References: https://docs.microsoft.com/windows/win32/fileio/naming-a-file

> Query:

```// a threshold can be enabled, see commented line below for PrevSeenCount
let threshold = 1;
// Reserved FileNames/Extension for Windows
let Reserved = dynamic([CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9, LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, LPT9]);
let starttime = 8d;
let endtime = 1d;
OfficeActivity | where TimeGenerated >= ago(endtime)
| where isnotempty(SourceFileExtension)
| where SourceFileName !~ SourceFileExtension
| where SourceFileExtension in~ (Reserved) or SourceFileName in~ (Reserved)
| where UserAgent !has "Mac OS" 
| project TimeGenerated, OfficeId, OfficeWorkload, RecordType, Operation, UserType, UserKey, UserId, ClientIP, UserAgent, Site_Url, SourceRelativeUrl, SourceFileName, SourceFileExtension 
| join kind= leftanti (
OfficeActivity | where TimeGenerated between (ago(starttime) .. ago(endtime))
| where isnotempty(SourceFileExtension)
| where SourceFileName !~ SourceFileExtension
| where SourceFileExtension in~ (Reserved) or SourceFileName in~ (Reserved)
| where UserAgent !has "Mac OS" 
| summarize SourceRelativeUrl = make_set(SourceRelativeUrl), UserId = make_set(UserId), SourceFileName = make_set(SourceFileName) , PrevSeenCount = count() by SourceFileExtension
// To exclude previous matches when only above a specific count, change threshold above and uncomment the line below
//| where PrevSeenCount > threshold
| mvexpand SourceRelativeUrl, UserId, SourceFileName
| extend SourceRelativeUrl = tostring(SourceRelativeUrl), UserId = tostring(UserId), SourceFileName = tostring(SourceFileName)
) on SourceFileExtension
| extend SiteUrlUserFolder = tolower(split(Site_Url, /)[-2])
| extend UserIdUserFolderFormat = tolower(replace(@|\\., _,UserId))
// identify when UserId is not a match to the specific site url personal folder reference
| extend UserIdDiffThanUserFolder = iff(Site_Url has /personal/ and SiteUrlUserFolder != UserIdUserFolderFormat, true , false ) 
| summarize TimeGenerated = make_list(TimeGenerated), StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), Operations = make_list(Operation), UserAgents = make_list(UserAgent), 
OfficeIds = make_list(OfficeId), SourceRelativeUrls = make_list(SourceRelativeUrl), FileNames = make_list(SourceFileName)
by OfficeWorkload, RecordType, UserType, UserKey, UserId, ClientIP, Site_Url, SourceFileExtension, SiteUrlUserFolder, UserIdUserFolderFormat, UserIdDiffThanUserFolder
// Use mvexpand on any list items and you can expand out the exact time and other metadata about the hit```
## Previously unseen bot or applicaiton added to Teams
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/NewBotAdded.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'Collection']

### Hunt details

> Description: This hunting query helps identify new, and potentially unapproved applications or bots being added to Teams.

> Query:

```// If you have more than 14 days worth of Teams data change this value
let data_date = 14d;
let historical_bots = (
OfficeActivity
| where TimeGenerated > ago(data_date)
| where OfficeWorkload =~ "MicrosoftTeams"
| where isnotempty(AddonName)
| project AddonName);
OfficeActivity
| where TimeGenerated > ago(1d)
| where OfficeWorkload =~ "MicrosoftTeams"
// Look for add-ins we have never seen before
| where AddonName in (historical_bots)
| extend timestamp = TimeGenerated, AccountCustomEntity = UserId```
## External user from a new organisation added
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/NewExternalOrg.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence']

### Hunt details

> Description: This query identifies external users added to Teams where the users domain is not one previously seen in Teams data.

> Query:

```// If you have more than 14 days worth of Teams data change this value
let data_date = 14d;
// If you want to look at users further back than the last day change this value
let lookback_data = 1d;
let known_orgs = (
OfficeActivity
| where TimeGenerated > ago(data_date)
| where OfficeWorkload =~ "MicrosoftTeams"
| where Operation =~ "MemberAdded" or Operation =~ "TeamsSessionStarted"
// Extract the correct UPN and parse our external organization domain
| extend UPN = iif(Operation == "MemberAdded", tostring(parse_json(Members)[0].UPN), UserId)
| extend Organization = tostring(split(split(UPN, "_")[1], "#")[0])
| where isnotempty(Organization)
| summarize by Organization);
OfficeActivity
| where TimeGenerated > ago(lookback_data)
| where OfficeWorkload =~ "MicrosoftTeams"
| where Operation =~ "MemberAdded"
| extend UPN = tostring(parse_json(Members)[0].UPN)
| extend Organization = tostring(split(split(UPN, "_")[1], "#")[0])
| where isnotempty(Organization)
| where Organization !in (known_orgs)
| extend timestamp = TimeGenerated, AccountCustomEntity = UPN```
## Non-owner mailbox login activity
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/nonowner_MailboxLogin.yaml)

### ATT&CK Tags

> Tactics: [u'Collection', u'Exfiltration']

### Hunt details

> Description: This will help you determine if mailbox access observed with Admin/Delegate Logontype. The logon type indicates mailbox accessed from non-owner user. Exchange allows Admin and delegate permissions to access other users inbox.If your organization has valid admin, delegate access given to users, you can whitelist those and investigate other results.References: https://docs.microsoft.com/office/office-365-management-api/office-365-management-activity-api-schema#logontype

> Query:

```let timeframe = 1d;
OfficeActivity
| where TimeGenerated >= ago(timeframe)
| where Operation == "MailboxLogin" and Logon_Type != "Owner" 
| summarize count(), min(TimeGenerated), max(TimeGenerated) by Operation, OrganizationName, UserType, UserId, MailboxOwnerUPN, Logon_Type
| extend timestamp = min_TimeGenerated, AccountCustomEntity = UserId```
## Office Mail Forwarding - Hunting Version
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/OfficeMailForwarding_hunting.yaml)

### ATT&CK Tags

> Tactics: [u'Collection', u'Exfiltration']

### Hunt details

> Description: Adversaries often abuse email-forwarding rules to monitor activities of a victim, steal information and further gain intelligence onvictim or victims organization.This query over Office Activity data highlights cases where user mail is being forwarded and shows if it is being forwarded to external domains as well.

> Query:

```let timeframe = 14d;
OfficeActivity
| where TimeGenerated >= ago(timeframe)
| where (Operation =~ "Set-Mailbox" and Parameters contains ForwardingSmtpAddress) 
or (Operation =~ New-InboxRule and Parameters contains ForwardTo)
| extend parsed=parse_json(Parameters)
| extend fwdingDestination_initial = (iif(Operation=~"Set-Mailbox", tostring(parsed[1].Value), tostring(parsed[2].Value)))
| where isnotempty(fwdingDestination_initial)
| extend fwdingDestination = iff(fwdingDestination_initial has "smtp", (split(fwdingDestination_initial,":")[1]), fwdingDestination_initial )
| parse fwdingDestination with * @ ForwardedtoDomain 
| parse UserId with *@ UserDomain
| extend subDomain = ((split(strcat(tostring(split(UserDomain, .)[-2]),.,tostring(split(UserDomain, .)[-1])), .) [0]))
| where ForwardedtoDomain !contains subDomain
| extend Result = iff( ForwardedtoDomain != UserDomain ,"Mailbox rule created to forward to External Domain", "Forward rule for Internal domain")
| extend ClientIPAddress = case( ClientIP has ".", tostring(split(ClientIP,":")[0]), ClientIP has "[", tostring(trim_start(@[[],tostring(split(ClientIP,"]")[0]))), ClientIP )
| extend Port = case(
ClientIP has ".", (split(ClientIP,":")[1]),
ClientIP has "[", tostring(split(ClientIP,"]:")[1]),
ClientIP
)
| project TimeGenerated, UserId, UserDomain, subDomain, Operation, ForwardedtoDomain, ClientIPAddress, Result, Port, OriginatingServer, OfficeObjectId, fwdingDestination
| extend timestamp = TimeGenerated, AccountCustomEntity = UserId, IPCustomEntity = ClientIPAddress, HostCustomEntity =  OriginatingServer```
## Powershell or non-browser mailbox login activity
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/powershell_or_nonbrowser_MailboxLogin.yaml)

### ATT&CK Tags

> Tactics: [u'Execution', u'Persistence', u'Collection']

### Hunt details

> Description: This will help you determine if mailbox login was done from Exchange Powershell session. By default, all accounts you create in Office 365 are allowed to use Exchange Online PowerShell. Administrators can use Exchange Online PowerShell to enable or disable a users ability to connect to Exchange Online PowerShell.Whitelist any benign scheduled activities using exchange powershell if applicable in your environment.References: https://docs.microsoft.com/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/connect-to-exchange-online-powershell?view=exchange-ps

> Query:

```let timeframe = 1d;
OfficeActivity
| where TimeGenerated >= ago(timeframe)
| where Operation == "MailboxLogin"
| where ClientInfoString == "Client=Microsoft.Exchange.Powershell; Microsoft WinRM Client"
| summarize count(), min(TimeGenerated), max(TimeGenerated) by Operation, OrganizationName, UserType, UserId, MailboxOwnerUPN, Logon_Type, ClientInfoString
| extend timestamp = min_TimeGenerated, AccountCustomEntity = UserId```
## SharePointFileOperation via clientIP with previously unseen user agents
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/sharepoint_downloads.yaml)

### ATT&CK Tags

> Tactics: [u'Exfiltration']

### Hunt details

> Description: New user agents associated with a clientIP for sharepoint file uploads/downloads.

> Query:

```let starttime = 14d;
let endtime = 1d;
let historicalUA=
OfficeActivity
| where  RecordType == "SharePointFileOperation"
| where Operation in ("FileDownloaded", "FileUploaded")
| where TimeGenerated between(ago(starttime)..ago(endtime))
| summarize by ClientIP, UserAgent;
let recentUA = OfficeActivity
| where  RecordType == "SharePointFileOperation"
| where Operation in ("FileDownloaded", "FileUploaded")
| where TimeGenerated > ago(endtime) 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by ClientIP, UserAgent;
recentUA | join kind=leftanti (
   historicalUA 
) on ClientIP, UserAgent
// Some OfficeActivity records do not contain ClientIP information - exclude these for fewer results:
| where not(isempty(ClientIP)) 
| extend timestamp = StartTimeUtc, IPCustomEntity = ClientIP```
## Files uploaded to teams and access summary
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/TeamsFilesUploaded.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess', u'Exfiltration']

### Hunt details

> Description: Provides a summary of files uploaded to teams chats and extracts the users and IP addresses that have accessed them.

> Query:

```OfficeActivity 
| where RecordType =~ "SharePointFileOperation" 
| where UserId != "app@sharepoint"
| where SourceRelativeUrl contains "Microsoft Teams Chat Files" 
| where Operation =~ "FileUploaded" 
| join kind= leftouter ( 
   OfficeActivity 
    | where RecordType =~ "SharePointFileOperation"
    | where UserId != "app@sharepoint"
    | where SourceRelativeUrl contains "Microsoft Teams Chat Files" 
    | where Operation =~ "FileDownloaded" or Operation =~ "FileAccessed" 
) on OfficeObjectId 
| extend userBag = pack(UserId1, ClientIP1) 
| summarize makeset(UserId1), make_bag(userBag) by TimeGenerated, UserId, OfficeObjectId, SourceFileName 
| extend NumberUsers = array_length(bag_keys(bag_userBag))
| project timestamp=TimeGenerated, AccountCustomEntity=UserId, FileLocation=OfficeObjectId, FileName=SourceFileName, AccessedBy=bag_userBag, NumberOfUsersAccessed=NumberUsers```
## Windows Reserved Filenames staged on Office file services
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/WindowsReservedFileNamesOnOfficeFileServices.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl']

### Hunt details

> Description: Identifies when Windows Reserved Filenames show up on Office services such as SharePoint and OneDrive.List currently includes CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9, LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, LPT9 file extensions.Additionally, identifies when a given user is uploading these files to another users workspace.This may be indication of a staging location for malware or other malicious activity.References: https://docs.microsoft.com/windows/win32/fileio/naming-a-file

> Query:

```// Reserved FileNames/Extension for Windows
let Reserved = dynamic([CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9, LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, LPT9]);
let endtime = 1d;
OfficeActivity | where TimeGenerated >= ago(endtime)
| where isnotempty(SourceFileExtension)
| where SourceFileExtension in~ (Reserved) or SourceFileName in~ (Reserved)
| where UserAgent !has "Mac OS" 
| extend SiteUrlUserFolder = tolower(split(Site_Url, /)[-2])
| extend UserIdUserFolderFormat = tolower(replace(@|\\., _,UserId))
// identify when UserId is not a match to the specific site url personal folder reference
| extend UserIdDiffThanUserFolder = iff(Site_Url has /personal/ and SiteUrlUserFolder != UserIdUserFolderFormat, true , false ) 
| summarize TimeGenerated = make_list(TimeGenerated), StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), Operations = make_list(Operation), UserAgents = make_list(UserAgent), 
OfficeIds = make_list(OfficeId), SourceRelativeUrls = make_list(SourceRelativeUrl), FileNames = make_list(SourceFileName)
by OfficeWorkload, RecordType, UserType, UserKey, UserId, ClientIP, Site_Url, SourceFileExtension,SiteUrlUserFolder, UserIdUserFolderFormat, UserIdDiffThanUserFolder
// Use mvexpand on any list items and you can expand out the exact time and other metadata about the hit```
## External user added and removed in short timeframe
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/Teams/ExternalUserAddedRemoved.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence']

### Hunt details

> Description: This hunting query identifies external user accounts that are added to a Team and then removed withinone hour.This query is works with the built-in Teams data connector only.

> Query:

```// If you want to look at user added further than 7 days ago adjust this value
let time_ago = 7d;
// If you want to change the timeframe of how quickly accounts need to be added and removed change this value
let time_delta = 1h;
OfficeActivity
| where TimeGenerated > ago(time_ago)
| where OfficeWorkload =~ "MicrosoftTeams"
| where Operation =~ "MemberAdded"
| extend UPN = tostring(Members[0].UPN)
| where UPN contains ("#EXT#")
| project TimeAdded=TimeGenerated, Operation, UPN, UserWhoAdded = UserId, TeamName, TeamGuid
| join (
OfficeActivity
| where TimeGenerated > ago(time_ago)
| where OfficeWorkload =~ "MicrosoftTeams"
| where Operation =~ "MemberRemoved"
| extend UPN = tostring(Members[0].UPN)
| where UPN contains ("#EXT#")
| project TimeDeleted=TimeGenerated, Operation, UPN, UserWhoDeleted = UserId, TeamName, TeamGuid) on UPN, TeamGuid
| where TimeDeleted < (TimeAdded + time_delta)
| project TimeAdded, TimeDeleted, UPN, UserWhoAdded, UserWhoDeleted, TeamName, TeamGuid
// Uncomment the following line to map query entities is you plan to use this as a detection query
//| extend timestamp = TimeAdded, AccountCustomEntity = UPN```
## Summarize files uploads in a Teams chat
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/Teams/FilesUploadedTeamsChat.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: This hunting queries identifies files uploaded to SharePoint via a Teams chat andsummarizes users and IP addresses that have accessed these files. This allows for identification of anomolous file sharing patterns.

> Query:

```let timeframe = 7d;
OfficeActivity
| where TimeGenerated > ago(timeframe)
| where RecordType =~ "SharePointFileOperation"
| where SourceRelativeUrl has "Microsoft Teams Chat Files"
| where Operation =~ "FileUploaded"
| join kind= leftouter (
  OfficeActivity
    | where TimeGenerated > ago(timeframe)
    | where RecordType =~ "SharePointFileOperation"
    | where SourceRelativeUrl has "Microsoft Teams Chat Files"
    | where Operation =~ "FileDownloaded" or Operation =~ "FileAccessed"
) on OfficeObjectId
| extend userBag = pack(UserId1, ClientIP1)
| summarize make_set(UserId1), make_bag(userBag) by TimeGenerated, UserId, OfficeObjectId, SourceFileName
| project UploadTime=TimeGenerated, Uploader=UserId, FileLocation=OfficeObjectId, FileName=SourceFileName, AccessedBy=bag_userBag
| extend timestamp=UploadTime, AccountCustomEntity=Uploader```
## Multiple Teams deleted by a single user
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/Teams/MultipleTeamsDeletes.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: This hunting query identifies where multiple Teams have been deleted by a single user in a short timeframe. This query is works with the built-in Teams data connector only.

> Query:

```// Adjust this value to change how many Teams should be deleted before including
let max_delete = 3;
// Adjust this value to change the timewindow the query runs over
let time_window = 1d;
let deleting_users = (
OfficeActivity
| where TimeGenerated > ago(time_window)
| where OfficeWorkload =~ "MicrosoftTeams"
| where Operation =~ "TeamDeleted"
| summarize count() by UserId
| where count_ > max_delete
| project UserId);
  OfficeActivity
| where TimeGenerated > ago(time_window)
| where OfficeWorkload =~ "MicrosoftTeams"
| where Operation =~ "TeamDeleted"
| where UserId in (deleting_users)
// Uncomment the following line to map query entities is you plan to use this as a detection query
//| extend timestamp = TimeGenerated, AccountCustomEntity = UserId```
## Bots added to multiple teams
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/Teams/MultiTeamBot.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'Collection']

### Hunt details

> Description: This hunting query helps identify bots added to multiple Teams in a short space of time. This query is works with the built-in Teams data connector only.

> Query:

```// Adjust these thresholds to suit your environment.
let threshold = 2;
let time_threshold = timespan(5m);
let timeframe = 30d;
OfficeActivity
  | where TimeGenerated > ago(timeframe)
  | where OfficeWorkload =~ "MicrosoftTeams"
  | where Operation =~ "BotAddedToTeam"
  | summarize Start=max(TimeGenerated), End=min(TimeGenerated), Teams = makeset(TeamName)
  | extend CountOfTeams = array_length(Teams)
  | extend TimeDelta = End - Start 
  | where CountOfTeams > threshold
  | where TimeDelta >= time_threshold
  | project Start, End, Teams, CountOfTeams```
## User made Owner of multiple teams
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/Teams/MultiTeamOwner.yaml)

### ATT&CK Tags

> Tactics: [u'PrivilegeEscalation']

### Hunt details

> Description: This hunting query identifies users who have been made Owner of multiple Teams. This query is works with the built-in Teams data connector only.

> Query:

```// Adjust this value to change how many teams a user is made owner of before detecting
let max_owner_count = 3;
// Change this value to adjust how larger timeframe the query is run over.
let time_window = 1d;
let high_owner_count = (OfficeActivity
| where TimeGenerated > ago(time_window)
| where OfficeWorkload =~ "MicrosoftTeams"
| where Operation =~ "MemberRoleChanged"
| extend Member = tostring(Members[0].UPN) 
| extend NewRole = toint(Members[0].Role) 
| where NewRole == 2
| summarize dcount(TeamName) by Member
| where dcount_TeamName > max_owner_count
| project Member);
OfficeActivity
| where TimeGenerated > ago(time_window)
| where OfficeWorkload =~ "MicrosoftTeams"
| where Operation =~ "MemberRoleChanged"
| extend Member = tostring(Members[0].UPN) 
| extend NewRole = toint(Members[0].Role) 
| where NewRole == 2
| where Member in (high_owner_count)
// Uncomment the following line to map query entities is you plan to use this as a detection query
//| extend timestamp = TimeGenerated, AccountCustomEntity = Member```
## External user from a new organisation added
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/Teams/NewExternalOrg.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence']

### Hunt details

> Description: This query identifies external users added to Teams where the users domain is not one previously seen in Teams data.This query is works with the built-in Teams data connector only.

> Query:

```// If you have more than 14 days worth of Teams data change this value
let data_date = 14d;
// If you want to look at users further back than the last day change this value
let lookback_date = 1d;
let known_orgs = (
OfficeActivity 
| where TimeGenerated > ago(data_date)
| where OfficeWorkload =~ "MicrosoftTeams"
| where Operation =~ "MemberAdded" or Operation =~ "TeamsSessionStarted"
// Extract the correct UPN and parse our external organization domain
| extend UPN = iif(Operation == "MemberAdded", tostring(Members[0].UPN), UserId)
| extend Organization = tostring(split(split(UPN, "_")[1], "#")[0])
| where isnotempty(Organization)
| summarize by Organization);
OfficeActivity 
| where TimeGenerated > ago(lookback_date)
| where OfficeWorkload =~ "MicrosoftTeams"
| where Operation =~ "MemberAdded"
| extend UPN = tostring(parse_json(Members)[0].UPN)
| extend Organization = tostring(split(split(UPN, "_")[1], "#")[0])
| where isnotempty(Organization)
| where Organization !in (known_orgs)
// Uncomment the following line to map query entities is you plan to use this as a detection query
//| extend timestamp = TimeGenerated, AccountCustomEntity = UPN```
## User added to Team and immediately uploads file
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/OfficeActivity/Teams/TeamsUserAddUpload.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: This hunting queries identifies users who are added to a Team or Teams chatand within 1 minute of being added upload a file via the chat. This might bean indicator of suspicious activity.

> Query:

```let timeframe = 7d;
let threshold = 1m;
OfficeActivity
| where TimeGenerated > ago(timeframe)
| where OfficeWorkload =~ "MicrosoftTeams"
| where Operation == "MemberAdded"
| extend TeamName = iff(isempty(TeamName), Members[0].UPN, TeamName)
| project TimeGenerated, UploaderID=UserId, TeamName
| join (
  OfficeActivity
  | where TimeGenerated > ago(timeframe)
  | where RecordType == "SharePointFileOperation"
  | where SourceRelativeUrl has "Microsoft Teams Chat Files"
  | where Operation == "FileUploaded"
  | project UploadTime=TimeGenerated, UploaderID=UserId, FileLocation=OfficeObjectId, FileName=SourceFileName
  ) on UploaderID
| where UploadTime > TimeGenerated and UploadTime < TimeGenerated+threshold
| project-away UploaderID1
| extend timestamp=TimeGenerated, AccountCustomEntity = UploaderID```
## Alerts related to IP
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityAlert/AlertsForIP.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'Discovery', u'LateralMovement', u'Collection']

### Hunt details

> Description: Any Alerts that fired related to a given IpAddress during the range of +6h and -3d

> Query:

```let GetAllAlertsWithIp = (suspiciousEventTime:datetime, v_ipAddress:string){
//-3d and +6h as some alerts fire after accumulation of events
let v_StartTime = suspiciousEventTime-3d;
let v_EndTime = suspiciousEventTime+6h;
SecurityAlert
| where TimeGenerated between (v_StartTime .. v_EndTime)
// expand JSON properties
| extend Extprop = parsejson(Entities)
| mv-expand Extprop
| extend Extprop = parsejson(Extprop)
| extend IpAddress = iff(Extprop["Type"] == "ip",Extprop[Address], ) 
| where IpAddress == v_ipAddress
| extend Account = Extprop[Name]
| extend Domain = Extprop[UPNSuffix]
| extend Account = iif(isnotempty(Domain) and Extprop[Type]=="account", tolower(strcat(Account, "@", Domain)), iif(Extprop[Type]=="account", tolower(Account), ""))
| extend Computer = iff(Extprop[Type]=="host", Extprop[HostName], )
| project StartTimeUtc = StartTime, EndTimeUtc = EndTime, AlertName, Computer, Account, IpAddress, ExtendedProperties, Entities
| extend timestamp = StartTimeUtc, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress
};
// change datetime value and <ipaddress> value below
GetAllAlertsWithIp(datetime(2019-02-05T10:02:51.000), ("<ipaddress>"))```
## Alerts related to account
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityAlert/AlertsForUser.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'Discovery', u'LateralMovement', u'Collection']

### Hunt details

> Description: Any Alerts that fired related to a given account during the range of +6h and -3d

> Query:

```let GetAllAlertsForUser = (suspiciousEventTime:datetime, v_User:string){
//-3d and +6h as some alerts fire after accumulation of events
let v_StartTime = suspiciousEventTime-3d;
let v_EndTime = suspiciousEventTime+6h;
SecurityAlert
| where TimeGenerated between (v_StartTime .. v_EndTime)
| extend Extprop = parsejson(Entities)
| mv-expand Extprop
| extend Extprop = parsejson(Extprop)
| extend Account = Extprop[Name]
| extend Domain = Extprop[UPNSuffix]
| extend Account = iif(isnotempty(Domain) and Extprop[Type]=="account", tolower(strcat(Account, "@", Domain)), iif(Extprop[Type]=="account", tolower(Account), ""))
| where Account contains v_User
| extend Computer = iff(Extprop[Type]=="host", Extprop[HostName], )
| extend IpAddress = iff(Extprop["Type"] == "ip",Extprop[Address], ) 
| project TimeGenerated, AlertName, Computer, Account, IpAddress, ExtendedProperties 
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress
};
// change datetime value and username value below
GetAllAlertsForUser(datetime(2019-01-20T10:02:51.000), toupper("<username>"))```
## Alerts On Host
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityAlert/AlertsOnHost.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'Discovery', u'LateralMovement', u'Collection']

### Hunt details

> Description: Any Alerts that fired on a given host during the range of +6h and -3d

> Query:

```let GetAllAlertsOnHost = (suspiciousEventTime:datetime, v_Host:string){
//-3d and +6h as some alerts fire after accumulation of events
let v_StartTime = suspiciousEventTime-3d;
let v_EndTime = suspiciousEventTime+6h;
SecurityAlert
| where TimeGenerated between (v_StartTime .. v_EndTime)
| where Computer contains v_Host
// expand JSON properties
| extend Extprop = parsejson(ExtendedProperties)
| extend Computer = iff(isnotempty(toupper(tostring(Extprop["Compromised Host"]))), toupper(tostring(Extprop["Compromised Host"])), tostring(parse_json(Entities)[0].HostName))
| extend Account = iff(isnotempty(tolower(tostring(Extprop["User Name"]))), tolower(tostring(Extprop["User Name"])), tolower(tostring(Extprop["user name"])))
| extend IpAddress = tostring(parse_json(ExtendedProperties).["Client Address"]) 
| project TimeGenerated, AlertName, Computer, Account, IpAddress, ExtendedProperties
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress
};
// change datetime value and hostname value below
GetAllAlertsOnHost(datetime(2019-01-20T10:02:51.000), toupper("<hostname>"))```
## Alerts related to File
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityAlert/AlertsWithFile.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'Discovery', u'LateralMovement', u'Collection']

### Hunt details

> Description: Any Alerts that fired related to a given File during the range of +6h and -3d

> Query:

```let GetAllAlertsWithFile = (suspiciousEventTime:datetime, v_File:string){
let v_StartTime = suspiciousEventTime-1d;
let v_EndTime = suspiciousEventTime+1d;
SecurityAlert
| where TimeGenerated between (v_StartTime .. v_EndTime)
| where ExtendedProperties has v_File
| extend Computer = iff(isnotempty(toupper(tostring(Extprop["Compromised Host"]))), toupper(tostring(Extprop["Compromised Host"])), tostring(parse_json(Entities)[0].HostName))
| extend Account = iff(isnotempty(tolower(tostring(Extprop["User Name"]))), tolower(tostring(Extprop["User Name"])), tolower(tostring(Extprop["user name"])))
| extend IpAddress = tostring(parse_json(ExtendedProperties).["Client Address"]) 
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress
};
// change datetime value and <filename> value below
GetAllAlertsWithFile(datetime(2019-01-18T10:36:07Z), "<filename>")```
## Alerts With This Process
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityAlert/AlertsWithProcess.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'Discovery', u'LateralMovement', u'Collection']

### Hunt details

> Description: Any Alerts that fired on any host with this same process in the range of +-1d

> Query:

```let GetAllAlertsWithProcess = (suspiciousEventTime:datetime, v_Process:string){
let v_StartTime = suspiciousEventTime-1d;
let v_EndTime = suspiciousEventTime+1d;
SecurityAlert
| where TimeGenerated between (v_StartTime .. v_EndTime)
| where Entities has v_Process
| extend Extprop = parsejson(Entities)
| mv-expand Extprop
| extend Extprop = parsejson(Extprop)
| extend CmdLine = iff(Extprop[Type]=="process", Extprop[CommandLine], )
| extend File = iff(Extprop[Type]=="file", Extprop[Name], )
| extend Account = Extprop[Name]
| extend Domain = Extprop[UPNSuffix]
| extend Account = iif(isnotempty(Domain) and Extprop[Type]=="account", tolower(strcat(Account, "@", Domain)), iif(Extprop[Type]=="account", tolower(Account), ""))
| extend Computer = iff(Extprop[Type]=="host", Extprop[HostName], )
| extend IpAddress = iff(Extprop["Type"] == "ip",Extprop[Address], )
| extend Process = iff(isnotempty(CmdLine), CmdLine, File)
| summarize max(TimeGenerated), make_set(AlertName), make_set(Process), make_set(Computer), make_set(Account), make_set(IpAddress), make_set(Entities) by SystemAlertId
| project TimeGenerated = max_TimeGenerated, AlertName=set_AlertName[0], Process=set_Process[1], Account = set_Account[1], Computer=set_Computer[0], IPAddress = set_IpAddress[1], Entities=set_Entities
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IPAddress
| top 10 by TimeGenerated desc nulls last
};
// change datetime value and <processname> value below
GetAllAlertsWithProcess(datetime(2019-01-18T10:36:07Z), "<processname>")```
## Web shell command alert enrichment
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityAlert/WebShellCommandAlertEnrich.yaml)

### ATT&CK Tags

> Tactics: [u'PrivilegeEscalation', u'Persistence']

### Hunt details

> Description: Extracts MDATP Alerts that indicate a command was executed by a web shell. Uses time window based querying to idneitfy the potential web shell location on the server, then enriches with Attacker IP and User Agent

> Query:

```let scriptExtensions = dynamic([".php", ".jsp", ".js", ".aspx", ".asmx", ".asax", ".cfm", ".shtml"]);
let timeRange = 3d; 
let lookupWindow = 1m;  
let lookupBin = lookupWindow / 2.0; 
let distinctIpThreshold = 3; 
let alerts = SecurityAlert  
| where TimeGenerated > ago(timeRange) 
| extend alertData = parse_json(Entities), recordGuid = new_guid(); 
let shellAlerts = alerts 
| where ProviderName =~ "MDATP"  
| mvexpand alertData 
| where alertData.Type =~ "file" and alertData.Name =~ "w3wp.exe" 
| distinct SystemAlertId 
| join kind=inner (alerts) on SystemAlertId; 
let alldata = shellAlerts  
| mvexpand alertData 
| extend Type = alertData.Type; 
let filedata = alldata  
| extend id = tostring(alertData.$id)  
| extend ImageName = alertData.Name  
| where Type =~ "file" and ImageName != "w3wp.exe" 
| extend imagefileref = id;  
let commanddata = alldata  
| extend CommandLine = tostring(alertData.CommandLine)  
| extend creationtime = tostring(alertData.CreationTimeUtc)  
| where Type =~ "process"  
| where isnotempty(CommandLine)  
| extend imagefileref = tostring(alertData.ImageFile.$ref); 
let hostdata = alldata 
| where Type =~ "host" 
| project HostName = tostring(alertData.HostName), DnsDomain = tostring(alertData.DnsDomain), SystemAlertId 
| distinct HostName, DnsDomain, SystemAlertId; 
let commandKeyedData = filedata 
| join kind=inner (  
commanddata  
) on imagefileref 
| join kind=inner (hostdata) on SystemAlertId 
| project recordGuid, TimeGenerated, ImageName, CommandLine, TimeKey = bin(TimeGenerated, lookupBin), HostName, DnsDomain 
| extend Start = TimeGenerated; 
let baseline = W3CIISLog  
| where TimeGenerated > ago(timeRange) 
| project-rename SourceIP=cIP, PageAccessed=csUriStem 
| summarize dcount(SourceIP) by PageAccessed 
| where dcount_SourceIP <= distinctIpThreshold; 
commandKeyedData 
| join kind=inner ( 
W3CIISLog  
| where TimeGenerated > ago(timeRange) 
| where csUriStem has_any(scriptExtensions)  
| extend splitUriStem = split(csUriStem, "/")  
| extend FileName = splitUriStem[-1] | extend firstDir = splitUriStem[-2] | extend TimeKey = range(bin(TimeGenerated-lookupWindow, lookupBin), bin(TimeGenerated, lookupBin),lookupBin)  
| mv-expand TimeKey to typeof(datetime)  
| summarize StartTime=min(TimeGenerated), EndTime=max(TimeGenerated) by Site=sSiteName, HostName=sComputerName, AttackerIP=cIP, AttackerUserAgent=csUserAgent, csUriStem, filename=tostring(FileName), tostring(firstDir), TimeKey 
) on TimeKey, HostName 
| where (StartTime - EndTime) between (0min .. lookupWindow) 
| extend IPCustomEntity = AttackerIP, timestamp = StartTime
| extend attackerP = pack(AttackerIP, AttackerUserAgent)  
| summarize Site=make_set(Site), Attacker=make_bag(attackerP) by csUriStem, filename, tostring(ImageName), CommandLine, HostName, IPCustomEntity, timestamp
| project Site, ShellLocation=csUriStem, ShellName=filename, ParentProcess=ImageName, CommandLine, Attacker, HostName, IPCustomEntity, timestamp
| join kind=inner (baseline) on $left.ShellLocation == $right.PageAccessed```
## Web shell file alert enrichment
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityAlert/WebShellFileAlertEnrich.yaml)

### ATT&CK Tags

> Tactics: [u'PrivilegeEscalation', u'Persistence']

### Hunt details

> Description: Extracts MDATP Alert for a web shell being placed on the server and then enriches this event with information from W3CIISLog to idnetigy the Attacker that placed the shell

> Query:

```let timeWindow = 3d;
let scriptExtensions = dynamic([".php", ".jsp", ".js", ".aspx", ".asmx", ".asax", ".cfm", ".shtml"]);  
SecurityAlert  
| where TimeGenerated > ago(timeWindow)  
| where ProviderName =~ "MDATP" 
| extend alertData = parse_json(Entities)  
| mvexpand alertData  
// Get only the file type from the JSON, this gives us the file name
| where alertData.Type =~ "file"  
// This can be expanded to include other script extensions 
| where alertData.Name has_any(scriptExtensions)
| extend FileName = alertData.Name 
| project TimeGenerated, tostring(FileName), alertData.Directory 
| join (  
W3CIISLog  
| where TimeGenerated > ago(timeWindow)  
| where csUriStem has_any(scriptExtensions) 
| extend splitUriStem = split(csUriStem, "/")  
| extend FileName = splitUriStem[-1] 
| summarize StartTime=min(TimeGenerated), EndTime=max(TimeGenerated) by AttackerIP=cIP, AttackerUserAgent=csUserAgent, SiteName=sSiteName, ShellLocation=csUriStem, tostring(FileName)  
) on FileName 
| project StartTime, EndTime, AttackerIP, AttackerUserAgent, SiteName, ShellLocation
| extend timestamp = StartTime, IPCustomEntity = AttackerIP```
## AD Account Lockout
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/ADAccountLockouts.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: Detects Active Directory account lockouts

> Query:

```let timeframe = 7d;
SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID == 4740
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), LockoutsCount = count() by Activity, Account, TargetSid, TargetDomainName, SourceComputerId, SourceDomainController = Computer
| extend timestamp = StartTime, AccountCustomEntity = Account, HostCustomEntity = TargetDomainName```
## Cscript script daily summary breakdown
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/cscript_summary.yaml)

### ATT&CK Tags

> Tactics: [u'Execution']

### Hunt details

> Description: breakdown of scripts running in the environment

> Query:

```let timeframe = 1d;
let ProcessCreationEvents=() {
let processEvents=SecurityEvent
| where EventID==4688
| project EventTime=TimeGenerated, ComputerName=Computer,AccountName=SubjectUserName, AccountDomain=SubjectDomainName,
FileName=tostring(split(NewProcessName, \\)[-1]),  ProcessCommandLine = CommandLine, 
InitiatingProcessFileName=ParentProcessName,InitiatingProcessCommandLine="",InitiatingProcessParentFileName="";
processEvents;
};
// Daily summary of cscript activity - extracting script name and parameters from commandline:
ProcessCreationEvents 
| where EventTime >= ago(timeframe)
| where FileName =~ "cscript.exe"
// remove commandline switches
| project EventTime, ComputerName, AccountName, removeSwitches = replace(@"/+[a-zA-Z0-9:]+", "", ProcessCommandLine)
// remove the leading cscript.exe process name 
| project EventTime, ComputerName, AccountName, CommandLine = trim(@"[a-zA-Z0-9\\:""]*cscript(.exe)?("")?(\s)+", removeSwitches)
// extract the script name:
| project EventTime, ComputerName, AccountName, 
// handle case where script name is enclosed in " characters or is not enclosed in quotes 
ScriptName= iff(CommandLine startswith @"""", 
extract(@"([:\\a-zA-Z_\-\s0-9\.()]+)(""?)", 0, CommandLine), 
extract(@"([:\\a-zA-Z_\-0-9\.()]+)(""?)", 0, CommandLine)), CommandLine 
| project EventTime, ComputerName, AccountName, ScriptName=trim(@"""", ScriptName) , ScriptNameLength=strlen(ScriptName), CommandLine 
// extract remainder of commandline as script parameters: 
| project EventTime, ComputerName, AccountName, ScriptName, ScriptParams = iff(ScriptNameLength < strlen(CommandLine), substring(CommandLine, ScriptNameLength +1), "")
| summarize min(EventTime), count() by ComputerName, AccountName, ScriptName, ScriptParams
| order by count_ asc nulls last 
| extend timestamp = min_EventTime, HostCustomEntity = ComputerName, AccountCustomEntity = AccountName```
## VIP account more than 6 failed logons in 10
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/CustomUserList_FailedLogons.yaml)

### ATT&CK Tags

> Tactics: [u'CredentialAccess']

### Hunt details

> Description: VIP Account with more than 6 failed logon attempts in 10 minutes, include your own VIP list in the table below NTSTATUS codes - https://docs.microsoft.com/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55

> Query:

```// Create DataTable with your own values, example below shows dummy usernames and domain
let List = datatable(VIPUser:string, Domain:string)["Bob", "Domain", "joe", "domain", "MATT", "DOMAIN", "administrator", ""];
let timeframe = 10m;
List
| project TargetUserName = tolower(VIPUser), TargetDomainName = toupper(Domain)
| join kind= rightsemi ( 
SecurityEvent 
| where TimeGenerated > ago(2*timeframe) 
| where EventID == "4625"
| where AccountType == "User"
) on TargetUserName, TargetDomainName
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), FailedVIPLogons = count() by EventID, Activity, WorkstationName, Account, TargetAccount, TargetUserName, TargetDomainName, LogonType, LogonTypeName, LogonProcessName, Status, SubStatus
| where FailedVIPLogons >= 6
// map the most common ntstatus codes
| extend StatusDesc = case(
Status =~ "0x80090302", "SEC_E_UNSUPPORTED_FUNCTION",
Status =~ "0x80090308", "SEC_E_INVALID_TOKEN",
Status =~ "0x8009030E", "SEC_E_NO_CREDENTIALS",
Status =~ "0xC0000008", "STATUS_INVALID_HANDLE",
Status =~ "0xC0000017", "STATUS_NO_MEMORY",
Status =~ "0xC0000022", "STATUS_ACCESS_DENIED",
Status =~ "0xC0000034", "STATUS_OBJECT_NAME_NOT_FOUND",
Status =~ "0xC000005E", "STATUS_NO_LOGON_SERVERS",
Status =~ "0xC000006A", "STATUS_WRONG_PASSWORD",
Status =~ "0xC000006D", "STATUS_LOGON_FAILURE",
Status =~ "0xC000006E", "STATUS_ACCOUNT_RESTRICTION",
Status =~ "0xC0000073", "STATUS_NONE_MAPPED",
Status =~ "0xC00000FE", "STATUS_NO_SUCH_PACKAGE",
Status =~ "0xC000009A", "STATUS_INSUFFICIENT_RESOURCES",
Status =~ "0xC00000DC", "STATUS_INVALID_SERVER_STATE",
Status =~ "0xC0000106", "STATUS_NAME_TOO_LONG",
Status =~ "0xC000010B", "STATUS_INVALID_LOGON_TYPE",
Status =~ "0xC000015B", "STATUS_LOGON_TYPE_NOT_GRANTED",
Status =~ "0xC000018B", "STATUS_NO_TRUST_SAM_ACCOUNT",
Status =~ "0xC0000224", "STATUS_PASSWORD_MUST_CHANGE",
Status =~ "0xC0000234", "STATUS_ACCOUNT_LOCKED_OUT",
Status =~ "0xC00002EE", "STATUS_UNFINISHED_CONTEXT_DELETED",
"See - https://docs.microsoft.com/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55"
)
| extend SubStatusDesc = case(
SubStatus =~ "0x80090325", "SEC_E_UNTRUSTED_ROOT",
SubStatus =~ "0xC0000008", "STATUS_INVALID_HANDLE",
SubStatus =~ "0xC0000022", "STATUS_ACCESS_DENIED",
SubStatus =~ "0xC0000064", "STATUS_NO_SUCH_USER",
SubStatus =~ "0xC000006A", "STATUS_WRONG_PASSWORD",
SubStatus =~ "0xC000006D", "STATUS_LOGON_FAILURE",
SubStatus =~ "0xC000006E", "STATUS_ACCOUNT_RESTRICTION",
SubStatus =~ "0xC000006F", "STATUS_INVALID_LOGON_HOURS",
SubStatus =~ "0xC0000070", "STATUS_INVALID_WORKSTATION",
SubStatus =~ "0xC0000071", "STATUS_PASSWORD_EXPIRED",
SubStatus =~ "0xC0000072", "STATUS_ACCOUNT_DISABLED",
SubStatus =~ "0xC0000073", "STATUS_NONE_MAPPED",
SubStatus =~ "0xC00000DC", "STATUS_INVALID_SERVER_STATE",
SubStatus =~ "0xC0000133", "STATUS_TIME_DIFFERENCE_AT_DC",
SubStatus =~ "0xC000018D", "STATUS_TRUSTED_RELATIONSHIP_FAILURE",
SubStatus =~ "0xC0000193", "STATUS_ACCOUNT_EXPIRED",
SubStatus =~ "0xC0000380", "STATUS_SMARTCARD_WRONG_PIN",
SubStatus =~ "0xC0000381", "STATUS_SMARTCARD_CARD_BLOCKED",
SubStatus =~ "0xC0000382", "STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED",
SubStatus =~ "0xC0000383", "STATUS_SMARTCARD_NO_CARD",
SubStatus =~ "0xC0000384", "STATUS_SMARTCARD_NO_KEY_CONTAINER",
SubStatus =~ "0xC0000385", "STATUS_SMARTCARD_NO_CERTIFICATE",
SubStatus =~ "0xC0000386", "STATUS_SMARTCARD_NO_KEYSET",
SubStatus =~ "0xC0000387", "STATUS_SMARTCARD_IO_ERROR",
SubStatus =~ "0xC0000388", "STATUS_DOWNGRADE_DETECTED",
SubStatus =~ "0xC0000389", "STATUS_SMARTCARD_CERT_REVOKED",
"See - https://docs.microsoft.com/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55"
)
| project StartTimeUtc, EndTimeUtc, FailedVIPLogons, EventID, Activity, WorkstationName, Account, TargetAccount, TargetUserName, TargetDomainName, LogonType, LogonTypeName, LogonProcessName, Status, StatusDesc, SubStatus, SubStatusDesc
| extend timestamp = StartTimeUtc, AccountCustomEntity = Account```
## Enumeration of users and groups
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/enumeration_user_and_group.yaml)

### ATT&CK Tags

> Tactics: [u'Discovery']

### Hunt details

> Description: Finds attempts to list users or groups using the built-in Windows net tool 

> Query:

```let timeframe = 1d;
let ProcessCreationEvents=() {
let processEvents=SecurityEvent
| where EventID==4688
| project TimeGenerated, ComputerName=Computer,AccountName=SubjectUserName,        AccountDomain=SubjectDomainName,
FileName=tostring(split(NewProcessName, \\)[-1]),
ProcessCommandLine = CommandLine, 
FolderPath = "",
InitiatingProcessFileName=ParentProcessName,InitiatingProcessCommandLine="",InitiatingProcessParentFileName="";
processEvents};
ProcessCreationEvents
| where TimeGenerated >= ago(timeframe)
| where FileName == net.exe and AccountName != "" and ProcessCommandLine !contains \\  and ProcessCommandLine !contains /add 
| where (ProcessCommandLine contains  user  or ProcessCommandLine contains  group ) and (ProcessCommandLine endswith  /do or ProcessCommandLine endswith  /domain) 
| extend Target = extract("(?i)[user|group] (\"*[a-zA-Z0-9-_ ]+\"*)", 1, ProcessCommandLine) | filter Target  !=  
| summarize minTimeGenerated=min(TimeGenerated), maxTimeGenerated=max(TimeGenerated), count() by AccountName, Target, ProcessCommandLine, ComputerName
| project minTimeGenerated, maxTimeGenerated, count_, AccountName, Target, ProcessCommandLine, ComputerName
| sort by AccountName, Target
| extend timestamp = minTimeGenerated, AccountCustomEntity = AccountName, HostCustomEntity = ComputerName```
## Summary of failed user logons by reason of failure
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/FailedUserLogons.yaml)

### ATT&CK Tags

> Tactics: [u'CredentialAccess', u'LateralMovement']

### Hunt details

> Description: A summary of failed logons can be used to infer lateral movement with the intention of discovering credentials and sensitive data

> Query:

```let timeframe = 1d;
SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where AccountType == User and EventID == 4625
| extend Reason = case(
SubStatus == 0xc000005e, No logon servers available to service the logon request,
SubStatus == 0xc0000062, Account name is not properly formatted,
SubStatus == 0xc0000064, Account name does not exist,
SubStatus == 0xc000006a, Incorrect password,    SubStatus == 0xc000006d, Bad user name or password,
SubStatus == 0xc000006f, User logon blocked by account restriction,
SubStatus == 0xc000006f, User logon outside of restricted logon hours,
SubStatus == 0xc0000070, User logon blocked by workstation restriction,
SubStatus == 0xc0000071, Password has expired,
SubStatus == 0xc0000072, Account is disabled,
SubStatus == 0xc0000133, Clocks between DC and other computer too far out of sync,
SubStatus == 0xc000015b, The user has not been granted the requested logon right at this machine,
SubStatus == 0xc0000193, Account has expirated,
SubStatus == 0xc0000224, User is required to change password at next logon,
SubStatus == 0xc0000234, Account is currently locked out,
strcat(Unknown reason substatus: , SubStatus))
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count() by Reason
| extend timestamp = StartTimeUtc```
## Group added to Built in Domain Local or Global Group
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/GroupAddedToPrivlegeGroup.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'PrivilegeEscalation']

### Hunt details

> Description: A Group created in the last 7 days was added to a privileged built in domain local group or global group such as the Enterprise Admins, Cert Publishers or DnsAdmins.  Be sure to verify this is an expected addition

> Query:

```let timeframe = 7d;
// For AD SID mappings - https://docs.microsoft.com/windows/security/identity-protection/access-control/active-directory-security-groups
let WellKnownLocalSID = "S-1-5-32-5[0-9][0-9]$";
// The SIDs for DnsAdmins and DnsUpdateProxy can be different than *-1102 and -*1103. Check these SIDs in your domain before running the query 
let WellKnownGroupSID = "S-1-5-21-[0-9]*-[0-9]*-[0-9]*-5[0-9][0-9]$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-1102$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-1103$";
let GroupAddition = SecurityEvent 
| where TimeGenerated > ago(timeframe)
// 4728 - A member was added to a security-enabled global group
// 4732 - A member was added to a security-enabled local group
// 4756 - A member was added to a security-enabled universal group  
| where EventID in ("4728", "4732", "4756") 
| where AccountType == "User" and MemberName == "-"
// Exclude Remote Desktop Users group: S-1-5-32-555
| where TargetSid !in ("S-1-5-32-555")
| where TargetSid matches regex WellKnownLocalSID or TargetSid matches regex WellKnownGroupSID
| project GroupAddTime = TimeGenerated, GroupAddEventID = EventID, GroupAddActivity = Activity, GroupAddComputer = Computer, 
GroupAddTargetUserName = TargetUserName, GroupAddTargetDomainName = TargetDomainName, GroupAddTargetSid = TargetSid,  
GroupAddSubjectUserName = SubjectUserName, GroupAddSubjectUserSid = SubjectUserSid, GroupSid = MemberSid, Account, Computer
| extend AccountCustomEntity = Account, HostCustomEntity = Computer;
let GroupCreated = SecurityEvent
| where TimeGenerated > ago(timeframe)
// 4727 - A security-enabled global group was created
// 4731 - A security-enabled local group was created
// 4754 - A security-enabled universal group was created
| where EventID in ("4727", "4731", "4754")
| where AccountType == "User"
| project GroupCreateTime = TimeGenerated, GroupCreateEventID = EventID, GroupCreateActivity = Activity, GroupCreateComputer = Computer, 
GroupCreateTargetUserName = TargetUserName, GroupCreateTargetDomainName = TargetDomainName, GroupCreateSubjectUserName = SubjectUserName, 
GroupCreateSubjectDomainName = SubjectDomainName, GroupCreateSubjectUserSid = SubjectUserSid, GroupSid = TargetSid, Account, Computer;
GroupCreated
| join (
GroupAddition
) on GroupSid
| extend timestamp = GroupCreateTime, AccountCustomEntity = Account, HostCustomEntity = Computer```
## Host Exporting Mailbox and Removing Export
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/HostExportingMailboxAndRemovingExport.yaml)

### ATT&CK Tags

> Tactics: [u'Collection']

### Hunt details

> Description: This hunting query looks for hosts exporting a mailbox from an on-prem Exchange server, followed bythat same host removing the export within a short time window. This pattern has been observed by attackers when exfiltrating emails from a target environment. A Mailbox export is unlikely to be a common command run so look foractivity from unexpected hosts and accounts.Reference: https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/

> Query:

```// Adjust the timeframe to change the window events need to occur within to alert
let timeframe = 1h;
SecurityEvent
| where EventID == 4688
| where Process in~ ("powershell.exe", "cmd.exe")
| where CommandLine contains New-MailboxExportRequest
| summarize by Computer, timekey = bin(TimeGenerated, timeframe), CommandLine, SubjectUserName
| join kind=inner (SecurityEvent
| where EventID == 4688
| where Process in~ ("powershell.exe", "cmd.exe")
| where CommandLine contains Remove-MailboxExportRequest
| summarize by Computer, timekey = bin(TimeGenerated, timeframe), CommandLine, SubjectUserName) on Computer, timekey, SubjectUserName
| extend commands = pack_array(CommandLine1, CommandLine)
| summarize by timekey, Computer, tostring(commands), SubjectUserName
| project-reorder timekey, Computer, SubjectUserName, [commands]
| extend HostCustomEntity = Computer, AccountCustomEntity = SubjectUserName```
## Hosts with new logons
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/HostsWithNewLogons.yaml)

### ATT&CK Tags

> Tactics: [u'CredentialAccess', u'LateralMovement']

### Hunt details

> Description: Shows new accounts that have logged onto a host for the first time - this may clearly be benign activity but an account logging onto multiple hosts for the first time can also be used to look for evidence of that account being used to move laterally across a network.

> Query:

```let starttime = 7d;
let endtime = 1d;
let LogonEvents=() { 
let logonSuccess=SecurityEvent 
| where EventID==4624 
| project TimeGenerated, ComputerName=Computer, AccountName=TargetUserName, AccountDomain=TargetDomainName, IpAddress, ActionType=Logon;
let logonFail=SecurityEvent 
| where EventID==4625 
| project TimeGenerated, ComputerName=Computer, AccountName=TargetUserName, AccountDomain=TargetDomainName, IpAddress, ActionType=LogonFailure;
logonFail 
| union logonSuccess
};
LogonEvents 
| where TimeGenerated > ago(endtime) 
| where ActionType == Logon 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count() by ComputerName, AccountName 
| join kind=leftanti ( 
LogonEvents 
| where TimeGenerated between(ago(starttime)..ago(endtime)) 
| where ActionType == Logon 
| summarize count() by ComputerName, AccountName 
) on ComputerName, AccountName 
| summarize StartTimeUtc = min(StartTimeUtc), EndTimeUtc = max(EndTimeUtc), HostCount=dcount(ComputerName), HostSet=makeset(ComputerName, 10)  by AccountName, ComputerName
| extend timestamp = StartTimeUtc, AccountCustomEntity = AccountName```
## Least Common Parent And Child Process Pairs
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/Least_Common_Parent_Child_Process.yaml)

### ATT&CK Tags

> Tactics: [u'Execution']

### Hunt details

> Description: Looks across your environment for least common Parent/Child process combinations.  Will possibly find some malicious activity disguised as well known process names.  By ZanCo

> Query:

```let Allowlist = dynamic ([foo.exe, baz.exe]);
let Sensitivity = 5;
let StartDate = ago(7d);
let Duration = 7d;
SecurityEvent
| where EventID == 4688 and TimeGenerated > StartDate and TimeGenerated < (StartDate + Duration) and isnotnull(ParentProcessName)
| extend ProcArray = split(NewProcessName, \\), ParentProcArray = split(ParentProcessName, \\)
// ProcArrayLength is Folder Depth
| extend ProcArrayLength = arraylength(ProcArray), ParentProcArrayLength = arraylength(ParentProcArray)
| extend LastIndex = ProcArrayLength - 1, ParentLastIndex = ParentProcArrayLength - 1
| extend Proc = ProcArray[LastIndex], ParentProc = ParentProcArray[ParentLastIndex]
| where Proc !in (Allowlist)
| extend ParentChildPair = strcat(ParentProc ,  > , Proc)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), TimesSeen = count(), HostCount = dcount(Computer), Hosts = makeset(Computer), UserCount = dcount(SubjectUserName), Users = makeset(SubjectUserName) by ParentChildPair
| where TimesSeen < Sensitivity
| extend timestamp = StartTimeUtc```
## Least Common Processes by Command Line
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/Least_Common_Process_Command_Lines.yaml)

### ATT&CK Tags

> Tactics: [u'Execution']

### Hunt details

> Description: Looks across your environment for least common Process Command Lines, may be noisy and require allowlisting.  By ZanCo

> Query:

```let Allowlist = dynamic ([foo.exe, baz.exe]);
let Sensitivity = 5;
let StartDate = ago(7d);
let Duration = 7d;
SecurityEvent
| where EventID == 4688 and TimeGenerated > StartDate and TimeGenerated < (StartDate + Duration) and NewProcessName !endswith conhost.exe
| extend ProcArray = split(NewProcessName, \\)
// ProcArrayLength is Folder Depth
| extend ProcArrayLength = arraylength(ProcArray)
| extend LastIndex = ProcArrayLength - 1
| extend Proc = ProcArray[LastIndex]
| where Proc !in (Allowlist)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), TimesSeen = count(), HostCount = dcount(Computer), Hosts = makeset(Computer), UserCount = dcount(SubjectUserName), Users = makeset(SubjectUserName) by CommandLine
| where TimesSeen < Sensitivity
| extend timestamp = StartTimeUtc```
## Least Common Processes Including Folder Depth
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/Least_Common_Process_With_Depth.yaml)

### ATT&CK Tags

> Tactics: [u'Execution']

### Hunt details

> Description: Looks across your environment for least common Process Command Lines, may be noisy and require allowlisting.  By ZanCo

> Query:

```let Allowlist = dynamic ([foo.exe, baz.exe]);
let Sensitivity = 15;
let StartDate = ago(7d);
let Duration = 7d;
SecurityEvent
| where EventID == 4688 and TimeGenerated > StartDate and TimeGenerated < (StartDate + Duration)
| extend ProcArray = split(NewProcessName, \\)
// ProcArrayLength is Folder Depth
| extend ProcArrayLength = arraylength(ProcArray)
| extend LastIndex = ProcArrayLength - 1
| extend Proc = ProcArray[LastIndex]
| where Proc !in (Allowlist)
// ProcArray[0] is the procs Drive
| extend DriveDepthProc = strcat(ProcArray[0], -, ProcArrayLength, -, Proc)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), TimesSeen = count(), HostCount = dcount(Computer), Hosts = makeset(Computer), UserCount = dcount(SubjectUserName), Users = makeset(SubjectUserName) by DriveDepthProc
| where TimesSeen < Sensitivity
| extend timestamp = StartTimeUtc```
## Masquerading files
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/masquerading_files.yaml)

### ATT&CK Tags

> Tactics: [u'Execution']

### Hunt details

> Description: Malware writers often use windows system process names for their malicious process names to make them blend in with other legitimate commands that the Windows system executes.An analyst can create a simple query looking for a process named svchost.exe. It is recommended to filter out well-known security identifiers (SIDs) that are used to launch the legitimate svchost.exe process. The query also filters out the legitimate locations from which svchost.exe is launched.

> Query:

```let timeframe = 1d;
SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where NewProcessName endswith "\\svchost.exe"
| where SubjectUserSid !in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
| where NewProcessName !contains ":\\Windows\\System32"
| where NewProcessName !contains ":\\Windows\\Syswow64"
| summarize minTimeGenerated=min(TimeGenerated), maxTimeGenerated=max(TimeGenerated), count() by Computer, SubjectUserName, NewProcessName, CommandLine, Account
| project minTimeGenerated , maxTimeGenerated , count_ , Computer , SubjectUserName , NewProcessName , CommandLine, Account 
| extend timestamp = minTimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account```
## Multiple explicit credential usage - 4648 events
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/MultipleExplicitCredentialUsage4648Events.yaml)

### ATT&CK Tags

> Tactics: [u'Discovery', u'LateralMovement']

### Hunt details

> Description: Based on recent investigations related to Solorigate, adversaries were seen to obtain and abuse credentials of multiple accounts  to connect to multiple machines. This query uses Security Event 4648 (A logon was attempted using explicit credentials)  to find machines in an environment, from where different accounts were used to connect to multiple hosts. Scoring is done based on  protocols seen in Solorigate. While this mentions Solorigate, this hunting query can be used to identify this type of pattern for  any attacker. Reference - https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4648

> Query:

```let WellKnownLocalSIDs = "S-1-5-[0-9][0-9]$";
let protocols = dynamic([cifs, ldap, RPCSS, host , HTTP, RestrictedKrbHost, TERMSRV, msomsdksvc, mssqlsvc]);
SecurityEvent
| where TimeGenerated >= ago(1d)
| where EventID == 4648
| where SubjectUserSid != S-1-0-0 // this is the Nobody SID which really means No security principal was included.
| where not(SubjectUserSid matches regex WellKnownLocalSIDs) //excluding system account/service account as this is generally normal
| where TargetInfo has / //looking for only items that indicate an interesting protocol is included
| where Computer !has tostring(split(TargetServerName,$)[0])
| where TargetAccount !~ tostring(split(SubjectAccount,$)[0])
| extend TargetInfoProtocol = tolower(split(TargetInfo, /)[0]), TargetInfoMachine = toupper(split(TargetInfo, /)[1])
| extend TargetAccount = tolower(TargetAccount), SubjectAccount = tolower(SubjectAccount)
| extend UncommonProtocol = case(not(TargetInfoProtocol has_any (protocols)), TargetInfoProtocol, NotApplicable)
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), AccountsUsedCount = dcount(TargetAccount), AccountsUsed = make_set(TargetAccount), TargetMachineCount = dcount(TargetInfoMachine), 
TargetMachines = make_set(TargetInfoMachine), TargetProtocols = dcount(TargetInfoProtocol), Protocols = make_set(TargetInfoProtocol), Processes = make_set(Process) by Computer, SubjectAccount, UncommonProtocol
| where TargetMachineCount > 1 or UncommonProtocol != NotApplicable
| extend ProtocolCount = array_length(Protocols)
| extend ProtocolScore = case(
  Protocols has rpcss and Protocols has host and Protocols has cifs, 10, //observed in Solorigate and depending on which are used together the higher the score
  Protocols has rpcss and Protocols has host, 5,
  Protocols has rpcss and Protocols has cifs, 5,
  Protocols has host and Protocols has cifs, 5,
  Protocols has ldap or Protocols has rpcss or Protocols has host or Protocols has cifs, 1, //ldap is more commonly seen in general, this was also seen with Solorigate but not usually to the same machines as the others above
  UncommonProtocol != NotApplicable, 3,
  0 //other protocols may be of interest, but in relation to observations for enumeration/execution in Solorigate they receive 0
)
| extend Score = ProtocolScore + ProtocolCount + AccountsUsedCount
| where Score >= 9 or (UncommonProtocol != NotApplicable and Score >= 4) // Score must be 9 or better as this will include 5 points for atleast 2 of the interesting protocols + the count of protocols (min 2) + the number of accounts used for execution (min 2) = min of 9 OR score must be 4 or greater for an uncommon protocol
| extend TimePeriod = EndTime - StartTime //This identifies the time between start and finish for the use of the explicit credentials, shorter time period may indicate scripted executions
| project-away UncommonProtocol
| extend timestamp = StartTime, AccountCustomEntity = SubjectAccount, HostCustomEntity = Computer
| order by Score desc```
## New processes observed in last 24 hours
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/new_processes.yaml)

### ATT&CK Tags

> Tactics: [u'Execution']

### Hunt details

> Description: These new processes could be benign new programs installed on hosts; however, especially in normally stable environments, these new processes could provide an indication of an unauthorized/malicious binary that has been installed and run. Reviewing the wider context of the logon sessions in which these binaries ran can provide a good starting point for identifying possible attacks.

> Query:

```let starttime = 14d;
let endtime = 1d;
let ProcessCreationEvents=() {
let processEvents=SecurityEvent
| where EventID==4688
| where TimeGenerated >= ago(starttime) 
| project TimeGenerated, ComputerName=Computer,AccountName=SubjectUserName, AccountDomain=SubjectDomainName, FileName=tostring(split(NewProcessName, @)[(-1)]), ProcessCommandLine = CommandLine, InitiatingProcessFileName=ParentProcessName,InitiatingProcessCommandLine=,InitiatingProcessParentFileName=;
processEvents};
ProcessCreationEvents
| where TimeGenerated >= ago(starttime) and TimeGenerated < ago(endtime)
| summarize HostCount=dcount(ComputerName) by tostring(FileName)
| join kind=rightanti (
    ProcessCreationEvents
    | where TimeGenerated >= ago(endtime)
    | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), Computers = makeset(ComputerName) , HostCount=dcount(ComputerName) by tostring(FileName)
) on FileName
| project StartTimeUtc, Computers, HostCount, FileName
| extend timestamp = StartTimeUtc```
## Summary of users created using uncommon/undocumented commandline switches
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/persistence_create_account.yaml)

### ATT&CK Tags

> Tactics: [u'CredentialAccess', u'LateralMovement']

### Hunt details

> Description: Summarizes uses of uncommon & undocumented commandline switches to create persistenceUser accounts may be created to achieve persistence on a machine.Read more here: https://attack.mitre.org/wiki/Technique/T1136Query for users being created using "net user" command"net user" commands are noisy, so needs to be joined with another signal -e.g. in this example we look for some undocumented variations (e.g. /ad instead of /add)

> Query:

```let timeframe = 1d;
SecurityEvent
| where TimeGenerated >= ago(timeframe) 
| where EventID==4688
| project TimeGenerated, ComputerName=Computer,AccountName=SubjectUserName, 
    AccountDomain=SubjectDomainName, FileName=tostring(split(NewProcessName, \\)[-1]), 
    ProcessCommandLine = CommandLine, 
    FolderPath = "", InitiatingProcessFileName=ParentProcessName,
    InitiatingProcessCommandLine="",InitiatingProcessParentFileName=""
| where FileName in~ ("net.exe", "net1.exe")
| parse kind=regex flags=iU ProcessCommandLine with * "user " CreatedUser " " * "/ad"
| where not(FileName =~ "net1.exe" and InitiatingProcessFileName =~ "net.exe" and replace("net", "net1", InitiatingProcessCommandLine) =~ ProcessCommandLine)
| extend CreatedOnLocalMachine=(ProcessCommandLine !contains "/do")
| where ProcessCommandLine contains "/add" or (CreatedOnLocalMachine == 0 and ProcessCommandLine !contains "/domain")
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), MachineCount=dcount(ComputerName) by CreatedUser, CreatedOnLocalMachine, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| extend timestamp = StartTimeUtc, AccountCustomEntity = CreatedUser```
## PowerShell downloads
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/powershell_downloads.yaml)

### ATT&CK Tags

> Tactics: [u'Execution', u'CommandAndControl']

### Hunt details

> Description: Finds PowerShell execution events that could involve a download

> Query:

```let timeframe = 1d;
let ProcessCreationEvents=() {
let processEvents=SecurityEvent
| where EventID==4688
| project  TimeGenerated, ComputerName=Computer,AccountName=SubjectUserName,        AccountDomain=SubjectDomainName,
  FileName=tostring(split(NewProcessName, \\)[-1]),
ProcessCommandLine = CommandLine, 
InitiatingProcessFileName=ParentProcessName,InitiatingProcessCommandLine="",InitiatingProcessParentFileName="";
processEvents};
ProcessCreationEvents
| where TimeGenerated >= ago(timeframe) 
| where FileName in~ ("powershell.exe", "powershell_ise.exe")
| where ProcessCommandLine has "Net.WebClient"
   or ProcessCommandLine has "DownloadFile"
   or ProcessCommandLine has "Invoke-WebRequest"
   or ProcessCommandLine has "Invoke-Shellcode"
   or ProcessCommandLine contains "http:"
| project TimeGenerated, ComputerName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| top 100 by TimeGenerated
| extend timestamp = TimeGenerated, HostCustomEntity = ComputerName, AccountCustomEntity = AccountName```
## New PowerShell scripts encoded on the commandline
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/powershell_newencodedscipts.yaml)

### ATT&CK Tags

> Tactics: [u'Execution', u'CommandAndControl']

### Hunt details

> Description: Identify and decode new encoded powershell scripts this week versus previous 14 days

> Query:

```let starttime = 21d;
let midtime = 14d;
let endtime = 7d;
let ProcessCreationEvents=() {
let processEvents=SecurityEvent
| where EventID==4688
| project  TimeGenerated, ComputerName=Computer,AccountName=SubjectUserName,AccountDomain=SubjectDomainName,
  FileName=tostring(split(NewProcessName, \\)[-1]),
ProcessCommandLine = CommandLine, 
InitiatingProcessFileName=ParentProcessName,InitiatingProcessCommandLine="",InitiatingProcessParentFileName="";
processEvents};
let encodedPSScripts = 
ProcessCreationEvents 
| where TimeGenerated >= ago(midtime)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "-encodedCommand";
encodedPSScripts
| where TimeGenerated > ago(endtime)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count() by ProcessCommandLine
| parse ProcessCommandLine with * "-EncodedCommand " encodedCommand
| project StartTimeUtc, EndTimeUtc, decodedCommand=base64_decodestring(substring(encodedCommand, 0, 
 strlen(encodedCommand) - (strlen(encodedCommand) %8))), encodedCommand 
| join kind=anti (encodedPSScripts
  | where TimeGenerated between(ago(starttime)..ago(endtime))
  | summarize count() by ProcessCommandLine
  | parse ProcessCommandLine with * "-EncodedCommand " encodedCommand
  | project decodedCommand=base64_decodestring(substring(encodedCommand, 0, 
   strlen(encodedCommand) - (strlen(encodedCommand) %8))), encodedCommand 
) on encodedCommand, decodedCommand 
| extend timestamp = StartTimeUtc```
## Entropy for Processes for a given Host
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/ProcessEntropy.yaml)

### ATT&CK Tags

> Tactics: [u'Execution']

### Hunt details

> Description: Entropy calculation used to help identify Hosts where they have a high variety of processes(a high entropy process list on a given Host over time).This helps us identify rare processes on a given Host. Rare here means a process shows up on the Host relatively few times in the the last 7days.The Weight is calculated based on the Entropy, Process Count and Distinct Hosts with that Process. The lower the Weight/ProcessEntropy the, more interesting.The Weight calculation increases the Weight if the process executes more than once on the Host or has executed on more than 1 Hosts.In general, this should identify processes on a Host that are rare and rare for the environment.References: https://medium.com/udacity/shannon-entropy-information-gain-and-picking-balls-from-buckets-5810d35d54b4https://en.wiktionary.org/wiki/Shannon_entropy

> Query:

```// exclude when over # of machines have the process
let excludeThreshold = 10;
// exclude when more than percent (default 10%)
let ratioHighCount = 0.1;
// exclude when less than percent (default 3%)
let ratioMidCount = 0.03;
// Process count limit in one day per machine, perf improvement (default every 20 minutes for 24 hours - 3*24 = 72)
let procLimit = 3*24;
// Decrease possibility of hitting memory limit by removing high process count items across all machines (default every 10 minutes for 24 hours - 6*24 = 144)
let maxLimit = 6*24;
let removeHigh = SecurityEvent 
| where TimeGenerated >= ago(1d)
| where EventID == 4688 | summarize count() by NewProcessName = tolower(NewProcessName) | where count_ > maxLimit
| summarize make_set(NewProcessName);
let SecEvents = SecurityEvent
| where TimeGenerated >= ago(1d)
| where EventID == 4688 | where tolower(NewProcessName) !in~ (removeHigh)
// removing common items that may still show up in small environments, add here if you have additional exclusions 
| where NewProcessName !has :\\Windows\\System32\\conhost.exe and ParentProcessName !has :\\Windows\\System32\\conhost.exe 
| where ParentProcessName !has :\\Windows\\System32\\wuauclt.exe and NewProcessName !has:\\Windows\\System32\\wuauclt.exe and NewProcessName !startswith C:\\Windows\\SoftwareDistribution\\Download\\Install\\AM_Delta_Patch_ 
| where ParentProcessName !has :\\WindowsAzure\\GuestAgent_ and NewProcessName !has :\\WindowsAzure\\GuestAgent_ 
| where ParentProcessName !has :\\WindowsAzure\\WindowsAzureNetAgent_ and NewProcessName !has :\\WindowsAzure\\WindowsAzureNetAgent_ 
| where ParentProcessName !has :\\ProgramData\\Microsoft\\Windows Defender\\platform\\ and NewProcessName !has "\\Windows Defender Advanced Threat Protection\\SenseCncProxy.exe" and NewProcessName !has "\\Windows Defender Advanced Threat Protection\\SenseIR.exe.exe" 
| where NewProcessName !has :\\ProgramData\\Microsoft\\Windows Defender\\platform\\ 
| where NewProcessName !has :\\Windows\\Microsoft.NET\\Framework and not(NewProcessName endswith \\ngentask.exe or NewProcessName endswith \\ngen.exe) 
| where ParentProcessName !has :\\Windows\\Microsoft.NET\\Framework and not(ParentProcessName endswith \\ngentask.exe or ParentProcessName endswith \\ngen.exe) 
| where NewProcessName !has :\\Windows\\System32\\taskhostw.exe and ParentProcessName !has :\\Windows\\System32\\taskhostw.exe 
| where ParentProcessName !has :\\Windows\\SoftwareDistribution\\Download\\Install\\ and not(NewProcessName endswith \\MpSigStub.exe) 
| where NewProcessName !has :\\Program Files\\Microsoft Monitoring Agent\\Agent\\Health Service State\\ and ParentProcessName !has :\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe 
| where NewProcessName !has :\\Windows\\servicing\\trustedinstaller.exe 
| where ParentProcessName !has :\\Program Files\\Microsoft Dependency Agent\\bin\\MicrosoftDependencyAgent.exe 
| where ParentProcessName !has :\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe
| project TimeGenerated, EventID, Computer, SubjectUserSid, Account, AccountType, Process, NewProcessName, CommandLine, ParentProcessName, _ResourceId, SourceComputerId;
let Exclude = SecEvents 
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), ExcludeCompCount = dcount(Computer), ExcludeProcCount = count() by Process 
// Removing general limit for noise in one day 
| extend timediff = iff(datetime_diff(day, EndTime, StartTime) > 0, datetime_diff(day, EndTime, StartTime), 1) 
// Default exclude of 48 (2 per hour) or more executions in 24 hours on a given machine 
| where ExcludeProcCount > procLimit*timediff 
// Removing noisy processes for an environment, adjust as needed 
| extend compRatio = ExcludeCompCount/toreal(ExcludeProcCount) 
| where compRatio == 0 or (ExcludeCompCount > excludeThreshold and compRatio < ratioHighCount) or (ExcludeCompCount between (2 .. excludeThreshold) and compRatio < ratioMidCount);
let AllSecEvents =  
SecEvents | project Computer, Process 
| join kind= leftanti (  
SecEvents 
// Removing general limit for noise in one day 
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), procCount = count() by Computer, Process 
| extend timediff = iff(datetime_diff(day, EndTime, StartTime) > 0, datetime_diff(day, EndTime, StartTime), 1) 
// Default exclude 48 (2 per hour) or more executions in 24 hours on a given machine to remove them from overall comparison list 
| where procCount > procLimit*timediff 
) on Computer, Process 
| project Computer, Process;
// Removing noisy process from full list 
let Include = materialize(AllSecEvents 
| join kind= leftanti ( 
Exclude 
) on Process);
// Identifying prevalence for a given process in the environment 
let DCwPC = materialize(Include 
| summarize DistinctHostsProcessCount = dcount(Computer) by Process 
| join kind=inner ( 
Include 
) on Process 
| distinct Computer, Process, DistinctHostsProcessCount);
// Getting the Total process count on each host to use as the denominator in the entropy calc 
let AHPC = materialize(Include 
| summarize AllHostsProcessCount = count() by Computer 
| join kind=inner ( 
Include 
) on Computer 
| distinct Computer, Process, AllHostsProcessCount 
//Getting a decimal value for later computation 
| extend AHPCValue = todecimal(AllHostsProcessCount));
// Need the count of each class in my bucket or also said as count of ProcName(Class) per Host(Bucket) for use in the entropy calc 
let PCoH = Include 
| summarize ProcessCountOnHost = count() by Computer, Process 
| join kind=inner ( 
Include 
) on Computer,Process 
| distinct Computer, Process, ProcessCountOnHost 
//Getting a decimal value for later computation 
| extend PCoHValue = todecimal(ProcessCountOnHost); 
let Combined = DCwPC 
| join ( 
AHPC 
) on Computer, Process 
| join ( 
PCoH 
) on Computer, Process;
let Results = Combined 
// Entropy calculation 
| extend ProcessEntropy = -log2(PCoHValue/AHPCValue)*(PCoHValue/AHPCValue) 
// Calculating Weight, see details in description 
| extend Weight = toreal(ProcessEntropy*ProcessCountOnHost*DistinctHostsProcessCount) 
// Remove or increase value to see processes with low entropy, meaning more common. 
| where Weight <= 100
| project Computer, Process, Weight , ProcessEntropy, AllHostsProcessCount, ProcessCountOnHost, DistinctHostsProcessCount; 
// Join back full entry 
Results 
| join kind= inner ( 
SecEvents
| project TimeGenerated, EventID, Computer, SubjectUserSid, Account, AccountType, Process, NewProcessName, CommandLine, ParentProcessName, _ResourceId, SourceComputerId 
) on Computer, Process 
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), ResultCount = count() by EventID, Computer, SubjectUserSid, Account, AccountType, Weight, ProcessEntropy,  
Process, NewProcessName, CommandLine, ParentProcessName, AllHostsProcessCount, ProcessCountOnHost, DistinctHostsProcessCount, _ResourceId, SourceComputerId
| project-reorder StartTime, EndTime, ResultCount, EventID, Computer, SubjectUserSid, Account, AccountType, Weight, ProcessEntropy,  
Process, NewProcessName, CommandLine, ParentProcessName, AllHostsProcessCount, ProcessCountOnHost, DistinctHostsProcessCount, _ResourceId, SourceComputerId
| sort by Weight asc, ProcessEntropy asc, NewProcessName asc 
| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account```
## Rare processes run by Service accounts
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/RareProcbyServiceAccount.yaml)

### ATT&CK Tags

> Tactics: [u'Execution']

### Hunt details

> Description: Service accounts normally are supposed to perform a limited set of tasks in a stable environment. The query collects a list of service account and then joins them with rare processes in an environment to detect anomalous behaviours.

> Query:

```let timeframe = 1d;
let excludeList = dynamic ( ["NT AUTHORITY","Local System", "Local Service", "Network Service"] );
let List1 = datatable(AccountName:string)["MSSQLSERVER", "ReportServer", "MSDTSServer100", "IUSR"];         
// Provide a list of service account/ built-in accounts in an environment.
let List2 = SecurityEvent                                                                                   
// Self generating a list of Service account using event Id :4624
| where TimeGenerated >= ago(timeframe)
| where EventID == 4624
| where LogonType == "5"
| where not(Account has_any (excludeList))
| extend AccountName = Account 
| distinct AccountName;
let Accounts = List1 | union (List2 | distinct AccountName);
let ProcessCreationEvents=() {
    let processEvents=SecurityEvent
	| where TimeGenerated >= ago(timeframe)
    | where EventID==4688
    // filter out common randomly named files related to MSI installers and browsers
    | where not(NewProcessName matches regex @"\\TRA[0-9A-Fa-f]{3}\.tmp")
    | where not(NewProcessName matches regex @"\\TRA[0-9A-Fa-f]{4}\.tmp")
    | where not(NewProcessName matches regex @"Installer\\MSI[0-9A-Fa-f]{3}\.tmp")
    | where not(NewProcessName matches regex @"Installer\\MSI[0-9A-Fa-f]{4}\.tmp")
    | project TimeGenerated, 
      ComputerName=Computer,
      AccountName=SubjectUserName, 
      AccountDomain=SubjectDomainName,
      FileName=tostring(split(NewProcessName, \\)[-1]),
      ProcessCommandLine = CommandLine, 
      InitiatingProcessFileName=ParentProcessName,
      InitiatingProcessCommandLine="",
      InitiatingProcessParentFileName="";
    processEvents;
    };
    let normalizedProcesses = ProcessCreationEvents 
       // normalize guids
       | project TimeGenerated, AccountName, FileName = replace("[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}", "<guid>", FileName)
       // normalize digits away
       | project TimeGenerated, AccountName, FileName=replace(@\d, n, FileName); 
let freqs = normalizedProcesses
    | summarize frequency = count() by FileName
    | join kind= leftouter (
       normalizedProcesses
       | summarize Since=min(TimeGenerated), LastSeen=max(TimeGenerated)  by FileName, AccountName
    ) on FileName;
   let Finalfreqs = freqs 
    | where frequency <= toscalar( freqs | serialize | project frequency | summarize percentiles(frequency, 10))
    | order by frequency asc
    | project FileName, frequency, Since, LastSeen , AccountName 
    // restrict results to unusual processes seen in last day 
    | where LastSeen >= ago(timeframe);
Accounts
    | join kind= inner (
        Finalfreqs
) on AccountName
| where frequency < 10
| project-away AccountName1
| extend AccountCustomEntity = AccountName```
## Hosts running a rare process
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/RareProcess_forWinHost.yaml)

### ATT&CK Tags

> Tactics: [u'Execution', u'Persistence', u'Discovery', u'LateralMovement', u'Collection']

### Hunt details

> Description: Looking for hosts running a rare process. Less than 1% of the average for 30 days and less than a count of 100 on a given host or less than a 14 count on a given host from the last 7 days

> Query:

```let v_StartTime = ago(1d);
let v_EndTime = ago(1m);
let basic=materialize(
  SecurityEvent
    | where TimeGenerated >= ago(30d)
    | where EventID == 4688
    | summarize FullCount = count()
                , Count= countif(TimeGenerated between (v_StartTime .. v_EndTime))
                , min_TimeGenerated=min(TimeGenerated)
                , max_TimeGenerated=max(TimeGenerated) 
                      by Computer, NewProcessName
    | where Count > 0 and Count < 100);
let basic_avg = basic
    | summarize Avg = avg(FullCount) by  NewProcessName;
basic | project-away FullCount
  | join kind=inner 
basic_avg 
  on NewProcessName | project-away NewProcessName1
  | where Count < 14 or (Count <= Avg*0.01 and Count < 100) 
  | extend HostCustomEntity=Computer```
## Rare Process Path
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/RareProcessPath.yaml)

### ATT&CK Tags

> Tactics: [u'Execution']

### Hunt details

> Description: Identifies when a process is running from a rare path. This could indicate malicious or unexpected activity as attacks often try to use common process names running from non-standard locations

> Query:

```let end = startofday(now());
let start = end - 8d;
let processEvents=
SecurityEvent
| where TimeGenerated >= start and TimeGenerated <= end
| where EventID==4688
// excluding well known processes
| where NewProcessName !endswith :\\Windows\\System32\\conhost.exe and ParentProcessName !endswith :\\Windows\\System32\\conhost.exe
| where ParentProcessName !endswith ":\\Windows\\System32\\wuauclt.exe" and NewProcessName !startswith "C:\\Windows\\SoftwareDistribution\\Download\\Install\\AM_Delta_Patch_"
| where NewProcessName !has ":\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack_" and ParentProcessName !has ":\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack_"
| where NewProcessName !endswith ":\\WindowsAzure\\SecAgent\\WaSecAgentProv.exe" 
| where ParentProcessName !has ":\\WindowsAzure\\GuestAgent_" and NewProcessName !has ":\\WindowsAzure\\GuestAgent_"
| where ParentProcessName !has ":\\WindowsAzure\\WindowsAzureNetAgent_" and NewProcessName !has ":\\WindowsAzure\\WindowsAzureNetAgent_"
| where ParentProcessName !has ":\\ProgramData\\Microsoft\\Windows Defender\\platform\\" and ParentProcessName !endswith "\\MpCmdRun.exe" 
| where NewProcessName !has ":\\ProgramData\\Microsoft\\Windows Defender\\platform\\" and NewProcessName !endswith "\\MpCmdRun.exe" 
| where NewProcessName !has :\\Program Files\\Microsoft Monitoring Agent\\Agent\\
// filter out common randomly named paths and files
| where not(NewProcessName matches regex @"\\TRA[0-9A-Fa-f]{3}\.tmp")
| where not(NewProcessName matches regex @"\\TRA[0-9A-Fa-f]{4}\.tmp")
| where not(NewProcessName matches regex @"Installer\\MSI[0-9A-Fa-f]{3}\.tmp")
| where not(NewProcessName matches regex @"Installer\\MSI[0-9A-Fa-f]{4}\.tmp")
| where not(NewProcessName matches regex @"\\Windows\\Temp\\[0-9A-Za-z-]*\\DismHost\.exe")
| where not(NewProcessName matches regex @"\\Users\\[0-9A-Za-z-_~\.]*\\AppData\\Local\\Temp\\[0-9A-Za-z-]*\\DismHost\.exe")
| where not(NewProcessName matches regex @"\\Windows\\Temp\\[0-9A-Za-z-]*\\MpSigStub\.exe")
| where not(NewProcessName matches regex @"\\[0-9A-Za-z]*\\amd64\\setup\.exe") and (ParentProcessName !has ":\\Windows\\SoftwareDistribution\\Download\\Install\\" 
or ParentProcessName !has "\\AppData\\Local\\Temp\\mpam-")
| where not(NewProcessName matches regex @"\\Windows\\Microsoft.NET\\(Framework|Framework64)\\v[0-9].[0-9].[0-9]*\\(csc\.exe|cvtres\.exe|mscorsvw\.exe|ngentask\.exe|ngen\.exe)")
| where not(NewProcessName matches regex @"\\WindowsAzure\\GuestAgent_[0-9].[0-9].[0-9]*.[0-9]*_[0-9]*-[0-9]*-[0-9]*_[0-9]*\\") 
and not(ParentProcessName matches regex @"\\WindowsAzure\\GuestAgent_[0-9].[0-9].[0-9]*.[0-9]*_[0-9]*-[0-9]*-[0-9]*_[0-9]*\\")
| where not(NewProcessName matches regex @"\\[0-9A-Za-z]*\\epplauncher.exe")
| where not(NewProcessName matches regex @"\\Packages\\Plugins\\Microsoft\.")
| extend path_parts = parse_path(NewProcessName)
| extend ProcessPath = tostring(path_parts.DirectoryPath)
;
let normalizedProcessPath = processEvents
| extend NormalizedProcessPath = ProcessPath
// normalize guids
| project TimeGenerated, Computer, Account, Process, ProcessPath, 
NormalizedProcessPath = replace("[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}", "<guid>", NormalizedProcessPath)
// normalize digits away
| project TimeGenerated, Computer, Account, Process, ProcessPath, NormalizedProcessPath = replace(@\d, #, NormalizedProcessPath)
; 
let freqs = normalizedProcessPath
| summarize makelist(Computer), makelist(Account), makelist(ProcessPath), frequency=count() by NormalizedProcessPath, Process
| join kind= leftouter (
normalizedProcessPath
| summarize StartTimeUtc=min(TimeGenerated), EndTimeUtc=max(TimeGenerated) by NormalizedProcessPath, Process
) on NormalizedProcessPath, Process;
freqs
| where frequency <= toscalar( freqs | serialize | project frequency | summarize percentiles(frequency, 5))
| order by frequency asc  
| mvexpand Computer = list_Computer, Account = list_Account, ProcessPath = list_ProcessPath
| project StartTimeUtc, EndTimeUtc, frequency, Process, NormalizedProcessPath, tostring(ProcessPath), tostring(Computer), tostring(Account)```
## Hosts running a rare process with commandline
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/RareProcessWithCmdLine.yaml)

### ATT&CK Tags

> Tactics: [u'Execution', u'Persistence', u'Discovery', u'LateralMovement', u'Collection']

### Hunt details

> Description: Looking for hosts running a rare process. Less than 1% of the average for 30 days and less than a count of 100 on a given host or less than a 14 count on a given host from the last 7 days

> Query:

```let v_StartTime = ago(7d);
let v_EndTime = ago(1m);
let basic=materialize(
  SecurityEvent
    | where TimeGenerated >= ago(30d)
    | where EventID == 4688
    | where isnotempty(CommandLine) and NewProcessName !endswith ":\\windows\\system32\\conhost.exe" and CommandLine !~ NewProcessName and CommandLine !~ strcat(\",NewProcessName,\"," ")
    | extend CommandLine=tolower(CommandLine)
    | summarize FullCount = count()
                , Count= countif(TimeGenerated between (v_StartTime .. v_EndTime))
                , min_TimeGenerated=min(TimeGenerated)
                , max_TimeGenerated=max(TimeGenerated) 
                      by Computer, NewProcessName, CommandLine
    | where Count > 0 and Count < 100);
let basic_avg = basic
    | summarize Avg = avg(FullCount) by  NewProcessName, CommandLine;
basic | project-away FullCount
  | join kind=inner 
basic_avg 
  on NewProcessName, CommandLine | project-away NewProcessName1, CommandLine1
  | where Count < 7 or (Count <= Avg*0.01 and Count < 100) 
  | extend HostCustomEntity=Computer```
## Suspicious enumeration using Adfind tool
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/Suspicious_enumeration_using_adfind.yaml)

### ATT&CK Tags

> Tactics: [u'Execution', u'Discovery', u'Collection']

### Hunt details

> Description: Attackers can use Adfind which is administrative tool to gather information about Domain controllers, ADFS Servers. They may also rename executables with other benign tools on the system.Below query will look for adfind usage in commandline arguments irrespective of executable name in short span of time. You can limit query this to your DC and ADFS servers.Below references talk about suspicious use of adfind by adversaries.- https://thedfirreport.com/2020/05/08/adfind-recon/- https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html- https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/

> Query:

```let startdate = 1d;
let lookupwindow = 2m;
let threshold = 3; //number of commandlines in the set below
let DCADFSServersList = dynamic (["DCServer01", "DCServer02", "ADFSServer01"]); // Enter a reference list of hostnames for your DC/ADFS servers
let tokens = dynamic(["objectcategory","domainlist","dcmodes","adinfo","trustdmp","computers_pwdnotreqd","Domain Admins", "objectcategory=person", "objectcategory=computer", "objectcategory=*"]);
SecurityEvent
//| where Computer in (DCADFSServersList) // Uncomment to limit it to your DC/ADFS servers list if specified above or any pattern in hostnames (startswith, matches regex, etc).
| where TimeGenerated between (ago(startdate) .. now())
| where EventID == 4688
| where CommandLine has_any (tokens)
| where CommandLine matches regex "(.*)>(.*)"
| summarize Commandlines = make_set(CommandLine), LastObserved=max(TimeGenerated) by bin(TimeGenerated, lookupwindow), Account, Computer, ParentProcessName, NewProcessName
| extend Count = array_length(Commandlines)
| where Count > threshold```
## Suspicious Windows Login outside normal hours
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/Suspicious_Windows_Login_outside_normal_hours.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess', u'LateralMovement']

### Hunt details

> Description: Looking for suspiciopus interactive logon events which are outside normal logon hours for the user. Current day logon events are comapred with last 14 days activity and filtered for events which are above or below of historical logon hour range seen for the user.

> Query:

```let v_StartTime = 14d;
let v_EndTime = 2d;
let lookback = 1d;
let AllLogonEvents = materialize(
SecurityEvent
| where TimeGenerated  between (ago(v_StartTime)..ago(v_EndTime))
| where EventID in (4624, 4625)
| where LogonTypeName in~ (2 - Interactive,10 - RemoteInteractive)
| where AccountType =~ User
| extend HourOfLogin = hourofday(TimeGenerated), DayNumberofWeek = dayofweek(TimeGenerated)
| extend DayofWeek = case(
DayNumberofWeek == "00:00:00", "Sunday", 
DayNumberofWeek == "1.00:00:00", "Monday", 
DayNumberofWeek == "2.00:00:00", "Tuesday", 
DayNumberofWeek == "3.00:00:00", "Wednesday", 
DayNumberofWeek == "4.00:00:00", "Thursday", 
DayNumberofWeek == "5.00:00:00", "Friday", 
DayNumberofWeek == "6.00:00:00", "Saturday","InvalidTimeStamp")
// map the most common ntstatus codes
| extend StatusDesc = case(
Status =~ "0x80090302", "SEC_E_UNSUPPORTED_FUNCTION",
Status =~ "0x80090308", "SEC_E_INVALID_TOKEN",
Status =~ "0x8009030E", "SEC_E_NO_CREDENTIALS",
Status =~ "0xC0000008", "STATUS_INVALID_HANDLE",
Status =~ "0xC0000017", "STATUS_NO_MEMORY",
Status =~ "0xC0000022", "STATUS_ACCESS_DENIED",
Status =~ "0xC0000034", "STATUS_OBJECT_NAME_NOT_FOUND",
Status =~ "0xC000005E", "STATUS_NO_LOGON_SERVERS",
Status =~ "0xC000006A", "STATUS_WRONG_PASSWORD",
Status =~ "0xC000006D", "STATUS_LOGON_FAILURE",
Status =~ "0xC000006E", "STATUS_ACCOUNT_RESTRICTION",
Status =~ "0xC0000073", "STATUS_NONE_MAPPED",
Status =~ "0xC00000FE", "STATUS_NO_SUCH_PACKAGE",
Status =~ "0xC000009A", "STATUS_INSUFFICIENT_RESOURCES",
Status =~ "0xC00000DC", "STATUS_INVALID_SERVER_STATE",
Status =~ "0xC0000106", "STATUS_NAME_TOO_LONG",
Status =~ "0xC000010B", "STATUS_INVALID_LOGON_TYPE",
Status =~ "0xC000015B", "STATUS_LOGON_TYPE_NOT_GRANTED",
Status =~ "0xC000018B", "STATUS_NO_TRUST_SAM_ACCOUNT",
Status =~ "0xC0000224", "STATUS_PASSWORD_MUST_CHANGE",
Status =~ "0xC0000234", "STATUS_ACCOUNT_LOCKED_OUT",
Status =~ "0xC00002EE", "STATUS_UNFINISHED_CONTEXT_DELETED",
EventID == 4624, "Success",
"See - https://docs.microsoft.com/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55"
)
| extend SubStatusDesc = case(
SubStatus =~ "0x80090325", "SEC_E_UNTRUSTED_ROOT",
SubStatus =~ "0xC0000008", "STATUS_INVALID_HANDLE",
SubStatus =~ "0xC0000022", "STATUS_ACCESS_DENIED",
SubStatus =~ "0xC0000064", "STATUS_NO_SUCH_USER",
SubStatus =~ "0xC000006A", "STATUS_WRONG_PASSWORD",
SubStatus =~ "0xC000006D", "STATUS_LOGON_FAILURE",
SubStatus =~ "0xC000006E", "STATUS_ACCOUNT_RESTRICTION",
SubStatus =~ "0xC000006F", "STATUS_INVALID_LOGON_HOURS",
SubStatus =~ "0xC0000070", "STATUS_INVALID_WORKSTATION",
SubStatus =~ "0xC0000071", "STATUS_PASSWORD_EXPIRED",
SubStatus =~ "0xC0000072", "STATUS_ACCOUNT_DISABLED",
SubStatus =~ "0xC0000073", "STATUS_NONE_MAPPED",
SubStatus =~ "0xC00000DC", "STATUS_INVALID_SERVER_STATE",
SubStatus =~ "0xC0000133", "STATUS_TIME_DIFFERENCE_AT_DC",
SubStatus =~ "0xC000018D", "STATUS_TRUSTED_RELATIONSHIP_FAILURE",
SubStatus =~ "0xC0000193", "STATUS_ACCOUNT_EXPIRED",
SubStatus =~ "0xC0000380", "STATUS_SMARTCARD_WRONG_PIN",
SubStatus =~ "0xC0000381", "STATUS_SMARTCARD_CARD_BLOCKED",
SubStatus =~ "0xC0000382", "STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED",
SubStatus =~ "0xC0000383", "STATUS_SMARTCARD_NO_CARD",
SubStatus =~ "0xC0000384", "STATUS_SMARTCARD_NO_KEY_CONTAINER",
SubStatus =~ "0xC0000385", "STATUS_SMARTCARD_NO_CERTIFICATE",
SubStatus =~ "0xC0000386", "STATUS_SMARTCARD_NO_KEYSET",
SubStatus =~ "0xC0000387", "STATUS_SMARTCARD_IO_ERROR",
SubStatus =~ "0xC0000388", "STATUS_DOWNGRADE_DETECTED",
SubStatus =~ "0xC0000389", "STATUS_SMARTCARD_CERT_REVOKED",
EventID == 4624, "Success",
"See - https://docs.microsoft.com/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55"
)
| project StartTime = TimeGenerated, DayofWeek, HourOfLogin, EventID, Activity, IpAddress, WorkstationName, Computer, TargetUserName, TargetDomainName, ProcessName, SubjectUserName, PrivilegeList, LogonTypeName, StatusDesc, SubStatusDesc
);
AllLogonEvents
| where TargetDomainName !in ("Window Manager","Font Driver Host")
| summarize max(HourOfLogin), min(HourOfLogin), historical_DayofWeek=make_set(DayofWeek) by TargetUserName
| join kind= inner
(
    AllLogonEvents
    | where StartTime > ago(lookback)
)
on TargetUserName
// Filtering for logon events based on range of max and min of historical logon hour values seen
| where HourOfLogin > max_HourOfLogin or HourOfLogin < min_HourOfLogin
// Also populating additional column showing historical days of week when logon was seen
| extend historical_DayofWeek = tostring(historical_DayofWeek)
| summarize Total= count(), max(HourOfLogin), min(HourOfLogin), current_DayofWeek =make_set(DayofWeek), StartTime=max(StartTime), EndTime = min(StartTime), SourceIP = make_set(IpAddress), SourceHost = make_set(WorkstationName), SubjectUserName = make_set(SubjectUserName), HostLoggedOn = make_set(Computer) by EventID, Activity, TargetDomainName, TargetUserName , ProcessName , LogonTypeName, StatusDesc, SubStatusDesc, historical_DayofWeek
| extend historical_DayofWeek = todynamic(historical_DayofWeek) 
| extend timestamp = StartTime, AccountCustomEntity = TargetUserName```
## Uncommon processes - bottom 5%
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/uncommon_processes.yaml)

### ATT&CK Tags

> Tactics: [u'Execution']

### Hunt details

> Description: Shows the rarest processes seen running for the first time. (Performs best over longer time ranges - eg 3+ days rather than 24 hours!)These new processes could be benign new programs installed on hosts; However, especially in normally stable environments, these new processes could provide an indication of an unauthorized/malicious binary that has been installed and run. Reviewing the wider context of the logon sessions in which these binaries ran can provide a good starting point for identifying possible attacks.

> Query:

```let timeframe = 1d;
let ProcessCreationEvents=() {
let processEvents=SecurityEvent
| where EventID==4688
// filter out common randomly named files related to MSI installers and browsers
| where not(NewProcessName matches regex @"\\TRA[0-9A-Fa-f]{3}\.tmp")
| where not(NewProcessName matches regex @"\\TRA[0-9A-Fa-f]{4}\.tmp")
| where not(NewProcessName matches regex @"Installer\\MSI[0-9A-Fa-f]{3}\.tmp")
| where not(NewProcessName matches regex @"Installer\\MSI[0-9A-Fa-f]{4}\.tmp")
| project TimeGenerated, ComputerName=Computer, AccountName=SubjectUserName, AccountDomain=SubjectDomainName,
FileName=tostring(split(NewProcessName, \\)[-1]), ProcessCommandLine = CommandLine, 
InitiatingProcessFileName=ParentProcessName, InitiatingProcessCommandLine="", InitiatingProcessParentFileName="";
processEvents;
};
let normalizedProcesses = ProcessCreationEvents 
| where TimeGenerated >= ago(timeframe)
// normalize guids
| project TimeGenerated, FileName = replace("[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}", "<guid>", FileName)
// normalize digits away
| project TimeGenerated, FileName=replace(@\d, n, FileName); 
let freqs = normalizedProcesses
| summarize frequency=count() by FileName
| join kind= leftouter (
normalizedProcesses
| summarize Since=min(TimeGenerated), LastSeen=max(TimeGenerated) by FileName
) on FileName;
freqs 
| where frequency <= toscalar( freqs | serialize | project frequency | summarize percentiles(frequency, 5))
| order by frequency asc
| project FileName, frequency, Since, LastSeen 
// restrict results to unusual processes seen in last day 
| where LastSeen >= ago(1d)
| extend timestamp = LastSeen```
## Summary of user logons by logon type
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/User%20Logons%20By%20Logon%20Type.yaml)

### ATT&CK Tags

> Tactics: [u'CredentialAccess', u'LateralMovement']

### Hunt details

> Description: Comparing succesful and nonsuccessful logon attempts can be used to identify attempts to move laterally within the environment with the intention of discovering credentials and sensitive data.

> Query:

```let timeframe = 1d;
SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID in (4624, 4625)
| where AccountType == User 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), Amount = count() by LogonTypeName
| extend timestamp = StartTimeUtc```
## User Account added to Built in Domain Local or Global Group
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/UserAccountAddedToPrivlegeGroup.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'PrivilegeEscalation']

### Hunt details

> Description: User account was added to a privileged built in domain local group or global group such as the Enterprise Adminis, Cert Publishers or DnsAdminsBe sure to verify this is an expected addition.

> Query:

```let timeframe = 10d;
// For AD SID mappings - https://docs.microsoft.com/windows/security/identity-protection/access-control/active-directory-security-groups
let WellKnownLocalSID = "S-1-5-32-5[0-9][0-9]$";
let WellKnownGroupSID = "S-1-5-21-[0-9]*-[0-9]*-[0-9]*-5[0-9][0-9]$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-1102$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-1103$";
SecurityEvent 
| where TimeGenerated > ago(timeframe) 
| where AccountType == "User"
// 4728 - A member was added to a security-enabled global group
// 4732 - A member was added to a security-enabled local group
// 4756 - A member was added to a security-enabled universal group
| where EventID in ("4728", "4732", "4756")   
| where TargetSid matches regex WellKnownLocalSID or TargetSid matches regex WellKnownGroupSID
// Exclude Remote Desktop Users group: S-1-5-32-555
| where TargetSid !in ("S-1-5-32-555")
| project StartTimeUtc = TimeGenerated, EventID, Activity, Computer, TargetUserName, TargetDomainName, TargetSid, UserPrincipalName, SubjectUserName, SubjectUserSid 
| extend timestamp = StartTimeUtc, HostCustomEntity = Computer, AccountCustomEntity = UserPrincipalName```
## Long lookback User Account Created and Deleted within 10mins
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/UserAccountCreatedDeleted.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'PrivilegeEscalation']

### Hunt details

> Description: User account created and then deleted within 10 minutes across last 14 days

> Query:

```// TimeFrame is the number of lookback days, default is last 14 days
let timeframe = 14d;
// TimeDelta is the difference between when the account was created and when it was deleted, default is set to 10min or less
let timedelta = 10m;
SecurityEvent 
| where TimeGenerated > ago(timeframe) 
// A user account was created
| where EventID == "4720"
| where AccountType == "User"
| project creationTime = TimeGenerated, CreateEventID = EventID, Activity, Computer, TargetUserName, UserPrincipalName, 
AccountUsedToCreate = SubjectUserName, TargetSid, SubjectUserSid 
| join kind= inner (
   SecurityEvent
   | where TimeGenerated > ago(timeframe) 
   // A user account was deleted 
   | where EventID == "4726" 
| where AccountType == "User"
| project deletionTime = TimeGenerated, DeleteEventID = EventID, Activity, Computer, TargetUserName, UserPrincipalName, 
AccountUsedToDelete = SubjectUserName, TargetSid, SubjectUserSid 
) on Computer, TargetUserName
| where deletionTime - creationTime < timedelta
| extend TimeDelta = deletionTime - creationTime
| where tolong(TimeDelta) >= 0
| project TimeDelta, creationTime, CreateEventID, Computer, TargetUserName, UserPrincipalName, AccountUsedToCreate, 
deletionTime, DeleteEventID, AccountUsedToDelete
| extend timestamp = creationTime, HostCustomEntity = Computer, AccountCustomEntity = UserPrincipalName```
## User account added or removed from a security group by an unauthorized user
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/UserAdd_RemToGroupByUnauthorizedUser.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'PrivilegeEscalation']

### Hunt details

> Description: User account added or removed from a security group by an unauthorized user, pass in a list

> Query:

```// Create DataTable with your own values, example below shows dummy usernames that are authorized and for what domain
let List = datatable(AuthorizedUser:string, Domain:string)["Bob", "Domain", "joe", "domain", "MATT", "DOMAIN"];
let timeframe = 1d;
SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID in (4728, 4729, 4732, 4733, 4746, 4747, 4751, 4752, 4756, 4757, 4761, 4762)
| join kind= leftanti (
    List
    | project SubjectUserName = tolower(AuthorizedUser), SubjectDomainName = toupper(Domain)
) on SubjectUserName, SubjectDomainName
| project TimeGenerated, Computer, Account, SubjectUserName, SubjectDomainName, TargetAccount, EventID, Activity
| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account```
## User created by unauthorized user
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/UserCreatedByUnauthorizedUser.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'PrivilegeEscalation']

### Hunt details

> Description: User account created by an unauthorized user, pass in a list

> Query:

```// Create DataTable with your own values, example below shows dummy usernames that are authorized and for what domain
let List = datatable(AuthorizedUser:string, Domain:string)["Bob", "Domain", "joe", "domain", "MATT", "DOMAIN"];
let timeframe = 1d;
SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID == 4720
| where AccountType == "User"
| join kind= leftanti (
    List
    | project SubjectUserName = tolower(AuthorizedUser), SubjectDomainName = toupper(Domain)
) on SubjectUserName, SubjectDomainName
| project TimeGenerated, Computer, Account, SubjectUserName, SubjectDomainName, TargetAccount, EventID, Activity
| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account```
## VIP account more than 6 failed logons in 10
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/VIPAccountFailedLogons.yaml)

### ATT&CK Tags

> Tactics: [u'CredentialAccess']

### Hunt details

> Description: VIP Account with more than 6 failed logon attempts in 10 minutes, include your own VIP list in the table below

> Query:

```// Create DataTable with your own values, example below shows dummy usernames that are authorized and for what domain
let List = datatable(VIPUser:string, Domain:string)["Bob", "Domain", "joe", "domain", "MATT", "DOMAIN"];
let timeframe = 10m;
List | extend Account = strcat(Domain,"\\",VIPUser) | join kind= inner (
SecurityEvent 
| where TimeGenerated > ago(timeframe) 
| where EventID == "4625"
| where AccountType == "User"
| where LogonType == "2" or LogonType == "3"
) on Account 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), FailedVIPLogons = count() by LogonType, Account
| where FailedVIPLogons >= 6
| extend timestamp = StartTimeUtc, AccountCustomEntity = Account```
## Windows System Time changed on hosts
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SecurityEvent/WindowsSystemTimeChange.yaml)

### ATT&CK Tags

> Tactics: [u'DefenseEvasion']

### Hunt details

> Description: Identifies when the system time was changed on a Windows host which can indicate potential timestomping activities.Reference: Event ID 4616 is only available when the full event collection is enabled - https://docs.microsoft.com/azure/sentinel/connect-windows-security-events

> Query:

```SecurityEvent
| where EventID == 4616
| where not(ProcessName has_any (":\\Windows\\System32\\svchost.exe", ":\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe"))
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), count() by Computer, EventID, Activity, Account, AccountType, NewTime, PreviousTime, ProcessName, ProcessId, SubjectAccount, SubjectUserSid, SourceComputerId, _ResourceId
| extend timestamp = StartTime, HostCustomEntity = Computer, AccountCustomEntity = SubjectAccount```
## Anomalous Azure Active Directory apps based on authentication location
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/anomalous_app_azuread_signin.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: This query over Azure AD sign-in activity highlights Azure AD apps with an unusually high ratio of distinct geolocations versus total number of authentications

> Query:

```let timeRange=ago(14d);
let azureSignIns = 
SigninLogs
| where TimeGenerated >= timeRange
| where SourceSystem == "Azure AD"
| where OperationName == "Sign-in activity"
| project TimeGenerated, OperationName, AppDisplayName , Identity, UserId, UserPrincipalName, Location, LocationDetails, 
ClientAppUsed, DeviceDetail, ConditionalAccessPolicies;
azureSignIns
| extend locationString = strcat(tostring(LocationDetails["countryOrRegion"]), "/", 
tostring(LocationDetails["state"]), "/", tostring(LocationDetails["city"]), ";" , tostring(LocationDetails["geoCoordinates"]))
| summarize rawSigninCount = count(), countByAccount = dcount(UserId), locationCount = dcount(locationString) by AppDisplayName
// tail - pick a threshold to rule out the very-high volume Azure AD apps
| where rawSigninCount < 1000
// more locations than accounts
| where locationCount>countByAccount
// almost as many / more locations than sign-ins!
| where 1.0*rawSigninCount / locationCount > 0.8 
| order by rawSigninCount  desc
| join kind = leftouter (
   azureSignIns 
) on AppDisplayName 
| project AppDisplayName, TimeGenerated , Identity, rawSigninCount, countByAccount, locationCount,  
locationString = strcat(tostring(LocationDetails["countryOrRegion"]), "/", tostring(LocationDetails["state"]), "/", 
tostring(LocationDetails["city"]), ";" , tostring(LocationDetails["geoCoordinates"])), UserPrincipalName
| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName 
| order by AppDisplayName, TimeGenerated desc```
## Anomalous sign-in location by user account and authenticating application
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/AnomalousUserAppSigninLocationIncrease.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: This query over Azure Active Directory sign-in considers all user sign-ins for each Azure Active Directory application and picks out the most anomalous change in location profile for a user within an individual application. The intent is to hunt for user account compromise, possibly via a specific applicationvector.

> Query:

```let timeRange=ago(14d);
SigninLogs 
// Forces Log Analytics to recognize that the query should be run over full time range
| where TimeGenerated >= timeRange
| extend  locationString= strcat(tostring(LocationDetails["countryOrRegion"]), "/", 
tostring(LocationDetails["state"]), "/", tostring(LocationDetails["city"]), ";") 
| project TimeGenerated, AppDisplayName, UserPrincipalName, locationString 
// Create time series 
| make-series dLocationCount = dcount(locationString) on TimeGenerated in range(timeRange,now(), 1d) 
by UserPrincipalName, AppDisplayName 
// Compute best fit line for each entry 
| extend (RSquare, Slope, Variance, RVariance, Interception, LineFit) = series_fit_line(dLocationCount) 
// Chart the 3 most interesting lines  
// A 0-value slope corresponds to an account being completely stable over time for a given Azure Active Directory application
| top 3 by Slope desc
| extend AccountCustomEntity = UserPrincipalName 
| render timechart```
## Anomalous sign-in location by user account and authenticating application - with sign-in details
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/AnomalousUserAppSigninLocationIncreaseDetail.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: This query over Azure Active Directory sign-in considers all user sign-ins for each Azure Active Directory application and picks out the most anomalous change in location profile for a user within an individual application. The intent is to hunt for user account compromise, possibly via a specific applicationvector.This variation of the query joins the results back onto the original sign-in data to allow review of the location set with each identified user in tabular form.

> Query:

```let timeRange = ago(14d);
SigninLogs 
// Forces Log Analytics to recognize that the query should be run over full time range
| where TimeGenerated >= timeRange
| extend  locationString= strcat(tostring(LocationDetails["countryOrRegion"]), "/", 
tostring(LocationDetails["state"]), "/", tostring(LocationDetails["city"]), ";") 
| project TimeGenerated, AppDisplayName , UserPrincipalName, locationString 
// Create time series 
| make-series dLocationCount = dcount(locationString) on TimeGenerated in range(timeRange,now(), 1d) 
by UserPrincipalName, AppDisplayName 
// Compute best fit line for each entry 
| extend (RSquare,Slope,Variance,RVariance,Interception,LineFit)=series_fit_line(dLocationCount) 
// Chart the 3 most interesting lines  
// A 0-value slope corresponds to an account being completely stable over time for a given Azure Active Directory application
| top 3 by Slope desc  
// Extract the set of locations for each top user:
| join kind=inner (SigninLogs
| where TimeGenerated >= timeRange
| extend  locationString= strcat(tostring(LocationDetails["countryOrRegion"]), "/", 
tostring(LocationDetails["state"]), "/", tostring(LocationDetails["city"]), ";")
| summarize locationList = makeset(locationString), threeDayWindowLocationCount=dcount(locationString) by AppDisplayName, UserPrincipalName, 
timerange=bin(TimeGenerated, 3d)) on AppDisplayName, UserPrincipalName
| order by UserPrincipalName, timerange asc
| project timerange, AppDisplayName , UserPrincipalName, threeDayWindowLocationCount, locationList 
| order by AppDisplayName, UserPrincipalName, timerange asc
| extend timestamp = timerange, AccountCustomEntity = UserPrincipalName```
## Attempts to sign in to disabled accounts by account name
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/DisabledAccountSigninAttempts.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: Failed attempts to sign in to disabled accounts summarized by account name

> Query:

```let timeRange = 14d;
SigninLogs 
| where TimeGenerated >= ago(timeRange)
| where ResultType == "50057" 
| where ResultDescription == "User account is disabled. The account has been disabled by an administrator." 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count() by AppDisplayName, UserPrincipalName
| extend timestamp = StartTimeUtc, AccountCustomEntity = UserPrincipalName
| order by count_ desc```
## Attempts to sign in to disabled accounts by IP address
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/DisabledAccountSigninAttemptsByIP.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: Failed attempts to sign in to disabled accounts summarized by the IP address from from the sign-in attempts originate

> Query:

```let timeRange = 14d;
SigninLogs 
| where TimeGenerated >= ago(timeRange)
| where ResultType == "50057" 
| where ResultDescription == "User account is disabled. The account has been disabled by an administrator." 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), numberAccountsTargeted = dcount(UserPrincipalName), 
numberApplicationsTargeted = dcount(AppDisplayName), accountSet = makeset(UserPrincipalName), applicationSet=makeset(AppDisplayName), 
numberLoginAttempts = count() by IPAddress
| extend timestamp = StartTimeUtc, IPCustomEntity = IPAddress
| order by numberLoginAttempts desc```
## Inactive or new account signins
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/InactiveAccounts.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: Query for accounts seen signing in for the first time - these could be associatedwith stale/inactive accounts that ought to have been deleted but werent - and have subseuqently been compromised. Results for user accounts created in the last 7 days are filtered out

> Query:

```//Inactive accounts that sign in - first-time logins for accounts created in last 7 days are filtered out
let starttime = 14d;
let midtime = 7d;
let endtime = 1d;
SigninLogs
| where TimeGenerated >= ago(endtime)
// successful sign-in
| where ResultType == 0
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), loginCountToday=count() by UserPrincipalName, Identity
| join kind=leftanti (
   SigninLogs
   // historical successful sign-in
   | where TimeGenerated < ago(endtime)
   | where TimeGenerated >= ago(starttime)
   | where ResultType == 0
   | summarize by UserPrincipalName, Identity
) on UserPrincipalName 
| join kind= leftanti (
   // filter out newly created user accounts
   AuditLogs
   | where TimeGenerated >= ago(midtime)
   | where OperationName == "Add user" 
   // Normalize to lower case in order to match against equivalent UPN in Signin logs
   | extend NewUserPrincipalName = tolower(extractjson("$.userPrincipalName", tostring(TargetResources[0]), typeof(string)))
) on $left.UserPrincipalName == $right.NewUserPrincipalName 
| extend timestamp = StartTimeUtc, AccountCustomEntity = UserPrincipalName```
## Login attempts using Legacy Auth
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/LegacyAuthAttempt.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess', u'Persistence']

### Hunt details

> Description: This query over Azure AD sign-in activity highlights use of legacy authentication protocol in the environment. Because conditional access policies are not evaluated when legacy authentication is used, legacy authentication can be used to circumvent all Azure Conditional Access policies.

> Query:

```let endtime = 1d;
let starttime = 7d;
let legacyAuthentications =
SigninLogs
| where TimeGenerated >= ago(starttime)
// success logons only
| where ResultType == 0
| extend ClientAppUsed = iff(isempty(ClientAppUsed)==true,"Unknown" ,ClientAppUsed)
| extend isLegacyAuth = case(
ClientAppUsed contains "Browser", "No", 
ClientAppUsed contains "Mobile Apps and Desktop clients", "No", 
ClientAppUsed contains "Exchange ActiveSync", "No", 
ClientAppUsed contains "Other clients", "Yes", 
"Unknown")
| where isLegacyAuth=="Yes";
legacyAuthentications 
| where TimeGenerated >= ago(endtime)
// Dont alert for accounts already seen using legacy auth in prior 7 days
| join kind=leftanti (
   legacyAuthentications 
   | where TimeGenerated between(ago(starttime) .. ago(endtime))
) on UserPrincipalName, ClientAppUsed, AppDisplayName, IPAddress
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser
| extend LocationString= strcat(tostring(LocationDetails["countryOrRegion"]), "/", 
tostring(LocationDetails["state"]), "/", tostring(LocationDetails["city"]))
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), AttemptCount = count() 
by UserPrincipalName, ClientAppUsed, AppDisplayName, IPAddress, isLegacyAuth, tostring(OS), tostring(Browser), LocationString
| sort by AttemptCount desc nulls last 
| extend timestamp = StartTimeUtc, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress```
## Login spike with increase failure rate
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/LoginSpikeWithIncreaseFailureRate.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: This query over SiginLogs will summarise the total number of login attempts for each hour of the day on week days, this can be edited.The query then uses Kusto anomaly detection to find login spikes for each hour across all days. The query will then calculate thepercentage change between the anomalous period and the average logins for that period. Finally the query will determine the successand failure rate for logins for the given 1 hour period, if a specified % change in logins is detected alongside a specified failure ratea result is presented.

> Query:

```let timerange = 30d;
let failureThreshold = 15;
let percentageChangeThreshold = 50;
SigninLogs
//Collect number of users logging in for each hour
| where TimeGenerated > ago(timerange)
| summarize dcount(UserPrincipalName) by bin(TimeGenerated, 1h)
| extend hour = datetime_part("Hour",TimeGenerated)
| extend day = dayofweek(TimeGenerated)
//Exclude Saturday and Sunday as they skew the data, change depending on your weekend days
| where day != 6d and day != 7d
| order by TimeGenerated asc
//Summarise users trying to authenticate by each hour of the day
| summarize make_list(dcount_UserPrincipalName), make_list(TimeGenerated), avg(dcount_UserPrincipalName), make_list(day) by hour
//Find outlier hours where the number of users trying to authenticate spikes, expand and then keep only anomalous rows
| extend series_decompose_anomalies(list_dcount_UserPrincipalName)
| mv-expand list_dcount_UserPrincipalName, series_decompose_anomalies_list_dcount_UserPrincipalName_ad_flag, list_TimeGenerated, list_day
| where series_decompose_anomalies_list_dcount_UserPrincipalName_ad_flag == 1
//Calculate the percentage change between the spike and the average users authenticating
| project TimeGenerated=todatetime(list_TimeGenerated), Hour=hour, WeekDay=list_day, AccountsAuthenticating=list_dcount_UserPrincipalName, AverageAccountsAuthenticatin=round(avg_dcount_UserPrincipalName, 0), PercentageChange = round  ((list_dcount_UserPrincipalName - avg_dcount_UserPrincipalName) / avg_dcount_UserPrincipalName * 100,   2)
| order by PercentageChange desc 
//As an additional feature we collect successful and unsuccessful logins during the 1h windows with anomalies
| join kind=inner(
SigninLogs 
| where TimeGenerated >= ago(timerange) 
| where ResultType == "0" 
| summarize Success=dcount(UserPrincipalName), SuccessAccounts=make_set(UserPrincipalName) by bin(TimeGenerated, 1h)
| join kind=inner(
    SigninLogs 
    | where TimeGenerated >= ago(timerange) 
    //Failed sign-ins based on failed username/password combos or failed MFA
    | where ResultType in ("50126", "50074", "50057", "51004") 
    | summarize Failed=dcount(UserPrincipalName), FailedAccounts=make_set(UserPrincipalName) by bin(TimeGenerated, 1h)
) on TimeGenerated
| project-away TimeGenerated1
| extend Total = Failed + Success
| project TimeGenerated, SuccessRate = round((toreal(Success) / toreal(Total)) *100) , round(FailureRate = (toreal(Failed) / toreal(Total)) *100), SuccessAccounts, FailedAccounts
) on TimeGenerated
| order by PercentageChange
| project-away TimeGenerated1
//Thresholds, 15% account authentication failure rate at a 50% increase in accounts attempting to authenticate by default
//Comment out line below to see all anomalous results
| where FailureRate >= failureThreshold and PercentageChange >= percentageChangeThreshold```
## Login attempt by Blocked MFA user
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/MFAUserBlocked.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: An account could be blocked if there are too many failed authentication attempts in a row. This hunting query identifies if a MFA user account that is set to blocked tries to login to Azure AD.

> Query:

```let timeRange = 1d;
let lookBack = 7d;
let isGUID = "[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}";
let MFABlocked = SigninLogs
| where TimeGenerated >= ago(timeRange)
| where ResultType != "0" 
| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails), Status = strcat(ResultType, ": ", ResultDescription)
| where StatusDetails =~ "MFA denied; user is blocked"
| extend Unresolved = iff(Identity matches regex isGUID, true, false);
// Lookup up resolved identities from last 7 days
let identityLookup = SigninLogs
| where TimeGenerated >= ago(lookBack)
| where not(Identity matches regex isGUID)
| summarize by UserId, lu_UserDisplayName = UserDisplayName, lu_UserPrincipalName = UserPrincipalName;
// Join resolved names to unresolved list from MFABlocked signins
let unresolvedNames = MFABlocked | where Unresolved == true | join kind= inner (
 identityLookup 
) on UserId
| extend UserDisplayName = lu_UserDisplayName, UserPrincipalName = lu_UserPrincipalName
| project-away lu_UserDisplayName, lu_UserPrincipalName;
// Join Signins that had resolved names with list of unresolved that now have a resolved name
let u_MFABlocked = MFABlocked | where Unresolved == false | union unresolvedNames;
u_MFABlocked 
| extend OS = tostring(DeviceDetail.operatingSystem), Browser = tostring(DeviceDetail.browser)
| extend FullLocation = strcat(Location,|, LocationDetails.state, |, LocationDetails.city)
| summarize TimeGenerated = makelist(TimeGenerated), Status = makelist(Status), IPAddresses = makelist(IPAddress), IPAddressCount = dcount(IPAddress), 
  AttemptCount = count() by UserPrincipalName, UserId, UserDisplayName, AppDisplayName, Browser, OS, FullLocation , CorrelationId 
| mvexpand TimeGenerated, IPAddresses, Status
| extend TimeGenerated = todatetime(tostring(TimeGenerated)), IPAddress = tostring(IPAddresses), Status = tostring(Status)
| project-away IPAddresses
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserPrincipalName, UserId, UserDisplayName, Status,  IPAddress, IPAddressCount, AppDisplayName, Browser, OS, FullLocation
| extend timestamp = StartTime, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress```
## Azure Active Directory signins from new locations
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/new_locations_azuread_signin.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: New Azure Active Directory signin locations today versus historical Azure Active Directory signin dataIn the case of password spraying or brute force attacks one might see authentication attempts for many accounts from a new location

> Query:

```let starttime = 14d;
let endtime = 1d;
let countThreshold = 1;
SigninLogs
| where TimeGenerated >= ago(endtime)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), perIdentityAuthCount = count() 
by Identity, locationString = strcat(tostring(LocationDetails["countryOrRegion"]), "/", tostring(LocationDetails["state"]), "/", 
tostring(LocationDetails["city"]), ";" , tostring(LocationDetails["geoCoordinates"]))
| summarize StartTimeUtc = min(StartTimeUtc), EndTimeUtc = max(EndTimeUtc), distinctAccountCount = count(), identityList=makeset(Identity) by locationString
| extend identityList = iff(distinctAccountCount<10, identityList, "multiple (>10)")
| join kind= anti (
SigninLogs
  | where TimeGenerated >= ago(starttime) and TimeGenerated < ago(endtime)
  | project locationString= strcat(tostring(LocationDetails["countryOrRegion"]), "/", tostring(LocationDetails["state"]), "/", 
  tostring(LocationDetails["city"]), ";" , tostring(LocationDetails["geoCoordinates"]))
  | summarize priorCount = count() by locationString
) 
on locationString
// select threshold above which #new accounts from a new location is deemed suspicious
| where distinctAccountCount > countThreshold
| extend timestamp = StartTimeUtc```
## Azure Active Directory sign-in burst from multiple locations
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/signinBurstFromMultipleLocations.yaml)

### ATT&CK Tags

> Tactics: [u'CredentialAccess']

### Hunt details

> Description: This query over Azure Active Directory sign-in activity highlights accounts associatedwith multiple authentications from different geographical locations in a short space of time.

> Query:

```let timeRange = ago(10d);
let signIns = SigninLogs
| where TimeGenerated >= timeRange
| extend locationString= strcat(tostring(LocationDetails["countryOrRegion"]), "/",
 tostring(LocationDetails["state"]), "/", tostring(LocationDetails["city"]))
| where locationString != "//" 
// filter out signins associated with top 100 signin locations 
| join kind=anti (
SigninLogs
  | extend locationString= strcat(tostring(LocationDetails["countryOrRegion"]), "/", 
  tostring(LocationDetails["state"]), "/", tostring(LocationDetails["city"]))
  | where locationString != "//"
  | summarize count() by locationString
  | order by count_ desc
  | take 100) on locationString ; // TODO - make this threshold percentage-based
// We will perform a time window join to identify signins from multiple locations within a 10-minute period
let lookupWindow = 10m;
let lookupBin = lookupWindow / 2.0; // lookup bin = equal to 1/2 of the lookup window
signIns 
| project-rename Start=TimeGenerated 
| extend TimeKey = bin(Start, lookupBin)
| join kind = inner (
signIns 
| project-rename End=TimeGenerated, EndLocationString=locationString 
  // TimeKey on the right side of the join - emulates this authentication appearing several times
  | extend TimeKey = range(bin(End - lookupWindow, lookupBin),
  bin(End, lookupBin), lookupBin)
  | mvexpand TimeKey to typeof(datetime) // translate TimeKey arrange range to a column
) on Identity, TimeKey
| where End > Start
| project timeSpan = End - Start, Identity, locationString, EndLocationString,tostring(Start), tostring(End), UserPrincipalName
| where locationString != EndLocationString
| summarize by timeSpan, Identity, locationString, EndLocationString, Start, End, UserPrincipalName
| extend timestamp = Start, AccountCustomEntity = UserPrincipalName 
| order by Identity```
## Signin Logs with expanded Conditional Access Policies
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/SignInLogsWithExpandedPolicies.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: Example query for SigninLogs showing how to break out packed fields.  In this case extending conditional access Policies 

> Query:

```let timeframe = 1d;
SigninLogs 
| where TimeGenerated >= ago(timeframe)
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser
| extend ConditionalAccessPol0Name = tostring(ConditionalAccessPolicies[0].displayName), ConditionalAccessPol0Result = tostring(ConditionalAccessPolicies[0].result)
| extend ConditionalAccessPol1Name = tostring(ConditionalAccessPolicies[1].displayName), ConditionalAccessPol1Result = tostring(ConditionalAccessPolicies[1].result)
| extend ConditionalAccessPol2Name = tostring(ConditionalAccessPolicies[2].displayName), ConditionalAccessPol2Result = tostring(ConditionalAccessPolicies[2].result)
| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
| extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city)
| extend Date = startofday(TimeGenerated), Hour = datetime_part("Hour", TimeGenerated)
| summarize count() by Date, Identity, UserDisplayName, UserPrincipalName, IPAddress, ResultType, ResultDescription, StatusCode, StatusDetails, 
ConditionalAccessPol0Name, ConditionalAccessPol0Result, ConditionalAccessPol1Name, ConditionalAccessPol1Result, ConditionalAccessPol2Name, ConditionalAccessPol2Result, 
Location, State, City
| extend timestamp = Date, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
| sort by Date```
## Signins From VPS Providers
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/Signins-From-VPS-Providers.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: Looks for successful logons from known VPS provider network ranges with suspicious token based logon patterns.This is not an exhaustive list of VPS provider ranges but covers some of the most prevelent providers observed.

> Query:

```let IP_Data = (externaldata(network:string)
[@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/VPS_Networks.csv"] with (format="csv"));
SigninLogs
| where ResultType == 0
| extend additionalDetails = tostring(Status.additionalDetails)
| evaluate ipv4_lookup(IP_Data, IPAddress, network, return_unmatched = false)
| summarize make_set(additionalDetails), min(TimeGenerated), max(TimeGenerated) by IPAddress, UserPrincipalName
// Uncomment the remaining lines to only see logons from VPS providers with token only logons.
//| where array_length(set_additionalDetails) == 2
//| where (set_additionalDetails[1] == "MFA requirement satisfied by claim in the token" and set_additionalDetails[0] == "MFA requirement satisfied by claim provided by external provider") or (set_additionalDetails[0] == "MFA requirement satisfied by claim in the token" and set_additionalDetails[1] == "MFA requirement satisfied by claim provided by external provider")
| extend timestamp = min_TimeGenerated, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
| project IPCustomEntity, AccountCustomEntity, timestamp, max_TimeGenerated```
## Sign-ins from IPs that attempt sign-ins to disabled accounts
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/SuccessfulAccount-SigninAttemptsByIPviaDisabledAccounts.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess', u'Persistence']

### Hunt details

> Description: Identifies IPs with failed attempts to sign in to one or more disabled accounts signed in successfully to another account.References: https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes50057 - User account is disabled. The account has been disabled by an administrator. This analytic will additionally identify the successful signed in accounts as the mapped account entities for investigation in Sentinel.

> Query:

```let lookBack = 1d;
let threshold = 100;
SigninLogs 
| where TimeGenerated >= ago(lookBack)
| where ResultType == "50057" 
| where ResultDescription == "User account is disabled. The account has been disabled by an administrator." 
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), disabledAccountLoginAttempts = count(), 
disabledAccountsTargeted = dcount(UserPrincipalName), applicationsTargeted = dcount(AppDisplayName), disabledAccountSet = makeset(UserPrincipalName), 
applicationSet = makeset(AppDisplayName) by IPAddress
| order by disabledAccountLoginAttempts desc
| join kind= leftouter (
    // Consider these IPs suspicious - and alert any related  successful sign-ins
    SigninLogs
    | where TimeGenerated >= ago(lookBack)
    | where ResultType == 0
    | summarize successfulAccountSigninCount = dcount(UserPrincipalName), successfulAccountSigninSet = makeset(UserPrincipalName, 15) by IPAddress
    // Assume IPs associated with sign-ins from 100+ distinct user accounts are safe
    | where successfulAccountSigninCount < threshold
) on IPAddress  
// IPs from which attempts to authenticate as disabled user accounts originated, and had a non-zero success rate for some other account
| where successfulAccountSigninCount != 0
// Successful Account Signins occur within the same lookback period as the failed 
| extend SuccessBeforeFailure = iff(TimeGenerated < StartTime, true, false) 
| project StartTime, EndTime, IPAddress, disabledAccountLoginAttempts, disabledAccountsTargeted, disabledAccountSet, applicationSet, 
successfulAccountSigninCount, successfulAccountSigninSet
| order by disabledAccountLoginAttempts
// Break up the string of Succesfully signed into accounts into individual events
| mvexpand successfulAccountSigninSet
| extend AccountCustomEntity = tostring(successfulAccountSigninSet), timestamp = StartTime, IPCustomEntity = IPAddress```
## Same User - Successful logon for a given App and failure on another App within 1m and low distribution
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/SuccessThenFail_SameUserDiffApp.yaml)

### ATT&CK Tags

> Tactics: [u'Discovery', u'LateralMovement']

### Hunt details

> Description: This identifies when a user account successfully logs onto a given App and within 1 minute fails to logon to a different App.This may indicate a malicious attempt at accessing disallowed Apps for discovery or potential lateral movement

> Query:

```let timeFrame = ago(1d);
let logonDiff = 1m;
let Success = SigninLogs 
| where TimeGenerated >= timeFrame 
| where ResultType == "0" 
| where AppDisplayName !in ("Office 365 Exchange Online", "Skype for Business Online", "Office 365 SharePoint Online")
| project SuccessLogonTime = TimeGenerated, UserPrincipalName, IPAddress , SuccessAppDisplayName = AppDisplayName;
let Fail = SigninLogs 
| where TimeGenerated >= timeFrame 
| where ResultType !in ("0", "50140") 
| where ResultDescription !~ "Other" 
| where AppDisplayName !in ("Office 365 Exchange Online", "Skype for Business Online", "Office 365 SharePoint Online")
| project FailedLogonTime = TimeGenerated, UserPrincipalName, IPAddress , FailedAppDisplayName = AppDisplayName, ResultType, ResultDescription;
let InitialDataSet = 
Success | join kind= inner (
Fail
) on UserPrincipalName, IPAddress 
| where isnotempty(FailedAppDisplayName)
| where SuccessLogonTime < FailedLogonTime and FailedLogonTime - SuccessLogonTime <= logonDiff and SuccessAppDisplayName != FailedAppDisplayName;
let InitialHits = 
InitialDataSet
| summarize FailedLogonTime = min(FailedLogonTime), SuccessLogonTime = min(SuccessLogonTime) 
by UserPrincipalName, SuccessAppDisplayName, FailedAppDisplayName, IPAddress, ResultType, ResultDescription;
// Only take hits where there is 5 or less distinct AppDisplayNames on the success side as this limits highly active applications where failures occur more regularly
let Distribution =
InitialDataSet
| summarize count(SuccessAppDisplayName) by SuccessAppDisplayName, ResultType
| where count_SuccessAppDisplayName <= 5;
InitialHits | join (
   Distribution 
) on SuccessAppDisplayName, ResultType
| project UserPrincipalName, SuccessLogonTime, IPAddress, SuccessAppDisplayName, FailedLogonTime, FailedAppDisplayName, ResultType, ResultDescription 
| extend timestamp = SuccessLogonTime, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress```
## Failed attempt to access Azure Portal
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/UnauthUser_AzurePortal.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: Access attempts to Azure Portal from an unauthorized user.  Either invalid password or the user account does not exist.

> Query:

```let timeRange=ago(7d);
SigninLogs
| where TimeGenerated >= timeRange
| where AppDisplayName contains "Azure Portal"
// 50126 - Invalid username or password, or invalid on-premises username or password.
// 50020? - The user doesnt exist in the tenant.
| where ResultType in ( "50126" , "50020")
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser
| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
| extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), IPAddresses = makeset(IPAddress), DistinctIPCount = dcount(IPAddress), 
makeset(OS), makeset(Browser), makeset(City), AttemptCount = count() 
by UserDisplayName, UserPrincipalName, AppDisplayName, ResultType, ResultDescription, StatusCode, StatusDetails, Location, State
| extend timestamp = StartTimeUtc, AccountCustomEntity = UserPrincipalName
| sort by AttemptCount```
## User Login IP Address Teleportation
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SigninLogs/UserLoginIPAddressTeleportation.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: This query over SiginLogs will identify user accounts that have logged in from two different countrieswithin a specified time window, by default this is a 10 minute window either side of the previous login.This query will detect users roaming onto VPNs, its possible to exclude known VPN IP address ranges.

> Query:

```let timeRange = 7d;
let windowTime = 20min / 2; //Window to lookup anomalous logins within
let excludeKnownVPN = dynamic([127.0.0.1, 0.0.0.0]); //Known VPN IP addresses to exclude
SigninLogs
| where TimeGenerated > ago(timeRange)
| where ConditionalAccessStatus =~ "success"
| extend country = LocationDetails[countryOrRegion]
| where country != ""
| summarize count() by tostring(country)
| join (
    //Get the total number of logins from any country and join it to the previous count in a single table
    SigninLogs
    | where TimeGenerated > ago(timeRange)
    | where ConditionalAccessStatus =~ "success"
    | extend country = LocationDetails[countryOrRegion]
    | where country != ""
    | summarize count(), make_list(tostring(country))
    | mv-expand list_country
    | extend country = tostring(list_country)
) on country
| summarize by country, count_, count_1
//Now calculate each countries prevalence within login events
| extend prevalence = toreal(count_) / toreal(count_1) * 100
| project-away count_1
| where prevalence < 0.01
| join kind=rightsemi(
    SigninLogs
    | where TimeGenerated >= ago(timeRange)
    //Enable to limit to o365 exchange logins
    //| where AppDisplayName =~ "Office 365 Exchange Online"
    | where ConditionalAccessStatus =~ "success"
    | where IPAddress != ""
    | extend country = tostring(LocationDetails[countryOrRegion])
    | summarize count() by TimeGenerated, UserPrincipalName, country, IPAddress
) on country
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated >= ago(timeRange)
    //Enable to limit to o365 exchange logins
    //| where AppDisplayName =~ "Office 365 Exchange Online"
    | where ConditionalAccessStatus =~ "success"
    | extend country = tostring(LocationDetails[countryOrRegion])
    | summarize by TimeGenerated, IPAddress, UserPrincipalName, country
) on UserPrincipalName
| where IPAddress != IPAddress1 and country != country1
| extend WindowStart = TimeGenerated1 - windowTime
| extend WindowEnd = TimeGenerated1 + windowTime
| where TimeGenerated between (WindowStart .. WindowEnd)
| project Account=UserPrincipalName, AnomalousIP=IPAddress, AnomalousLoginTime=TimeGenerated, AnomalousCountry=country, OtherLoginIP=IPAddress1, OtherLoginCountry=country1, OtherLoginWindowStart=WindowStart, OtherLoginWindowEnd=WindowEnd
| where AnomalousIP !in(excludeKnownVPN) and OtherLoginIP !in(excludeKnownVPN)```
## Failed Logon Attempts on SQL Server
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SQLServer/SQL-Failed%20SQL%20Logons.yaml)

### ATT&CK Tags

> Tactics: [u'CredentialAccess']

### Hunt details

> Description: This query is based on the SQLEvent KQL Parser function (link below) and detects failed logons on SQL Server SQLEvent KQL Parser provided at https://github.com/Azure/Azure-Sentinel/tree/master/Parsers/SQLSeverDetailed blog post on Monitoring SQL Server with Azure Sentinel https://techcommunity.microsoft.com/t5/azure-sentinel/monitoring-sql-server-with-azure-sentinel/ba-p/1502960

> Query:

```// SQLEvent is not the table name, it is the function name that should already be imported into your workspace.
// The underlying table where the data exists is the Event table.
SQLEvent
| where TimeGenerated >= ago(1d)
| where LogonResult has "failed"
| summarize count() by TimeGenerated, CurrentUser, Reason, ClientIP
| extend timestamp = TimeGenerated, AccountCustomEntity = CurrentUser, IPCustomEntity = ClientIP```
## Failed Logon on SQL Server from Same IPAddress in Short time Span
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SQLServer/SQL-MultipleFailedLogon_FromSameIP.yaml)

### ATT&CK Tags

> Tactics: [u'CredentialAccess']

### Hunt details

> Description: This hunitng query identifies multiple failed logon attempts from same IP within short span of time.This query is based on the SQLEvent KQL Parser function (link below)SQLEvent KQL Parser provided at https://github.com/Azure/Azure-Sentinel/tree/master/Parsers/SQLSeverDetailed blog post on Monitoring SQL Server with Azure Sentinel https://techcommunity.microsoft.com/t5/azure-sentinel/monitoring-sql-server-with-azure-sentinel/ba-p/1502960

> Query:

```// SQLEvent is not the table name, it is the function name that should already be imported into your workspace.
// The underlying table where the data exists is the Event table.
// the timeframe and threshold can be changed below as per requirement.
//
let TimeFrame = 1d;
let failedThreshold = 3;
SQLEvent
| where TimeGenerated >= ago(TimeFrame) 
| where LogonResult has "failed"
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), TotalFailedLogons = count() by ClientIP, CurrentUser, Computer
| where TotalFailedLogons >= failedThreshold
| project StartTime, ClientIP, TotalFailedLogons, CurrentUser, Computer
| extend timestamp = StartTime, AccountCustomEntity = CurrentUser, IPCustomEntity = ClientIP```
## Multiple Failed Logon on SQL Server in Short time Span
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SQLServer/SQL-MultipleFailedLogon_InShortSpan.yaml)

### ATT&CK Tags

> Tactics: [u'CredentialAccess']

### Hunt details

> Description: This hunting queries looks for multiple failed logon attempts in short span of time.This query is based on the SQLEvent KQL Parser function (link below)SQLEvent KQL Parser provided at https://github.com/Azure/Azure-Sentinel/tree/master/Parsers/SQLSeverDetailed blog post on Monitoring SQL Server with Azure Sentinel https://techcommunity.microsoft.com/t5/azure-sentinel/monitoring-sql-server-with-azure-sentinel/ba-p/1502960

> Query:

```// SQLEvent is not the table name, it is the function name that should already be imported into your workspace.
// The underlying table where the data exists is the Event table.
// the timeframe and threshold can be changed below as per requirement
//
let TimeFrame = 1d;
let failedThreshold = 3;
SQLEvent
| where TimeGenerated >= ago(TimeFrame) 
| where LogonResult has "failed"
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), TotalFailedLogons = count() by CurrentUser, ClientIP
| where TotalFailedLogons >= failedThreshold
| project StartTime, CurrentUser, TotalFailedLogons, ClientIP
| extend timestamp = StartTime, AccountCustomEntity = CurrentUser, IPCustomEntity = ClientIP```
## New User created on SQL Server
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SQLServer/SQL-New_UserCreated.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence']

### Hunt details

> Description: This hunting query identifies creation of a new user from SQL ServerThis query is based on the SQLEvent KQL Parser function (link below) SQLEvent KQL Parser provided at https://github.com/Azure/Azure-Sentinel/tree/master/Parsers/SQLSeverDetailed blog post on Monitoring SQL Server with Azure Sentinel https://techcommunity.microsoft.com/t5/azure-sentinel/monitoring-sql-server-with-azure-sentinel/ba-p/1502960

> Query:

```// SQLEvent is not the table name, it is the function name that should already be imported into your workspace.
// The underlying table where the data exists is the Event table.
// This query checks for new user account created on SQL Server using the SQLEvent() parser
//
SQLEvent
| where TimeGenerated >= ago(1d)
| where Statement has "Create Login"
| parse Statement with "CREATE LOGIN [" TargetUser:string "]" *
| project TimeGenerated, Computer, Action, ClientIP, CurrentUser, DatabaseName, TargetUser, ObjectName, Statement
| extend timestamp = TimeGenerated, AccountCustomEntity = CurrentUser, IPCustomEntity = ClientIP```
## User added to SQL Server SecurityAdmin Group
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SQLServer/SQL-UserAdded_to_SecurityAdmin.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'PrivilegeEscalation']

### Hunt details

> Description: This hunting query identifies user added in the SecurityAdmin group of SQL ServerThis query is based on the SQLEvent KQL Parser function (link below)SQLEvent KQL Parser provided at https://github.com/Azure/Azure-Sentinel/tree/master/Parsers/SQLSeverDetailed blog post on Monitoring SQL Server with Azure Sentinel https://techcommunity.microsoft.com/t5/azure-sentinel/monitoring-sql-server-with-azure-sentinel/ba-p/1502960

> Query:

```// SQLEvent is not the table name, it is the function name that should already be imported into your workspace.
// The underlying table where the data exists is the Event table.
// This query tracks user added into SecurityAdmingroup
SQLEvent
| where TimeGenerated >= ago(1d)
| where Statement has "Alter Server role" and Statement has "add member"
| parse Statement with * "ADD MEMBER [" TargetUser:string "]" *
| where ObjectName has "securityadmin"
| project TimeGenerated, Computer, Action, ClientIP, CurrentUser, DatabaseName, TargetUser, ObjectName, Statement 
| extend timestamp = TimeGenerated, AccountCustomEntity = CurrentUser, IPCustomEntity = ClientIP```
## SQL User deleted from Database
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SQLServer/SQL-UserDeletedFromDatabase.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'PrivilegeEscalation', u'Impact']

### Hunt details

> Description: This hunting query identifies deletion of user from SQL DatabaseThis query is based on the SQLEvent KQL Parser function (link below)SQLEvent KQL Parser provided at https://github.com/Azure/Azure-Sentinel/tree/master/Parsers/SQLSeverDetailed blog post on Monitoring SQL Server with Azure Sentinel https://techcommunity.microsoft.com/t5/azure-sentinel/monitoring-sql-server-with-azure-sentinel/ba-p/1502960

> Query:

```// SQLEvent is not the table name, it is the function name that should already be imported into your workspace.
// The underlying table where the data exists is the Event table.
// This query checks for user removed from a database by parsing the statement field at the query time.
//
SQLEvent
| where TimeGenerated >= ago(1d)
| where Statement has "Alter role" and Statement has "drop member"
| parse Statement with * "DROP MEMBER [" TargetUser:string "]" *
| project TimeGenerated, Computer, Action, ClientIP, CurrentUser, DatabaseName, TargetUser, ObjectName, Statement
| extend timestamp = TimeGenerated, AccountCustomEntity = CurrentUser, IPCustomEntity = ClientIP```
## User removed from SQL Server SecurityAdmin Group
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SQLServer/SQL-UserRemovedFromSecurityAdmin.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'PrivilegeEscalation', u'Impact']

### Hunt details

> Description: This hunting query identifies user removed from the SecurityAdmin group of SQL ServerThis query is based on the SQLEvent KQL Parser function (link below) SQLEvent KQL Parser provided at https://github.com/Azure/Azure-Sentinel/tree/master/Parsers/SQLSeverDetailed blog post on Monitoring SQL Server with Azure Sentinel https://techcommunity.microsoft.com/t5/azure-sentinel/monitoring-sql-server-with-azure-sentinel/ba-p/1502960

> Query:

```// SQLEvent is not the table name, it is the function name that should already be imported into your workspace.
// The underlying table where the data exists is the Event table.
// This query checks for user removed from SecurityAdmin Role
SQLEvent
| where TimeGenerated >= ago(1d)
| where Statement has "Alter Server role" and Statement has "drop member"
| parse Statement with * "DROP MEMBER [" TargetUser:string "]" *
| where ObjectName has "securityadmin"
| project TimeGenerated, Computer, Action, ClientIP, CurrentUser, DatabaseName, TargetUser, ObjectName, Statement 
| extend timestamp = TimeGenerated, AccountCustomEntity = CurrentUser, IPCustomEntity = ClientIP```
## User removed from SQL Server Roles
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SQLServer/SQL-UserRemovedFromServerRole.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'PrivilegeEscalation', u'Impact']

### Hunt details

> Description: This hunting query identifies user removed from a SQL Server Role.This query is based on the SQLEvent KQL Parser function (link below) SQLEvent KQL Parser provided at https://github.com/Azure/Azure-Sentinel/tree/master/Parsers/SQLSeverDetailed blog post on Monitoring SQL Server with Azure Sentinel https://techcommunity.microsoft.com/t5/azure-sentinel/monitoring-sql-server-with-azure-sentinel/ba-p/1502960

> Query:

```// SQLEvent is not the table name, it is the function name that should already be imported into your workspace.
// The underlying table where the data exists is the Event table.
// This query checks for user removed from a ServerRole
SQLEvent
| where TimeGenerated >= ago(1d)
| where Statement has "Alter Server role" and Statement has "drop member"
| parse Statement with * "DROP MEMBER [" TargetUser:string "]" *
| project TimeGenerated, Computer, Action, ClientIP, CurrentUser, DatabaseName, TargetUser, ObjectName, Statement 
| extend timestamp = TimeGenerated, AccountCustomEntity = CurrentUser, IPCustomEntity = ClientIP```
## User Role altered on SQL Server
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/SQLServer/SQL-UserRoleChanged.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'PrivilegeEscalation']

### Hunt details

> Description: This hunting query identifies user role altered on SQL ServerThis query is based on the SQLEvent KQL Parser function (link below) SQLEvent KQL Parser provided at https://github.com/Azure/Azure-Sentinel/tree/master/Parsers/SQLSeverDetailed blog post on Monitoring SQL Server with Azure Sentinel https://techcommunity.microsoft.com/t5/azure-sentinel/monitoring-sql-server-with-azure-sentinel/ba-p/1502960

> Query:

```// SQLEvent is not the table name, it is the function name that should already be imported into your workspace.
// The underlying table where the data exists is the Event table.
// This query looking for Alter role commands and extracts username which was altered and target objectName
SQLEvent
| where TimeGenerated >= ago(1d)
| where Statement contains "Alter role" and Statement has "add member"
| parse Statement with * "ADD MEMBER [" TargetUser:string "]" *
| project TimeGenerated, Computer, Action, ClientIP, CurrentUser, DatabaseName, TargetUser, ObjectName, Statement
| extend timestamp = TimeGenerated, AccountCustomEntity = CurrentUser, IPCustomEntity = ClientIP```
## Crypto currency miners EXECVE
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/Syslog/CryptoCurrencyMiners.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'Execution']

### Hunt details

> Description: This query hunts through EXECVE syslog data generated by AUOMS to find instances of crypto currency miners beingdownloaded.  It returns a table of suspicious command lines.Find more details on collecting EXECVE data into Azure Sentinel - https://techcommunity.microsoft.com/t5/azure-sentinel/hunting-threats-on-linux-with-azure-sentinel/ba-p/1344431

> Query:

```// Extract EventType and EventData from AUOMS Syslog message
Syslog
| parse SyslogMessage with "type=" EventType " audit(" * "): " EventData
| project TimeGenerated, EventType, Computer, EventData 
// Extract AUOMS_EXECVE details from EventData
| where EventType =~ "AUOMS_EXECVE"
| parse EventData with * "syscall=" syscall " syscall_r=" * " success=" success " exit=" exit " a0" * " ppid=" ppid " pid=" pid " audit_user=" audit_user " auid=" auid " user=" user " uid=" uid " group=" group " gid=" gid "effective_user=" effective_user " euid=" euid " set_user=" set_user " suid=" suid " filesystem_user=" filesystem_user " fsuid=" fsuid " effective_group=" effective_group " egid=" egid " set_group=" set_group " sgid=" sgid " filesystem_group=" filesystem_group " fsgid=" fsgid " tty=" tty " ses=" ses " comm=\"" comm "\" exe=\"" exe "\"" * "cwd=\"" cwd "\"" * "name=\"" name "\"" * "cmdline=\"" cmdline "\" containerid=" containerid
// Find wget and curl commands
| where comm in ("wget", "curl")
// Find command lines featuring known crypto currency miner names
| where cmdline contains "nicehashminer" or cmdline contains "ethminer" or cmdline contains "equihash" or cmdline contains "NsCpuCNMiner64" or cmdline contains "minergate" or cmdline contains "minerd" or cmdline contains "cpuminer" or cmdline contains "xmr-stak-cpu" or cmdline contains "xmrig" or cmdline contains "stratum+tcp" or cmdline contains "cryptonight" or cmdline contains "monero" or cmdline contains "oceanhole" or cmdline contains "dockerminer" or cmdline contains "xmrdemo"
| project TimeGenerated, Computer, audit_user, user, cmdline
| extend AccountCustomEntity = user, HostCustomEntity = Computer, timestamp = TimeGenerated
| sort by TimeGenerated desc```
## Disabled accounts using Squid proxy
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/Syslog/disabled_account_squid_usage.yaml)

### ATT&CK Tags

> Tactics: [u'CredentialAccess']

### Hunt details

> Description: Look for accounts that have a been recorded as disabled by AD in the previous week but are still using the proxy during the current week. This query presumes the default squid log format is being used. http://www.squid-cache.org/Doc/config/access_log/

> Query:

```let starttime = 14d;
let endtime = 7d;
let disabledAccounts = (){
SigninLogs 
| where TimeGenerated between(ago(starttime) .. ago(endtime))
| where ResultType == 50057
| where ResultDescription =~ "User account is disabled. The account has been disabled by an administrator." 
};
let proxyEvents = (){
Syslog
| where TimeGenerated > ago(endtime)
| where ProcessName contains "squid"
| extend URL = extract("(([A-Z]+ [a-z]{4,5}:\\/\\/)|[A-Z]+ )([^ :]*)",3,SyslogMessage), 
         SourceIP = extract("([0-9]+ )(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3}))",2,SyslogMessage), 
         Status = extract("(TCP_(([A-Z]+)(_[A-Z]+)*)|UDP_(([A-Z]+)(_[A-Z]+)*))",1,SyslogMessage), 
         HTTP_Status_Code = extract("(TCP_(([A-Z]+)(_[A-Z]+)*)|UDP_(([A-Z]+)(_[A-Z]+)*))/([0-9]{3})",8,SyslogMessage),
         User = extract("(CONNECT |GET )([^ ]* )([^ ]+)",3,SyslogMessage),
         RemotePort = extract("(CONNECT |GET )([^ ]*)(:)([0-9]*)",4,SyslogMessage),
         Domain = extract("(([A-Z]+ [a-z]{4,5}:\\/\\/)|[A-Z]+ )([^ :\\/]*)",3,SyslogMessage),
         Bytes = toint(extract("([A-Z]+\\/[0-9]{3} )([0-9]+)",2,SyslogMessage)),
         contentType = extract("([a-z/]+$)",1,SyslogMessage)
| extend TLD = extract("\\.[a-z]*$",0,Domain)
};
proxyEvents 
| where Status !contains DENIED
| join kind=inner disabledAccounts on $left.User == $right.UserPrincipalName
| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName, URLCustomEntity = URL```
## Rare process running on a Linux host
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/Syslog/RareProcess_ForLxHost.yaml)

### ATT&CK Tags

> Tactics: [u'Execution', u'Persistence']

### Hunt details

> Description: Looks for rare processes that are running on Linux hosts. Looks for process seen less than 14 times in last 7 days,  or observed rate is less than 1% of of the average for the environment and fewer than 100.

> Query:

```let starttime = 7d;
let endtime = 1m;
let lookback = 30d;
let count_threshold = 100;
let perc_threshold = 0.01;
let host_threshold = 14;
let basic=materialize(
  Syslog
    | where TimeGenerated >= ago(lookback)
    | summarize FullCount = count()
                , Count= countif(TimeGenerated between (ago(starttime) .. ago(endtime)))
                , min_TimeGenerated=min(TimeGenerated)
                , max_TimeGenerated=max(TimeGenerated) 
                      by Computer, ProcessName
    | where Count > 0 and Count < count_threshold);
let basic_avg = basic
    | summarize Avg = avg(FullCount) by  ProcessName;
basic | project-away FullCount
  | join kind=inner 
basic_avg 
  on ProcessName | project-away ProcessName1
  | where Count < host_threshold or (Count <= Avg*perc_threshold and Count < count_threshold) 
  | extend HostCustomEntity=Computer```
## Linux scheduled task Aggregation
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/Syslog/SchedTaskAggregation.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'Execution']

### Hunt details

> Description: This query aggregates information about all of the scheduled tasks (Cron jobs) and presents the data in a chart.The aggregation is done based on unique user-commandline pairs. It returns how many times a command line hasbeen run from a particular user, how many computers that pair has run on, and what percentage that is of thetotal number of computers in the tenant.

> Query:

```// Change startdate below if you want a different timespan
let startdate = 7d;
// Pull messages from Syslog-cron where the process name is "CRON" or "CROND", the severity level is info, and the SyslogMessage contains "CMD".
// It also parses out the user and commandline from the message.
let RawCommands = Syslog 
| where TimeGenerated >= ago(startdate)
| where Facility =~ "cron" 
| where SeverityLevel =~ "info" 
| where ProcessName =~ "CRON" or ProcessName =~ "CROND"  
| where SyslogMessage contains "CMD " 
| project TenantId, TimeGenerated, Computer, SeverityLevel, ProcessName, SyslogMessage
| extend TrimmedSyslogMsg = trim_end(@"\)", SyslogMessage)
| parse TrimmedSyslogMsg with * "(" user  ") CMD (" cmdline 
| project TenantId, TimeGenerated, Computer, user, cmdline; 
// Count how many times a particular commandline has been seen based on unique Computer, User, and cmdline sets
let CommandCount = RawCommands
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count(cmdline) by Computer, user, cmdline
| project StartTimeUtc, EndTimeUtc, Computer, user, cmdline, CmdlineCount = count_cmdline ; 
// Count how many computers have run a particular user and cmdline pair
let DistComputerCount = RawCommands
| summarize dcount(Computer) by TenantId, user, cmdline
| project TenantId, user, cmdline, ComputerCount = dcount_Computer ; 
// Join above counts based on user and commandline pair
let CommandSummary = CommandCount | join (DistComputerCount) on user, cmdline
| project StartTimeUtc, EndTimeUtc, TenantId, user, CmdlineCount, ComputerCount, cmdline ;
// Count the total number of computers reporting cron messages in the tenant
let TotalComputers = Syslog
| where Facility =~ "cron"
| summarize dcount(Computer) by TenantId ;
// Join the previous counts with the total computers count. Calculate the percentage of total computers value.
let FinalSummary = CommandSummary | join kind= leftouter (TotalComputers) on TenantId
| project StartTimeUtc, EndTimeUtc, user, TimesCmdlineSeen = CmdlineCount, CompsThatHaveRunCmdline = ComputerCount, 
AsPercentOfTotalComps = round(100 * (toreal(ComputerCount)/toreal(dcount_Computer)),2), cmdline
| order by user asc, TimesCmdlineSeen desc;
FinalSummary 
| extend timestamp = StartTimeUtc, AccountCustomEntity = user```
## Editing Linux scheduled tasks through Crontab
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/Syslog/SchedTaskEditViaCrontab.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'Execution']

### Hunt details

> Description: This query shows when users have edited or replaced the scheduled tasks using crontab. The events are bucketed into 10 minute intervals and all the actions that a particular used took are collected into the List of Actions. Default query is for seven days.

> Query:

```// Change startdate below if you want a different timespan
let startdate = 14d;
// Pull messages from Syslog-cron logs where the process is crontab and the severity level is "info". Extract the User and Action information from the SyslogMessage
Syslog 
| where TimeGenerated  >= ago(startdate)
| where Facility =~ "cron" 
| where ProcessName =~ "crontab" 
| where SeverityLevel =~ "info" 
| project TimeGenerated, Computer, SeverityLevel, ProcessName, SyslogMessage
| parse SyslogMessage with * "(" user  ") " Action " (" *
// Only look for messages that contain edit or replace
| where Action contains "EDIT" or Action contains "REPLACE"
//| summarize all the actions into a single set based on 10 minute time intervals
| summarize makeset(Action) by bin(TimeGenerated, 10m), Computer, user  
| project EventTime10MinInterval = TimeGenerated, Computer, user, ListOfActions = set_Action 
| order by Computer asc nulls last, EventTime10MinInterval asc
| extend timestamp = EventTime10MinInterval, AccountCustomEntity = user, HostCustomEntity = Computer```
## Squid commonly abused TLDs
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/Syslog/squid_abused_tlds.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl']

### Hunt details

> Description: Some top level domains (TLDs) are more commonly associated with malware for a range of reasons - including how easy domains on these TLDs are to obtain. Many of these may be undesirable from an enterprise policy perspective. The clientCount column provides an initial insight into how widespread the domain usage is across the estate. This query presumes the default squid log format is being used. http://www.squid-cache.org/Doc/config/access_log/

> Query:

```let suspicious_tlds = dynamic([ ".click", ".club", ".download",  ".xxx", ".xyz"]);
let timeframe = 14d;
Syslog
| where TimeGenerated >= ago(timeframe) 
| where ProcessName contains "squid"
| extend URL = extract("(([A-Z]+ [a-z]{4,5}:\\/\\/)|[A-Z]+ )([^ :]*)",3,SyslogMessage), 
         SourceIP = extract("([0-9]+ )(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3}))",2,SyslogMessage), 
         Status = extract("(TCP_(([A-Z]+)(_[A-Z]+)*)|UDP_(([A-Z]+)(_[A-Z]+)*))",1,SyslogMessage), 
         HTTP_Status_Code = extract("(TCP_(([A-Z]+)(_[A-Z]+)*)|UDP_(([A-Z]+)(_[A-Z]+)*))/([0-9]{3})",8,SyslogMessage),
         User = extract("(CONNECT |GET )([^ ]* )([^ ]+)",3,SyslogMessage),
         RemotePort = extract("(CONNECT |GET )([^ ]*)(:)([0-9]*)",4,SyslogMessage),
         Domain = extract("(([A-Z]+ [a-z]{4,5}:\\/\\/)|[A-Z]+ )([^ :\\/]*)",3,SyslogMessage)
| extend TLD = extract("\\.[a-z]*$",0,Domain)
| where TLD in (suspicious_tlds)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), clientCount = dcount(SourceIP) by TLD, User, URL
| order by TLD asc, clientCount desc
| extend timestamp = StartTimeUtc, AccountCustomEntity = User, URLCustomEntity = URL```
## Squid malformed requests
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/Syslog/squid_malformed_requests.yaml)

### ATT&CK Tags

> Tactics: [u'Discovery']

### Hunt details

> Description: Malformed web requests are sometimes used for reconnaissance to detect the presence of network security devices.Hunting for a large number of requests from a single source may assist in locating compromised hosts. Note: internal sites maybe detected by this query and may need excluding on a individual basis. This query presumes the default squid log format isbeing used.

> Query:

```let timeframe = 14d;
Syslog
| where TimeGenerated >= ago(timeframe) 
| where ProcessName contains "squid"
| extend URL = extract("(([A-Z]+ [a-z]{4,5}:\\/\\/)|[A-Z]+ )([^ :]*)",3,SyslogMessage), 
         SourceIP = extract("([0-9]+ )(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3}))",2,SyslogMessage), 
         Status = extract("(TCP_(([A-Z]+)(_[A-Z]+)*)|UDP_(([A-Z]+)(_[A-Z]+)*))",1,SyslogMessage), 
         HTTP_Status_Code = extract("(TCP_(([A-Z]+)(_[A-Z]+)*)|UDP_(([A-Z]+)(_[A-Z]+)*))/([0-9]{3})",8,SyslogMessage),
         User = extract("(CONNECT |GET )([^ ]* )([^ ]+)",3,SyslogMessage),
         RemotePort = extract("(CONNECT |GET )([^ ]*)(:)([0-9]*)",4,SyslogMessage),
         Domain = extract("(([A-Z]+ [a-z]{4,5}:\\/\\/)|[A-Z]+ )([^ :\\/]*)",3,SyslogMessage),
         Bytes = toint(extract("([A-Z]+\\/[0-9]{3} )([0-9]+)",2,SyslogMessage)),
         contentType = extract("([a-z/]+$)",1,SyslogMessage)
| extend TLD = extract("\\.[a-z]*$",0,Domain)
| where Domain !contains . and isnotempty(Domain)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), badRequestCount = count() by Domain, SourceIP, User, URL
| order by badRequestCount desc
| extend timestamp = StartTimeUtc, AccountCustomEntity = User, IPCustomEntity = SourceIP, URLCustomEntity = URL```
## Squid data volume timeseries anomalies
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/Syslog/squid_volume_anomalies.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl', u'Exfiltration']

### Hunt details

> Description: Malware infections or data exfiltration activity often leads to anomalies in network data volumethis hunting query looks for anomalies in the volume of bytes traversing a squid proxy. Anomalies require further investigation to determine cause. This query presumes the default squid log format is being used.

> Query:

```let starttime = 14d;
let endtime = 1d;
let timeframe = 1h;
let TimeSeriesData = 
Syslog
| where TimeGenerated between (startofday(ago(starttime))..startofday(ago(endtime)))
| where ProcessName contains "squid"
| extend URL = extract("(([A-Z]+ [a-z]{4,5}:\\/\\/)|[A-Z]+ )([^ :]*)",3,SyslogMessage), 
         SourceIP = extract("([0-9]+ )(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3}))",2,SyslogMessage), 
         Status = extract("(TCP_(([A-Z]+)(_[A-Z]+)*)|UDP_(([A-Z]+)(_[A-Z]+)*))",1,SyslogMessage), 
         HTTP_Status_Code = extract("(TCP_(([A-Z]+)(_[A-Z]+)*)|UDP_(([A-Z]+)(_[A-Z]+)*))/([0-9]{3})",8,SyslogMessage),
         User = extract("(CONNECT |GET )([^ ]* )([^ ]+)",3,SyslogMessage),
         RemotePort = extract("(CONNECT |GET )([^ ]*)(:)([0-9]*)",4,SyslogMessage),
         Domain = extract("(([A-Z]+ [a-z]{4,5}:\\/\\/)|[A-Z]+ )([^ :\\/]*)",3,SyslogMessage),
         Bytes = toint(extract("([A-Z]+\\/[0-9]{3} )([0-9]+)",2,SyslogMessage)),
         contentType = extract("([a-z/]+$)",1,SyslogMessage)
| extend TLD = extract("\\.[a-z]*$",0,Domain)
| where isnotempty(Bytes)
| make-series TotalBytesSent=sum(Bytes) on TimeGenerated from startofday(ago(starttime)) to startofday(ago(endtime)) step timeframe by ProcessName;
TimeSeriesData
| extend (anomalies, score, baseline) = series_decompose_anomalies(TotalBytesSent,3, -1, linefit)
| extend timestamp = TimeGenerated
| render timechart with (title="Squid Time Series anomalies")```
## Preview - TI map File entity to OfficeActivity Event
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/ThreatIntelligenceIndicator/FileEntity_OfficeActivity.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: Identifies a match in OfficeActivity Event data from any FileName IOC from TI.As File name matches can create noise, this is best as hunting query

> Query:

```let dt_lookBack = 1h;
let ioc_lookBack = 14d;
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| where Active == true
| where isnotempty(FileName)
|  join (
OfficeActivity| where TimeGenerated >= ago(dt_lookBack)
      | where isnotempty(SourceFileName)
      | extend OfficeActivity_TimeGenerated = TimeGenerated
)
on $left.FileName == $right.SourceFileName
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| project LatestIndicatorTime, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
OfficeActivity_TimeGenerated, FileName, UserId, ClientIP, OfficeObjectId
| extend timestamp = OfficeActivity_TimeGenerated, AccountCustomEntity = UserId, IPCustomEntity = ClientIP, URLCustomEntity = Url```
## Preview - TI map File entity to Security Event
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/ThreatIntelligenceIndicator/FileEntity_SecurityEvent.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: Identifies a match in Security Event data from any FileName IOC from TI.As File name matches can create noise, this is best as hunting query

> Query:

```let dt_lookBack = 1h;
let ioc_lookBack = 14d;
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| where Active == true
| where isnotempty(FileName)
|  join (
  SecurityEvent | where TimeGenerated >= ago(dt_lookBack)
      | where EventID in ("4688","8002","4648","4673")
                 | where isnotempty(Process)
      | extend SecurityEvent_TimeGenerated = TimeGenerated, Event = EventID
)
on $left.FileName == $right.Process
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| project LatestIndicatorTime, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
SecurityEvent_TimeGenerated, FileName, Computer, IpAddress, Account, Event, Activity
| extend timestamp = SecurityEvent_TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress, URLCustomEntity = Url```
## Preview - TI map File entity to Syslog Event
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/ThreatIntelligenceIndicator/FileEntity_Syslog.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: Identifies a match in Syslog Event data from any FileName IOC from TI.As File name matches can create noise, this is best as hunting query

> Query:

```let dt_lookBack = 1h;
let ioc_lookBack = 14d;
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| where Active == true
| where isnotempty(FileName)
| extend TI_ProcessEntity = tostring(split(FileName, ".")[-2])
|  join (
     Syslog | where TimeGenerated >= ago(dt_lookBack)
     | where isnotempty(ProcessName)
     | extend Syslog_TimeGenerated = TimeGenerated
)
on $left.TI_ProcessEntity == $right.ProcessName
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| project LatestIndicatorTime, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
Syslog_TimeGenerated, FileName, Computer, HostIP, SyslogMessage
| extend timestamp = Syslog_TimeGenerated, HostCustomEntity = Computer, IPCustomEntity = HostIP, URLCustomEntity = Url```
## Preview - TI map File entity to VMConnection Event
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/ThreatIntelligenceIndicator/FileEntity_VMConnection.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: Identifies a match in VMConnection Event data from any FileName IOC from TI.As File name matches can create noise, this is best as hunting query

> Query:

```let dt_lookBack = 1h;
let ioc_lookBack = 14d;
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| where Active == true
| where isnotempty(FileName)
| extend TI_ProcessEntity = tostring(split(FileName, ".")[-2])
|  join (
   VMConnection | where TimeGenerated >= ago(dt_lookBack)
   | where isnotempty(ProcessName)
   | extend VMConnection_TimeGenerated = TimeGenerated
)
on $left.TI_ProcessEntity == $right.ProcessName
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| project LatestIndicatorTime, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
VMConnection_TimeGenerated, FileName, Computer, Direction, SourceIp, DestinationIp, RemoteIp, DestinationPort, Protocol
| extend timestamp = VMConnection_TimeGenerated, IPCustomEntity = RemoteIp, HostCustomEntity = Computer, URLCustomEntity = Url```
## Preview - TI map File entity to WireData Event
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/ThreatIntelligenceIndicator/FileEntity_WireData.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: Identifies a match in WireData Event data from any FileName IOC from TI.As File name matches can create noise, this is best as hunting query

> Query:

```let dt_lookBack = 1h;
let ioc_lookBack = 14d;
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()
| where Active == true
| where isnotempty(FileName)
|  join (
 WireData | where TimeGenerated >= ago(dt_lookBack)
          | where isnotempty(ProcessName)
          | extend Process =reverse(substring(reverse(ProcessName), 0, indexof(reverse(ProcessName), "\\")))
      | extend WireData_TimeGenerated = TimeGenerated
)
on $left.FileName == $right.Process
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| project LatestIndicatorTime, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
WireData_TimeGenerated, FileName, Computer, Direction, LocalIP, RemoteIP, LocalPortNumber, RemotePortNumber
| extend timestamp = WireData_TimeGenerated, HostCustomEntity = Computer, IPCustomEntity = RemoteIP, URLCustomEntity = Url```
## Preview - DNS Events that match threat intelligence
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/ThreatIntelligenceIndicator/Sample-DNSEventsMatchToThreatIntel.yaml)

### ATT&CK Tags

> Tactics: [u'Impact']

### Hunt details

> Description: This sample hunting query demonstrates how to utilize the threat intelligence data with the DNS event logs

> Query:

```let timeframe = 1d;
DnsEvents
| where TimeGenerated >= ago(timeframe)
| join (ThreatIntelligenceIndicator
  | summarize arg_max(TimeGenerated, *) by IndicatorId
  | summarize by Url) on $left.Name == $right.Url
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count()
by Computer, ClientIP, ThreatIntel_Related_Domain = Name, Url
| extend timestamp = StartTimeUtc, HostCustomEntity = Computer, IPCustomEntity = ClientIP, URLCustomEntity = Url```
## Same IP address with multiple csUserAgent
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/W3CIISLog/ClientIPwithManyUserAgents.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: This alerts when the same client IP (cIP) is connecting with more than 1 but less than 15 different useragent string (csUserAgent) in less than 1 hour.We limit to 50 or less connections to avoid high traffic sites. This may indicate malicious activity as this is a method of probing an environmentReferences: Status code mappings for your convenienceIIS status code mapping - https://support.microsoft.com/help/943891/the-http-status-code-in-iis-7-0-iis-7-5-and-iis-8-0Win32 Status code mapping - https://msdn.microsoft.com/library/cc231199.aspx

> Query:

```let timeFrame = ago(1h);
W3CIISLog
| where TimeGenerated >= timeFrame
| where scStatus !startswith "20" and scStatus !startswith "30" and cIP !startswith "192.168." and cIP != sIP and cIP != "::1"
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), makeset(csUserAgent), ConnectionCount = count() 
by Computer, sSiteName, sIP, sPort, cIP, csMethod
| extend csUserAgentPerIPCount = arraylength(set_csUserAgent)
| where  csUserAgentPerIPCount between ( 2 .. 15 ) and ConnectionCount <=50
| extend timestamp = StartTimeUtc, IPCustomEntity = cIP, HostCustomEntity = Computer```
## Potential IIS brute force
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/W3CIISLog/Potential_IIS_BF.yaml)

### ATT&CK Tags

> Tactics: [u'CredentialAccess']

### Hunt details

> Description: This query shows when 1200 (20 per minute) or more failed attempts by cIP per hour occur on a given server and then a successful logon by cIP. This only includes when more than 1 user agent strings is used or more than 1 port is used.This could be indicative of successful probing and password brute force success on your IIS servers. Feel free to adjust the threshold as needed - ConnectionCount >= 1200 References: Status code mappings for your convenience, also inline if the mapping is not availableIIS status code mapping - https://support.microsoft.com/help/943891/the-http-status-code-in-iis-7-0-iis-7-5-and-iis-8-0Win32 Status code mapping - https://msdn.microsoft.com/library/cc231199.aspx

> Query:

```let timeFrame = ago(1h);
W3CIISLog
| where TimeGenerated >= timeFrame
| where scStatus in ("401","403")
| where cIP !startswith "192.168." and cIP != sIP and cIP != "::1" //and csUserName != "-" 
// Handling Exchange specific items in IIS logs to remove the unique log identifier in the URI
| extend csUriQuery = iff(csUriQuery startswith "MailboxId=", tostring(split(csUriQuery, "&")[0]) , csUriQuery )
| extend csUriQuery = iff(csUriQuery startswith "X-ARR-CACHE-HIT=", strcat(tostring(split(csUriQuery, "&")[0]),tostring(split(csUriQuery, "&")[1])) , csUriQuery )
| summarize FailStartTimeUtc = min(TimeGenerated), FailEndTimeUtc = max(TimeGenerated), makeset(sPort), makeset(csUserAgent), makeset(csUserName), csUserNameCount = dcount(csUserName), ConnectionCount = count() by Computer, sSiteName, sIP, cIP, csUriQuery, csMethod, scStatus, scSubStatus, scWin32Status
| extend csUserAgentPerIPCount = arraylength(set_csUserAgent)
| extend sPortCount = arraylength(set_sPort)
| extend scStatusFull = strcat(scStatus, ".",scSubStatus) 
// Map common IIS codes
| extend scStatusFull_Friendly = case(
scStatusFull == "401.0", "Access denied.",
scStatusFull == "401.1", "Logon failed.",
scStatusFull == "401.2", "Logon failed due to server configuration.",
scStatusFull == "401.3", "Unauthorized due to ACL on resource.",
scStatusFull == "401.4", "Authorization failed by filter.",
scStatusFull == "401.5", "Authorization failed by ISAPI/CGI application.",
scStatusFull == "403.0", "Forbidden.",
scStatusFull == "403.4", "SSL required.",
"See - https://support.microsoft.com/help/943891/the-http-status-code-in-iis-7-0-iis-7-5-and-iis-8-0")
// Mapping to Hex so can be mapped using website in comments above
| extend scWin32Status_Hex = tohex(tolong(scWin32Status)) 
// Map common win32 codes
| extend scWin32Status_Friendly = case(
scWin32Status_Hex =~ "52e", "Logon failure: Unknown user name or bad password.", 
scWin32Status_Hex =~ "533", "Logon failure: Account currently disabled.", 
scWin32Status_Hex =~ "2ee2", "The request has timed out.", 
scWin32Status_Hex =~ "0", "The operation completed successfully.", 
scWin32Status_Hex =~ "1", "Incorrect function.", 
scWin32Status_Hex =~ "2", "The system cannot find the file specified.", 
scWin32Status_Hex =~ "3", "The system cannot find the path specified.", 
scWin32Status_Hex =~ "4", "The system cannot open the file.", 
scWin32Status_Hex =~ "5", "Access is denied.", 
scWin32Status_Hex =~ "8009030e", "SEC_E_NO_CREDENTIALS", 
scWin32Status_Hex =~ "8009030C", "SEC_E_LOGON_DENIED", 
"See - https://msdn.microsoft.com/library/cc231199.aspx")
// decode URI when available
| extend decodedUriQuery = url_decode(csUriQuery)
| where (ConnectionCount >= 1200 and csUserAgentPerIPCount > 1) or (ConnectionCount >= 1200 and sPortCount > 1)
// now join back to see if there is a successful logon after so many failures
| join (
W3CIISLog
| where TimeGenerated >= timeFrame
| where scStatus startswith "20"
| where cIP !startswith "192.168." and cIP != sIP and cIP != "::1"
| extend LogonSuccessTimeUtc = TimeGenerated, Success_scStatus = scStatus
| distinct LogonSuccessTimeUtc, Computer, sSiteName, sIP, cIP, Success_scStatus
) on Computer, sSiteName, sIP, cIP
| where FailEndTimeUtc < LogonSuccessTimeUtc and not(LogonSuccessTimeUtc between (FailStartTimeUtc .. FailEndTimeUtc))
| summarize makeset(LogonSuccessTimeUtc) by FailStartTimeUtc, FailEndTimeUtc, Computer, sSiteName, sIP, cIP, tostring(set_csUserName), csUserNameCount, csUriQuery, csMethod, scStatus, scSubStatus, scWin32Status, tostring(set_sPort), tostring(set_csUserAgent), ConnectionCount, csUserAgentPerIPCount, sPortCount, scStatusFull, scStatusFull_Friendly, scWin32Status_Hex, scWin32Status_Friendly
| project FailStartTimeUtc, FailEndTimeUtc, set_LogonSuccessTimeUtc, Computer, sSiteName, sIP, cIP, set_csUserName, csUserNameCount, csUriQuery, csMethod, scStatus, scSubStatus, scWin32Status, set_sPort, set_csUserAgent, ConnectionCount, csUserAgentPerIPCount, sPortCount, scStatusFull, scStatusFull_Friendly, scWin32Status_Hex, scWin32Status_Friendly
| extend timestamp = FailStartTimeUtc, IPCustomEntity = cIP, HostCustomEntity = Computer```
## Potential IIS code injection attempt
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/W3CIISLog/Potential_IIS_CodeInject.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: Potential code injection into web server roles via scan of IIS logs. This represents an attempt to gain initial access to a system using a drive-by compromise technique.  This sort of attack happens routinely as part of security scans, of both authorized and malicious types. The initial goal of this detection is to flag these events when they occur and give an opportunity to review the data and filter out authorized activity.

> Query:

```let lookback = 7d;
// set cIP and csMethod count limit to indicate potentially noisy events, this will be listed at the top of the results 
// for any returns that are gt or equal to the default of 50
let cIP_MethodCountLimit = 50;
// Exclude private ip ranges from cIP list
let PrivateIPregex = @^127\.|^10\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.|^192\.168\.;
// Exclude common csMethods, add/modify this list as needed for your environment
let csMethodExclude = dynamic([GET, DEBUG, DELETE, LOCK, MKCOL, MOVE, PATCH, POST, PROPPATCH, 
PUT, SEARCH, TRACE, TRACK, UNLOCK, OPTIONS, HEAD, RPC_IN_DATA, RPC_OUT_DATA, PROPFIND,BITS_POST,CCM_POST]);
// Include in the list expected IPs where remote methods such as vuln scanning may be expected for your environment
let expectedIPs = dynamic([X.X.X.X, Y.Y.Y.Y]);
let codeInjectionAttempts = W3CIISLog
| where TimeGenerated >= ago(lookback)
| extend cIPType = iff(cIP matches regex PrivateIPregex,"private" ,"public" )
| where cIPType =="public"
| where cIP !in (expectedIPs)
| project TimeGenerated, cIP, csUserName, csMethod, csCookie, csHost, sIP, scStatus, csUriStem, csUriQuery, csUserAgent, csReferer 
// Throwing entire record into a single string column for attributable string matching
| extend pak = tostring(pack_all())
// Adding "arr" column containing indicators of matched suspicious strings
| extend arr = dynamic([])
| extend arr = iff(pak contains <script , array_concat(arr, pack_array(STRING MATCH : script)), arr)
| extend arr = iff(pak contains %3Cscript , array_concat(arr, pack_array(STRING MATCH : script)), arr)
| extend arr = iff(pak contains %73%63%72%69%70%74 , array_concat(arr, pack_array(STRING MATCH : encoded script)), arr)
| extend arr = iff(pak contains <img , array_concat(arr, pack_array(STRING MATCH : img)), arr)
| extend arr = iff(pak contains %3Cimg , array_concat(arr, pack_array(STRING MATCH : img)), arr)
| extend arr = iff(pak contains passwd , array_concat(arr, pack_array(STRING MATCH : passwd)), arr)
| extend arr = iff(csUserAgent contains nmap , array_concat(arr, pack_array(STRING MATCH : nmap)), arr)
| extend arr = iff(csUserAgent contains nessus , array_concat(arr, pack_array(STRING MATCH : nessus)), arr)
| extend arr = iff(csUserAgent contains qualys , array_concat(arr, pack_array(STRING MATCH : qualys)), arr)
| extend arr = iff(csMethod !in (csMethodExclude), array_concat(arr, pack_array(INVALID HTTP METHOD)), arr)
| extend arr = iff(csUriStem == /current_config/passwd , array_concat(arr, pack_array(STRING MATCH : dahua scan url )), arr)
| extend arr = iff(csUriQuery contains .. and csUriQuery !endswith ..., array_concat(arr, pack_array(BACKTRACK ATTEMPT IN QUERY)), arr)
| extend arr = iff(csUriQuery contains http://www.webscantest.com , array_concat(arr, pack_array(STRING MATCH : webscantest)), arr)
| extend arr = iff(csUriQuery contains http://appspidered.rapid7.com , array_concat(arr, pack_array(STRING MATCH : appspider)), arr)
| where array_length(arr) > 0
| project-away pak;
let cIP_MethodHighCount = codeInjectionAttempts 
| summarize StartTimeUtc = max(TimeGenerated), EndTimeUtc = min(TimeGenerated), cIP_MethodCount = count() 
by cIP, tostring(arr), cIP_MethodCountType = "High Count of cIP and csMethod, this may be noise" 
| where cIP_MethodCount >=  cIP_MethodCountLimit;
let codeInjectAtt = 
codeInjectionAttempts 
| summarize StartTimeUtc = max(TimeGenerated), EndTimeUtc = min(TimeGenerated), cIP_MethodCount = count() 
by cIP, cIP_MethodCountType = "Count of repeated entries, this is to reduce rowsets returned", csMethod, 
tostring(arr), csHost, scStatus, sIP, csUriStem, csUriQuery, csUserName, csUserAgent, csCookie, csReferer;
// union the events and sort by cIP_MethodCount to identify potentially noisy entries.  Additionally, cIP_MethodCountType 
// indicates whether it is a high count or simply a count of repeated entries
(union isfuzzy=true
cIP_MethodHighCount, codeInjectAtt
| sort by cIP_MethodCount desc, cIP desc, StartTimeUtc desc)
| extend timestamp = StartTimeUtc, IPCustomEntity = cIP, HostCustomEntity = csHost, AccountCustomEntity = csUserName, URLCustomEntity = csUriQuery```
## Web shell Detection
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/W3CIISLog/PotentialWebshell.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence', u'PrivilegeEscalation']

### Hunt details

> Description: Web shells are script that when uploaded to a web server can be used for remote administration. Attackers often use web shells to obtain unauthorized access, escalate //privilege as well as further compromise the environment. The query detects web shells that use GET requests by keyword searches in URL strings. This is based out of sigma rules described //here (https://github.com/Neo23x0/sigma/blob/master/rules/web/web_webshell_keyword.yml). There could be some web sites like wikis with articles on os commands and pages that include the os //commands in the URLs that might cause FP.

> Query:

```let timeFrame = ago(1d);
let command = "(?i)net(1)?(.exe)?(%20){1,}user|cmd(.exe)?(%20){1,}/c(%20){1,}";
W3CIISLog
| where TimeGenerated >= timeFrame
| where csMethod == "GET" 
| where ( csUriQuery has "whoami" or csUriQuery matches regex command ) or 
        ( csUriStem has "whoami" or csUriStem matches regex command ) or
        ( csReferer has "whoami" or csReferer matches regex command )
| summarize StartTimeUtc = max(TimeGenerated), EndTimeUtc = min(TimeGenerated), ConnectionCount = count() 
by Computer, sSiteName, sIP, cIP, csUserName, csUriQuery, csMethod, scStatus, scSubStatus, scWin32Status
| extend timestamp = StartTimeUtc, IPCustomEntity = cIP, HostCustomEntity = Computer, AccountCustomEntity = csUserName```
## URI requests from single client
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/W3CIISLog/RareClientFileAccess.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: This will look for connections to files on the server that are requested by only a single client. This analytic will be effective where an actor is utilising relatively static operational IP addresses. The threshold can be modified. The larger the execution window for this query the more reliable the results returned.

> Query:

```let timeRange = 7d;
let clientThreshold = 1;
let scriptExtensions = dynamic([".php", ".aspx", ".asp", ".cfml"]);
let data = W3CIISLog
| where csUriStem has_any(scriptExtensions)
//Exclude local addresses, needs editing to match your network configuration
| where cIP !startswith "10." and cIP !startswith "fe80" and cIP !startswith "::" and cIP !startswith "127." and cIP !startswith "172."
| summarize makelist(cIP), count(TimeGenerated) by csUriStem, sSiteName, csUserAgent;
data
| mvexpand list_cIP
| distinct tostring(list_cIP), csUriStem, sSiteName, csUserAgent
| summarize dcount(list_cIP), makelist(list_cIP), makelist(sSiteName) by csUriStem, csUserAgent
| where dcount_list_cIP == clientThreshold 
//Selects user agent strings that are probably browsers, comment out to see all
| where csUserAgent startswith "Mozilla"```
## Rare User Agent strings
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/W3CIISLog/RareUserAgentStrings.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: This will check for Rare User Agent strings over the last 3 days.  This can indicate potential probing of your IIS servers.

> Query:

```let timeframe = 3d;
W3CIISLog | where TimeGenerated >= ago(timeframe)
// The below line can be used to exclude local IPs if these create noise
//| where cIP !startswith "192.168." and cIP != "::1"
| where isnotempty(csUserAgent) and csUserAgent !in~ ("-", "MSRPC")
| extend csUserAgent_size = string_size(csUserAgent)
| project TimeGenerated, sSiteName, sPort, csUserAgent, csUserAgent_size, csUserName , csMethod, csUriStem, sIP, cIP, scStatus, 
scSubStatus, scWin32Status, csHost 
| join (
    W3CIISLog | where TimeGenerated >= ago(timeframe) 
	  // The below line can be used to exclude local IPs if these create noise
    //| where cIP !startswith "192.168." and cIP != "::1"
    | where isnotempty(csUserAgent) and csUserAgent !in~ ("-", "MSRPC") 
    | extend csUserAgent_size = string_size(csUserAgent)
    | summarize csUserAgent_count = count() by bin(csUserAgent_size, 1)
    | top 20 by csUserAgent_count asc nulls last 
) on csUserAgent_size
| project TimeGenerated, sSiteName, sPort, sIP, cIP, csUserAgent, csUserAgent_size, csUserAgent_count, csUserName , csMethod, csUriStem, 
scStatus, scSubStatus, scWin32Status, csHost
| extend timestamp = TimeGenerated, IPCustomEntity = cIP, HostCustomEntity = csHost, AccountCustomEntity = csUserName```
## Suspect Mailbox Export on IIS/OWA
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/W3CIISLog/SuspectedMailBoxExportHostonOWA.yaml)

### ATT&CK Tags

> Tactics: [u'Exfiltration']

### Hunt details

> Description: The hunting query looks for suspicious files accessed on a IIS server that might indicate exfiltration hosting.This technique has been observed when exporting mailbox files from OWA servers.Reference: https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/

> Query:

```let excludeIps = dynamic(["127.0.0.1", "::1"]);
let scriptingExt = dynamic(["aspx", "ashx", "asp"]);
W3CIISLog
| where csUriStem contains "/owa/"
//The actor pulls a file back but wont send it any URI params
| where isempty(csUriQuery)
| extend file_ext = tostring(split(csUriStem, ".")[-1])
//Giving your file a known scripting extension will throw an error
//rather than just serving the file as it will try to interpret the script
| where file_ext !in~ (scriptingExt)
//The actor was seen using image files, but we go wider in case they change this behaviour
//| where file_ext in~ ("jpg", "jpeg", "png", "bmp")
| extend file_name = tostring(split(csUriStem, "/")[-1])
| where file_name != ""
| where cIP !in~ (excludeIps)
| project file_ext, csUriStem, file_name, Computer, cIP, sIP, TenantId, TimeGenerated
| summarize dcount(cIP), AccessingIPs=make_set(cIP), AccessTimes=make_set(TimeGenerated), Access=count() by TenantId, file_name, Computer, csUriStem
//Collection of the exfiltration will occur only once, lets check for 2 accesses in case they mess up
//Tailor this for hunting
| where Access <= 2 and dcount_cIP == 1```
## Detect beacon like pattern based on repetitive time intervals in Wire Data Traffic
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/WireData/WireDataBeacon.yaml)

### ATT&CK Tags

> Tactics: [u'CommandAndControl']

### Hunt details

> Description: This query will identify beaconing patterns from Wire Data logs based on timedelta patterns. The query leverages various KQL functionsto calculate time delta and then compare it with total events observed in a day to find percentage of beaconing.  Results of such beaconing patterns to untrusted public networks can be a good starting point for investigation.References: Blog about creating dataset to identify network beaconing via repetitive time intervals seen against total traffic between same source-destination pair. http://www.austintaylor.io/detect/beaconing/intrusion/detection/system/command/control/flare/elastic/stack/2017/06/10/detect-beaconing-with-flare-elasticsearch-and-intrusion-detection-systems/

> Query:

```let starttime = 7d; 
let endtime = 1d; 
let TimeDeltaThreshold = 10; 
let TotalEventsThreshold = 15; 
let PercentBeaconThreshold = 95; 
let PrivateIPregex = @^127\.|^10\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.|^192\.168\.; 
WireData
| where TimeGenerated between (ago(starttime)..ago(endtime)) 
| extend RemoteIPType = iff(RemoteIP matches regex PrivateIPregex,"private" ,"public" ) 
| where RemoteIPType =="public" 
| project TimeGenerated , LocalIP , LocalPortNumber , RemoteIP, RemotePortNumber, ReceivedBytes, SentBytes 
| sort by LocalIP asc,TimeGenerated asc, RemoteIP asc, RemotePortNumber asc 
| serialize
| extend nextTimeGenerated = next(TimeGenerated, 1), nextLocalIP = next(LocalIP, 1) 
| extend TimeDeltainSeconds = datetime_diff(second,nextTimeGenerated,TimeGenerated) 
| where LocalIP == nextLocalIP 
//Whitelisting criteria/ threshold criteria 
| where TimeDeltainSeconds > TimeDeltaThreshold  
| where RemotePortNumber != "0"
| project TimeGenerated, TimeDeltainSeconds, LocalIP, LocalPortNumber,RemoteIP,RemotePortNumber, ReceivedBytes, SentBytes 
| summarize count(), sum(ReceivedBytes), sum(SentBytes), make_list(TimeDeltainSeconds) by TimeDeltainSeconds, bin(TimeGenerated, 1h), LocalIP, RemoteIP, RemotePortNumber 
| summarize (MostFrequentTimeDeltaCount, MostFrequentTimeDeltainSeconds)=arg_max(count_, TimeDeltainSeconds), TotalEvents=sum(count_), TotalSentBytes=sum(sum_SentBytes),TotalReceivedBytes=sum(sum_ReceivedBytes) by bin(TimeGenerated, 1h), LocalIP, RemoteIP, RemotePortNumber 
| where TotalEvents > TotalEventsThreshold  
| extend BeaconPercent = MostFrequentTimeDeltaCount/toreal(TotalEvents) * 100 
| where BeaconPercent > PercentBeaconThreshold
| extend timestamp = TimeGenerated, IPCustomEntity = RemoteIP```
## Zoom room high CPU alerts
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/ZoomLogs/HighCPURoom.yaml)

### ATT&CK Tags

> Tactics: [u'DefenseEvasion', u'Persistence']

### Hunt details

> Description: This hunting query identifies Zoom room systems with high CPU alerts that may be a sign of device compromise.

> Query:

```let hunt_time = 14d; 
ZoomLogs 
| where TimeGenerated >= ago(hunt_time) 
| where Event =~ "zoomroom.alert" 
| extend AlertType = toint(parse_json(RoomEvents).AlertType), AlertKind = toint(parse_json(RoomEvents).AlertKind) 
| extend RoomName = payload_object_room_name_s, User = payload_object_email_s
| where AlertType == 1 and AlertKind == 1 
| extend timestamp = TimeGenerated, AccountCustomEntity = User
// Uncomment the lines below to analyse event over time
//| summarize count() by bin(TimeGenerated, 1h), RoomName
//| render timechart```
## User denied multiple registration events successfully registering
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/ZoomLogs/MultipleRegistrationDenies.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: This hunting query identifies users that have attempted to register for multiple webinars or recordings and has been denied by the organizer but have also successfully register for at least one event. The number of events a user needs to be rejected from to be included in this query is adjusted with the threshold variable.

> Query:

```let hunt_time = 14d; 
let threshold = 2; 
let failed_users = (
ZoomLogs 
| where TimeGenerated >= ago(hunt_time) 
| where Event =~ "webinar.registration_denied" or Event =~ "recording.registration_denied" 
| extend RegisteringUser = columnifexists(payload_object_registrant_email_s, payload_object_registrant_email_s)
| extend ItemId = columnifexists(tostring(parse_json(WebinarEvents).WebinarId),payload_object_uuid_s)
| summarize dcount(ItemId) by RegisteringUser
| where dcount_ItemId > threshold
| project RegisteringUser);
ZoomLogs 
| where TimeGenerated >= ago(hunt_time) 
| where Event =~ "webinar.registration_approved" or Event =~ "recording.registration_approved" 
| extend RegisteringUser = columnifexists(payload_object_registrant_email_s, columnifexists(payload_object_registrant_email_s, "")) 
| extend ItemId = columnifexists(tostring(parse_json(WebinarEvents).WebinarId),columnifexists(payload_object_uuid_s, ""))
| extend EventName = columnifexists(tostring(parse_json(WebinarEvents).WebinarName),columnifexists(payload_object_topic_s, ""))
| extend EventHost = columnifexists(payload_object_host_id,"")
| extend EventStart = columnifexists(tostring(parse_json(WebinarEvents).Start),columnifexists(payload_object_start_time_s ,""))
| where RegisteringUser !in (failed_users)
| project TimeGenerated, RegisteringUser, EventName, ItemId, EventHost, EventStart
| extend timestamp = TimeGenerated, AccountCustomEntity = RegisteringUser```
## New domain added to Whitelist
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/ZoomLogs/NewDomainAccess.yaml)

### ATT&CK Tags

> Tactics: [u'Persistence']

### Hunt details

> Description: This hunting query identifies new domains added to the domain login whitelist in Zoom.

> Query:

```let hunt_time = 14d; 
ZoomLogs 
| where TimeGenerated >= ago(hunt_time)
| where Event =~ "account.settings_updated"
| extend NewDomains = columnifexists("payload_object_enforce_logon_domains", "")
| where isnotempty(NewDomains)
| project TimeGenerated, Event, User, NewDomains
| extend timestamp = TimeGenerated, AccountCustomEntity = User```
## New time zone observed
### Hunt Tags

> Author: [microsoft](https://www.metsys.fr/)

> Reference: [Link to medium post](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/ZoomLogs/NewTZ.yaml)

### ATT&CK Tags

> Tactics: [u'InitialAccess']

### Hunt details

> Description: This hunting query identifies users joining a meeting from a time zone that a user has not been observed from in the last 30 days.

> Query:

```let hunt_time = 1d;
let lookback_time = 14d;
let previous_tz = (
  ZoomLogs
  | where TimeGenerated >= ago(lookback_time)
  | where Event =~ "meeting.participant_joined"
  | extend TimeZone = columnifexists(payload_object_timezone_s, "")
  | summarize by TimeZone
);
ZoomLogs 
| where TimeGenerated >= ago(hunt_time)
| where Event =~ "meeting.participant_joined"
| extend TimeZone = columnifexists(payload_object_timezone_s, "")
| where isnotempty(TimeZone) and TimeZone in (previous_tz)
| extend timestamp = TimeGenerated, AccountCustomEntity = User```
