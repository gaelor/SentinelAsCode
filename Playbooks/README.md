[![Metsys](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg)](https://www.metsys.fr/ "Metsys")
# Playbooks
JSON files in this folder are ARM templates that define Playbooks that need to be deployed on a given Sentinel environment.
## Restrict-CAIPAddress
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Restrict-CAIPAddress.json)

### Playbook Requirements

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

> CA_LocationName:

The azure integration account resource group name.

> integrationAccount_resourceGroup:

The azure integration account resource group name.

> integrationAccount:

The azure integration account name.

### Playbook details

> Description: This playbook will block ip address on conditional access in Microsoft Azure.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FRestrict-CAIPAddress.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Isolate-NSGMachine
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Isolate-NSGMachine.json)

### Playbook Requirements

> Office365ConnectionName:

The office 365 connection name used by the logic app.

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

> EmailApprovalContact:

The approval email address.

### Playbook details

> Description: This playbook will take host entites from triggered incident and search for matches in the enterprises subscriptions. An email for approval will be sent to isolate Azure VM. Upon approval a new NSG Deny All is created and applied to the Azure VM, The Azure VM is restarted to remove any persisted connections.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FIsolate-NSGMachine.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Restrict-MDATPDomain
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Restrict-MDATPDomain.json)

### Playbook Requirements

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> MDATPConnectionName:

The mdatp connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

### Playbook details

> Description: This playbook will block domain on the machine in Microsoft Defender ATP.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FRestrict-MDATPDomain.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Unisolate-MDATPMachine
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Unisolate-MDATPMachine.json)

### Playbook Requirements

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> MDATPConnectionName:

The mdatp connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

### Playbook details

> Description: This playbook will unisolate the machine in Microsoft Defender ATP.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FUnisolate-MDATPMachine.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Get-URLReputation
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Get-URLReputation.json)

### Playbook Requirements

> Virustotal_Key:

The virustotal api key.

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

> AzureLAConnectionName:

The azure log analytics connection name used by the logic app.

### Playbook details

> Description: This playbook will take each URL entity and query VirusTotal for URL  Report.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FGet-URLReputation.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Block-MDATPAppExecution
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Block-MDATPAppExecution.json)

### Playbook Requirements

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> MDATPConnectionName:

The mdatp connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

### Playbook details

> Description: This playbook will block app execution on the machine in Microsoft Defender ATP.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FBlock-MDATPAppExecution.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Isolate-MDATPMachine
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Isolate-MDATPMachine.json)

### Playbook Requirements

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> MDATPConnectionName:

The mdatp connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

### Playbook details

> Description: This playbook will isolate the machine in Microsoft Defender ATP.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FIsolate-MDATPMachine.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Scan-MDATPMachine
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Scan-MDATPMachine.json)

### Playbook Requirements

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> MDATPConnectionName:

The mdatp connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

### Playbook details

> Description: This playbook will launch antivirus scan on the machine in Microsoft Defender ATP.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FScan-MDATPMachine.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Unblock-MDATPAppExecution
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Unblock-MDATPAppExecution.json)

### Playbook Requirements

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> MDATPConnectionName:

The mdatp connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

### Playbook details

> Description: This playbook will unblock app execution on the machine in Microsoft Defender ATP.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FUnblock-MDATPAppExecution.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Get-IPReputation
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Get-IPReputation.json)

### Playbook Requirements

> Virustotal_Key:

The virustotal api key.

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

> integrationAccount_resourceGroup:

The azure integration account resource group name.

> integrationAccount:

The azure integration account name.

### Playbook details

> Description: This playbook will collect ip reputation on virustotal API.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FGet-IPReputation.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Get-FileReputation
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Get-FileReputation.json)

### Playbook Requirements

> Virustotal_Key:

The virustotal api key.

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

### Playbook details

> Description: This playbook will collect file reputation on virustotal API.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FGet-FileReputation.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Restrict-NSGIPAddress
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Restrict-NSGIPAddress.json)

### Playbook Requirements

> NSG_Group:

The azure network security group name.

> NSG_ResourceGroup:

The azure resource group name hosted the azure network security group name.

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

> TriClient:

The client name trigram.

> CA_LocationName:

The azure integration account resource group name.

> integrationAccount_resourceGroup:

The azure integration account resource group name.

> integrationAccount:

The azure integration account name.

### Playbook details

> Description: This playbook will block ip address on a NSG in Microsoft Azure.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FRestrict-NSGIPAddress.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Block-AADUser
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Block-AADUser.json)

### Playbook Requirements

> AzureADConnectionName:

The azure ad connection name used by the logic app.

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

### Playbook details

> Description: This playbook will disable the user in Azure Active Directoy and add a comment to the incident

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FBlock-AADUser.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Open-jira-Ticket
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Open-jira-Ticket.json)

### Playbook Requirements

> Jira_Organization:

The client organization in jira.

> Jira_URL:

The jira url.

> Jira_Pwd:

The jira password used to authenticate on the API.

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

> Jira_User:

The jira account name used to authenticate on the API.

> integrationAccount_resourceGroup:

The azure integration account resource group name.

> integrationAccount:

The azure integration account name.

### Playbook details

> Description: This playbook will open a ticket on Jira with incident informations using the client organization.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FOpen-jira-Ticket.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Prompt-User
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Prompt-User.json)

### Playbook Requirements

> AzureADConnectionName:

The azure ad connection name used by the logic app.

> Office365ConnectionName:

The o365 connection name used by the logic app.

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

### Playbook details

> Description: This playbook will ask the user if they completed the action from the Incident in Azure Sentinel.  If so, it will close the incident and add a comment.  If not, it will add a comment to the incident.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FPrompt-User.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Reset-AADUserPassword
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Reset-AADUserPassword.json)

### Playbook Requirements

> Office365ConnectionName:

The office 365 connection name used by the logic app.

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

> Office365UsersConnectionName:

The office 365 users connection name used by the logic app.

### Playbook details

> Description: This playbook will disable the user in Azure Active Directoy and add a comment to the incident

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FReset-AADUserPassword.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Restrict-MDATPIPAddress
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Restrict-MDATPIPAddress.json)

### Playbook Requirements

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> MDATPConnectionName:

The mdatp connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

> integrationAccount_resourceGroup:

The azure integration account resource group name.

> integrationAccount:

The azure integration account name.

### Playbook details

> Description: This playbook will block ip address on the machine in Microsoft Defender ATP.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FRestrict-MDATPIPAddress.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Investigate-MDATPMachine
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Investigate-MDATPMachine.json)

### Playbook Requirements

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> MDATPConnectionName:

The mdatp connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

### Playbook details

> Description: This playbook will launch automated investigation on the machine in Microsoft Defender ATP.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FInvestigate-MDATPMachine.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Restrict-MDATPFileHash
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Restrict-MDATPFileHash.json)

### Playbook Requirements

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> MDATPConnectionName:

The mdatp connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

### Playbook details

> Description: This playbook will block hash file on the machine in Microsoft Defender ATP.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FRestrict-MDATPFileHash.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Restrict-MDATPUrl
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Restrict-MDATPUrl.json)

### Playbook Requirements

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> MDATPConnectionName:

The mdatp connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

### Playbook details

> Description: This playbook will block url on the machine in Microsoft Defender ATP.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FRestrict-MDATPUrl.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Collect-MDATPMachine
### Playbook Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://github.com/gaelor/SentinelAsCode/tree/master/Playbooks/Collect-MDATPMachine.json)

### Playbook Requirements

> AzureSentinelConnectionName:

The azure sentinel connection name used by the logic app.

> MDATPConnectionName:

The mdatp connection name used by the logic app.

> Azure_ServiceAccount:

The service account used to run the logic app.

### Playbook details

> Description: This playbook will collect investigation package on the machine in Microsoft Defender ATP.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2FCollect-MDATPMachine.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton""/>
</a>

