# LocalScripts

## Install Sentinel script (InstallSentinel.ps1)

Reads configuration file under Onboard folder and installs SecurityInsights (Sentinel) solution where required.

### Syntax

`InstallSentinel.ps1 -OnboardingFile <String>`

### Sample

`.\LocalScripts\InstallSentinel.ps1 -OnboardingFile Onboard\onboarding.json`

## Analytics Rules deployment script (CreateAnalyticsRules.ps1)

Reads the config file in the AnalyticsRules folder and deploys its contents to a specific environment. The script will detect if the alert is brand new and needs to be created or if the alert is already active and just needs to be updated. The script also supports attaching a playbook to the rule.

### Syntax 

`CreateAnalyticsRules.ps1 -Workspace <String> -RulesFile <String>`

### Sample

`.\LocalScripts\CreateAnalyticsRules.ps1 -OnboardingFile Onboard\onboarding.json -RulesFile AnalyticsRules\analytics-rules.json`

## Hunting Rules deployment script (CreateHuntingRulesAPI.ps1)

Reads the config file in the HuntingRules folder and deploys its contents to a specific environment. The script will detect if the hunting rule is brand new and needs to be created or if it's already active and just needs to be updated.

### Syntax

`CreateHuntingRulesAPI.ps1 -Workspace <String> -RulesFile <String>`

### Sample

`.\LocalScripts\CreateHuntingRulesAPI.ps1 -OnboardingFile Onboard\onboarding.json -RulesFile HuntingRules\hunting-rules.json`

## Playbooks deployment script (CreatePLaybooks.ps1)

Takes all the json files within a folder (specified as PlaybooksFolder parameter) and deploys them as playbooks (Logic Apps).

### Syntax

`CreatePlaybooks.ps1 -ResourceGroup <String> -PlaybooksFolder <String> -PlaybooksParams <String> -Azure_ServiceAccount <String> -Jira_User <String> -Jira_Pwd '<String>' -Virustotal_Key '<String>'`

### Sample

`.\Script\CreatePlaybooks.ps1 -OnboardingFile Onboard\onboarding.json -PlaybooksFolder Playbooks -PlaybooksParams Playbooks\Playbooks.params -Azure_ServiceAccount thomas.couilleaux@theclemvp.com -Jira_User couilleaux -Jira_Pwd '<String>' -Virustotal_Key '<String>'`

## Workbooks deployment script (CreateWorkbooks.ps1)

Takes all the json files within a folder (specified as WorkbooksFolder) and deploys them as Workbooks in the Sentinel environment. Parameter *WorkbookSourceId* is needed to specify that the workbook will be located inside Sentinel environment. If no parameter is provided, the workbook will be deployed in Azure Monitor.

### Syntax

`CreateWorkbooks.ps1 -OnboardingFile <String> -WorkbooksFolder <String>`

### Sample

`.\LocalScripts\CreateWorkbooks.ps1 -OnboardingFile Onboard\onboarding.json -WorkbooksFolder Workbooks`