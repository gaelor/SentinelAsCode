# Scripts

## Install Sentinel script (InstallSentinel.ps1)

Reads configuration file under Onboard folder and installs SecurityInsights (Sentinel) solution where required.

### Syntax

`InstallSentinel.ps1 -OnboardingFile <String> -Azure_User <String> -Azure_Pwd '<String>'`

### Sample

`.\InstallSentinel.ps1 -OnboardingFile ..\Onboard\onboarding.json -Azure_User thomas.couilleaux@theclemvp.com -Azure_Pwd '<String>'`

## Analytics Rules deployment script (CreateAnalyticsRules.ps1)

Reads the config file in the AnalyticsRules folder and deploys its contents to a specific environment. The script will detect if the alert is brand new and needs to be created or if the alert is already active and just needs to be updated. The script also supports attaching a playbook to the rule.

### Syntax 

`CreateAnalyticsRules.ps1 -Workspace <String> -RulesFile <String> -Azure_User <String> -Azure_Pwd '<String>'`

### Sample

`.\CreateAnalyticsRules.ps1 -OnboardingFile "..\Onboard\onboarding.json" -RulesFile "..\AnalyticsRules\analytics-rules.json" -Azure_User thomas.couilleaux@theclemvp.com -Azure_Pwd '<String>'`

## Hunting Rules deployment script (CreateHuntingRulesAPI.ps1)

Reads the config file in the HuntingRules folder and deploys its contents to a specific environment. The script will detect if the hunting rule is brand new and needs to be created or if it's already active and just needs to be updated.

### Syntax

`CreateHuntingRulesAPI.ps1 -Workspace <String> -RulesFile <String> -Azure_User <String> -Azure_Pwd '<String>'`

### Sample

`.\CreateHuntingRulesAPI.ps1 -OnboardingFile "..\Onboard\onboarding.json" -RulesFile "..\HuntingRules\hunting-rules.json" -Azure_User thomas.couilleaux@theclemvp.com -Azure_Pwd '<String>'`

## Playbooks deployment script (CreatePLaybooks.ps1)

Takes all the json files within a folder (specified as PlaybooksFolder parameter) and deploys them as playbooks (Logic Apps).

### Syntax

`CreatePlaybooks.ps1 -ResourceGroup <String> -PlaybooksFolder <String> -PlaybooksParams <String>`

### Sample

`.\CreatePlaybooks.ps1 -OnboardingFile "..\Onboard\onboarding.json" -PlaybooksFolder "..\Playbooks\" -PlaybooksParams "..\Playbooks\Playbooks.params"`

## Workbooks deployment script (CreateWorkbooks.ps1)

Takes all the json files within a folder (specified as WorkbooksFolder) and deploys them as Workbooks in the Sentinel environment. Parameter *WorkbookSourceId* is needed to specify that the workbook will be located inside Sentinel environment. If no parameter is provided, the workbook will be deployed in Azure Monitor.

### Syntax

`CreateWorkbooks.ps1 -OnboardingFile <String> -WorkbooksFolder <String> -Azure_User <String> -Azure_Pwd '<String>'`

### Sample

`.\CreateWorkbooks.ps1 -OnboardingFile "..\Onboard\onboarding.json" -WorkbooksFolder "..\Workbooks\" -Azure_User thomas.couilleaux@theclemvp.com -Azure_Pwd '<String>'`