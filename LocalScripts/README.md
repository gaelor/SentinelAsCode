![](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg "Metsys")

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

## Generate Onboarding Template (GenOnboarding.ps1)

Generate a onboarding template with all workspaces from the tenant.

### Syntax

`GenOnboarding.ps1 -OnboardingFolder <String> -TenantID <String> -SubscriptionID <String>`

### Sample

`.\LocalScripts\GenOnboarding.ps1 -OnboardingFolder Onboard -TenantID <String> -SubscriptionID <String>`

## Generate MS AnalyticsRules Template (GenAnalyticsRules.ps1)

Generate a MS AnalyticsRules Template with all rules templates available from a workspace.

### Syntax

`GenAnalyticsRules.ps1 -AnalyticsRulesFolder <String> -TenantID <String> -SubscriptionID <String> -Workspace <String>`

### Sample

`.\LocalScripts\GenAnalyticsRules.ps1 -AnalyticsRulesFolder AnalyticsRules -TenantID <String> -SubscriptionID <String> -Workspace <String>`

## Generate MS Huntingrules Template (GenMSHuntingRules.ps1)

Generate a MS Huntingrules Template with all rules templates available from MS Sentinel github.

### Syntax

`GenMSHuntingRules.ps1 -HuntingRulesFolder <String>`

### Sample

`.\LocalScripts\GenMSHuntingRules.ps1 -HuntingRulesFolder HuntingRules`

## Generate Wortell Huntingrules Template (GenWortellHuntingRules.ps1)

Generate a Wortell Huntingrules Template with all rules templates available from Wortell KQL github.

### Syntax

`GenWortellHuntingRules.ps1 -HuntingRulesFolder <String>`

### Sample

`.\LocalScripts\GenWortellHuntingRules.ps1 -HuntingRulesFolder HuntingRules`

## Generate RodTrent Huntingrules Template (GenRodTrentlHuntingRules.ps1)

Generate a RodTrent Huntingrules Template with all rules templates available from RodTrent KQL github.

### Syntax

`GenRodTrentHuntingRules.ps1 -HuntingRulesFolder <String>`

### Sample

`.\LocalScripts\GenRodTrentHuntingRules.ps1 -HuntingRulesFolder HuntingRules`

## Generate BlueTeam Huntingrules Template (GenBlueTeamHuntingRules.ps1)

Generate a BlueTeam Huntingrules Template with all rules templates available from BlueTeam KQL github.

### Syntax

`GenBlueTeamHuntingRules.ps1 -HuntingRulesFolder <String>`

### Sample

`.\LocalScripts\GenBlueTeamHuntingRules.ps1 -HuntingRulesFolder HuntingRules`