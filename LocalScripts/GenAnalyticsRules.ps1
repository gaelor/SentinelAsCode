param(
    [Parameter(Mandatory=$true)]$AnalyticsRulesFolder,
    [Parameter(Mandatory=$true)]$TenantID,
    [Parameter(Mandatory=$true)]$SubscriptionID,
    [Parameter(Mandatory=$true)]$Workspace,
    [Parameter(Mandatory=$true)]$GIT_USER,
    [Parameter(Mandatory=$true)]$GIT_EMAIL
)

Install-Module Az.OperationalInsights -AllowClobber -Scope CurrentUser -Force
Import-Module Az.OperationalInsights
Clear-AzContext

Connect-AzAccount -Tenant $TenantID -Subscription $SubscriptionID

#Getting all workspaces

$Date = Get-Date -Format "ddMMyyyy"

Export-AzSentinel -WorkspaceName $Workspace -OutputFolder $AnalyticsRulesFolder + $Workspace + "_" -Kind Templates
Remove-Item -r $AnalyticsRulesFolder + "accorinvest_\"
Rename-Item -Path $AnalyticsRulesFolder + "accorinvest_*" + "_" + $Date + ".json" -NewName $AnalyticsRulesFolder + $Workspace + $Date + "_analytics-rules.json"

git config --global user.name $GIT_USER
git config --global user.email $GIT_EMAIL
git add $OnboardingFolder\onboarding_$Date.json
git commit -am "Automated OnboardFile"
git push