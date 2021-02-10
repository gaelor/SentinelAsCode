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

$Date = Get-Date -Format "ddMMyyyy"

Export-AzSentinel -WorkspaceName $Workspace -OutputFolder $AnalyticsRulesFolder$Workspace"_" -Kind Templates
Remove-Item -r $AnalyticsRulesFolder$Workspace"_\"
Move-Item -Path $AnalyticsRulesFolder$Workspace"_Templates_*"$Date".json" $AnalyticsRulesFolder$Workspace"_"$Date"_analytics-rules.json"