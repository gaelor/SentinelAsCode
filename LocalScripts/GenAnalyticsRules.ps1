param(
    [Parameter(Mandatory=$true)]$AnalyticsRulesFolder,
    [Parameter(Mandatory=$true)]$TenantID,
    [Parameter(Mandatory=$true)]$SubscriptionID,
    [Parameter(Mandatory=$true)]$Workspace
)

Install-Module Az.OperationalInsights -AllowClobber -Scope CurrentUser -Force
Import-Module Az.OperationalInsights
Clear-AzContext

Connect-AzAccount -Tenant $TenantID -Subscription $SubscriptionID

$Date = Get-Date -Format "ddMMyyyy"

Export-AzSentinel -WorkspaceName $Workspace -OutputFolder $AnalyticsRulesFolder"_" -Kind Templates
Remove-Item -r $AnalyticsRulesFolder"_\"
Move-Item -Path $AnalyticsRulesFolder"_Templates_*"$Date".json" $AnalyticsRulesFolder"analytics-rules_"$Date".json"