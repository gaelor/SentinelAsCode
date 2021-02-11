param(
    [Parameter(Mandatory=$true)]$AnalyticsRulesFolder,
    [Parameter(Mandatory=$true)]$TenantID,
    [Parameter(Mandatory=$true)]$SubscriptionID,
    [Parameter(Mandatory=$true)]$Workspace,
    [Parameter(Mandatory=$true)]$GIT_USER,
    [Parameter(Mandatory=$true)]$GIT_EMAIL,
    [Parameter(Mandatory=$true)]$Azure_User,
    [Parameter(Mandatory=$true)]$Azure_Pwd
)

Install-Module AzSentinel -AllowClobber -Scope CurrentUser -Force
Import-Module AzSentinel

$AzurePwd = ConvertTo-SecureString -String $Azure_Pwd -AsPlainText -Force

$Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $Azure_User,$AzurePwd

Connect-AzAccount -Credential $Credential -Tenant $TenantID -Subscription $SubscriptionID

$Date = Get-Date -Format "ddMMyyyy"

Export-AzSentinel -WorkspaceName $Workspace -OutputFolder $AnalyticsRulesFolder"_" -Kind Templates
Remove-Item -r $AnalyticsRulesFolder"_\"
Move-Item -Path $AnalyticsRulesFolder"_Templates_*"$Date".json" $AnalyticsRulesFolder"_"$Date"_analytics-rules.json"