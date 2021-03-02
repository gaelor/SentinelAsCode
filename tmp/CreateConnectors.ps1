param(
    [Parameter(Mandatory=$true)]$OnboardingFile,
    [Parameter(Mandatory=$true)]$Azure_User,
    [Parameter(Mandatory=$true)]$Azure_Pwd
)

#Adding AzSentinel module
#Install-Module AzSentinel -AllowClobber -Scope CurrentUser -Force
#Import-Module AzSentinel

#Getting all workspaces from file
$workspaces = Get-Content -Raw -Path $OnboardingFile | ConvertFrom-Json

$AzurePwd = ConvertTo-SecureString -String $Azure_Pwd -AsPlainText -Force

$Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $Azure_User,$AzurePwd

Connect-AzAccount -Credential $Credential -Tenant $workspaces.tenant -Subscription $workspaces.subscription

foreach ($item in $workspaces.deployments){
    Write-Host "Processing resourcegroup $($item.resourcegroup) and workspace $($item.workspace) ..."
    try {
        #New-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -Office365 -Exchange "Enabled" -SharePoint "Enabled"
        New-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -AzureActiveDirectory -Alerts "Enabled"
        New-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -AzureAdvancedThreatProtection -Alerts "Enabled"
        New-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -AzureSecurityCenter -Alerts "Enabled" -SubscriptionId ((Get-AzContext).Subscription.Id)
        #New-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -Indicators -Alerts "Enabled" -SubscriptionId ((Get-AzContext).Subscription.Id)
        #New-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -ThreatIntelligence -Alerts "Enabled" -SubscriptionId ((Get-AzContext).Subscription.Id)
        #New-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -Logs -Alerts "Enabled" -SubscriptionId ((Get-AzContext).Subscription.Id)
        #New-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -MicrosoftDefenderAdvancedThreatProtection -Alerts "Enabled" -SubscriptionId ((Get-AzContext).Subscription.Id)
        #New-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -MicrosoftCloudAppSecurity -Alerts "Enabled" -SubscriptionId ((Get-AzContext).Subscription.Id)
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Error "Connector import failed with message: $ErrorMessage" 
    }
}