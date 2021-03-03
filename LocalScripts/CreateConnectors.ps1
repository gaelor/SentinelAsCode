param(
    [Parameter(Mandatory=$true)]$OnboardingFile
)

#Adding AzSentinel module
Install-Module Az.SecurityInsights -AllowClobber -Scope CurrentUser -Force
Import-Module Az.SecurityInsights

#Getting all workspaces from file
$workspaces = Get-Content -Raw -Path $OnboardingFile | ConvertFrom-Json

Connect-AzAccount -Tenant $workspaces.tenant -Subscription $workspaces.subscription

foreach ($item in $workspaces.deployments){
    Write-Host "Processing resourcegroup $($item.resourcegroup) and workspace $($item.workspace) ..."
    try {
        if($DeleteAll.IsPresent){
            $Connectors = Get-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace
            foreach ($connector in $Connectors){
                Write-Host "Processing connector $($connector.Kind) suppression"
                Remove-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -DataConnectorId $connector.name
            }
        }
        #New-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -Office365 -Exchange "Enabled" -SharePoint "Enabled"
        New-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -AzureActiveDirectory -Alerts "Enabled"
        New-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -AzureAdvancedThreatProtection -Alerts "Enabled"
        New-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -AzureSecurityCenter -Alerts "Enabled" -SubscriptionId ((Get-AzContext).Subscription.Id)
        New-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -ThreatIntelligence -Indicators "Enabled"
        New-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -MicrosoftDefenderAdvancedThreatProtection -Alerts "Enabled"
        New-AzSentinelDataConnector -ResourceGroupName $item.resourcegroup -WorkspaceName $item.workspace -MicrosoftCloudAppSecurity -Alerts "Enabled" -DiscoveryLogs "Disabled"
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Error "Connector import failed with message: $ErrorMessage" 
    }
}