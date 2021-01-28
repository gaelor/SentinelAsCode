param(
    [Parameter(Mandatory=$true)]$OnboardingFile,
    [Parameter(Mandatory=$true)]$RulesFile
)

#Adding AzSentinel module
Install-Module AzSentinel -AllowClobber -Scope CurrentUser -Force
Import-Module AzSentinel
Clear-AzContext

#Getting all workspaces from file
$workspaces = Get-Content -Raw -Path $OnboardingFile | ConvertFrom-Json

Connect-AzAccount -Tenant $workspaces.tenant -Subscription $workspaces.subscription

foreach ($item in $workspaces.deployments){
    Write-Host "Processing workspace $($item.workspace) ..."
    try {
        Import-AzSentinelAlertRule -WorkspaceName $item.workspace -SettingsFile $RulesFile
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Error "Rule import failed with message: $ErrorMessage" 
    }

}