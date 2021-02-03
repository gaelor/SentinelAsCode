param (
    [Parameter(Mandatory=$true)]$OnboardingFile,
    [Parameter(Mandatory=$true)]$Azure_User,
    [Parameter(Mandatory=$true)]$Azure_Pwd
)

Install-Module AzSentinel -Scope CurrentUser -Force
Import-Module AzSentinel
Install-Module Az.OperationalInsights -Scope CurrentUser -Force
Import-Module Az.OperationalInsights

Write-Host $Azure_User
Write-Host $Azure_Pwd

#Getting all workspaces from file
$workspaces = Get-Content -Raw -Path $OnboardingFile | ConvertFrom-Json

$Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $Azure_User,$Azure_Pwd

Connect-AzAccount -Credential $Credential -Tenant $workspaces.tenant -Subscription $workspaces.subscription

foreach ($item in $workspaces.deployments){
    Write-Host "Processing workspace $($item.workspace) ..."
    $solutions = Get-AzOperationalInsightsIntelligencePack -resourcegroupname $item.resourcegroup -WorkspaceName $item.workspace -WarningAction:SilentlyContinue

    if (($solutions | Where-Object Name -eq 'SecurityInsights').Enabled) {
        Write-Host "SecurityInsights solution is already enabled for workspace $($item.workspace)"
    }
    else {
        Set-AzSentinel -WorkspaceName $item.workspace -Confirm:$false
    }
}