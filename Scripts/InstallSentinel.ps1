param (
    [Parameter(Mandatory=$true)]$OnboardingFile
)

#Adding AzSentinel module
Uninstall-Module -Name AzureRm -AllVersions -Force

Install-Module AzSentinel -Scope CurrentUser -Force
Import-Module AzSentinel

Get-InstalledModule

#Getting all workspaces from file
$workspaces = Get-Content -Raw -Path $OnboardingFile | ConvertFrom-Json

$User = 'thomas.couilleaux@theclemvp.com'
$PWord = ConvertTo-SecureString -String 'ENL8wbISkdwZw$3N4ural' -AsPlainText -Force
$Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $User,$PWord

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