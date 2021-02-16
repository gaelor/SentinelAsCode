param(
    [Parameter(Mandatory=$true)]$OnboardingFile,
    [Parameter(Mandatory=$true)]$PlaybooksFolder,
    [Parameter(Mandatory=$true)]$PlaybooksParams
)

#Adding AzSentinel module
Install-Module AzSentinel -AllowClobber -Scope CurrentUser -Force
Import-Module AzSentinel
Install-Module Az.Resources -AllowClobber -Scope CurrentUser -Force
Import-Module Az.Resources
Clear-AzContext

#Getting all workspaces from file
$workspaces = Get-Content -Raw -Path $OnboardingFile | ConvertFrom-Json

Connect-AzAccount -Tenant $workspaces.tenant -Subscription $workspaces.subscription

Write-Host "Folder is: $($PlaybooksFolder)"
Write-Host "Playbooks Parameter Files is: $($PlaybooksParams)"

Write-Host "Processing resourcegroup $($workspaces.deployments[0].resourcegroup)"

#Getting all playbooks from folder
$armTemplateFiles = Get-ChildItem -Path $PlaybooksFolder -Filter *.json

foreach ($armTemplate in $armTemplateFiles) {
    $playbookFileName = Split-Path $armTemplate -leaf
    $playbookDisplayName = $playbookFileName.replace('.json', '')
    try {
        Write-Host "Deploying : $playbookDisplayName in the resource group: $($workspaces.deployments[0].resourcegroup)"
        New-AzResourceGroupDeployment -ResourceGroupName $workspaces.deployments[0].resourcegroup -TemplateFile $armTemplate -TemplateParameterFile $PlaybooksParams
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Error "Playbook deployment failed with message: $ErrorMessage"
    }
}