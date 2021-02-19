param(
    [Parameter(Mandatory=$true)]$OnboardingFile,
    [Parameter(Mandatory=$true)]$WorkbooksFolder
)

# Variables
$workbookType = "sentinel"

#Adding AzSentinel module
Install-Module AzSentinel -AllowClobber -Scope CurrentUser -Force
Import-Module AzSentinel
Install-Module Az.Resources -AllowClobber -Scope CurrentUser -Force
Import-Module Az.Resources
Clear-AzContext

#Getting all workspaces from file
$workspaces = Get-Content -Raw -Path $OnboardingFile | ConvertFrom-Json

Connect-AzAccount -Tenant $workspaces.tenant -Subscription $workspaces.subscription

Write-Host "Folder is: $($WorkbooksFolder)"

$armTemplateFiles = Get-ChildItem -Path $WorkbooksFolder -Filter *.json
foreach ($armTemplate in $armTemplateFiles) {
    $workbookFileName = Split-Path $armTemplate -leaf
    $workbookDisplayName = $workbookFileName.replace('.json', '')
    try {
        Write-Host "Deploying : $workbookDisplayName of type $workbookType in the resource group: $($workspaces.deployments[0].resourcegroup)"
        New-AzResourceGroupDeployment -Name $(("$workbookDisplayName - $($workspaces.deployments[0].workspace)").replace(' ', '')) `
        -ResourceGroupName $($workspaces.deployments[0].resourcegroup) `
        -TemplateFile $armTemplate `
        -Workspace $workspaces.deployments[0].workspace `
        -workbookDisplayName $workbookDisplayName `
        -workbookType $workbookType `
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Error "Workbook deployment failed with message: $($ErrorMessage)"
    }
}