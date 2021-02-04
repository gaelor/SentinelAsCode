param(
    [Parameter(Mandatory=$true)]$OnboardingFile,
    [Parameter(Mandatory=$true)]$WorkbooksFolder
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

Write-Host "Folder is: $($WorkbooksFolder)"

foreach ($item in $workspaces.deployments){
    Write-Host "Processing resourcegroup $($item.resourcegroup) ..."

    #Getting all playbooks from folder
    $armTemplateFiles = Get-ChildItem -Path $WorkbooksFolder -Filter *.json

    Write-Host "Files are: " $armTemplateFiles

    $workbookSourceId = "/subscriptions/$($workspaces.subscription)/resourcegroups/$($item.resourcegroup)/providers/microsoft.operationalinsights/workspaces/$($item.workspace)"

    foreach ($armTemplate in $armTemplateFiles) {
        try {
            New-AzResourceGroupDeployment -ResourceGroupName $item.resourcegroup -TemplateFile $armTemplate -WorkbookSourceId $workbookSourceId 
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Error "Workbook deployment failed with message: $ErrorMessage" 
        }
    }
}