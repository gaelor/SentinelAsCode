param(
    [Parameter(Mandatory=$true)]$OnboardingFile,
    [Parameter(Mandatory=$true)]$PlaybooksFolder,
    [Parameter(Mandatory=$true)]$PlaybooksParams
)

#Adding AzSentinel module
Install-Module AzSentinel -AllowClobber -Scope CurrentUser -Force
Import-Module AzSentinel
Clear-AzContext

#Getting all workspaces from file
$workspaces = Get-Content -Raw -Path $OnboardingFile | ConvertFrom-Json

Connect-AzAccount -Tenant $workspaces.tenant -Subscription $workspaces.subscription

Write-Host "Folder is: $($PlaybooksFolder)"
Write-Host "Playbooks Parameter Files is: $($PlaybooksParams)"

foreach ($item in $workspaces.deployments){
    Write-Host "Processing resourcegroup $($item.resourcegroup) ..."

    #Getting all playbooks from folder
    $armTemplateFiles = Get-ChildItem -Path $PlaybooksFolder -Filter *.json

    Write-Host "Files are: " $armTemplateFiles

    foreach ($armTemplate in $armTemplateFiles) {
        try {
            New-AzResourceGroupDeployment -ResourceGroupName $item.resourcegroup -TemplateFile $armTemplate -TemplateParameterFile $PlaybooksParams
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Error "Playbook deployment failed with message: $ErrorMessage" 
        }
    }
}