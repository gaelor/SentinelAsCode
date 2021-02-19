param(
    [Parameter(Mandatory=$true)]$OnboardingFile,
    [Parameter(Mandatory=$true)]$PlaybooksFolder,
    [Parameter(Mandatory=$false)]$PlaybooksFilter,
    [Parameter(Mandatory=$false)]$PlaybooksParamsFile,
    [Parameter(Mandatory=$false)]$PlaybooksParams
)

#Adding AzSentinel module
#Install-Module AzSentinel -AllowClobber -Scope CurrentUser -Force
#Import-Module AzSentinel
#Install-Module Az.Resources -AllowClobber -Scope CurrentUser -Force
#Import-Module Az.Resources
#Clear-AzContext

Connect-AzAccount -Tenant $workspaces.tenant -Subscription $workspaces.subscription

#Getting all workspaces from file
$workspaces = Get-Content -Raw -Path $OnboardingFile | ConvertFrom-Json

Write-Host "Playbook Folder is: $($PlaybooksFolder)"

Write-Host "Processing resourcegroup $($workspaces.deployments[0].resourcegroup)"

#Getting all playbooks from folder
$armTemplateFiles = Get-ChildItem -Path $PlaybooksFolder -Filter $PlaybooksFilter

if($null -eq $PlaybooksFilter){
    $PlaybooksFilter = '*.json'
}

if($null -eq $PlaybooksParamsFile){
    foreach ($armTemplate in $armTemplateFiles) {
        $PlaybooksParamsFile = $armTemplate -replace [regex]::Escape('.json'), ('.params')
        $playbookFileName = Split-Path $armTemplate -leaf
        $playbookDisplayName = $playbookFileName.replace('.json', '')
        Write-Host "Playbook is: $playbookDisplayName"
        Write-Host "Playbook Template File is: $armTemplate"
        Write-Host "Playbook Parameters File is: $PlaybooksParamsFile"
        Write-Host "Playbook Parameters are:"@PlaybooksParams
                try {
            Write-Host "Deploying: $playbookDisplayName, with template file: $armTemplate, with parameters file: $PlaybooksParamsFile, in the resource group: $($workspaces.deployments[0].resourcegroup)"
            New-AzResourceGroupDeployment -PlaybookName $(("$playbookDisplayName").replace(' ', '')) -ResourceGroupName $($workspaces.deployments[0].resourcegroup) -TemplateFile `'$armTemplate`' -TemplateParameterFile $PlaybooksParamsFile -playbookDisplayName $playbookDisplayName @PlaybooksParams
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Error "Playbook deployment failed with message: $ErrorMessage"
        }
    }
}
else{
    foreach ($armTemplate in $armTemplateFiles) {
        $playbookFileName = Split-Path $armTemplate -leaf
        $playbookDisplayName = $playbookFileName.replace('.json', '')
        Write-Host "Playbook is: $playbookDisplayName"
        Write-Host "Playbook Template File is: $armTemplate"
        Write-Host "Playbook Parameters File is: $PlaybooksParamsFile"
        Write-Host "Playbook Parameters are:"@PlaybooksParams
        try {
            Write-Host "Deploying: $playbookDisplayName, with template file: $armTemplate, with parameters file: $PlaybooksParamsFile, in the resource group: $($workspaces.deployments[0].resourcegroup)"
            New-AzResourceGroupDeployment -PlaybookName $(("$playbookDisplayName").replace(' ', '')) -ResourceGroupName $($workspaces.deployments[0].resourcegroup) -TemplateFile `'$armTemplate`' -TemplateParameterFile $PlaybooksParamsFile -playbookDisplayName $playbookDisplayName @PlaybooksParams
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Error "Playbook deployment failed with message: $ErrorMessage"
        }
    }
}