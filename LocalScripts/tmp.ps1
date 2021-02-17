param(
    [Parameter(Mandatory=$true)]$OnboardingFile,
    [Parameter(Mandatory=$true)]$PlaybooksFolder,
    [Parameter(Mandatory=$true)]$PlaybooksFilter,
    [Parameter(Mandatory=$false)]$PlaybooksParamsFile,
    [Parameter(Mandatory=$false)]$PlaybooksParams
)
$workspaces = Get-Content -Raw -Path $OnboardingFile | ConvertFrom-Json

Write-Host "Playbook Folder is: $($PlaybooksFolder)"

Write-Host "Processing resourcegroup $($workspaces.deployments[0].resourcegroup)"

#Getting all playbooks from folder
$armTemplateFiles = Get-ChildItem -Path $PlaybooksFolder -Filter $PlaybooksFilter

foreach ($armTemplate in $armTemplateFiles) {
    $playbookFileName = Split-Path $armTemplate -leaf
    $playbookDisplayName = $playbookFileName.replace('.json', '')
    Write-Host "Playbook is: $playbookDisplayName"
    Write-Host "Playbook Template File is: $armTemplate"
    Write-Host "Playbook Parameters File is: $PlaybooksParamsFile"
    try {
        Write-Host "Deploying: $playbookDisplayName, with template file: $armTemplate, with parameters file: $PlaybooksParamsFile, with parameters: @PlaybooksParams, in the resource group: $($workspaces.deployments[0].resourcegroup)"
        #$Params = $PlaybooksParams -replace('^','-') -replace('=',' ')
        $Params = @{
            Jira_User="toto"
            Jira_Pwd="tata"
        }
        #$Params[0].split(' ')[0]

        Write-Host "New-AzResourceGroupDeployment -Name $(("$playbookDisplayName").replace(' ', '')) -ResourceGroupName $($workspaces.deployments[0].resourcegroup) -TemplateFile `'$armTemplate`' -TemplateParameterFile $PlaybooksParamsFile -playbookDisplayName $playbookDisplayName @Params"
        #New-AzResourceGroupDeployment -Name $(("$playbookDisplayName").replace(' ', '')) -ResourceGroupName $($workspaces.deployments[0].resourcegroup) -TemplateFile `'$armTemplate`' -TemplateParameterFile $PlaybooksParamsFile -playbookDisplayName $playbookDisplayName -Jira_User $Params[0].split(' ')[1]
        Write-Host @Params
        Write-Host @PlaybooksParams
        New-AzResourceGroupDeployment -Name $(("$playbookDisplayName").replace(' ', '')) -ResourceGroupName $($workspaces.deployments[0].resourcegroup) -TemplateFile `'$armTemplate`' -TemplateParameterFile $PlaybooksParamsFile -playbookDisplayName $playbookDisplayName @PlaybooksParams
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Error "Playbook deployment failed with message: $ErrorMessage"
    }
}