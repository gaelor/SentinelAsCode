param(
    [Parameter(Mandatory=$true)]$OnboardingFile,
    [Parameter(Mandatory=$true)]$WorkbooksFolder,
    [Parameter(Mandatory=$true)]$Azure_User,
    [Parameter(Mandatory=$true)]$Azure_Pwd
)

# Variables
$workbookType = "sentinel"

#Adding AzSentinel module
Install-Module AzSentinel -AllowClobber -Scope CurrentUser -Force
Import-Module AzSentinel
Install-Module Az.Resources -AllowClobber -Scope CurrentUser -Force
Import-Module Az.Resources

#Getting all workspaces from file
$workspaces = Get-Content -Raw -Path $OnboardingFile | ConvertFrom-Json

$AzurePwd = ConvertTo-SecureString -String $Azure_Pwd -AsPlainText -Force

$Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $Azure_User,$AzurePwd

Connect-AzAccount -Credential $Credential -Tenant $workspaces.tenant -Subscription $workspaces.subscription

Write-Host "Folder is: $($WorkbooksFolder)"

$armTemplateFiles = Get-ChildItem -Recurse -Path $WorkbooksFolder -Filter *.json
foreach ($armTemplate in $armTemplateFiles) {
    $workbookFileName = Split-Path $armTemplate -leaf
    $workbookDisplayName = $workbookFileName.replace('.json', '')
    foreach ($item in $workspaces.deployments){
        try {
            Write-Host "Deploying : $workbookDisplayName of type $workbookType in the resource group: $($item.resourcegroup)"
            New-AzResourceGroupDeployment -Name $(("$workbookDisplayName - $($item.workspace)").replace(' ', '')) -ResourceGroupName $($item.resourcegroup) `
            -TemplateFile $armTemplate `
            -Workspace $item.workspace `
            -workbookDisplayName $workbookDisplayName `
            -workbookType $workbookType `
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Error "Workbook deployment failed with message: $($ErrorMessage)"
        }
    }
}