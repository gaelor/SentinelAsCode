param(
    [Parameter(Mandatory=$true)]$OnboardingFile,
    [Parameter(Mandatory=$true)]$PlaybooksFolder,
    [Parameter(Mandatory=$true)]$PlaybooksParams,
    [Parameter(Mandatory=$true)]$Azure_User,
    [Parameter(Mandatory=$true)]$Azure_Pwd
)

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

Write-Host "Folder is: $($PlaybooksFolder)"
Write-Host "Playbooks Parameter Files is: $($PlaybooksParams)"

$Params = Get-Content -Path $PlaybooksParams
Write-Host $Params.replace('thomas.couilleaux@theclemvp.com','toto@theclemvp.com')

foreach ($item in $workspaces.deployments){
    Write-Host "Processing resourcegroup $($item.resourcegroup) ..."

    #Getting all playbooks from folder
    $armTemplateFiles = Get-ChildItem -Recurse -Path $PlaybooksFolder -Filter *NSGIPAddress.json

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