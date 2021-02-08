param(
    [Parameter(Mandatory=$true)]$OnboardingFile,
    [Parameter(Mandatory=$true)]$PlaybooksFolder,
    [Parameter(Mandatory=$true)]$PlaybooksParams,
    [Parameter(Mandatory=$true)]$Azure_ServiceAccount,
    [Parameter(Mandatory=$true)]$Azure_User,
    [Parameter(Mandatory=$true)]$Azure_Pwd,
    [Parameter(Mandatory=$true)]$Jira_User,
    [Parameter(Mandatory=$true)]$Jira_Pwd,
    [Parameter(Mandatory=$true)]$Virustotal_Key
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
$TmpParams = $Params.replace('<username>@<domain>',$Azure_ServiceAccount).replace('<jira_user>',$Jira_User).replace('<jira_pwd>',$Jira_Pwd).replace('<virustotal_key>',$Virustotal_Key)
$TmpParamsFile = New-TemporaryFile
$TmpParams | out-file -filepath $TmpParamsFile
Write-Host $TmpParams

Write-Host "Processing resourcegroup $($workspaces.deployments[0].resourcegroup)"
#Getting all playbooks from folder
$armTemplateFiles = Get-ChildItem -Recurse -Path $PlaybooksFolder -Filter Get*Reputation.json
Write-Host "Files are: " $armTemplateFiles
foreach ($armTemplate in $armTemplateFiles) {
    try {
        New-AzResourceGroupDeployment -ResourceGroupName $workspaces.deployments[0].resourcegroup -TemplateFile $armTemplate -TemplateParameterFile $TmpParamsFile
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Error "Playbook deployment failed with message: $ErrorMessage"
    }
}