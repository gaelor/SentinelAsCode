param(
    [Parameter(Mandatory=$true)]$OnboardingFile,
    [Parameter(Mandatory=$true)]$RulesFile,
    [Parameter(Mandatory=$true)]$Azure_User,
    [Parameter(Mandatory=$true)]$Azure_Pwd
)

#Adding AzSentinel module
Install-Module AzSentinel -AllowClobber -Scope CurrentUser -Force
Import-Module AzSentinel

#Getting all workspaces from file
$workspaces = Get-Content -Raw -Path $OnboardingFile | ConvertFrom-Json

$AzurePwd = ConvertTo-SecureString -String $Azure_Pwd -AsPlainText -Force

$Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $Azure_User,$AzurePwd

Connect-AzAccount -Credential $Credential -Tenant $workspaces.tenant -Subscription $workspaces.subscription

#Getting all hunting rules from file
$rules = Get-Content -Raw -Path $rulesFile | ConvertFrom-Json

foreach ($item in $workspaces.deployments){
    Write-Host "Processing workspace $($item.workspace) ..."
    foreach ($rule in $rules.hunting) {
        Write-Host "Processing hunting rule: " -NoNewline 
        Write-Host "$($rule.displayName)" -ForegroundColor Green

        $existingRule = Get-AzSentinelHuntingRule -WorkspaceName $item.workspace -RuleName $rule.displayName -ErrorAction SilentlyContinue

        if ($existingRule && $rule.description) {
            Write-Host "Hunting rule $($rule.displayName) already exists. Updating..."

            New-AzSentinelHuntingRule -WorkspaceName $item.workspace -DisplayName $rule.displayName -Description $rule.description -Tactics $rule.tactics -Query $rule.query -confirm:$false
        }
        elseif ($existingRule && -not $rule.description) {
            Write-Host "Hunting rule $($rule.displayName) already exists. Updating..."

            New-AzSentinelHuntingRule -WorkspaceName $item.workspace -DisplayName $rule.displayName -Description " " -Tactics $rule.tactics -Query $rule.query -confirm:$false
        }
        elseif (-not $existingRule && $rule.description) {
            Write-Host "Hunting rule $($rule.displayName) doesn't exist. Creating..."

            New-AzSentinelHuntingRule -WorkspaceName $item.workspace -DisplayName $rule.displayName -Description $rule.description -Tactics $rule.tactics -Query $rule.query -confirm:$false
        }
        else {
            Write-Host "Hunting rule $($rule.displayName) doesn't exist. Creating..."

            New-AzSentinelHuntingRule -WorkspaceName $item.workspace -DisplayName $rule.displayName -Description " " -Tactics $rule.tactics -Query $rule.query -confirm:$false
        }
    }
}