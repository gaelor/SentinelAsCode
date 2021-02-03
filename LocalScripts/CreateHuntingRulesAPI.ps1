param(
    [Parameter(Mandatory=$true)]$OnboardingFile,
    [Parameter(Mandatory=$true)]$RulesFile
)

#Adding AzSentinel module
Install-Module AzSentinel -AllowClobber -Scope CurrentUser -Force
Import-Module AzSentinel
Clear-AzContext

#Getting all workspaces from file
$workspaces = Get-Content -Raw -Path $OnboardingFile | ConvertFrom-Json

Connect-AzAccount -Tenant $workspaces.tenant -Subscription $workspaces.subscription

#Getting all hunting rules from file
$rules = Get-Content -Raw -Path $rulesFile | ConvertFrom-Json


foreach ($item in $workspaces.deployments){
    Write-Host "Processing workspace $($item.workspace) ..."
    foreach ($rule in $rules.hunting) {
        Write-Host "Processing hunting rule: " -NoNewline 
        Write-Host "$($rule.displayName)" -ForegroundColor Green

        $existingRule = Get-AzSentinelHuntingRule -WorkspaceName $item.workspace -RuleName $rule.displayName -ErrorAction SilentlyContinue

        if ($existingRule) {
            Write-Host "Hunting rule $($rule.displayName) already exists. Updating..."

            New-AzSentinelHuntingRule -WorkspaceName $item.workspace -DisplayName $rule.displayName -Description $rule.description -Tactics $rule.tactics -Query $rule.query -confirm:$false
        }
        else {
            Write-Host "Hunting rule $($rule.displayName) doesn't exist. Creating..."

            New-AzSentinelHuntingRule -WorkspaceName $item.workspace -DisplayName $rule.displayName -Description $rule.description -Tactics $rule.tactics -Query $rule.query -confirm:$false
        }
    }
}