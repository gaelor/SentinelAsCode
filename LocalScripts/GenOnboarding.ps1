param(
    [Parameter(Mandatory=$true)]$OnboardingFolder,
    [Parameter(Mandatory=$true)]$TenantID,
    [Parameter(Mandatory=$true)]$SubscriptionID,
    [Parameter(Mandatory=$true)]$GIT_USER,
    [Parameter(Mandatory=$true)]$GIT_EMAIL
)

Install-Module Az.OperationalInsights -AllowClobber -Scope CurrentUser -Force
Import-Module Az.OperationalInsights
Clear-AzContext

Connect-AzAccount -Tenant $TenantID -Subscription $SubscriptionID

#Getting all workspaces
$workspaces = Get-AzOperationalInsightsWorkspace | Where-Object -Property Name -notmatch "Default" | Select-Object Name, ResourceGroupName

$Date = Get-Date -Format "ddMMyyyy"

$Onboarding =  "{   `"tenant`": `"$TenantID`"," + "`r`n"
$Onboarding += "    `"subscription`": `"$SubscriptionID`"," + "`r`n"
$Onboarding += "    `"deployments`": [" + "`r`n"
foreach ($item in $workspaces){
    if ($item -ne $workspaces[-1]){
        $Onboarding += "        {" + "`r`n"
        $Onboarding += "            `"resourcegroup`": `"" + $item.ResourceGroupName + "`"," + "`r`n"
        $Onboarding += "            `"workspace`": `"" + $item.Name + "`"," + "`r`n"
        $Onboarding += "        }," + "`r`n"
    }
    else {
        $Onboarding += "        {" + "`r`n"
        $Onboarding += "            `"resourcegroup`": `"" + $item.ResourceGroupName + "`"," + "`r`n"
        $Onboarding += "            `"workspace`": `"" + $item.Name + "`"" + "`r`n"
        $Onboarding += "        }" + "`r`n"
    }
}
$Onboarding += "    ]" + "`r`n"
$Onboarding += "}" + "`r`n"
Out-File -Path $OnboardingFolder\onboarding_$Date.json -InputObject $Onboarding