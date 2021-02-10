param(
    [Parameter(Mandatory=$true)]$OnboardingFolder,
    [Parameter(Mandatory=$true)]$TenantID,
    [Parameter(Mandatory=$true)]$SubscriptionID,
    [Parameter(Mandatory=$true)]$GIT_USER,
    [Parameter(Mandatory=$true)]$GIT_EMAIL,
    [Parameter(Mandatory=$true)]$Azure_User,
    [Parameter(Mandatory=$true)]$Azure_Pwd
)

Install-Module Az.OperationalInsights -AllowClobber -Scope CurrentUser -Force
Import-Module Az.OperationalInsights

$AzurePwd = ConvertTo-SecureString -String $Azure_Pwd -AsPlainText -Force

$Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $Azure_User,$AzurePwd

Connect-AzAccount -Credential $Credential -Tenant $TenantID -Subscription $SubscriptionID

#Getting all workspaces
$workspaces = Get-AzOperationalInsightsWorkspace | Where-Object -Property Name -notmatch "Default" | Select-Object Name, ResourceGroupName

$Date = Get-Date -Format "ddMMyyyy"

$Onboarding =  "{   `"tenant`": `"$TenantID`"," + "`r`n"
$Onboarding += "    `"subscription`": `"$SubscriptionID`"," + "`r`n"
$Onboarding += "    `"deployments`": [" + "`r`n"
foreach ($item in $workspaces){
    if ($item -ne $workspaces[-1]){
        $Onboarding += "        {" + "`r`n"
        $Onboarding += "            `"resourcegroup`": `"$item.ResourceGroupName`"," + "`r`n"
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
git config --global user.name $GIT_USER
git config --global user.email $GIT_EMAIL
git add $OnboardingFolder\onboarding_$Date.json
git commit -am "Automated OnboardFile"
git push