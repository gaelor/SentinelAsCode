param(
    [Parameter(Mandatory=$true)]$HuntingRulesFolder
)
git clone https://github.com/rod-trent/SentinelKQL.git tmp/RodTrent_KQL
$Date = Get-Date -Format "ddMMyyyy"
$Files = Get-ChildItem -Path '.\tmp\RodTrent_KQL\'  -Filter *.txt -Recurse -File -Name
$HuntingRulesTemplate = "{`r`n"
$HuntingRulesTemplate += "  `"hunting`": [`r`n"
foreach ($file in $Files){
    if ($file -ne $Files[-1]) {
        $filecontent = Get-Content -Path tmp\RodTrent_KQL\$file
        if ($null -ne $filecontent) {
        $HuntingRulesTemplate += "    {`r`n"
        $HuntingRulesTemplate += "      `"author`": `"rod trent`",`r`n"
        $HuntingRulesTemplate += "      `"displayName`": `"" + $file.tostring().replace(".txt","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"reference`": `"https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/" + $file.tostring() + "`",`r`n"
        $HuntingRulesTemplate += "      `"description`": `"" + $file.tostring().replace(".txt","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"query`": `"" + $filecontent.replace("\","\\").replace("`"","\`"").replace("`'","").replace("`t","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"tactics`": [`r`n`        `"Collection`"`r`n      ]`r`n"
        $HuntingRulesTemplate += "    },`r`n"}
    }
    else {
        $filecontent = Get-Content -Path tmp\RodTrent_KQL\$file
        if ($null -ne $filecontent) {
        $HuntingRulesTemplate += "    {`r`n"
        $HuntingRulesTemplate += "      `"author`": `"rod trent`",`r`n"
        $HuntingRulesTemplate += "      `"displayName`": `"" + $file.tostring().replace(".txt","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"reference`": `"https://raw.githubusercontent.com/rod-trent/SentinelKQL/master/" + $file.tostring() + "`",`r`n"
        $HuntingRulesTemplate += "      `"description`": `"" + $file.tostring().replace(".txt","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"query`": `"" + $filecontent.replace("\","\\").replace("`"","\`"").replace("`'","").replace("`t","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"tactics`": [`r`n`        `"Collection`"`r`n      ]`r`n"
        $HuntingRulesTemplate += "    }`r`n"}
    }
}
$HuntingRulesTemplate += "  ]`r`n"
$HuntingRulesTemplate += "}`r`n"
Out-File -Path $HuntingRulesFolder\"RodTrent_hunting-rules_"$Date".json" -InputObject $HuntingRulesTemplate
Start-Sleep -s 20
Remove-Item -Path tmp/RodTrent_KQL –Recurse -Force