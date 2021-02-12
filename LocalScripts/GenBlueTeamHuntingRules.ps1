param(
    [Parameter(Mandatory=$true)]$HuntingRulesFolder
)
git clone https://github.com/BlueTeamLabs/sentinel-attack.git tmp/BlueTeam_KQL
$Date = Get-Date -Format "ddMMyyyy"
$Files = Get-ChildItem -Path '.\tmp\BlueTeam_KQL\detections\'  -Filter *.txt -Recurse -File -Name
$HuntingRulesTemplate = "{`r`n"
$HuntingRulesTemplate += "  `"hunting`": [`r`n"
foreach ($file in $Files){
    if ($file -ne $Files[-1]) {
        $filecontent = Get-Content -Path tmp\BlueTeam_KQL\$file
        if ($null -ne $filecontent) {
        $HuntingRulesTemplate += "    {`r`n"
        $HuntingRulesTemplate += "      `"author`": `"blueteam`",`r`n"
        $HuntingRulesTemplate += "      `"displayName`": `"" + $file.tostring().replace(".txt","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"reference`": `"https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/" + $file.tostring() + "`",`r`n"
        $HuntingRulesTemplate += "      `"description`": `"" + [regex]::Match($filecontent, "// Description: (.*?) //").Groups[1].Value.replace("#","").replace(", ","`",`"") + "`",`r`n"
        $HuntingRulesTemplate += "      `"query`": `"" + $filecontent.replace("\","\\").replace("`"","\`"").replace("`'","").replace("`t","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"tactics`": [`r`n`        `"" + [regex]::Match($filecontent, "// Tactics: (.*?) //").Groups[1].Value.replace("#","").replace(", ","`",`"") + "`"`r`n      ]`r`n"
        $HuntingRulesTemplate += "    },`r`n"}
    }
    else {
        $filecontent = Get-Content -Path tmp\BlueTeam_KQL\$file
        if ($null -ne $filecontent) {
        $HuntingRulesTemplate += "    {`r`n"
        $HuntingRulesTemplate += "      `"author`": `"blueteam`",`r`n"
        $HuntingRulesTemplate += "      `"displayName`": `"" + $file.tostring().replace(".txt","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"reference`": `"https://raw.githubusercontent.com/BlueTeamLabs/sentinel-attack/master/detections/" + $file.tostring() + "`",`r`n"
        $HuntingRulesTemplate += "      `"description`": `"" + [regex]::Match($filecontent, "// Description: (.*?) //").Groups[1].Value.replace("#","").replace(", ","`",`"") + "`",`r`n"
        $HuntingRulesTemplate += "      `"query`": `"" + $filecontent.replace("\","\\").replace("`"","\`"").replace("`'","").replace("`t","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"tactics`": [`r`n`        `"" + [regex]::Match($filecontent, "// Tactics: (.*?) //").Groups[1].Value.replace("#","").replace(", ","`",`"") + "`"`r`n      ]`r`n"
        $HuntingRulesTemplate += "    }`r`n"}
    }
}
$HuntingRulesTemplate += "  ]`r`n"
$HuntingRulesTemplate += "}`r`n"
Out-File -Path $HuntingRulesFolder\"BlueTeam_hunting-rules_"$Date".json" -InputObject $HuntingRulesTemplate -Encoding ASCII
Start-Sleep -s 20
Remove-Item -Path tmp/BlueTeam_KQL –Recurse -Force