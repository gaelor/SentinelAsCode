param(
    [Parameter(Mandatory=$true)]$HuntingRulesFolder
)
Install-Module powershell-yaml -AllowClobber -Scope CurrentUser -Force
Import-Module powershell-yaml
git clone https://github.com/Azure/Azure-Sentinel.git tmp/Azure-Sentinel
$Date = Get-Date -Format "ddMMyyyy"
$Files = Get-ChildItem -Path '.\tmp\Azure-Sentinel\'  -Filter *.yaml -Recurse -File -Name | Select-String -Pattern "Hunting Queries"
$HuntingRulesTemplate = "{`r`n"
$HuntingRulesTemplate += "  `"hunting`": [`r`n"
foreach ($file in $Files){
    if ($file -ne $Files[-1]) {
        $content = ''
        $filecontent = Get-Content -Path tmp\Azure-Sentinel\$file
        foreach ($line in $filecontent) { $content = $content + "`n" + $line }
        $huntingrules = ConvertFrom-YAML $content
        $tactics = $huntingrules.tactics -join "`",`""
        $HuntingRulesTemplate += "    {`r`n"
        $HuntingRulesTemplate += "      `"author`": `"microsoft`",`r`n"
        $HuntingRulesTemplate += "      `"displayName`": `"" + $huntingrules.name + "`",`r`n"
        $HuntingRulesTemplate += "      `"reference`": `"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/" + $file.tostring().replace("\", "/").replace(" ","%20") + "`",`r`n"
        $HuntingRulesTemplate += "      `"description`": `"" + $huntingrules.description.replace("\","\\").replace("`"","\`"").replace("`'","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"query`": `"" + $huntingrules.query.replace("\","\\").replace("`"","\`"").replace("`'","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"tactics`": [`r`n`        `"" + $tactics + "`"`r`n      ]`r`n"
        $HuntingRulesTemplate += "    },`r`n"
    }
    else {
        $content = ''
        $filecontent = Get-Content -Path tmp\Azure-Sentinel\$file
        foreach ($line in $filecontent) { $content = $content + "`n" + $line }
        $huntingrules = ConvertFrom-YAML $content
        $tactics = $huntingrules.tactics -join "`",`""
        $HuntingRulesTemplate += "    {`r`n"
        $HuntingRulesTemplate += "      `"author`": `"microsoft`",`r`n"
        $HuntingRulesTemplate += "      `"displayName`": `"" + $huntingrules.name + "`",`r`n"
        $HuntingRulesTemplate += "      `"reference`": `"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/" + $file.tostring().replace("\", "/").replace(" ","%20") + "`",`r`n"
        $HuntingRulesTemplate += "      `"description`": `"" + $huntingrules.description.replace("\","\\").replace("`"","\`"").replace("`'","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"query`": `"" + $huntingrules.query.replace("\","\\").replace("`"","\`"").replace("`'","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"tactics`": [`r`n`        `"" + $tactics + "`"`r`n      ]`r`n"
        $HuntingRulesTemplate += "    }`r`n"
    }
}
$HuntingRulesTemplate += "  ]`r`n"
$HuntingRulesTemplate += "}`r`n"
Out-File -Path $HuntingRulesFolder\"MS_hunting-rules_"$Date".json" -InputObject $HuntingRulesTemplate -Encoding ASCII
Start-Sleep -s 20
Remove-Item -Path tmp/Azure-Sentinel –Recurse -Force