git clone https://github.com/Azure/Azure-Sentinel.git tmp/Azure-Sentinel
$Date = Get-Date -Format "ddMMyyyy"
$Files = Get-ChildItem -Path '.\tmp\Azure-Sentinel\'  -Filter *.yaml -Recurse -File -Name | Select-String -Pattern "Hunting Queries"
$HuntingRulesTemplate = "{`r`n"
$HuntingRulesTemplate += "  `"hunting`": [`r`n"
foreach ($file in $Files){
    if ($file -ne $Files[-1] -And $file -ne $Files[0]){
        $content = ''
        $filecontent = Get-Content -Path tmp\Azure-Sentinel\$file
        foreach ($line in $filecontent) { $content = $content + "`n" + $line }
        $huntingrules = ConvertFrom-YAML $content
        $HuntingRulesTemplate += "    {`r`n"
        $HuntingRulesTemplate += "      `"author`": `"microsoft`",`r`n"
        $HuntingRulesTemplate += "      `"displayName`": `"" + $huntingrules.name + "`",`r`n"
        $HuntingRulesTemplate += "      `"reference`": `"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/" + $file.tostring().replace("\", "/").replace(" ","%20") + "`",`r`n"
        $HuntingRulesTemplate += "      `"description`": `"" + $huntingrules.description.replace("`"","\`"").replace("`'","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"query`": `"" + $huntingrules.query.replace("\","\\").replace("`"","\`"").replace("`'","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"tactics`": [`r`n`        `"" + $huntingrules.tactics.tostring().replace(" ","`",`"") + "`"`r`n      ]`r`n"
        $HuntingRulesTemplate += "    },`r`n"
    }
    elseif ($file -ne $Files[0]){
        $content = ''
        $filecontent = Get-Content -Path tmp\Azure-Sentinel\$file
        foreach ($line in $filecontent) { $content = $content + "`n" + $line }
        $huntingrules = ConvertFrom-YAML $content
        $HuntingRulesTemplate += "    {`r`n"
        $HuntingRulesTemplate += "      `"author`": `"microsoft`",`r`n"
        $HuntingRulesTemplate += "      `"displayName`": `"" + $huntingrules.name + "`",`r`n"
        $HuntingRulesTemplate += "      `"reference`": `"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/" + $file.tostring().replace("\", "/").replace(" ","%20") + "`",`r`n"
        $HuntingRulesTemplate += "      `"description`": `"" + $huntingrules.description.replace("`"","\`"").replace("`'","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"query`": `"" + $huntingrules.query.replace("\","\\").replace("`"","\`"").replace("`'","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"tactics`": [`r`n`        `"" + $huntingrules.tactics.tostring().replace(" ","`",`"") + "`"`r`n      ]`r`n"
        $HuntingRulesTemplate += "    }`r`n"
    }
    else {}
}
$HuntingRulesTemplate += "  ]`r`n"
$HuntingRulesTemplate += "}`r`n"
Out-File -Path HuntingRules\"MS_"$Date"_hunting-rules.json" -InputObject $HuntingRulesTemplate
Start-Sleep -s 20
Remove-Item -Path tmp/Azure-Sentinel –Recurse -Force