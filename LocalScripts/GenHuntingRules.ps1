git clone https://github.com/Azure/Azure-Sentinel.git tmp/Azure-Sentinel
$Files = Get-ChildItem -Path '.\tmp\Azure-Sentinel\Hunting Queries\'  -Filter *.yaml -Recurse -File -Name
$HuntingRulesTemplate = "{`r`n"
$HuntingRulesTemplate += "  `"hunting`": [`r`n"
foreach ($file in $Files){
    if ($file -ne $Files[-1]){
        $content = ''
        foreach ($line in $file) { $content = $content + "`n" + $line }
        $huntingrules = ConvertFrom-YAML $content
        $HuntingRulesTemplate += "    {`r`n"
        $HuntingRulesTemplate += "      `"author`": `"microsoft`",`r`n"
        $HuntingRulesTemplate += "      `"displayName`": `"" + $huntingrules.name + "`",`r`n"
        $HuntingRulesTemplate += "      `"reference`": `"" + $url + "`",`r`n"
        $HuntingRulesTemplate += "      `"description`": `"" + $huntingrules.description + "`",`r`n"
        $HuntingRulesTemplate += "      `"query`": `"" + $huntingrules.query + "`",`r`n"
        $HuntingRulesTemplate += "      `"tactics`": [`r`n`        `"" + $huntingrules.tactics + "`"`r`n      ]`r`n"
        $HuntingRulesTemplate += "    },`r`n"
        }
    else {
        $content = ''
        foreach ($line in $file) { $content = $content + "`n" + $line }
        $huntingrules = ConvertFrom-YAML $content
        $HuntingRulesTemplate += "    {`r`n"
        $HuntingRulesTemplate += "      `"author`": `"microsoft`",`r`n"
        $HuntingRulesTemplate += "      `"displayName`": `"" + $huntingrules.name + "`",`r`n"
        $HuntingRulesTemplate += "      `"reference`": `"" + $url + "`",`r`n"
        $HuntingRulesTemplate += "      `"description`": `"" + $huntingrules.description + "`",`r`n"
        $HuntingRulesTemplate += "      `"query`": `"" + $huntingrules.query + "`",`r`n"
        $HuntingRulesTemplate += "      `"tactics`": [`r`n`        `"" + $huntingrules.tactics + "`"`r`n      ]`r`n"
        $HuntingRulesTemplate += "    }`r`n"
        }
    }
$HuntingRulesTemplate += "  ]`r`n"
$HuntingRulesTemplate += "}`r`n"
$HuntingRulesTemplate