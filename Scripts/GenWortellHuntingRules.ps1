param(
    [Parameter(Mandatory=$true)]$HuntingRulesFolder
)
git clone https://github.com/wortell/KQL.git tmp/Wortell_KQL
$Date = Get-Date -Format "ddMMyyyy"
$Excluded_Files = "KQL_win_sdbinst_shim_persistence.txt", "KQL_win_susp_calc", "KQL_win_susp_cli_escape"
$regex = $Excluded_Files -join '|'
$Files = Get-ChildItem -Path '.\tmp\Wortell_KQL\'  -Filter *.txt -Recurse -File -Name
$HuntingRulesTemplate = "{`r`n"
$HuntingRulesTemplate += "  `"hunting`": [`r`n"
foreach ($file in $Files){
    if ($file -ne $Files[-1] -And $file -notmatch $regex ) {
        $filecontent = Get-Content -Path tmp\Wortell_KQL\$file
        if ($null -ne $filecontent) {
        $HuntingRulesTemplate += "    {`r`n"
        $HuntingRulesTemplate += "      `"author`": `"wortell`",`r`n"
        $HuntingRulesTemplate += "      `"displayName`": `"" + $file.tostring().replace(".txt","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"reference`": `"https://raw.githubusercontent.com/wortell/KQL/master/" + $file.tostring() + "`",`r`n"
        $description = [regex]::Match($filecontent, "^(.*?) \|").Groups[1].Value.trim() | Select-String -pattern "//" -NotMatch
        $HuntingRulesTemplate += "      `"description`": `"" + $description + "`",`r`n"
        $HuntingRulesTemplate += "      `"query`": `"" + $filecontent.replace("\","\\").replace("`"","\`"").replace("`'","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"tactics`": [`r`n`        `"Collection`"`r`n      ]`r`n"
        $HuntingRulesTemplate += "    },`r`n"}
    }
    elseif ($file -eq $Files[-1] -And $file -notmatch $regex) {
        $filecontent = Get-Content -Path tmp\Wortell_KQL\$file
        if ($null -ne $filecontent) {
        $HuntingRulesTemplate += "    {`r`n"
        $HuntingRulesTemplate += "      `"author`": `"wortell`",`r`n"
        $HuntingRulesTemplate += "      `"displayName`": `"" + $file.tostring().replace(".txt","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"reference`": `"https://raw.githubusercontent.com/wortell/KQL/master/" + $file.tostring() + "`",`r`n"
        $description = [regex]::Match($filecontent, "^(.*?) \|").Groups[1].Value.trim() | Select-String -pattern "//" -NotMatch
        $HuntingRulesTemplate += "      `"description`": `"" + $description + "`",`r`n"
        $HuntingRulesTemplate += "      `"query`": `"" + $filecontent.replace("\","\\").replace("`"","\`"").replace("`'","") + "`",`r`n"
        $HuntingRulesTemplate += "      `"tactics`": [`r`n`        `"Collection`"`r`n      ]`r`n"
        $HuntingRulesTemplate += "    }`r`n"}
    }
}
$HuntingRulesTemplate += "  ]`r`n"
$HuntingRulesTemplate += "}`r`n"
Out-File -Path $HuntingRulesFolder\"Wortell_hunting-rules_"$Date".json" -InputObject $HuntingRulesTemplate -Encoding ASCII
Start-Sleep -s 20
Remove-Item -Path tmp/Wortell_KQL –Recurse -Force