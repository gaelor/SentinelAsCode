#git clone https://github.com/Azure/Azure-Sentinel.git tmp/Azure-Sentinel
$Files = Get-ChildItem -Path '.\tmp\Azure-Sentinel\'  -Filter *.yaml -Recurse -File -Name | Select-String -Pattern "Hunting Queries"
foreach ($file in $Files){
    $content = ''
    $filecontent = Get-Content -Path tmp\Azure-Sentinel\$file
    foreach ($line in $filecontent) { $content = $content + "`n" + $line }
    $huntingrules = ConvertFrom-YAML $content
    $tactics = $huntingrules.tactics -join "`",`""
    
    Write-Host "      `"tactics`": [`r`n`        `""$tactics"`"`r`n      ]`r`n"
}
#Start-Sleep -s 20
#Remove-Item -Path tmp/Azure-Sentinel –Recurse -Force