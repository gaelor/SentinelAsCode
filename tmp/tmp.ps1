param(
    [Parameter(Mandatory=$true)]$HuntingRulesFolder
)
#git clone https://github.com/BlueTeamLabs/sentinel-attack.git tmp/BlueTeam_KQL
$Files = Get-ChildItem -Path '.\tmp\BlueTeam_KQL\detections\'  -Filter *.txt -Recurse -File -Name
foreach ($file in $Files){
    $filecontent = Get-Content -Path tmp\BlueTeam_KQL\detections\$file
    $HuntingRulesTemplate = [regex]::Match($filecontent, "// Description: (.*?) //").Groups[1].Value.replace("#","").replace(", ","`",`"")
    $HuntingRulesTemplate
}