param(
    [Parameter(Mandatory=$true)]$HuntingRulesFolder
)
git clone https://github.com/rod-trent/SentinelKQL.git tmp/RodTrent_KQL
$Files = Get-ChildItem -Path '.\tmp\RodTrent_KQL\'  -Filter *.txt -Recurse -File -Name
foreach ($file in $Files){
    $filecontent = Get-Content -Path tmp\RodTrent_KQL\$file
    $HuntingRulesTemplate = [regex]::Match($filecontent, "^//.*  (.*?)\|").Groups[1].Value.trim().replace("//","") | Select-String -pattern " " -NotMatch
    $HuntingRulesTemplate
}