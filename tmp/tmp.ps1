param(
    [Parameter(Mandatory=$true)]$HuntingRulesFolder
)
git clone https://github.com/wortell/KQL.git tmp/Wortell_KQL
$Files = Get-ChildItem -Path '.\tmp\Wortell_KQL\'  -Filter *.txt -Recurse -File -Name
foreach ($file in $Files){
    $filecontent = Get-Content -Path tmp\Wortell_KQL\$file
    $HuntingRulesTemplate = [regex]::Match($filecontent, "^(.*?) \|").Groups[1].Value.trim() | Select-String -pattern "//" -NotMatch
    $HuntingRulesTemplate
}