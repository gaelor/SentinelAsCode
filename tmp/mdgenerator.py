import json

with open('c:\\Users\\thomas.couilleaux\\OneDrive - METSYS\\SentinelAsCode\\SentinelAsCode\\HuntingRules\\hunting-rules.json', 'r') as huntingrules:
    myjson = json.load(huntingrules)

for huntingrule in myjson:
    for item in myjson[huntingrule]:
        for key,value in item.items():
            if key == 'displayName' or key == 'author':
                print('![](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg "Metsys")')
                print('# Hunting Rules')
                print('# ' + value)
                print('## Hunt Tagsvalue')
                print('**Author:** [' + value + '](https://www.metsys.fr/)')