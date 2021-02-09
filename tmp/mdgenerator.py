import json

with open('c:\\Users\\thomas.couilleaux\\OneDrive - METSYS\\SentinelAsCode\\SentinelAsCode\\HuntingRules\\hunting-rules.json', 'r') as huntingrules:
    myjson = json.load(huntingrules)

print('![](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg "Metsys")')
print('# Hunting Rules')

for huntingrule in myjson:
    for item in myjson[huntingrule]:
#        for value in item.items():
#            if key == 'displayName' or key == 'author':
        print('> ' + item["displayName"])
        print('## Hunt Tags')
        print('**Author:** [' + item["author"] + '](https://www.metsys.fr/)')
        print('**Reference:** [Link to medium post](' + item["reference"] + ')')
        print('## ATT&CK Tags')
        print('Tactics: ' + str(item["tactics"]))
        print('## Hunt details')
        print('**Description:** ' + item["description"])
        print('**Query:**')
        print('```C#' + item["query"] + '```')