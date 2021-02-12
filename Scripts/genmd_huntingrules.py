import json
import sys

with open(sys.argv[1], 'r') as huntingrules:
    myjson = json.load(huntingrules, unicode=False)

print('![](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg "Metsys")')
print('# Hunting Rules')

for huntingrule in myjson:
    for item in myjson[huntingrule]:
        print('## ' + item["displayName"])
        print('### Hunt Tags\n')
        print('> Author: [' + item["author"] + '](https://www.metsys.fr/)' + '\n')
        print('> Reference: [Link to medium post](' + item["reference"] + ')' + '\n')
        print('### ATT&CK Tags\n')
        print('> Tactics: ' + str(item["tactics"]) + '\n')
        print('### Hunt details\n')
        print('> Description: ' + item["description"] + '\n')
        print('> Query:\n')
        print('```' + item["query"] + '```')