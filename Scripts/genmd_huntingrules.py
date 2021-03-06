import json
import sys

with open(sys.argv[1], 'r') as huntingrules:
    myjson = json.load(huntingrules, strict=False)

print('[![Metsys](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg)](https://www.metsys.fr/ "Metsys")')
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
        print('```t')
        print('```' + item["query"])
        print('```\n')