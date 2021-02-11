import json
import sys

with open(sys.argv[1], 'r') as analyticsrules:
    myjson = json.load(analyticsrules)

print('![](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg "Metsys")')
print('# Analytics Rules')

for analyticsrule in myjson:
    for item in myjson[analyticsrule]:
        print('## ' + item["displayName"])
        print('### Informations\n')
        print('> productFilter: ' + item["productFilter"] + '\n')
        print('> lastUpdatedDateUTC: ' + item["lastUpdatedDateUTC"] + '\n')
        print('> createdDateUTC: ' + item["createdDateUTC"] + '\n')
        print('### Details\n')
        print('> Requirements:\n')
        print('```' + item["requiredDataConnectors"] + '```')
        print('> Description: ' + item["description"] + '\n')