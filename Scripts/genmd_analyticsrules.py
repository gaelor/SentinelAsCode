import json
import sys

with open(sys.argv[1], 'r') as analyticsrules:
    myjson = json.load(analyticsrules)

print('[![Metsys](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg)](https://www.metsys.fr/ "Metsys")')
print('# Analytics Rules')

for analyticsrule in myjson:
    for item in myjson[analyticsrule]:
        print('## ' + item["displayName"].encode('utf-8') + '\n')
        print('### Informations\n')
        try:
            print('> productFilter: ' + item["productFilter"].encode('utf-8') + '\n')
        except:
            None
        try:
            print('> lastUpdatedDateUTC: ' + item["lastUpdatedDateUTC"].encode('utf-8') + '\n')
        except:
            None
        try:
            print('> createdDateUTC: ' + item["createdDateUTC"].encode('utf-8') + '\n')
        except:
            None
        print('### Details\n')
        try:
            print('> Tactics: ' + item["tactics"].encode('utf-8') + '\n')
        except:
            None
        try:
            print('> Requirements:\n```' + item["requiredDataConnectors"].encode('utf-8') + '```\n')
        except:
            None
        try:
            print('> Description: ' + item["description"].encode('utf-8') + '\n')
        except:
            None