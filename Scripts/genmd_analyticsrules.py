import json
import sys

with open(sys.argv[1], 'r') as analyticsrules:
    myjson = json.load(analyticsrules)

print('![](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg "Metsys")')
print('# Analytics Rules')

for analyticsrule in myjson:
    for item in myjson[analyticsrule]:
        print('## ' + item["displayName"].encode('ascii') + '\n')
        print('### Informations\n')
        try:
            print('> productFilter: ' + item["productFilter"].encode('ascii') + '\n')
        except:
            print('> productFilter: \n')
        try:
            print('> lastUpdatedDateUTC: ' + item["lastUpdatedDateUTC"].encode('ascii') + '\n')
        except:
            print('> lastUpdatedDateUTC: \n')
        try:
            print('> createdDateUTC: ' + item["createdDateUTC"].encode('ascii') + '\n')
        except:
            print('> createdDateUTC: \n')
        print('### Details\n')
        try:
            print('> Requirements:\n')
            print('```' + str(item["requiredDataConnectors"].encode('ascii')) + '```\n')
        except:
            print('> Requirements: \n')
        try:
            print('> Description: ' + item["description"].encode('ascii') + '\n')
        except:
            print('> Description: \n')