import json
import sys

with open(sys.argv[1], 'r') as analyticsrules:
    myjson = json.load(analyticsrules)

print('![](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg "Metsys")')
print('# Analytics Rules')

for analyticsrule in myjson:
    for item in myjson[analyticsrule]:
        print('## ' + item["displayName"] + '\n')
        print('### Informations\n')
        try:
            print('> productFilter: ' + item["productFilter"] + '\n')
        except:
            print('> productFilter: \n')
        try:
            print('> lastUpdatedDateUTC: ' + item["lastUpdatedDateUTC"] + '\n')
        except:
            print('> lastUpdatedDateUTC: \n')
        try:
            print('> createdDateUTC: ' + item["createdDateUTC"] + '\n')
        except:
            print('> createdDateUTC: \n')
        print('### Details\n')
        try:
            print('> Requirements:\n')
            print('```' + str(item["requiredDataConnectors"]) + '```\n')
        except:
            print('> Requirements: \n')
        try:
            print('> Description: ' + item["description"] + '\n')
        except:
            print('> Description: \n')