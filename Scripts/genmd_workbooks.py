import json
import sys
import re

with open(sys.argv[1], 'r') as workbooks:
    myjson = json.load(workbooks)

print('![](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg "Metsys")')
print('# Workbooks')

filename = re.sub('^.*/', '', sys.argv[1], flags=re.DOTALL).replace('.json','')

for key,workbook in myjson.items():
    if key == "parameters":
        print('## ' + filename)
        print('### Workbook Tags\n')
        print('> Author: ['+ workbook["author"]["defaultValue"].encode('utf-8') + '](https://www.metsys.fr/)' + '\n')
        print('> Reference: [Link to medium post](https://github.com/Azure/Azure-Sentinel/tree/master/' + sys.argv[1] + ')\n')
        print('### Workbook details\n')
        print('> Description: ' + workbook["description"]["defaultValue"].encode('utf-8') + '\n')
    if key == "resources":
        print('> Query:\n')
        print('```t')
        print(workbook[0]["properties"]["serializedData"].encode('utf-8'))
        print('```\n')