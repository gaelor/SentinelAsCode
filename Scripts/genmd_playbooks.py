import json
import sys
import re

with open(sys.argv[1], 'r') as playbooks:
    myjson = json.load(playbooks)

filename = re.sub('^.*/', '', sys.argv[1], flags=re.DOTALL).replace('.json','')

for key,playbook in myjson.items():
    if key == "parameters":
        print('## ' + filename)
        print('### Playbook Tags\n')
        print('> Author: ['+ playbook["author"]["defaultValue"].encode('utf-8') + '](https://www.metsys.fr/)' + '\n')
        print('> Reference: [Link to medium post](https://github.com/Azure/Azure-Sentinel/tree/master/' + sys.argv[1] + ')\n')
        print('### Playbook Requirements\n')
        for param_name, param_value in playbook.items():
            if param_name != 'description' and param_name != 'author':
                print('> ' + param_name + '\n')
                print(param_value['metadata']['description'] + '\n')
    if key == "variables":
        for var_name, var_value in playbook.items():
            print('> ' + str(var_value) + '\n')
    if key == "parameters":
        print('### Playbook details\n')
        print('> Description: ' + playbook["description"]["defaultValue"].encode('utf-8') + '\n')
        print('<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fgaelor%2FSentinelAsCode%2Fmaster%2FPlaybooks%2F' + filename + '.json" target="_blank">\n<img src="https://aka.ms/deploytoazurebutton""/>\n</a>\n')