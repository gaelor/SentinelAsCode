import json
import sys
import re

with open(sys.argv[1], 'r') as playbooks:
    myjson = json.load(playbooks)

filename = re.sub('^.*/', '', sys.argv[1], flags=re.DOTALL).replace('.json','')

for key,playbook in myjson.items():
    if key == "parameters":
        for param_name, param_value in playbook.items():
            if param_name != 'description' and param_name != 'author':
                print('> ' + param_value['metadata']['description'] + '\n')