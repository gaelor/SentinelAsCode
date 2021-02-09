import json

with open('../HuntingRules/hunting-rules.json', 'r') as huntingrules:
    myjson = json.load(huntingrules)

for huntingrule in huntingrules:
    print(huntingrule)