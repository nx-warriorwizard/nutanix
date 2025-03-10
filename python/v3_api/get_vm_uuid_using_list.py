'''
Aim : to get vm uuid using vm name (considering vm's are less than 500 on the cluster)
version : 10/03/2025
'''
import json
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
vm_name_uuid = {}

pcip = str(input('Enter pcip as 10.10.10.10 ...'))
username = str(input('Enter the username...'))
password = str(input('Enter the password...'))
headers = {'content-type': 'application/json'}

payload = {
    "kind": "vm",
    "offset": 0,
    "length": 500,
    "sort_order": "ASCENDING",
    "sort_attribute": "_created_timestamp_usecs_"
}

url = f"https://{pcip}:9440/api/nutanix/v3/vms/list"

resp = requests.post(url, verify=False, auth=(username, password), headers=headers, json=payload)
print(resp.status_code)

if resp.status_code == 200:
    json_resp = resp.json()
    total_matches = json_resp['metadata']['total_matches']
    for offset_value in range(0, total_matches, 500):
        payload['offset'] = offset_value
        resp = requests.post(url, verify=False, auth=(username, password), headers=headers, json=payload)
        if resp.status_code == 200:
            json_resp = resp.json()
            for entity in json_resp['entities']:
                vm_name_uuid[entity['metadata']['uuid']] = entity['status']['name']


print(vm_name_uuid.items())
customer_requirement = {}

with open("uuid.txt", "r") as uuid_list:
    for line in uuid_list:
        line = line.strip()
        if line in vm_name_uuid:
            customer_requirement[line] = vm_name_uuid[line]

with open("vm_name.txt", "w") as vm_name:
    for i in customer_requirement.values():
        vm_name.write(i, end = "\n")