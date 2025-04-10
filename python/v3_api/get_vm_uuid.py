'''
Aim : to get vm uuid using vm name ( considering vm's are less than 500 on the cluster)
version : 17/02/2025
'''
import json
import requests
import urllib3


pcip = str(input('Enter pcip as 10.10.10.10 ...'))
username = str(input('Enter the username...'))
password = str(input('Enter the password...'))
headers = {'content-type': 'application/json'}
payload = {
  "kind": "vm",
  "length": 1000,
  "offset": 0
}

url = f"https://{pcip}:9440/api/nutanix/v3/vms/list"
resp = requests.post(url, verify=False, auth=(username,password),headers=headers, json=payload )
print(resp.status_code)
if resp.status_code == 200: 
    json_resp = resp.json()
    # print()
    # pretty_json = json.dumps(json_resp, indent=4)
    # print(pretty_json)
    for entity in json_resp['entities']:
        print(f"{entity['status']['name']} -----> {entity['metadata']['uuid']}")




