'''
Aim : to get vm uuid using vm name ( considering vm's are less than 500 on the cluster)
version : 17/02/2025
'''
import json
import requests
import urllib3


pcip = "10.136.136.5"
username = "an"
password = "Nutanix.123"
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




