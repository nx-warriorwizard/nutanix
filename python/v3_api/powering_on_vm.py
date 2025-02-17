'''
The script can be utilized for changing the vm state from powering off to powering on of the VM.
version: 17/02/2025
'''

import json
import requests
import urllib3
import time

pcip = ""
username = ""
password = ""
headers = {'content-type': 'application/json'}
uuid=""


def get_vm_uuid(pcip: str):
    '''
    gets all of the vms as well as uuid associated with it in a form of dictionary
    '''
    vm_uuid= {}
    url = f"https://{pcip}:9440/api/nutanix/v3/vms/list"
    payload = {
        "kind": "vm",
        "length": 1000,
        "offset": 0
    }
    resp = requests.post(url, verify=False, auth=(username,password),headers=headers, json=payload )
    if resp.status_code == 200: 
        json_resp = resp.json()
        for entity in json_resp['entities']:
            
            vm_uuid[entity['status']['name']]=entity['metadata']['uuid']
            # print(f"{entity['status']['name']} -----> {entity['metadata']['uuid']}")
        return vm_uuid
    else:
        return {}

def fetch_vm_config(uuid,pcip):
    url = f"https://{pcip}:9440/api/nutanix/v3/vms/{uuid}"
    resp = requests.get(url, headers=headers, auth=(username, password),verify=False )
    print(resp.status_code)
    json_resp = resp.json()
    # pretty_json = json.dumps(json_resp, indent=4)
    # print(pretty_json)
    # for i in json_resp['spec']['resources']:
    #     print(i)
    del json_resp['status']
    json_resp['spec']['resources']['power_state']= 'ON'
    # print(json_resp['spec']['resources']['power_state'])
    return json_resp



def put_vm_config(payload, pcip, uuid):
    url = f"https://{pcip}:9440/api/nutanix/v3/vms/{uuid}"
    resp= requests.put(url,headers=headers, json=payload, verify=False, auth=(username, password) )
    print(resp.status_code)



#getting the dictionary of [vm_name : uuid]
vm_uuid_dict = get_vm_uuid(pcip) 
# for vm, uuid in vm_uuid_dict.items():
#     print(f"{vm} =====> {uuid}")

with open('vm.txt', 'r') as vm_list:
    vms = vm_list.readlines()
    for vm in vms:
        # print(i, end="")
        vm= vm.lstrip().rstrip()
        print(f"vm going to process is {vm}....")
        if vm in vm_uuid_dict.keys():
            json_payload = fetch_vm_config(vm_uuid_dict[vm], pcip)
            put_vm_config(json_payload, pcip, vm_uuid_dict[vm])
            time.sleep(20)