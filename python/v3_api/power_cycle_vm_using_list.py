'''
The script takes input the txt file which contains the vm name 
call cluster to get vm uuid and utilize the txt file get get uuid

later utilize the uuid to power cycle the vms
version : 17/02/2025
'''

import json
import requests
import urllib3
import time

pcip = ""
username = ""
password = ""
headers = {'content-type': 'application/json'}


get_uuid_url = f"https://{pcip}:9440/api/nutanix/v3/vms/list"


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
            print(f"{entity['status']['name']} -----> {entity['metadata']['uuid']}")
        return vm_uuid
    else:
        return {}
    

def vm_power_cycle(uuid : int, pcip : str):
    '''
    powercycle the vm whose ip is provided
    '''
    url=f"https://{pcip}:9440/api/nutanix/v3/vms/{uuid}/power_cycle"
    payload= {}
    resp = requests.post(url, verify=False, auth=(username,password),headers=headers, json=payload )
    if resp.status_code== 202:
        json_resp= resp.json()
        print('power cycle succeeded')
        print(json_resp)
    else:
        print('vm power cycle failed!!!')


#getting the dictionary of [vm_name : uuid]
vm_uuid_dict = get_vm_uuid(pcip) 
for vm, uuid in vm_uuid_dict.items():
    print(f"{vm} =====> {uuid}")

with open('vm.txt', 'r') as vm_list:
    vms = vm_list.readlines()
    for vm in vms:
        # print(i, end="")
        vm= vm.lstrip().rstrip()
        print(f"vm going to process is {vm}....")
        if vm in vm_uuid_dict.keys():
            vm_power_cycle(vm_uuid_dict[vm], pcip)
            print(f'power cycling vm {vm}')
            time.sleep(20)
        else:
            print('vm not found in vm dictionary!!!')





    