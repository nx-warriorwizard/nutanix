import json
import requests
import urllib3
import os
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fetch_vm_uuid(pcip, username, password, headers):
    vm_name_uuid = {}
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
                    vm_name_uuid[entity['status']['name']] = entity['metadata']['uuid']
    return vm_name_uuid

def get_vm_payload(pcip, username, password, headers, uuid):
    url = f"https://{pcip}:9440/api/nutanix/v3/vms/{uuid}"
    resp = requests.get(url, verify=False, auth=(username, password), headers=headers)
    print(f"get_vm_payload_status_code: {resp.status_code}")

    if resp.status_code == 200:
        json_resp = resp.json()
        print(json.dumps(json_resp, indent=4))
    return json_resp

def update_vm_payload(pcip, username, password, headers, uuid, payload):
    url = f"https://{pcip}:9440/api/nutanix/v3/vms/{uuid}"
    resp = requests.put(url, verify=False, auth=(username, password), headers=headers, json= payload)
    print(f"vm_payload_update_status: {resp.status_code}")
    # return resp.status_code

def modify_network_status(pcip, username, password, headers, uuid, payload):
    del payload['status']
    #check power state is is ON or OFF
    power_state = payload['spec']['resources']['power_state']
    print(f"power state: {power_state}")
    if power_state == "OFF":
        nic_list = payload['spec']['resources']['nic_list']
        no_of_nic = len(nic_list)
        # print(f"Total nic: {len(nic_list)}")
        if no_of_nic == 0:
            print('No nic attached to the network...')
        else:
            for nic in nic_list:
                current_is_connected = nic['is_connected']
                print(f'current nic status : {current_is_connected}')
                if current_is_connected == True:
                    nic['is_connected'] = False
    
        # call update_vm_payload
        update_vm_payload(pcip, username, password, headers, uuid, payload)
    else:
        print("VM is power on")
    return payload


if __name__ == "__main__":
    pcip = str(input('Enter pcip as 10.10.10.10 ...'))
    username = str(input('Enter the username...'))
    password = str(input('Enter the password...'))
    headers = {'content-type': 'application/json'}
    vm_name_uuid = fetch_vm_uuid(pcip, username, password, headers=headers )
    print(vm_name_uuid.items())


    script_dir = os.path.dirname(os.path.abspath(__file__))
    vm = os.path.join(script_dir, "vm.txt")
    with open(vm, "r") as file:
        for line in file:
            vm_name = line.strip()
            print(f"vm_name: {vm_name}")
            if vm_name not in vm_name_uuid.keys():
                print(" Can't fetch VM's uuid and Data...")
            else:
                uuid = vm_name_uuid[vm_name]
                vm_payload = get_vm_payload(pcip, username, password, headers=headers, uuid= uuid)
                modified_payload = modify_network_status(pcip, username, password, headers=headers, uuid= uuid, payload= vm_payload)
                print(f"Execution completed for {vm_name}")
                print("="*100)
                time.sleep(15)








    




