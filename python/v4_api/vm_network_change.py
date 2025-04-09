import requests
import json
import urllib3
import uuid
import warnings
warnings.filterwarnings("ignore")

def get_vm(header, api_server, username, password, vm_name):
    url = f'https://{api_server}:9440/api/vmm/v4.0/ahv/config/vms?$filter=name eq \'{vm_name}\''  
    vm_etag = None 
    vm_extId = None
    print(vm_name)
    try:
        response = requests.get(url=url, auth=(username, password), headers=header, verify=False)       
        if response.ok:
            result = json.loads(response.content)
            if result['data']:
                vm_extId = result['data'][0]['extId']
                
                url = f'https://{api_server}:9440/api/vmm/v4.0/ahv/config/vms/{vm_extId}'
                response = requests.get(url=url,auth=(username,password),headers=header,data=None, verify=False)
                if response.ok:
                    result = json.loads(response.content)
                    if result["data"]:
                        header = dict(response.headers)
                        print(f"VM etag is: {header['Etag']}")
                        return vm_extId,header['Etag'],result["data"]
                    else:
                        print(f"No data found with VM extId: {vm_extId}")
                else:
                    print("Error: ",response.status_code,response.text)               
                vm_etag = header['Etag']
                return vm_extId,vm_etag
            else:
                print("Incorrect VM name.")
        else:
            print(f"Error: {response.status_code}, {response.text}")
    
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
    
    return None  

def get_subnet_old(vm_data):
    if 'nics' not in vm_data:
        print("No nic found")
        return None
    elif len(vm_data['nics']) > 1:
        print("VM has multiple nics")
        exit(1)
    else:
        nic = vm_data['nics'][0]
        if not nic:
            return None
        else:
            subnet_extId = nic['networkInfo']['subnet']['extId']
            print("older Subnet extId: ",subnet_extId)
            return subnet_extId

def get_subnet_new(header,subnet_name,api_server,username,password):
    # header['If-Match'] = 
    subnet_name = subnet_name.replace(" ",'')
    print(subnet_name)
    subnet_extId = None
    subnet_etag = None
    url = f'https://{api_server}:9440/api/networking/v4.0/config/subnets?$filter=name eq \'{subnet_name}\''
    response = requests.get(url=url,auth=(username,password),headers=header,verify=False)   
    result = json.loads(response.content)   

    try:
        response = requests.get(url=url, auth=(username, password), headers=header, verify=False)       
        if response.ok:
            result = json.loads(response.content)
            if result['data']:
                subnet_extId = result['data'][0]['extId']

                url = f'https://{api_server}:9440/api/networking/v4.0/config/subnets/{subnet_extId}'
                response = requests.get(url=url,auth=(username,password),headers=header,data=None, verify=False)
                if response.ok:
                    result = json.loads(response.content)
                    if result["data"]:
                        header = dict(response.headers)
                        print(f'extId of Subnet to change: {subnet_extId}')
                        return subnet_extId,header['Etag']
                    else:
                        print(f"No data found with subnet extId: {subnet_extId}")
                else:
                    print("Error: ",response.status_code,response.text)               
                subnet_etag = header['Etag']
                return subnet_extId,subnet_etag
            else:
                print("Incorrect Subnet name.")
        else:
            print(f"Error: {response.status_code}, {response.text}")
    
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
    return None                       

import json
import uuid
import requests

def create_nic(header, api_server, username, password, vm_extId, vm_data, vm_etag, subnet_extId, ip_address):
    header['If-Match'] = vm_etag  
    header['NTNX-Request-Id'] = vm_extId  

    new_uuid = str(uuid.uuid4())  
    if not 'nics' in vm_data:
        print("No NICs found. Creating a new NIC.")

        payload = {
            "networkInfo": {
                "nicType": "NORMAL_NIC",
                "networkFunctionChain": {
                    "extId": new_uuid  
                },
                "networkFunctionNicType": "INGRESS",
                "subnet": {
                    "extId": subnet_extId  
                },
                "vlanMode": "ACCESS",
                "shouldAllowUnknownMacs": False,
                "ipv4Config": {
                    "shouldAssignIp": False,  
                    "ipAddress": {
                        "value": ip_address,  
                        "prefixLength": 32
                    },
                    "ipv4Info": {}
                }
            }
        }

        vm_data['nics'] = [payload]
    else:
        print("NICs already exist. Skipping NIC creation.")

    url = f'https://{api_server}:9440/api/vmm/v4.0/ahv/config/vms/{vm_extId}'
    vm_data_json = json.dumps(vm_data)

    response = requests.put(url=url, headers=header, auth=(username, password), data=vm_data_json, verify=False)

    if response.ok:
        result = response.json()
        print("VM updated successfully:")
        print(json.dumps(result, indent=4))
        return result
    else:
        print("Error: ", response.status_code, response.text)
        return None

        
def update_subnet(header,vm_extId, vm_etag,api_server,vm_data, subnet_extId, ip_address, username, password):
    header['If-Match'] = vm_etag
    
    # header['NTNX-Request-Id'] = vm_extId
    header['NTNX-Request-Id'] = str(uuid.uuid4())
    url = f'https://{api_server}:9440/api/vmm/v4.0/ahv/config/vms/{vm_extId}'
    
    if len(vm_data['nics']) > 1:
        print('More than one nics attached to the vm')
        exit(1) 
    
    else: 
        nic = vm_data['nics'][0]
          
        nic['networkInfo']['subnet']['extId'] = subnet_extId
        nic['networkInfo']['ipv4Config']['ipAddress']['value'] = ip_address
        vm_data = json.dumps(vm_data)
        response = requests.put(url=url,auth=(username,password),headers=header,data=vm_data,verify=False)
        print("*"*200)
        print("status_code",response.json())
        print("*"*200)
        breakpoint
        if response.ok:
            result = json.loads(response.content)
            print('Subnet updated sucessfully.')
            return result
        else:
            print(response.status_code,response.content)      
    return

def main():
    PC_IP=''
    username=''
    password=''
    input_csv = '''vm_name,subnet_name,ip_adresss
AN-VDI123-1, Native-136-IPAM  ,   10.136.136.229
AN-VDI11, Native-136-IPAM,  10.136.136.228'''
    input_csv = input_csv.splitlines()
    headers = input_csv[0].split(',')
    print(headers)
    expected_headers = "vm_name,subnet_name,ip_adresss".split(",")
    if headers != expected_headers:
        print("Headers are not aligned as vm_name,subnet_name,ip_adresss")
        exit(1)
        
    header = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    VM_Data = input_csv[1:]
    # print(VM_Data)
    for VM in VM_Data:
        vm_details = VM.split(',')
        vm_name = vm_details[0].strip()
        subnet_name = vm_details[1].strip()
        ip_adresss = vm_details[2].strip()
        vm_extID, vm_etag, vm_data = get_vm(header,api_server=PC_IP,username=username,password=password,vm_name=vm_name)
        new_subnet_extId,subnet_etag = get_subnet_new(header,subnet_name,api_server=PC_IP,username=username,password=password)
        older_subnet_extId = get_subnet_old(vm_data=vm_data)
        
        if not older_subnet_extId:
            print(f"Attaching new Nic with IP: {ip_adresss}...")
            create_nic(header, api_server=PC_IP, username=username, password=password, vm_extId=vm_extID, vm_data=vm_data, vm_etag=vm_etag, subnet_extId=new_subnet_extId,ip_address=ip_adresss)
            continue
        if older_subnet_extId == new_subnet_extId:
            continue
        else:
            print("Updating subnet to new...")
            vm_data = update_subnet(header,vm_extId=vm_extID, vm_etag=vm_etag,api_server=PC_IP,vm_data=vm_data, subnet_extId=new_subnet_extId, ip_address=ip_adresss, username=username, password=password)
            
main()