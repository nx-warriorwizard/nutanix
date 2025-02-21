# The code can be used for category migration from PC to PC
# author : amit.yadav@nutanix.com  
# version : 21/02/2025

import requests
import urllib3
import json

headers = {'content-type': 'application/json'}

pc1_cred= {
    "username": "username",
    "password": "password",
    "url": "10.10.10.10"
}

pc2_cred= {
    "username": "username",
    "password": "password",
    "url": "10.136.136.5"
}

source_pc = [pc1_cred]
destination_pc = [pc2_cred, ]

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def disable_warnings(func):
    def wrapper(*args, **kwargs):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return func(*args, **kwargs)
    return wrapper

@disable_warnings
def get_user_defined_category(pc):
    pc_url = pc['url']
    username = pc['username']
    password = pc['password']
    url = f"https://{pc_url}:9440/api/nutanix/v3/categories/list"
    
    palyload = {
        "kind": "category",
        "length": 1000
    }
    resp = requests.post(url,verify=False, json=palyload, headers=headers, auth=(username,password))
    print(resp.status_code)
    if resp.status_code == 200:
        json_resp = resp.json()
        # print(json.dumps(json_resp, indent=4))
        return json_resp
    else:
        return {}

@disable_warnings
def get_cat_values(pc,category_key):
    pc_url = pc['url']
    username = pc['username']
    password = pc['password']
    payload = {
        "kind": "category",
        "length": 100
        }
    url = f'https://{pc_url}:9440/api/nutanix/v3/categories/{category_key}/list'
    resp = requests.post(url, json=payload, headers=headers, auth=(username,password), verify=False)
    if resp.status_code == 200:
        json_resp = resp.json()
        # print(json.dumps(json_resp, indent=4))
        return json_resp
    else:
        return {}



cat_keys = get_user_defined_category(pc1_cred)
with open("category.csv","w") as category:
    for key_entity in cat_keys['entities']:
        # print(entity['system_defined'])
        if key_entity['system_defined'] == False:
            # print(key_entity['name'])
            #fetch category value for the user defined category key
            cat_values = get_cat_values(pc1_cred, key_entity['name']) # entity is category key
            # print(cat_values)
            for value_entity in cat_values['entities']:
                print(f" category  : {key_entity['name']} --> {value_entity['value']}")
                category.write(f"{key_entity['name']},{value_entity['value']}\n")





