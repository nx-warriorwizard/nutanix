# The code can be used for category migration from PC to PC
# author : amit.yadav@nutanix.com  
# version : 21/02/2025

import requests
import urllib3
import json
import time

headers = {'content-type': 'application/json'}
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
    
    payload = {
        "kind": "category",
        "length": 1000
    }
    resp = requests.post(url, verify=False, json=payload, headers=headers, auth=(username, password))
    # print(f"get_user_defined_category status code: {resp.status_code}")
    if resp.status_code == 200:
        json_resp = resp.json()
        return json_resp
    else:
        return {}

@disable_warnings
def get_cat_values(pc, category_key):
    pc_url = pc['url']
    username = pc['username']
    password = pc['password']
    payload = {
        "kind": "category",
        "length": 100
    }
    url = f'https://{pc_url}:9440/api/nutanix/v3/categories/{category_key}/list'
    resp = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
    # print(f"get_cat_values status code: {resp.status_code}")
    if resp.status_code == 200:
        json_resp = resp.json()
        return json_resp
    else:
        return {}

@disable_warnings
def get_cat_key(pc, category_name):
    pc_url = pc['url']
    username = pc['username']
    password = pc['password']
    url = f'https://{pc_url}:9440/api/nutanix/v3/categories/{category_name}'
    resp = requests.get(url, headers=headers, auth=(username, password), verify=False)
    # print(f"get_cat_key status code: {resp.status_code}")
    if resp.status_code != 200:
        print(f'{category_name} does not exist')
        return None
    json_resp = resp.json()
    return json_resp

@disable_warnings
def create_cat_key(pc, category_name):
    pc_url = pc['url']
    username = pc['username']
    password = pc['password']
    
    # Check if the category key already exists
    existing_key = get_cat_key(pc, category_name)
    if existing_key:
        print(f'Category key "{category_name}" already exists!')
        return existing_key
    
    payload = {
        "description": "string",
        "capabilities": {
            "cardinality": 1
        },
        "name": f'{category_name}'
    }
    url = f'https://{pc_url}:9440/api/nutanix/v3/categories/{category_name}'
    resp = requests.put(url, verify=False, headers=headers, auth=(username, password), json=payload)
    print(f"create_cat_key status code: {resp.status_code}")
    if resp.status_code == 200:
        print(f'Category key "{category_name}" created successfully!')
    else:
        print(f'Failed to create category key "{category_name}". Status code: {resp.status_code}')
    json_resp = resp.json()
    return json_resp

@disable_warnings
def get_cat_val(pc, category_name, value):
    pc_url = pc['url']
    username = pc['username']
    password = pc['password']
    url = f'https://{pc_url}:9440/api/nutanix/v3/categories/{category_name}/{value}'
    resp = requests.get(url, headers=headers, auth=(username, password), verify=False)
    print(f"get_cat_val status code: {resp.status_code}")
    if resp.status_code != 200:
        print('This val does not exist')
        return None
    json_resp = resp.json()
    return json_resp

@disable_warnings
def create_cat_val(pc, category_name, value):
    pc_url = pc['url']
    username = pc['username']
    password = pc['password']
    
    # Ensure the category key exists before creating the value
    if not get_cat_key(pc, category_name):
        create_cat_key(pc, category_name)
    
    payload = {
        "value": f'{value}'
    }
    url = f'https://{pc_url}:9440/api/nutanix/v3/categories/{category_name}/{value}'
    resp = requests.put(url, verify=False, headers=headers, auth=(username, password), json=payload)
    print(f"create_cat_val status code: {resp.status_code}")
    if resp.status_code == 200:
        print(f'Category value "{value}" for key "{category_name}" created successfully!')
    else:
        print(f'Failed to create category value "{value}" for key "{category_name}". Status code: {resp.status_code}')
    json_resp = resp.json()
    return json_resp

def fetch_category_to_csv(pc):
    cat_keys = get_user_defined_category(pc)
    with open("category.csv", "w") as category:
        for key_entity in cat_keys['entities']:
            if key_entity['system_defined'] == False:
                cat_values = get_cat_values(pc, key_entity['name'])
                for value_entity in cat_values['entities']:
                    print(f"category: {key_entity['name']} --> {value_entity['value']}")
                    category.write(f"{key_entity['name']},{value_entity['value']}\n")

def create_category_on_pc(pc):
    with open("category.csv", "r") as category_file:
        for line in category_file:
            category_name, value = line.strip().split(',')
            create_cat_key(pc, category_name)
            time.sleep(sleep_time)
            create_cat_val(pc, category_name, value)
            time.sleep(sleep_time)

if __name__ == "__main__":
    sleep_time = 4  # will wait for sec while creating each category
    pc1_cred = {
        "username": "username",
        "password": "password",
        "url": "10.10.10.10"
    }

    pc2_cred = {
        "username": "username",
        "password": "password",
        "url": "10.10.10.10"
    }

    source_pc = [pc1_cred]
    destination_pc = [pc2_cred]

    # For fetching category from source PC
    fetch_category_to_csv(source_pc[0])  # Comment this line if you have the CSV already

    # For creating category on different PCs at once
    # Comment the below lines if you just want the CSV
    for pc in destination_pc:
        create_category_on_pc(pc)