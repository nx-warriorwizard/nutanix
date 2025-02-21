import json
import requests
import urllib3
import secrets
import time


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
username = "SECRET.USERNAME"
password = "SECRET.PASSWORDN"
category_name = "Environment"
value = "Deva"
headers = {'content-type': 'application/json'}
PCIP = "SECRET.PCIP"
def get_cat_key(category_name):
    url = f'https://{PCIP}:9440/api/nutanix/v3/categories/{category_name}'
    resp = requests.get(url,headers=headers, auth=(username,password), verify=False)
    if resp.status_code != 200:
        print('This key does not exist ')
    return resp
# print(get_cat_key(category_name))
def get_cat_val(category_name, value):
    url = f'https://{PCIP}:9440/api/nutanix/v3/categories/{category_name}/{value}'
    resp = requests.get(url,headers=headers, auth=(username,password), verify=False)
    if resp.status_code != 200:
        print('This val does not exist ')
    return resp
# print(get_cat_val(category_name,'Dev'))
def create_cat_key(category_name):
    payload = {
        "description": "string",
        "capabilities": {
            "cardinality": 1
        },
        "name": f'{category_name}'
        }
    url = f'https://{PCIP}:9440/api/nutanix/v3/categories/{category_name}'
    resp = requests.put(url, verify=False, headers=headers, auth=(username,password),json= payload)
    if get_cat_key(category_name).status_code ==200:
        print('category key created succesfully !!!')
    return resp
# print(create_cat_key("test_category"))
def create_cat_val(category_name,value):
    payload = {
        "value": f'{value}'
    }
    url = f'https://{PCIP}:9440/api/nutanix/v3/categories/{category_name}/{value}'
    resp = requests.put(url, verify=False, headers=headers, auth = (username,password), json = payload)
    if get_cat_val(category_name, value).status_code ==200:
        print('category value created succesfully !!!')
    return resp
# print(create_cat_val('test_category', "two"))
df = pd.read_csv("./Documents/Sysco/sysco_cat.csv")
# print(df.keys())
print(df)
for index, row in df.iterrows():
    key= row['category_name']
    value= row['value']
    print( f"key : {key} and Value : {value}")
    resp = get_cat_key(key)
    if resp!=200 :
        create_cat_key(key)
    time.sleep(5)
    resp = get_cat_val(key, value)
    if resp != 200 :
        create_cat_val(key, value)