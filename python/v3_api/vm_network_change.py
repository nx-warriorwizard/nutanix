#!/usr/bin/python
################################################
########     http_requests.py           ########
################################################
# import json #tocomment
# from time import sleep #tocomment

import requests
import uuid, json
from time import sleep
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# For token-based authentication, omit user and password (so that they default to None), and add the following header to
# the headers list: 'Authorization': 'Bearer <token value>'
def process_request(url, method, user=None, password=None, cert=None, files=None,headers=None, payload=None, params=None, secure=False, timeout=120, retries=5, exit_on_failure=True):
    """
    Processes a web request and handles result appropriately with retries.
    Returns the content of the web request if successfull.
    """
    if payload is not None:
        payload = json.dumps(payload)

    sleep_between_retries=5
    headers['Authorization'] = 'Bearer @@{calm_jwt}@@' 
    headers['Authorization'] = 'Basic YW46TnV0YW5peC4xMjM='


    while retries > 0:
        try:

            if method == 'GET':
                response = requests.get(
                    url,
                    headers=headers,
                    auth=(user, password) if user else None,
                    cert=cert if cert else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'POST':
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password) if user else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PUT':
                response = requests.put(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password) if user else None,
                    files=files if files else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PATCH':
                response = requests.patch(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password) if user else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'DELETE':
                response = requests.delete(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password) if user else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )

        except requests.exceptions.RequestException as error_code:
            print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
            retries -= 1
            sleep(sleep_between_retries)
            continue
        
        if response.ok:
            return response
        elif response.status_code == 409:
            print(response.text)
            retries -= 1
            if retries == 0:
                if exit_on_failure:
                    exit(response.status_code)
                else:
                    return response
            sleep(sleep_between_retries)
            continue
        else:
            print(response.text)
            if exit_on_failure:
                exit(response.status_code)
            else:
                return response
            
def prism_monitor_task_apiv3(api_server,username,passwd,task_uuid,secure=False,exit_on_task_failure=True):

    """Given a Prism Central task uuid, loop until the task is completed
    exits if the task fails

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        task_uuid: Prism Central task uuid (generally returned by another action 
                   performed on PC).
        secure: boolean to verify or not the api server's certificate (True/False)
                   
    Returns:
        No value is returned
    """
    
    task_status_details = {}
    task_status = "RUNNING"

    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/tasks/{0}".format(task_uuid)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    print("Making a {} API call to {}".format(method, url))
    
    while True:
        resp = process_request(url,method,user=username,password=passwd,headers=headers,secure=secure)
        #print(json.loads(resp.content))
        if resp.ok:
            task_status_details = json.loads(resp.content)
            task_status = resp.json()['status']
            if task_status == "SUCCEEDED":
                print ("Task has completed successfully")
                return task_status_details
            elif task_status == "FAILED":
                print ("Task has failed: {}".format(   resp.json()['error_detail'] if 'error_detail' in resp.json() else "No Info" )       )
                if exit_on_task_failure:
                    exit(1)
                else:
                    return task_status_details
            else:
                print ("Task status is {} and percentage completion is {}. Current step is {}. Waiting for 30 seconds.".format(task_status,resp.json()['percentage_complete'],resp.json()['progress_message']))
                sleep(30)
        else:
            print("Request failed!")
            print("status code: {}".format(resp.status_code))
            print("reason: {}".format(resp.reason))
            print("text: {}".format(resp.text))
            print("raise_for_status: {}".format(resp.raise_for_status()))
            print("elapsed: {}".format(resp.elapsed))
            print("headers: {}".format(resp.headers))
            print(json.dumps(
                json.loads(resp.content),
                indent=4
            ))
            exit(resp.status_code)

    return task_status_details
            
def prism_get_entities(api_server,username,passwd,entity_type,entity_api_root,secure=False,print_f=True,filter=None):

    """Retrieve the list of entities from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        entity_type: kind (type) of entity as referenced in the entity json object
        entity_api_root: v3 apis root for this entity type. for example. for projects the list api is ".../api/nutanix/v3/projects/list".
                         the entity api root here is "projects"
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        filter: filter to be applied to the search
        
    Returns:
        An array of entities (entities part of the json response).
    """

    entities = []
    #region prepare the api call
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/{}/list".format(entity_api_root)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "POST"
    length = 100

    # Compose the json payload
    payload = {
        "kind": entity_type,
        "offset": 0,
        "length": length
    }
    if filter:
        payload["filter"] = filter
    #endregion
    while True:
        if print_f:
            print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
        resp = process_request(url,method,user=username,password=passwd,headers=headers,payload=payload,secure=secure)
        # deal with the result/response
        if resp.ok:
            json_resp = json.loads(resp.content)
            #json_resp = resp
            entities.extend(json_resp['entities'])
            key = 'length'
            if key in json_resp['metadata']:
                if json_resp['metadata']['length'] == length:
                    if print_f:
                        print("Processing results from {} to {} out of {}".format(
                            json_resp['metadata']['offset'], 
                            json_resp['metadata']['length']+json_resp['metadata']['offset'],
                            json_resp['metadata']['total_matches']))
                    payload = {
                        "kind": entity_type,
                        "offset": json_resp['metadata']['length'] + json_resp['metadata']['offset'] + 1,
                        "length": length
                    }
                else:
                    return entities
            else:
                return entities
        else:
            print("Request failed!")
            print("status code: {}".format(resp.status_code))
            print("reason: {}".format(resp.reason))
            print("text: {}".format(resp.text))
            print("raise_for_status: {}".format(resp.raise_for_status()))
            print("elapsed: {}".format(resp.elapsed))
            print("headers: {}".format(resp.headers))
            print("payload: {}".format(payload))
            print(json.dumps(
                json.loads(resp.content),
                indent=4
            ))
            raise

def prism_get_entity(api_server,username,passwd,entity_type,entity_api_root,entity_name=None,entity_uuid=None,secure=False,print_f=True):

    """Returns from Prism Central the uuid and details of a given entity name.
       If an entity_uuid is specified, it will skip retrieving all entities by specifying the uuid in the arguments (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        entity_type: kind (type) of entity as referenced in the entity json object
        entity_api_root: v3 apis root for this entity type. for example. for projects the list api is ".../api/nutanix/v3/projects/list".
                         the entity api root here is "projects"
        entity_name: Name of the entity (optional).
        entity_uuid: Uuid of the entity (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        A string containing the UUID of the entity (entity_uuid) and the json content
        of the entity details (entity_details)
    """
    
    entity_details = {}

    if entity_uuid is None:
        #get the entities list from Prism
        entity_list = prism_get_entities(api_server=api_server,username=username,passwd=passwd,
                                          entity_type=entity_type,entity_api_root=entity_api_root,
                                          secure=secure,print_f=print_f)
        entity_obj_list = [ entity for entity in entity_list if entity['status']['name'] == entity_name ] 
        if len(entity_obj_list) !=1:
            print("ERROR - found {} instance(s) of the entity {}".format(len(entity_obj_list),entity_name))
            return None, None
            # exit(1)

        for entity in entity_list:
            fetched_name = ""
            if "name" in entity['spec']:
                fetched_name = entity['spec']['name']
            elif "name" in entity['status']:
                fetched_name = entity['status']['name']
            else:
                print("ERROR - fetched entity name could not be extracted for entity {}".format(entity['metadata']['uuid']))
                raise
            if fetched_name == entity_name:
                entity_uuid = entity['metadata']['uuid']
                entity_details = entity.copy()
                break
        if entity_details == {} :
            print("[ERROR] - Entity {} not found".format(entity_name))
            return None, None
            # exit(1)
    else:
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        api_server_port = "9440"
        api_server_endpoint = "/api/nutanix/v3/{}/{}".format(entity_api_root,entity_uuid)
        url = "https://{}:{}{}".format(
            api_server,
            api_server_port,
            api_server_endpoint
        )
        method = "GET"
        if print_f:
            print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
        resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,secure=secure)
        if resp.ok:
            entity_details = json.loads(resp.content)
        else:
            print("Request failed!")
            print("status code: {}".format(resp.status_code))
            print("reason: {}".format(resp.reason))
            print("text: {}".format(resp.text))
            print("raise_for_status: {}".format(resp.raise_for_status()))
            print("elapsed: {}".format(resp.elapsed))
            print("headers: {}".format(resp.headers))
            print("payload: {}".format(payload))
            print(json.dumps(
                json.loads(resp.content),
                indent=4
            ))
            raise
    return entity_uuid, entity_details
            
def prism_get_vm(api_server,username,passwd,vm_name=None,vm_uuid=None,secure=False,print_f=True):
    
    """Returns from Prism Central the uuid and details of a given vm name.
       If a vm_uuid is specified, it will skip retrieving all vms (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        vm_name: Name of the vm(optional).
        vm_uuid: Uuid of the vm (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        A string containing the UUID of the vm (vm_uuid) and the json content
        of the vm details (vm_details)
    """

    vm_uuid, vm = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                                             entity_type="vm",entity_api_root="vms",entity_name=vm_name,entity_uuid=vm_uuid,
                                             secure=secure,print_f=print_f)
    return vm_uuid, vm
    
def prism_update_vm(api_server,username,passwd,vm_uuid,payload,secure=False):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/vms/{}".format(vm_uuid)
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "PUT"
    #print(" VM API PUT call '{}' with payload '{}' ".format(url,payload))
    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,payload=payload,secure=secure)
    task_uuid = None 
    if resp.ok:
        print("INFO - API PUT call initiated with success for VM : '{}'".format(vm_uuid))
        res = json.loads(resp.content)
        if "status" in res and "execution_context" in res["status"] \
                    and "task_uuid" in res["status"]["execution_context"]:
            task_uuid = res["status"]["execution_context"]["task_uuid"]
            task_status_details = prism_monitor_task_apiv3(api_server=api_server,username=username,passwd=passwd,secure=secure,task_uuid=task_uuid)
            return resp, task_status_details
    elif resp.status_code == 409:
        return resp, False 
    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(payload))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        return resp , False 

def prism_get_subnet(api_server,username,passwd,subnet_name=None,subnet_uuid=None,secure=False,print_f=True):

    """Returns from Prism Central the uuid and details of a given subnet name.
       If a subnet_uuid is specified, it will skip retrieving all subnets (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        subnet_name: Name of the subnet (optional).
        subnet_uuid: Uuid of the subnet (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        A string containing the UUID of the Subnet (subnet_uuid) and the json content
        of the subnet details (subnet)
    """

    subnet_uuid, subnet = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="subnet",entity_api_root="subnets",entity_name=subnet_name,entity_uuid=subnet_uuid,
                              secure=secure,print_f=print_f)
    return subnet["metadata"]["uuid"], subnet


cant_update_vm = []

api_server = "10.136.136.10"
input_csv = '''@@{CSV_Input}@@'''.replace(' ','')
input_csv = '''vm_name,subnet_name,ip_adresss
AN-VDI12, Native-136-IPAM  ,   10.136.136.227
AN-VDI1, Vlan-138-ipam,  10.136.138.225'''.replace(' ','')
input_csv = input_csv.splitlines()
headers = input_csv[0].split(',')
expected_headers = "vm_name,subnet_name,ip_adresss".split(',')
if headers != expected_headers:
    print("Headers are not aligned as vm_name,subnet_name,ip_adresss")
    exit(1)
VM_Data = input_csv[1:]
for VM in VM_Data:
  vm_details = VM.split(',')
  vm_name = vm_details[0].strip()
  subnet_name = vm_details[1].strip()
  ip_adresss = vm_details[2].strip()
  subnet_uuid, subnet = prism_get_subnet(api_server=api_server,username=None,passwd=None,subnet_name=subnet_name)
  vm_uuid, vm_spec = prism_get_vm(api_server=api_server,username=None,passwd=None,vm_name=vm_name)
  if subnet == None and vm_spec != None:
      cant_update_vm.append((vm_name, "[ERROR] nic not found!!!"))
      continue
  elif subnet == None and vm_spec == None:
      cant_update_vm.append((vm_name, "[ERROR] vm and subnet does not exists!!!"))
      continue
  elif subnet != None and vm_spec == None:
      cant_update_vm.append((vm_name, "[ERROR] subnet exists but vm not found!!!"))
      continue

  nic_spec = {
                    "nic_type": "NORMAL_NIC",
                    "is_connected": True,
                    "vlan_mode": "ACCESS",
                    "subnet_reference": {
                        "uuid": subnet_uuid,
                        "name": subnet_name,
                        "kind": "subnet"
                    },
                    "ip_endpoint_list": [
                        {
                            "ip": ip_adresss
                        }
                    ],
                    "uuid": str(uuid.uuid4())
                }
  if len(vm_spec['spec']['resources']['nic_list']) >= 2:
      print(f"[ERROR] {vm_name} has multiple nics")
      continue
#   if vm_spec['spec']['resources']['nic_list'] == [nic_spec]:
#       print("[INFO] Subnet already exist, skipping...")
#       print("*"*200)
#       print('[WARN]', vm_spec['spec']['resources']['nic_list'])
#       print(f"[WARN] {nic_spec}")
#       exit(1)
#   else:
    # exit(1)
  vm_spec['spec']['resources']['nic_list'] = [nic_spec]
  del vm_spec['status']
  resp, task_status_details = prism_update_vm(api_server=api_server,username=None,passwd=None,vm_uuid=vm_uuid,payload=vm_spec)
  print("[INFO]", vm_name, task_status_details['status'])

print("="*200)
# value is in format of (vm_name, "reason")
for vm in cant_update_vm:
    print(*vm)


print('cant_update_vm=',cant_update_vm)
# Generate a basic HTML report
html_report = """
<!DOCTYPE html>
<html>
<head>
    <title>VM Update Report</title>
    <style>
        table {
            border-collapse: collapse;
            width: 100%;
        }
        th, td {
            border: 1px solid black;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
    </style>
</head>
<body>
    <h1>VM Update Report</h1>
    <table>
        <tr>
            <th>VM Name</th>
            <th>Reason</th>
        </tr>
"""

for vm in cant_update_vm:
    html_report += f"""
        <tr>
            <td>{vm[0]}</td>
            <td>{vm[1]}</td>
        </tr>
    """

html_report += """
    </table>
</body>
</html>
"""


# Convert the HTML report into a single string without line breaks
# html_report = "".join(html_report.splitlines())

# # html_report =  "".join(html_report.replace('\n', ''))
# html_report = html_report.replace("\n", "")
print("html_report=", html_report)
# print(type(html_report))


# Save the HTML report to a file
# with open("vm_update_report.html", "w") as report_file:
#     report_file.write(html_report)

# print("HTML report generated: vm_update_report.html")

# sending mail



#   payload = {
#     "recipients": [
#         "sakshi.aherkar@nutanix.com"
#     ],
#     "subject": "VM Subnet update test",
#     "text": html_report
#     }
#   resp = process_request(url, 'POST', payload=payload, secure=False)

import re

def html_to_text(html):
    """Convert HTML content to plain text while handling tables properly."""
    # Remove script and style tags
    html = re.sub(r'<(script|style).*?>.*?</\1>', '', html, flags=re.DOTALL)

    # Replace table elements with formatted text
    html = re.sub(r'</tr>', '\n', html, flags=re.IGNORECASE)  # New line after row
    html = re.sub(r'</td>', ' | ', html, flags=re.IGNORECASE)  # Separate columns with '|'
    
    # Remove remaining table tags but keep the content
    html = re.sub(r'<.*?>', '', html)

    # Convert multiple spaces/newlines to a single space
    text = re.sub(r'\s+', ' ', html).strip()

    return text

# Example Usage
html_content = """
<table>
    <tr><td>Name</td><td>Age</td><td>City</td></tr>
    <tr><td>Alice</td><td>25</td><td>New York</td></tr>
    <tr><td>Bob</td><td>30</td><td>Los Angeles</td></tr>
</table>
"""

plain_text = html_to_text(html_content)
print(plain_text)


# import base64

# def send_mail(api_server):
#   url = f"https://{api_server}:9440/PrismGateway/services/rest/v1/cluster/send_email"
#   token = base64.b64encode("an@blrgso.lab:Nutanix.123".encode("utf-8")).decode("utf-8")
#   auth = f"Basic {token}"
#   print('auth is ', auth)
#   #   headers={
#   #           'Content-Type': 'application/json',
#   #           'Accept': 'application/json',
#   #           'Authorization': 'Bearer YW46TnV0YW5peC4xMjM='
#   #       } 
#   headers={
#           'Content-Type': 'application/json',
#           'Accept': 'application/json',
#           'Authorization': auth
#       }
#   payload = {
#     "recipients": [
#         "amit.yadav@nutanix.com"
#     ],
#     "subject": "VM Subnet update test",
#     "content": html_report
#     }

#   resp = requests.post(
#       url, 
#       json=payload, 
#       verify=False, 
#       headers=headers
      
      
#   )
#   print(resp.status_code)
#   print(resp.content)

# for i in range(1):
#   sleep(10)
#   send_mail("10.136.136.10")

# import requests
# import base64
# def send_mail(api_server):
#     url = f"https://10.136.136.10:9440/api/nutanix/v3/action_rules/trigger"

#     token = base64.b64encode("an@blrgso.lab:Nutanix.123".encode("utf-8")).decode("utf-8")
#     # auth = f"Basic {token}"
#     auth = ("an@blrgso.lab", "Nutanix.123");
#     # headers={
#     # 'Content-Type': 'application/json',
#     # 'Accept': 'application/json',
#     # 'Authorization': 'Basic YW46TnV0YW5peC4xMjM='
#     # }
#     headers={
#     'Content-Type': 'application/json',
#     'Accept': 'application/json'
#     }
#     payload = {
#     "trigger_type": "incoming_webhook_trigger",
#     "trigger_instance_list": [{
#         "webhook_id": "acb87c02-249a-43de-9923-0f237614c5dd",
#         "string1" : "amit.yadav@nutanix.com",
#         "string2" : "VM subnet update report",
#         "string3" : "Hi, PFA VM subnet update report",
#         "string4" : html_report,
#         "string5" : "Regards"
#     }]
#     }
#     resp = requests.post(url, headers=headers, json=payload, auth=auth, verify=False)
#     print("*"*200)
#     print(resp.status_code)
#     print(resp.content)


# send_mail("10.136.136.10")