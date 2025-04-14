import json #tocomment
from time import sleep #tocomment
import urllib3 #tocomment

import requests
import uuid
import base64
import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  #tocomment
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
    
    while retries > 0:
        try:

            if method == 'GET':
                response = requests.get(url, headers=headers, auth=(user, password) if user else None, cert=cert if cert else None, params=params, verify=secure, timeout=timeout)
            elif method == 'POST':
                response = requests.post(url, headers=headers, data=payload, auth=(user, password) if user else None, params=params, verify=secure, timeout=timeout)
            elif method == 'PUT':
                response = requests.put(url, headers=headers, data=payload, auth=(user, password) if user else None, files=files if files else None, params=params, verify=secure, timeout=timeout)
            elif method == 'PATCH':
                response = requests.patch(url, headers=headers, data=payload, auth=(user, password) if user else None, params=params, verify=secure, timeout=timeout)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, data=payload, auth=(user, password) if user else None, params=params, verify=secure, timeout=timeout)

        except requests.exceptions.RequestException as error_code:
            print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
            retries -= 1
            sleep(sleep_between_retries)
            continue
        
        sleep(1)
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

def prism_monitor_task_apiv3(api_server, username, passwd, task_uuid, wait_interval=30, secure=False):

    """Given a Prism Central task uuid, loop until the task is completed
    exits if the task fails

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
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
    url = "https://{}:{}{}".format(api_server, api_server_port, api_server_endpoint)
    method = "GET"
    print("[INFO] Making a {} API call to {}".format(method, url))
    
    while True:
        resp = process_request(url=url, method=method, user=username, password=passwd, headers=headers, secure=secure)
        sleep(1)
        #print(json.loads(resp.content))
        if resp.ok:
            task_status_details = json.loads(resp.content)
            task_status = resp.json()['status']
            if task_status == "SUCCEEDED":
                print ("[INFO] Task has completed successfully")
                return task_status_details
            elif task_status == "FAILED":
                print ("[ERROR] Task has failed: {}".format(   resp.json()['error_detail'] if 'error_detail' in resp.json() else "No Info" )       )
                exit(1)
            else:
                print ("[INFO] Task status is {} and percentage completion is {}. Current step is {}. Waiting for 30 seconds.".format(task_status,resp.json()['percentage_complete'],resp.json()['progress_message']))
                sleep(wait_interval)
        else:
            print("Request failed!")
            print("status code: {}".format(resp.status_code))
            print("reason: {}".format(resp.reason))
            print("text: {}".format(resp.text))
            print("raise_for_status: {}".format(resp.raise_for_status()))
            print("elapsed: {}".format(resp.elapsed))
            print("headers: {}".format(resp.headers))
            # print("payload: {}".format(payload))
            print(json.dumps(
                json.loads(resp.content),
                indent=4
            ))
            exit(resp.status_code)

    return task_status_details

def get_sources(api_server, username, passwd, headers, secure):
    url = f"https://{api_server}:9440/api/aiops/v4.0/config/sources"
    resp = process_request(url=url, method="GET", user=username, password=passwd, headers=headers, secure=secure)
    if not resp.ok:
        print(f"[ERROR] Get Source failed : {resp.content}")
        exit(1)
    result = json.loads(resp.content)
    print("*"*200)
    print(json.dumps(result))
    print("*"*200)

    source = [data['extId'] for data in result['data'] ]
    return source

def get_metrics(api_server, username, passwd, headers, secure):
    # vm_extId = "942f6d48-c33e-4a4d-8120-33eec1254614"
    vm_extId = "686c821a-8091-4aef-8224-65b48019cd34"
    sourceExtId = "db293e8a-5770-c3c7-4213-85dbbc1d3679"
    start_time = datetime.datetime.now() - datetime.timedelta(weeks=1)
    # Datetime needs to be in RFC3339 format
    end_time = datetime.datetime.now()
    # start_time = start_time.isoformat() + "Z"  # Convert to RFC3339 format
    # end_time = end_time.isoformat() + "Z"  # Convert to RFC3339 format
    print(start_time)
    url = f"https://{api_server}:9440/api/aiops/v4.0/stats/sources/{sourceExtId}/entities/{vm_extId}?startTime={start_time}&endTime={end_time}"
    resp = process_request(url=url, method="GET", user=username, password=passwd, headers=headers, secure=secure)
    if not resp.ok:
        print(f"[ERROR] Get Metrics failed : {resp.content}")
        exit(1)
    result = json.loads(resp.content)
    print("*"*200)
    print(json.dumps(result))
    print("*"*200)

def get_entity(api_server, username, passwd, headers, secure):
    sourceExtId = "db293e8a-5770-c3c7-4213-85dbbc1d3679"
    url = f"https://{api_server}:9440/api/aiops/v4.0/config/sources/{sourceExtId}/entity-types"
    resp = process_request(url=url, method="GET", user=username, password=passwd, headers=headers, secure=secure)
    if not resp.ok:
        print(f"[ERROR] Get Metrics failed : {resp.content}")
        exit(1)
    result = json.loads(resp.content)
    print("*"*200)
    print(json.dumps(result))
    print("*"*200)

PC_IP = "10.136.136.10"
PC_USER = "admin"
PC_PASSWD = "Nutanix@123"

credentials = f"{PC_USER}:{PC_PASSWD}".encode("utf-8")
encoded_credentials = base64.b64encode(credentials).decode("utf-8")

headers = {
        'Content-Type': 'application/json', 
        'Accept': 'application/json', 
        'Authorization': f'Basic {encoded_credentials}'
        }

def main(PC_IP, PC_USER, PC_PASSWD, headers):
    # source = get_sources(api_server=PC_IP, username=None, passwd=None, headers=headers, secure=False)
    # print("source : ", source)
    get_metrics(api_server=PC_IP, username=None, passwd=None, headers=headers, secure=False)
    # get_entity(api_server=PC_IP, username=None, passwd=None, headers=headers, secure=False)


main(PC_IP, PC_USER, PC_PASSWD, headers) 