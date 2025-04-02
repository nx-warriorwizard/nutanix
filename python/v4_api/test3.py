import json #tocomment
from time import sleep #tocomment
import urllib3 #tocomment

import requests
import uuid
import base64


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

def prism_monitor_task_apiv3(api_server,username,passwd,task_uuid, wait_interval=30,secure=False):

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
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    print("[INFO] Making a {} API call to {}".format(method, url))
    
    while True:
        resp = process_request(url,method,user=username,password=passwd,headers=headers,secure=secure)
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

def monitor_multiple_tasks_apiv3(api_server,username,passwd,task_uuid_list, nb_retries=120, wait_interval=30, secure=False):

    """Given a Prism Central list of tasks uuids, loop until all tasks finish or some task fails
    exits if the one of the tasks fails

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
        task_uuid_list: comma-separated list of tasks uuids
        nb_retries: number of retires before timeout
        wait_interval: interval between retries in seconds
        secure: boolean to verify or not the api server's certificate (True/False)

    Returns:
        No value is returned
    """

    if task_uuid_list == "":
        return
    for x in range(nb_retries):
        tasks_status_list = []
        for task_uuid in task_uuid_list.split(','):
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
            resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,secure=secure)
            if resp.ok:
                task_status = resp.json()['status']
            else:
                print("ERROR - Failed to fetch task {} ".format(task_uuid))
            tasks_status_list.append(
                {
                    "uuid": task_uuid,
                    "state": task_status
                }
            )

        print(">>>>> current tasks status:")
        print(tasks_status_list)


        overall_state = "SUCCEEDED"
        for task_status in tasks_status_list:
            if task_status["state"].upper() == "FAILED":
                overall_state = "FAILED"
                print("Task {} failed.".format(task_status["uuid"]))
            elif task_status["state"].upper() != "SUCCEEDED" and overall_state != "FAILED":
                overall_state = "inprogress"
        if overall_state == "FAILED":
            print("ERROR - Some Tasks failed.")
            exit(1)
        elif overall_state == "SUCCEEDED":
            print("INFO - All tasks finished Successfully.")
            return
        else:
            print("INFO - Tasks are still in progress, waiting...")
            sleep(wait_interval)
    #here the monitoring times out
    print("ERROR - Tasks monitoring timed out")
    exit(1)

def get_vpc(api_server, username, passwd, headers, vpc_name, secure):
    """
    Fetches the external ID, payload response, and ETag value of a specified VPC.

        api_server (str): The IP or FQDN of the Prism server.
        username (str): The Prism user name.
        passwd (str): The password for the Prism user.
        headers (dict): The headers for the API request.
        vpc_name (str): The name of the VPC to retrieve.
        secure (bool): Whether to verify the API server's SSL certificate (True/False).

        tuple: A tuple containing:
            - vpc_extId (str): The external ID of the VPC.
            - vpc_data (dict): The payload response of the matching VPC.
            - vpc_etag (str): The ETag value of the VPC.

    Raises:
        SystemExit: If the API request fails or the VPC data cannot be fetched.
    """
    url = f"https://{api_server}:9440/api/networking/v4.0/config/vpcs"
    resp = requests.get(url, headers=headers, verify=secure)
    resp = process_request(url, "GET", user= username, password= passwd, headers=headers, secure=secure )
    if resp.ok :
        result = json.loads(resp.content)
        for vpc_data in result['data']:
            if vpc_data["name"] == vpc_name:
                vpc_extId = vpc_data['extId']
                url = f"https://{api_server}:9440/api/networking/v4.0/config/vpcs/{vpc_extId}"
                resp2= process_request(url, 'GET', user=username, password=passwd, headers=headers, secure=secure )
                # print("type of resp2 : ", resp2.content)

                header = dict(resp2.headers)
                vpc_etag = header.get("Etag", None)
                if not(resp.ok):
                    print(f"[INFO] VPC Fetched Data Status: {resp2.status_code} : {resp2.content}")
                    exit()
                return vpc_extId, vpc_data, vpc_etag
    else:
        print(f"[INFO] GET_VPC_resp : {resp.status_code}")
        exit()

def update_vpc(api_server, username, passwd, headers, vpc_data, vpc_etag, vpc_extId, old_uuid, subnet_uuid, secure ):
    """
    Updates the VPC with new subnet details and returns the task UUID.
    Args:
        api_server (str): The API server address.
        username (str): The username for authentication.
        passwd (str): The password for authentication.
        headers (dict): The HTTP headers for the request.
        vpc_data (dict): The VPC configuration data to be updated.
        vpc_etag (str): The ETag value for the VPC resource.
        vpc_extId (str): The external ID of the VPC.
        old_uuid (str): The UUID of the old subnet.
        subnet_uuid (str): The UUID of the new subnet.
        secure (bool): Whether to use a secure connection (HTTPS).
    Returns:
        str: The UUID of the task created for the VPC update.
    """
    
    print(f"[INFO] Updating Subnet from {old_uuid} : {subnet_uuid}...")
    vpc_data['externalSubnets'][0]['subnetReference'] = subnet_uuid
    vpc_data['externalSubnets'][0]['externalIps'] = []
    vpc_data['externalSubnets'][0]['activeGatewayNode'] = {}

    print('[INFO] Updating VPC...')
    headers['NTNX-Request-Id'] = str(uuid.uuid4())
    headers['IF-Match'] = vpc_etag
    url = f'https://{api_server}:9440/api/networking/v4.0/config/vpcs/{vpc_extId}'
    resp = process_request(url, 'PUT', user=username, password=passwd, headers=headers, payload=vpc_data, secure=secure)
    result = json.loads(resp.content)
    task_uuid = result['data']['extId']
    return task_uuid

def get_vpc_route_table(api_server, username, passwd, headers, vpc_extId, secure):
    """
    Fetches the route table details for a specific VPC.
    Args:
        api_server (str): The API server address.
        username (str): The username for authentication.
        passwd (str): The password for authentication.
        headers (dict): The headers to include in the API request.
        vpc_extId (str): The external ID of the VPC.
        secure (bool): Whether to use secure (HTTPS) communication.
    Returns:
        tuple: A tuple containing:
            - route_table_extId (str): The external ID of the route table.
            - route_table_data (dict): The route table data.
            - route_table_etag (str or None): The ETag of the route table, if available.
    Raises:
        SystemExit: If the API request fails or returns an error response.
    Notes:
        - The function makes two API calls: one to fetch the list of route tables and another to fetch details of the specific route table.
        - If the route table's ETag is not found in the response headers, `None` is returned for the ETag.
    """

    url = f"https://{api_server}:9440/api/networking/v4.0/config/route-tables"
    resp = process_request(url, 'GET', user=username, password=passwd, headers=headers, secure=secure)
    if not( resp.ok ):
        print(f"[INFO] GET VPC ROUTE LIST : {resp.status_code} : {resp.content}")
        exit()
    result = json.loads(resp.content)
    for route_table_data in result["data"]:
        if route_table_data["vpcReference"] == vpc_extId:
            route_table_extId = route_table_data["extId"]
            url = f"https://{api_server}:9440/api/networking/v4.0/config/route-tables/{route_table_extId}"
            resp2 = process_request(url, 'GET', user=username, password=passwd, headers=headers, secure=secure)
            resp2_res = json.loads(resp2.content)
            if not (resp2.ok):
                print("[INFO] GET VPC ROUTE : {resp2.status_code} : {resp2.content}")
            header = dict(resp2.headers)
            route_table_etag = header.get("Etag", None)
            return route_table_extId, route_table_data, route_table_etag

def del_route(api_server, username, passwd, headers, route_table_extId, route_table_etag, route_data, subnet_uuid, secure):
    """
    Deletes a specific route from a route table in the VPC.
    Args:
        api_server (str): The API server address.
        username (str): The username for authentication.
        passwd (str): The password for authentication.
        headers (dict): HTTP headers for the request.
        route_table_extId (str): The external ID of the route table.
        route_table_etag (str): The ETag of the route table for concurrency control.
        route_data (dict): The route data containing route details.
        subnet_uuid (str): The UUID of the subnet to match the route's next hop.
        secure (bool): Whether to use a secure connection (HTTPS).
    Returns:
        str: The UUID of the task created for deleting the route.
    Raises:
        KeyError: If the expected keys are missing in the response or route data.
        ValueError: If the response content cannot be parsed as JSON.
    """

    for data in route_data['data']:
        if data["nexthop"]['nexthopReference'] == subnet_uuid:
            route_extId = data['extId']
            url = f"https://{api_server}:9440/api/networking/v4.0/config/route-tables/{route_table_extId}/routes/{route_extId}"
            headers['NTNX-Request-Id'] = str(uuid.uuid4())
            headers['IF-Match'] = route_table_etag
            # resp = process_request(url, 'GET', user=username, password=passwd, headers=headers, secure=secure)
            # print("*"*200)
            # print(json.loads(resp.content))
            # print("*"*200)
            resp2 = process_request(url, 'DELETE', user=username, password=passwd, headers=headers, secure=secure)
            result = json.loads(resp2.content)
            task_uuid = result['data']['extId']
            return task_uuid

def get_route(api_server, username, passwd, headers, route_table_extId, secure):
    # Fetch the total number of available routes and route data
    url = f"https://{api_server}:9440/api/networking/v4.0/config/route-tables/{route_table_extId}/routes"
    resp = process_request(url, 'GET', user=username, password=passwd, headers=headers, secure=secure)
    if not(resp.ok):
        print("[INFO] ROUTES  RETRIVE FAILED : {resp.status_code} : {resp.content}")
        exit()
    route_data = json.loads(resp.content)
    total_available_route = route_data['metadata']['totalAvailableResults']
    return total_available_route, route_data
    
def add_route(api_server, username, passwd, headers, vpc_extId, route_table_extId, subnet_uuid, subnet_name, secure):
    """
    Adds a static route to a specified route table in the VPC.
    Args:
        api_server (str): The API server address.
        username (str): The username for authentication.
        passwd (str): The password for authentication.
        headers (dict): The HTTP headers for the request.
        vpc_extId (str): The external ID of the VPC (currently unused in the payload).
        route_table_extId (str): The external ID of the route table to update.
        subnet_uuid (str): The UUID of the external subnet to use as the next hop.
        subnet_name (str): The name of the external subnet to use as the next hop.
        secure (bool): Whether to use a secure connection (HTTPS).
    Returns:
        str: The UUID of the task created for the route addition.
    Raises:
        Exception: If the API request fails or the response is invalid.
    """

    url = f"https://{api_server}:9440/api/networking/v4.0/config/route-tables/{route_table_extId}/routes"
    payload = {
        "routeType": "STATIC",
        "destination": {
            "ipv4": {
                "ip": {
                    "value": "0.0.0.0"
                },
                "prefixLength": 0
            }
        },
        "nexthop": {
            "nexthopType": "EXTERNAL_SUBNET"
        }
    }
    payload['nexthop']['nexthopName']= subnet_name
    payload['nexthop']['nexthopReference']= subnet_uuid
    payload['routeTableReference']= route_table_extId
    # payload['vpcReference']= vpc_extId
    headers['NTNX-Request-Id']= str(uuid.uuid4())
    resp = process_request(url, 'POST', user=username, password=passwd, headers=headers, payload=payload, secure=secure)
    print(f"[INFO] Update route {resp.status_code} : {resp.content}")
    result = json.loads(resp.content)
    task_uuid = result['data']['extId']
    # task_uuid = task_uuid.split('=:')[-1]
    # prism_monitor_task_apiv3(api_server, username, passwd, task_uuid, secure=False)
    return task_uuid

def prism_flow(api_server, username, passwd, headers, vpc_name, subnet_uuid, subnet_name, secure):
    """
    Manages the flow VPC including retrieving VPC details, managing routes, and updating VPC configurations.
    Args:
        api_server (str): The API server address.
        username (str): The username for authentication.
        passwd (str): The password for authentication.
        headers (dict): HTTP headers for API requests.
        vpc_name (str): The name of the VPC to manage.
        subnet_uuid (str): The UUID of the subnet to associate with the VPC.
        subnet_name (str): The name of the subnet to associate with the VPC.
        secure (bool, optional): Whether to use secure (HTTPS) communication. Defaults to False.
    Returns:
        None
    Raises:
        Exception: If any API call fails or an unexpected error occurs.
    Note:
        - This function performs multiple API calls to manage VPC and route configurations.
        - It ensures that the specified subnet is associated with the VPC and updates routes accordingly.
        - If the subnet is already associated, it skips redundant operations.
    """
    vpc_extId, vpc_data, vpc_etag = get_vpc(api_server, username, passwd, headers, vpc_name, secure=secure)
    route_table_extId, route_table_data, route_table_etag = get_vpc_route_table(api_server, username, passwd, headers, vpc_extId, secure=secure)
    total_available_route, route_data = get_route(api_server, username, passwd, headers, route_table_extId, secure)

    old_uuid = ""
    if 'externalSubnets' in vpc_data:
            old_uuid = vpc_data['externalSubnets'][0]['subnetReference']
    route_uuid = [data["nexthop"]['nexthopReference'] for data in route_data['data']] if total_available_route != 0 else []
    
    if total_available_route == 0 or old_uuid not in route_uuid:
        task_uuid = add_route(api_server, username, passwd, headers, vpc_extId, route_table_extId, subnet_uuid, subnet_name, secure=secure)
        print("[INFO] task_uuid :", task_uuid)
        task_uuid = task_uuid.split('=:')[-1]
        prism_monitor_task_apiv3(api_server, username, passwd, task_uuid, secure=False)

    if subnet_uuid == old_uuid:
        print("[INFO] Same subnet already exists!!!")
    else:
        total_available_route, route_data = get_route(api_server, username, passwd, headers, route_table_extId, secure)
        if total_available_route == 0:
            print("[INFO] No route Table exists")
        else:
            print("[INFO] Deleting route entry from route table.")
            task_uuid = del_route(api_server, username, passwd, headers, route_table_extId, route_table_etag, route_data, old_uuid, secure)
            task_uuid = task_uuid.split('=:')[-1]
            prism_monitor_task_apiv3(api_server, username, passwd, task_uuid, secure=False)

        # update vpc with new subnet uuid
        task_uuid = update_vpc(api_server, username, passwd, headers, vpc_data, vpc_etag, vpc_extId, old_uuid, subnet_uuid, secure)
        task_uuid = task_uuid.split('=:')[-1]
        prism_monitor_task_apiv3(api_server, username, passwd, task_uuid, secure=False)
        
        #adding static route
        print("[INFO] Route adding in progress ")
        task_uuid = add_route(api_server, username, passwd, headers, vpc_extId, route_table_extId, subnet_uuid, subnet_name, secure=secure)
        print("[INFO] task_uuid :", task_uuid)
        task_uuid = task_uuid.split('=:')[-1]
        prism_monitor_task_apiv3(api_server, username, passwd, task_uuid, secure=False)



########################################################################################################
########################################################################################################
########################################################################################################



# PC_IP = "@@{PC_IP}@@"
# PC_PROVIDER_USERNAME = "@@{prism_central.username}@@"
# PC_PROVIDER_PASSWD = "@@{prism_central.secret}@@"
# print(PC_PROVIDER_USERNAME)
# SUBNET_VPC_MAP = @@{SUBNET_VPC_MAP}@@   ### {      "ext-test2": ["3C VPC","CA VPC"],     "ext-test1": ["CCity VPC","HDC-DC VPC","SDC-DC VPC"]   }
# SUBNET_UUIDs = @@{SUBNET_UUID}@@  #   [{'ext-test2': '1732650a-090f-46f3-b502-a76c0ccff6e9'}, {'ext-test1': 'e1a7aad9-ef43-4ee5-b2f8-52c4ac7481fa'}]
# #

PC_IP = ""
PC_PROVIDER_USERNAME = ""
PC_PROVIDER_PASSWD = ""

SUBNET_VPC_MAP = {"ext-test2": ["CA VPC", "3C VPC"], "ext-test1": ["CCity VPC","HDC-DC VPC","SDC-DC VPC"] }
SUBNET_UUIDs = {'ext-test2': '1732650a-090f-46f3-b502-a76c0ccff6e9'}

#encoding the cred
credentials = f"{PC_PROVIDER_USERNAME}:{PC_PROVIDER_PASSWD}".encode("utf-8")
encoded_credentials = base64.b64encode(credentials).decode("utf-8")

headers = {
        'Content-Type': 'application/json', 
        'Accept': 'application/json', 
        'Authorization': f'Basic {encoded_credentials}'
        }


if len(SUBNET_UUIDs) == 1:
    for SUBNET_NAME in SUBNET_UUIDs:
        SUBNET_UUID = SUBNET_UUIDs[SUBNET_NAME]
        VPC_LIST = ','.join([ ','.join(SUBNET_VPC_MAP[i]) for i in SUBNET_VPC_MAP ]).split(',')
        print(VPC_LIST)
        for VPC_NAME in VPC_LIST:
            print("-"*180)
            print(f"[INFO] VPC IS : {VPC_NAME}")
            prism_flow(PC_IP, PC_PROVIDER_USERNAME, PC_PROVIDER_PASSWD, headers, VPC_NAME, SUBNET_UUID, SUBNET_NAME, secure=False)
            sleep(1)
else:
    print("[INFO] Restoring to the original state : ", SUBNET_VPC_MAP)
    for SUBNET_NAME in SUBNET_VPC_MAP:
        SUBNET_UUID = SUBNET_UUIDs[SUBNET_NAME]
        VPC_LIST = SUBNET_VPC_MAP[SUBNET_NAME]
        print(VPC_LIST)
        for VPC_NAME in VPC_LIST:
            print("-"*25)
            print(f"[INFO] VPC IS : {VPC_NAME}")
            prism_flow(PC_IP, PC_PROVIDER_USERNAME, PC_PROVIDER_PASSWD, headers, VPC_NAME, SUBNET_UUID, SUBNET_NAME, secure=False)
            sleep(1)

