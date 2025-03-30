
################################################
########     http_requests.py           ########
################################################
import json #tocomment
from time import sleep #tocomment
import urllib3 #tocomment

import requests
import uuid
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #tocomment


def process_request(url, method, cert=None, files=None,headers=None, payload=None, params=None, secure=False, timeout=120, retries=5, exit_on_failure=True):
    """
    Processes a web request and handles result appropriately with retries.
    Returns the content of the web request if successfull.
    """
    if payload is not None:
        payload = json.dumps(payload)

    sleep_between_retries=5
    #encoding the cred

    while retries > 0:
        try:

            if method == 'GET':
                response = requests.get(
                    url,
                    headers=headers,
                    cert=cert if cert else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'POST':
                response = requests.post(
                    url,
                    headers=headers,
                    json=payload,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PUT':
                response = requests.put(
                    url,
                    headers=headers,
                    json=payload,
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
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'DELETE':
                response = requests.delete(
                    url,
                    headers=headers,
                    data=payload,
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

def prism_monitor_task_apiv3(api_server, headers, task_uuid, wait_interval=30,secure=False):

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
        resp = process_request(url, method, headers=headers, secure=secure)
        #print(json.loads(resp.content))
        if resp.ok:
            task_status_details = json.loads(resp.content)
            task_status = resp.json()['status']
            if task_status == "SUCCEEDED":
                print ("Task has completed successfully")
                return task_status_details
            elif task_status == "FAILED":
                print ("Task has failed: {}".format(   resp.json()['error_detail'] if 'error_detail' in resp.json() else "No Info" )       )
                exit(1)
            else:
                print ("Task status is {} and percentage completion is {}. Current step is {}. Waiting for 30 seconds.".format(task_status,resp.json()['percentage_complete'],resp.json()['progress_message']))
                sleep(wait_interval)
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
            exit(resp.status_code)

    return task_status_details

def monitor_multiple_tasks_apiv3(api_server, headers, task_uuid_list, nb_retries=120, wait_interval=30, secure=False):

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
            api_server_port = "9440"
            api_server_endpoint = "/api/nutanix/v3/tasks/{0}".format(task_uuid)
            url = "https://{}:{}{}".format(
                api_server,
                api_server_port,
                api_server_endpoint
            )
            method = "GET"
            resp = process_request(url=url,method=method,headers=headers,secure=secure)
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

def get_vpc(api_server, headers, vpc_name, secure):
    url = f"https://{api_server}:9440/api/networking/v4.0/config/vpcs"
    resp = requests.get(url, headers=headers, verify=secure)
    if resp.ok :
        # print(json.dumps(resp.json()))
        result = json.loads(resp.content)
        for data in result['data']:
            if data["name"] == vpc_name:
                vpc_extId = data['extId']
                url = f"https://{api_server}:9440/api/networking/v4.0/config/vpcs/{vpc_extId}"
                # resp2 = requests.get(url, headers=headers, verify=secure)
                resp2 = process_request(url, 'GET', headers=headers, secure=secure)
                header = dict(resp2.headers)
                vpc_etag = header.get("Etag", None)
                print("Vpc Etag is : ", vpc_etag)
                # print(json.dumps(resp2.json()))
                if not(resp.ok):
                    print(f"VPC Fetched Data Status: {resp2.status_code} : {resp2.content}")
                    exit()
                return vpc_extId, data, vpc_etag
    else:
        print(f"GET_VPC_resp : {resp.status_code}")
        exit()

def get_vpc_route_table(api_server, headers, vpc_extId, secure):
    url = f"https://{api_server}:9440/api/networking/v4.0/config/route-tables"
    # resp = requests.get(url, headers=headers, verify=secure)
    resp= process_request(url, 'GET', headers=headers, secure=secure)
    if not( resp.ok ):
        print(f"GET VPC ROUTE LIST : {resp.status_code} : {resp.content}")
        exit()

    result = resp.json()

    for data in result["data"]:
        if data["vpcReference"] == vpc_extId:
            route_table_extId = data["extId"]
            url = f"https://{api_server}:9440/api/networking/v4.0/config/route-tables/{route_table_extId}"
            resp2 = process_request(url, 'GET', headers=headers, secure=secure)
            if not (resp2.ok):
                print("GET VPC ROUTE : {resp2.status_code} : {resp2.content}")
            header = dict(resp2.headers)
            route_table_etag = header.get("Etag", None)
            print("Route table Etag is : ", route_table_etag)
            return route_table_extId, data, route_table_etag
        
def del_route(api_server, headers, route_extId, route_table_etag,subnet_uuid,secure):
    url = f"https://{api_server}:9440/api/networking/v4.0/config/route-tables/{route_extId}/routes"
    #resp = requests.get(url, headers=headers, verify=secure)
    resp = process_request(url, 'GET', headers=headers, secure=secure)
    if not(resp.ok) or resp.json() or 'data' not in resp.json() or len(resp.json()['data'])==0:
        print("ROUTES  RETRIVE FAILED : {resp.status_code} : {resp.content}")
        return None, None, None, None
    print("resp is  ", resp.json())
    #result = resp.json(resp.content)
    result = resp.json()
    for data in result["data"]:
        if data["nexthop"]['nexthopReference'] == subnet_uuid :
            r_extId = data["extId"]  # Extract the specific route ID
            print(r_extId)
            url = f"https://{api_server}:9440/api/networking/v4.0/config/route-tables/{route_extId}/routes/{r_extId}"
            headers['NTNX-Request-Id'] = str(uuid.uuid4())
            headers['IF-Match'] = route_table_etag
            resp2 = process_request(url, 'GET', headers=headers, secure=secure)
            if resp2.ok:
                header = dict(resp2.headers)
                r_etag = header.get("Etag", None)
                resp3 = process_request(url, 'DELETE', headers=headers, secure=secure)
                if not(resp3.ok):
                    print(f"ROUTE DELETE FAILED : {resp2.status_code} : {resp2.content}")
                    exit()
                print("^"*200)
                print(resp3)
                print("^"*200)
                resp3_data = resp3.json()  # Parse the JSON content
                task_uuid = resp3_data['data']['extId']
            # result_route = json.loads(resp.content)
            print("data"*10)
            print(f"ROUTE RETRIEVE SUCCESS : {resp2.status_code}")
            # print(route_extId)
            print(json.dumps(data))
            print("="*200)
            return data, r_etag, r_extId, task_uuid

def update_route(api_server, headers, payload, route_extId, route_etag, vpc_reference, route_table_reference, subnet_uuid, subnet_name, secure):
    url = f"https://{api_server}:9440/api/networking/v4.0/config/route-tables/{route_table_reference}/routes"
    payload = {
	"$reserved": {
		"$fv": "v4.r0"
	},
	"$objectType": "networking.v4.config.Route",
	"extId": uuid.uuid4(),
	"isActive": true,
	"priority": 32768,
	"metadata": {
		"$reserved": {
			"$fv": "v1.r0"
		},
		"$objectType": "common.v1.config.Metadata"
	},
	"destination": {
		"$reserved": {
			"$fv": "v4.r0"
		},
		"$objectType": "networking.v4.config.IPSubnet",
		"ipv4": {
			"$reserved": {
				"$fv": "v4.r0"
			},
			"$objectType": "networking.v4.config.IPv4Subnet",
			"ip": {
				"$reserved": {
					"$fv": "v1.r0"
				},
				"$objectType": "common.v1.config.IPv4Address",
				"value": "0.0.0.0"
			},
			"prefixLength": 0
		}
	},
	"nexthop": {
		"$objectType": "networking.v4.config.Nexthop",
		"nexthopType": "EXTERNAL_SUBNET",
		"nexthopReference": subnet_uuid
	},
	"routeTableReference": route_table_reference,
	"vpcReference": vpc_reference,
	"routeType": "STATIC"
    }
    payload['nexthop']['nexthopName']= subnet_name
    payload['nexthop']['nexthopReference']= subnet_uuid
    payload['routeTableReference']= route_table_reference
    payload['vpcReference']= vpc_reference
    # payload['routeType']= "STATIC"


    print("--"*200)
    print(json.dumps(payload))
    print("="*200)
    # headers['IF-Match']= route_etag
    headers['NTNX-Request-Id']= str(uuid.uuid4())
    # resp = requests.post(url, headers=headers, json=payload, verify=secure)
    resp = process_request(url, 'POST', headers=headers, payload=payload, secure=secure)
    if not(resp.ok):
        print(f"ROUTE DELETE FAILED : {resp.status_code} : {resp.content}")
        exit()
    print("Route create successfully!!!")
    resp= resp.json()
    task_uuid = resp['data']['extId']
    return task_uuid

def prism_flow_update_vpc(api_server, headers, vpc_name, subnet_uuid, subnet_name, secure=False):
    vpc_extId, vpc_data, vpc_etag = get_vpc(api_server, headers, vpc_name, secure=secure)
    route_table_extId, route_data, route_table_etag = get_vpc_route_table(api_server, headers, vpc_extId, secure=secure)

    old_uuid = ""
    if 'externalSubnets' in vpc_data:
            old_uuid = vpc_data['externalSubnets'][0]['subnetReference']
    print("Older Subnet UUID:", old_uuid)
    if subnet_uuid == old_uuid:
        print("Same subnet already exists!!!")
    else:
        print(f"Updating Subnet from {old_uuid} : {subnet_uuid}...")
        vpc_data['externalSubnets'][0]['subnetReference'] = subnet_uuid
        vpc_data['externalSubnets'][0]['externalIps'] = []
        #TODO
        # vpc_data['spec']['resources']['external_subnet_list'][0]['active_gateway_count'] = 1
        vpc_data['externalSubnets'][0]['activeGatewayNode'] = {}
        

        print("Deleting existing route...")
        payload, r_etag, r_extId, task_uuid = del_route(api_server, headers, route_table_extId, route_table_etag,subnet_uuid, secure)
        #if task_uuid:
        # task_uuid = task_uuid.split('=:')[-1]
        # prism_monitor_task_apiv3(api_server=api_server, headers=headers, task_uuid=task_uuid, secure=False)
        sleep(5)


        print('Updating VPC...')
        headers['NTNX-Request-Id'] = str(uuid.uuid4())
        headers['IF-Match'] = vpc_etag
        url = f'https://{api_server}:9440/api/networking/v4.0/config/vpcs/{vpc_extId}'
        resp = requests.put(url, headers=headers, json=vpc_data, verify=secure )
        # resp = process_request(url, 'PUT', headers=headers, payload=vpc_data, secure=secure)

        print("1"*200)

        print("*"*200)
        print(resp.status_code)
        print("*"*200)
        print('creating route entry...')
        task_uuid= update_route(api_server, headers, payload, r_extId, r_etag, vpc_extId, route_table_extId, subnet_uuid, subnet_name, secure=secure)
        task_uuid = task_uuid.split('=:')[-1]
        prism_monitor_task_apiv3(api_server=api_server, headers=headers, task_uuid=task_uuid, secure=False)
        sleep(5)





SUBNET_VPC_MAP = {"ext-test2": ["3C VPC","CA VPC"], "ext-test1": ["CCity VPC","HDC-DC VPC","SDC-DC VPC"] }
SUBNET_UUIDs = {'ext-test1': 'e1a7aad9-ef43-4ee5-b2f8-52c4ac7481fa','ext-test2': '1732650a-090f-46f3-b502-a76c0ccff6e9'}

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
            prism_flow_update_vpc(PC_IP,headers,VPC_NAME,SUBNET_UUID,SUBNET_NAME)
else:
    print("Restoring to the original state : ", SUBNET_VPC_MAP)
    for SUBNET_NAME in SUBNET_VPC_MAP:
        SUBNET_UUID = SUBNET_UUIDs[SUBNET_NAME]
        VPC_LIST = SUBNET_VPC_MAP[SUBNET_NAME]
        print(VPC_LIST)
        for VPC_NAME in VPC_LIST:
            print(f"VPC IS : {VPC_NAME}")
            prism_flow_update_vpc(PC_IP,headers,VPC_NAME,SUBNET_UUID,SUBNET_NAME)