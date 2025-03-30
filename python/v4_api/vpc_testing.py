#!/usr/bin/python
################################################
########     http_requests.py           ########
################################################
# import json #tocomment
# from time import sleep #tocomment

import requests


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


################################################
############ pc_tasks.py            ############
################################################

############# Calm imports #################################################################
# CALM_USES http_requests.py
############################################################################################

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




################################################
############ pc_vpcs.py          ############
################################################

############# Calm imports #################################################################
# CALM_USES http_requests.py
############################################################################################

def prism_get_vpc(api_server, username, passwd, vpc_name, headers=None, secure=False):

    """Get a VPC object from its name.


    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
        vpc_name: Name of the vpc.
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        vpc_object which is the payload for the desired vpc object (can be null if vpc name was not found)
    """
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    
    method = "GET"
    url = 'https://{}:9440/api/networking/v4.0.b1/config/vpcs'.format(api_server)
    resp = process_request(url=url,method=method, user=username, password=passwd, headers=headers, payload=None, secure=secure)
    if resp.ok:
        result = json.loads(resp.content)
        #print(result)
        for i in result['data']:
            if i['name'] == vpc_name:
                url = 'https://{}:9440/api/networking/v4.0.b1/config/vpcs/{}'.format(api_server,i['extId'])
                resp2 = process_request(url,'GET', user=username, password=passwd, headers=headers, payload=None, secure=secure)
                if not(resp.ok):
                    print('ERROR - VPC get failed, status code: {}, msg: {}'.format(resp2.status_code, resp2.content))
                    exit(1)
                header = dict(resp2.headers)
                vpc_etag = header.get("Etag", None)
                print("VPC etag is :",vpc_etag)
                return i['extId'], i, vpc_etag
        print("VPC not found")
        exit(1)
    else:
        print('ERROR - VPC get failed, status code: {}, msg: {}'.format(resp.status_code, resp.content))
        exit(1)


########################################################################
############       w2_8_flow_virtual_networking.py          ############
########################################################################

############# Calm imports #################################################################
# CALM_USES pc_tasks.py, pc_vpcs.py
############################################################################################

def prism_get_vpc_routes(api_server, username, passwd, headers, vpc_uuid, secure=False):

    """gets routing table from a vpc.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
        vpc_uuid: uuid of the vpc to be updated.
        secure: boolean to verify or not the api server's certificate (True/False) 
        
    Returns:
        vpc_routes: vpc routing table object where spec.resources contains: 
          static_routes_list and default_route_nexthop.
    """

    url = 'https://{}:9440/api/networking/v4.0.b1/config/route-tables'.format(api_server)
    resp = process_request(url,'GET', user=username, password=passwd, headers=headers, payload=None, secure=secure)
    if resp.ok:
        result = json.loads(resp.content)     
        for i in result['data']:
            if i['vpcReference'] == vpc_uuid :
                url = 'https://{}:9440/api/networking/v4.0.b1/config/route-tables/{}'.format(api_server, i['extId'])
                resp2 = process_request(url,'GET', user=username, password=passwd, headers=headers, payload=None, secure=secure)
                if not(resp2.ok):
                    print('ERROR - Route-table GET failed, status code: {}, msg: {}'.format(resp2.status_code, resp2.content))
                    exit(1)
                header = dict(resp2.headers)
                route_table_etag = header.get("Etag", None)
                print("Route table Etag is :", route_table_etag)
                return i, route_table_etag
    else:
        print('ERROR - Route-table GET failed, status code: {}, msg: {}'.format(resp.status_code, resp.content))
        exit(1)

#TODO: completed: needs testing
def prism_flow_delete_routing_table(api_server, username, passwd, headers, vpc_route_table, route_table_etag, secure=False):

    """deletes all static and default routes from a VPC.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
        vpc_uuid: uuid of the vpc to be updated
        secure: boolean to verify or not the api server's certificate (True/False) 
        
    Returns:
        the uuid of the vpc update task
    """

    headers['NTNX-Request-Id'] = str(uuid.uuid4())
    headers['IF-Match'] = route_table_etag
    vpc_route_table['staticRoutes'] = []
    
    url = 'https://{}:9440/api/networking/v4.0.b1/config/route-tables/{}'.format(api_server, vpc_route_table['extId'])
    resp = process_request(url, 'PUT', user=username, password=passwd, headers=headers, payload=vpc_route_table, secure=secure)
    if resp.ok:
        result = json.loads(resp.content)
        task_uuid = result['data']['extId']
        print('INFO - Route Table deleted with status code: {}'.format(resp.status_code))
    else:
        print('ERROR - Route Table delete failed, status code: {}, msg: {}'.format(resp.status_code, resp.content))
        exit(1)
    return task_uuid

def prism_flow_update_routing_table(api_server, username, passwd, headers, vpc_route_table, subnet_uuid, route_table_etag, secure=False):

    """updates all static and default routes in a VPC.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
        vpc_uuid: uuid of the vpc to be updated
        secure: boolean to verify or not the api server's certificate (True/False) 
        
    Returns:
        the uuid of the vpc update task
    """

    headers['NTNX-Request-Id'] = str(uuid.uuid4())
    headers['IF-Match'] = route_table_etag

    vpc_route_table["staticRoutes"]= [
            {
                "destination": {
                    "ipv4": {
                        "ip": {
                            "value": "0.0.0.0",
                            "prefixLength": 32
                        },
                        "prefixLength": 0
                    }
                },
                "nexthopType": "EXTERNAL_SUBNET",
                "nexthopReference": subnet_uuid
            }
        ]
    
    url = 'https://{}:9440/api/networking/v4.0.b1/config/route-tables/{}'.format(api_server, vpc_route_table['extId'])
    resp = process_request(url, 'PUT', user=username, password=passwd, headers=headers, payload=vpc_route_table, secure=secure)
    if resp.ok:
        result = json.loads(resp.content)
        task_uuid = result['data']['extId']
        print('INFO - Route Table Updated with status code: {}'.format(resp.status_code))
    else:
        print('ERROR - Route Table Update failed, status code: {}, msg: {}'.format(resp.status_code, resp.content))
        exit(1)
    return task_uuid


def prism_flow_update_vpc(api_server, username, passwd, headers, vpc_name, subnet_uuid, subnet_name, secure=False):

    """Updates a VPC to update external connectivity.  Note that in order to update external connectivity, the VPC 
         routing table must not contain any reference to that external network.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
        vpc_name: name of the vpc to be created
        secure: boolean to verify or not the api server's certificate (True/False) 
        
    Returns:
        the uuid of the update task
    """

    #get vpc object
    vpc_uuid, vpc_obj, vpc_etag = prism_get_vpc(api_server=api_server, username=username, passwd=passwd, headers=headers, vpc_name=vpc_name, secure=secure)
    vpc_route_table, route_table_etag = prism_get_vpc_routes(api_server, username, passwd, headers, vpc_uuid, secure=secure)
    old_uuid = ""
    if 'externalSubnets' in vpc_obj:
        old_uuid = vpc_obj['externalSubnets'][0]['subnetReference'] 
    print("Older UUID:", old_uuid)
    
    print("Comparing the older subnet UUID with the runbook variable list")
    if old_uuid == subnet_uuid:
        print("Same Subnet already configured:{} {}. Skipping!!!".format(subnet_uuid, subnet_name))
        return
    else:
        print("Subnet to be updated from {} to {}".format(old_uuid, subnet_uuid))
    print("Updating VPC payload")
    vpc_obj['externalSubnets'][0]['subnetReference'] = subnet_uuid
    vpc_obj['externalSubnets'][0]['externalIps'] = []
    #TODO
    # vpc_obj['spec']['resources']['external_subnet_list'][0]['active_gateway_count'] = 1
    vpc_obj['externalSubnets'][0]['activeGatewayNode'] = {}
    vpc_obj['is_pc_dvs'] = True

    task_uuid = prism_flow_delete_routing_table(api_server=api_server, username=username, passwd=passwd, headers=headers, vpc_route_table=vpc_route_table, route_table_etag = route_table_etag)
    task_uuid = task_uuid.split('=:')[-1]
    prism_monitor_task_apiv3(api_server=api_server, username=username, passwd=passwd, task_uuid=task_uuid, secure=False)
    
    print("Making an API call to update VPC payload")

    headers['NTNX-Request-Id'] = str(uuid.uuid4())
    headers['IF-Match'] = vpc_etag
    url = 'https://{}:9440/api/networking/v4.0.b1/config/vpcs/{}'.format(api_server, vpc_uuid)
    resp = process_request(url, 'PUT', user=username, password=passwd, headers=headers, payload=vpc_obj , secure=secure)
    if resp.ok:
        result = json.loads(resp.content)
        task_uuid = result['data']['extId']
        task_uuid = task_uuid.split('=:')[-1]
        prism_monitor_task_apiv3(api_server, username, passwd, task_uuid, secure=False)
        # vpc_uuid = result['metadata']['uuid']
        print('INFO - VPC Updated with status code: {}'.format(resp.status_code))
        print('INFO - VPC uuid: {}'.format(vpc_uuid))
    else:
        print('ERROR - VPC updation failed, status code: {}, msg: {}'.format(resp.status_code, resp.content))
        exit(1)

    vpc_route_table, route_table_etag = prism_get_vpc_routes(api_server, username, passwd, headers, vpc_uuid, secure=secure)
    task_uuid = prism_flow_update_routing_table(api_server, username, passwd, headers, vpc_route_table=vpc_route_table, subnet_uuid=subnet_uuid, route_table_etag = route_table_etag)
    task_uuid = task_uuid.split('=:')[-1]
    prism_monitor_task_apiv3(api_server, username, passwd, task_uuid, secure=False)



############# Calm imports #################################################################
# CALM_USES w2_8_flow_virtual_networking.py
############################################################################################

headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
}

PC_IP = "@@{PC_IP}@@"
PC_PROVIDER_USERNAME = "@@{prism_central.username}@@"
PC_PROVIDER_PASSWD = "@@{prism_central.secret}@@"
print(PC_PROVIDER_USERNAME)
SUBNET_VPC_MAP = @@{SUBNET_VPC_MAP}@@   ### {      "ext-test2": ["3C VPC","CA VPC"],     "ext-test1": ["CCity VPC","HDC-DC VPC","SDC-DC VPC"]   }
SUBNET_UUIDs = @@{SUBNET_UUID}@@  #   [{'ext-test2': '1732650a-090f-46f3-b502-a76c0ccff6e9'}, {'ext-test1': 'e1a7aad9-ef43-4ee5-b2f8-52c4ac7481fa'}]
#

if len(SUBNET_UUIDs) == 1:
  for SUBNET_NAME in SUBNET_UUIDs:
    SUBNET_UUID = SUBNET_UUIDs[SUBNET_NAME]
    VPC_LIST = ','.join([ ','.join(SUBNET_VPC_MAP[i]) for i in SUBNET_VPC_MAP ]).split(',')
    for VPC_NAME in VPC_LIST:
      prism_flow_update_vpc(PC_IP,PC_PROVIDER_USERNAME,PC_PROVIDER_PASSWD,headers,VPC_NAME,SUBNET_UUID,SUBNET_NAME)
else:
  print("Restoring to the original state : ", SUBNET_VPC_MAP)
  for SUBNET_NAME in SUBNET_VPC_MAP: 
    SUBNET_UUID = SUBNET_UUIDs[SUBNET_NAME]
    VPC_LIST = SUBNET_VPC_MAP[SUBNET_NAME]
    for VPC_NAME in VPC_LIST:
      prism_flow_update_vpc(PC_IP,PC_PROVIDER_USERNAME,PC_PROVIDER_PASSWD,headers,VPC_NAME,SUBNET_UUID,SUBNET_NAME)