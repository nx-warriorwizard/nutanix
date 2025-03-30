#!/usr/bin/python
################################################
########     http_requests.py           ########
################################################
import json #tocomment
from time import sleep #tocomment
import requests
import urllib3

# Disable SSL warnings
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
        print(result)
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
############       pc_entities.py                           ############
########################################################################
#region CALM_USES http_requests.py


def prism_get_entities(api_server,username,passwd,entity_type,entity_api_root,secure=False,print_f=True,filter=None):

    """Retrieve the list of entities from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
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
        passwd: The Prism user name password.
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
            exit(1)
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
            print("ERROR - Entity {} not found".format(entity_name))
            exit(1)
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

#region testing
def prism_delete_entity(api_server,username,passwd,entity_type,entity_api_root,entity_name=None,entity_uuid=None,secure=False,print_f=True):

    """Deletes an entity given entity uuid or entity name.
       If an entity_uuid is specified, it will skip retrieving all entities to find uuid, by specifying the uuid in the arguments (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
        entity_type: kind (type) of entity as referenced in the entity json object
        entity_api_root: v3 apis root for this entity type. for example. for projects the list api is ".../api/nutanix/v3/projects/list".
                         the entity api root here is "projects"
        entity_name: Name of the entity (optional).
        entity_uuid: Uuid of the entity (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        Task uuid when entity deletion request returns task uuid under $.status.state.execution_context.task_uuid
        task uuid is returned as None when the returned json is of a different format for some entity type
    """

    entity_uuid, entity_details = prism_get_entity(api_server,username,passwd,
                                                   entity_type,entity_api_root,
                                                   entity_name=entity_name,entity_uuid=entity_uuid,
                                                   secure=secure,print_f=print_f)
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
    method = "DELETE"
    if print_f:
        print("{} API call to {} with secure set to {}".format(entity_type, url, secure))
    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,secure=secure)
    if resp.ok:
        if print_f:
            print("INFO - {} {} deletion task initiated with success".format(entity_type, entity_details["status"]["name"]))
        res = json.loads(resp.content)
        #when entity deletion request returns the common $.status.state.execution_context.task_uuid
        if "status" in res and "execution_context" in res["status"] \
                    and "task_uuid" in res["status"]["execution_context"]:
            return res["status"]["execution_context"]["task_uuid"]
        #otherwise return None. for example, app deletion returned json has a different format ($.status.ergon_task_uuid).
        #it has to be monitored by a specific function, not using the standard entities library
        else:
            return None
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


def prism_add_categories_to_entity(api_server,username,passwd,entity_type,entity_api_root,added_categories,entity_name=None,entity_uuid=None,secure=False,print_f=True):

    """adds categories to entity given uuid or entity name.
       If an entity_uuid is specified, it will skip retrieving all entities to find uuid, by specifying the uuid in the arguments (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
        entity_type: kind (type) of entity as referenced in the entity json object
        entity_api_root: v3 apis root for this entity type. for example. for projects the list api is ".../api/nutanix/v3/projects/list".
                         the entity api root here is "projects"
        entity_name: Name of the entity (optional).
        entity_uuid: Uuid of the entity (optional).
        added_categories: categories to add in the form:
            {
                "catgory1": "value1",
                "catgory2": "value2",
                ...
            }
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        Task uuid
    """

    entity_uuid, entity_details = prism_get_entity(api_server,username,passwd,
                                                   entity_type,entity_api_root,
                                                   entity_name=entity_name,entity_uuid=entity_uuid,
                                                   secure=secure,print_f=print_f)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/{}/{}".format(entity_api_root,entity_uuid)
    url = "https://{}:{}{}".format(api_server, api_server_port, api_server_endpoint)
    method = "PUT"
    new_categories = entity_details["metadata"]["categories"]
    for cat in added_categories:
        new_categories[cat] = added_categories[cat]
    payload = entity_details
    del(payload["status"])
    payload["metadata"]["categories"] = new_categories

    resp = process_request(url=url,method=method,user=username,password=passwd,headers=headers,payload=payload,secure=secure)

    if resp.ok:
        result = resp.json()
        task_uuid = result['status']['execution_context']['task_uuid']
        task_state = result['status']['state']
        print('INFO - Entity categories updated with status code: {}'.format(resp.status_code))
        print('INFO - task: {}, state: {}'.format(task_uuid, task_state))
        return task_uuid
    else:
        print('ERROR - Entity categories update failed, status code: {}, msg: {}'.format(resp.status_code, resp.content))
        exit(1)
#region testing

def prism_get_entity_no_fail(api_server,username,passwd,entity_type,entity_api_root,entity_uuid,secure=False,print_f=True, timeout=120):

    """Returns from Prism Central the uuid and details of a given entity uuid

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
        entity_type: kind (type) of entity as referenced in the entity json object
        entity_api_root: v3 apis root for this entity type. for example. for projects the list api is ".../api/nutanix/v3/projects/list".
                         the entity api root here is "projects"

        entity_uuid: Uuid of the entity
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        A string containing the UUID of the entity (entity_uuid) and the json content
        of the entity details (entity_details)
        None, None if not found
    """
    
    entity_details = {}

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
    if print_f:
        print("Making a {} API call to {} with secure set to {}".format('method', url, secure))
    resp = requests.get(url, headers=headers,
                    auth=(username, passwd),
                    cert=None,
                    params=None,
                    verify=secure,
                    timeout=timeout
                )
    
    if resp.ok:
        entity_details = json.loads(resp.content)
    else:
        if resp.status_code == 404:
            return None, None
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


################################################
############ pc_subnets.py          ############
################################################

############# Calm imports #################################################################
# CALM_USES pc_entities.py, http_requests.py
############################################################################################

def prism_get_subnets(api_server,username,passwd,secure=False,print_f=True,filter=None):

    """Retrieve the list of subnets from Prism Central.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
        secure: boolean to verify or not the api server's certificate (True/False)
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        filter: filter to be applied to the search
        
    Returns:
        A list of subnets (entities part of the json response).
    """

    return prism_get_entities(api_server=api_server,username=username,passwd=passwd,
                              entity_type="subnet",entity_api_root="subnets",secure=secure,print_f=print_f,filter=filter)


def prism_get_subnet(api_server,username,passwd,subnet_name=None,subnet_uuid=None,secure=False,print_f=True):

    """Returns from Prism Central the uuid and details of a given subnet name.
       If a subnet_uuid is specified, it will skip retrieving all subnets (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
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


def prism_get_subnets_v4(api_server,username,passwd,subnet_name=None,subnet_uuid=None,secure=False):

    """Returns from Prism Central the uuid and details of a given subnet name.
       If a subnet_uuid is specified, it will skip retrieving all subnets (faster).

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
        subnet_name: Name of the subnet (optional).
        subnet_uuid: Uuid of the subnet (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        
    Returns:
        A string containing the UUID of the Subnet (subnet_uuid) and the json content
        of the subnet details (subnet)
    """
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    method = "GET"
    url = "https://{}:9440/api/networking/v4.0.b1/config/subnets".format(api_server)
    if subnet_uuid:
        url += "/" + subnet_uuid
    if subnet_name:
        url += "?$filter=name eq '{}'".format(subnet_name)
    resp = process_request(url=url, method=method, user=username, password=passwd, headers=headers, payload=None, secure=False, timeout=20)
    if resp.ok:
        json_resp = json.loads(resp.content)
        if subnet_uuid:
            print("Searching for Subnet UUID: {}".format(subnet_uuid))
            return json_resp['extId'], json_resp['data']
        if subnet_name:
            print("Searching for Subnet: {}".format(subnet_name))
            for each_subnet in json_resp['data']:
                if each_subnet['name'] == subnet_name:
                    print("Found Subnet : {}".format(subnet_name))
                    return each_subnet['extId'], each_subnet
        else:
            return None, json_resp['data']
        
    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print(json.dumps(json.loads(resp.content),indent=4))
        raise


def prism_get_subnet_uuid(api_server,username,passwd,subnet_name,secure=False,print_f=True):

    """Returns from Prism Central the uuid given subnet name.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
        subnet_name: Name of the subnet
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        A string containing the UUID of the Subnet
    """

    subnet_uuid, subnet = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="subnet",entity_api_root="subnets",entity_name=subnet_name,entity_uuid=None,
                              secure=secure,print_f=print_f)
    return subnet["metadata"]["uuid"]


def prism_create_overlay_subnet_managed(api_server,username,passwd,subnet_name,
                                        subnet_ip,prefix_length,default_gateway_ip,dns_list_csv,ip_pool_start,ip_pool_end,vpc_uuid,
                                        secure=False):

    """createa an overlay subnet.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
        subnet_name: Name of the subnet to be created
        subnet_ip: ip of the ip to be created. example: "192.168.35.0"
        prefix_length: mask length (string) of the subnet to be created. example: "24"
        default_gateway_ip: ip address of the default gateway to be associated with the created subnet
        dns_list_csv: list of DNS resolvers ip addresses to be associated with this subnet ("ip1,ip2,...")
        ip_pool_start: first ip address of the ip pool
        ip_pool_end: last ip address of the ip pool
        vpc_uuid: uuid of the vpc where the subnet will be created
        secure: boolean to verify or not the api server's certificate (True/False) 
        
    Returns:
        the uuid of the created subnet and the uuid of the creation task
    """

    url = 'https://{}:9440/api/nutanix/v3/subnets'.format(api_server)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    payload = {
        "metadata": {
            "kind": "subnet"
        },
        "spec": {
            "name": subnet_name,
            "resources": {
                "ip_config": {
                    "subnet_ip": subnet_ip,
                    "prefix_length": int(prefix_length),
                    "default_gateway_ip": default_gateway_ip,
                    "pool_list": [
                        {
                            "range": "{} {}".format(ip_pool_start,ip_pool_end)
                        }
                    ],
                    "dhcp_options": {
                        "domain_search_list": dns_list_csv.split(','),
                    }
                },
                "subnet_type": "OVERLAY",
                "vpc_reference": {
                    "kind": "vpc",
                    "uuid": vpc_uuid
                }
            }
        },
        "api_version": "3.1.0"
    }

    print(json.dumps(payload))

    resp = process_request(url,'POST',user=username,password=passwd,headers=headers,payload=payload,secure=secure)

    if resp.status_code == 202:
        result = json.loads(resp.content)
        task_uuid = result['status']['execution_context']['task_uuid']
        subnet_uuid = result['metadata']['uuid']
        print('INFO - Subnet {}/{} created with status code: {}'.format(subnet_ip,prefix_length,resp.status_code))
        print('INFO - Subnet uuid: {}'.format(subnet_uuid))
    else:
        print('ERROR - Subnet {}/{} creation failed, status code: {}, msg: {}'.format(subnet_ip,prefix_length,resp.status_code, resp.content))
        exit(1)

    return subnet_uuid, task_uuid


def prism_delete_subnet(api_server,username,passwd,subnet_name=None,subnet_uuid=None,secure=False,print_f=True):

    """Deletes a subnet given its name or uuid.
       If a subnet_uuid is specified, it will skip retrieving all subnets (faster) to find the designated subnet name.


    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
        subnet_name: Name of the subnet (optional).
        subnet_uuid: uuid of the subnet (optional).
        secure: boolean to verify or not the api server's certificate (True/False) 
        print_f: True/False. if False the function does not print traces to the stdout, as long as there are no errors
        
    Returns:
        subnet deletion task uuid
    """

    task_uuid = prism_delete_entity(api_server=api_server,username=username,passwd=passwd,
                              entity_type="subnet",entity_api_root="subnets",entity_name=subnet_name,entity_uuid=subnet_uuid,
                              secure=secure,print_f=print_f)
    return task_uuid



########################################################################
############       w2_8_1_get_up_cluster_subnet.py                           ############
########################################################################

############# Calm imports #################################################################
# CALM_USES pc_entities.py, pc_subnets.py, pc_vpcs.py
############################################################################################

def prism_get_up_cluster_subnet(api_server,username,passwd,headers,subnet_list,secure=False):

    """gets the subnet from the up and running cluster.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        passwd: The Prism user name password.
        subnet_list: External Subnet List.
        secure: boolean to verify or not the api server's certificate (True/False) 
        
    Returns:
        subnet_uuid: returns uuid of the subnet from up and running cluster.
    """
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    
    subnet_uuid_list = {}
    for subnet in subnet_list:
        subnet_uuid, subnet_obj= prism_get_subnets_v4(api_server=api_server,username=username,passwd=passwd,
                                subnet_name=subnet,secure=secure)
        cluster_uuid = subnet_obj['clusterReference']
        cluster_uuid, cluster_obj = prism_get_entity(api_server=api_server,username=username,passwd=passwd,
                                entity_type="cluster",entity_api_root="clusters",entity_uuid=cluster_uuid,secure=secure,print_f=True)
        cluster_ip = cluster_obj['spec']['resources']['network']['external_ip']
        url = 'https://{}:9440/PrismGateway/services/rest/v2.0/'.format(cluster_ip)
        try:
            response = requests.get(url,headers=headers,auth=("dummy", "dummy") ,verify=secure,timeout=10)
            print(response.status_code, "for",url)
            if response.status_code in [ 401, 200 ]:
                subnet_uuid_list[subnet] = subnet_uuid
        except:
            continue

    return subnet_uuid_list


############# Calm imports #################################################################
# CALM_USES w2_8_1_get_up_cluster_subnet.py
############################################################################################

headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
}

# PC_IP = "@@{PC_IP}@@"
# PC_PROVIDER_USERNAME = "@@{prism_central.username}@@"
# PC_PROVIDER_PASSWD = "@@{prism_central.secret}@@"
# SUBNET_LIST= @@{SUBNET_VPC_MAP}@@.keys()

PC_IP= '10.136.136.10'
PC_PROVIDER_USERNAME="an"
PC_PROVIDER_PASSWD="Nutanix.123"
SUBNET_LIST={"ext-test1": ["3C VPC","CA VPC"],"ext-test2": ["CCity VPC","HDC-DC VPC","SDC-DC VPC"]}

subnet_uuid = prism_get_up_cluster_subnet(PC_IP,PC_PROVIDER_USERNAME,PC_PROVIDER_PASSWD,headers,SUBNET_LIST)

print("SUBNET_UUID={}".format(subnet_uuid))
