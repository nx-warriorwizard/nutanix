import requests
import json
import uuid
import base64
import urllib3
from time import sleep

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
url = 'https://{}:9440/api/networking/v4.0/config/route-tables/{}'.format("10.136.136.10", "cf33353d-c921-45f3-8933-a08504c43fe0")


PC_IP = "@@{PC_IP}@@"
PC_PROVIDER_USERNAME = "@@{prism_central.username}@@"
PC_PROVIDER_PASSWD = "@@{prism_central.secret}@@"
print(PC_PROVIDER_USERNAME)
SUBNET_VPC_MAP = @@{SUBNET_VPC_MAP}@@   ### {      "ext-test2": ["3C VPC","CA VPC"],     "ext-test1": ["CCity VPC","HDC-DC VPC","SDC-DC VPC"]   }
SUBNET_UUIDs = @@{SUBNET_UUID}@@  #   [{'ext-test2': '1732650a-090f-46f3-b502-a76c0ccff6e9'}, {'ext-test1': 'e1a7aad9-ef43-4ee5-b2f8-52c4ac7481fa'}]
#



SUBNET_VPC_MAP = {"ext-test2": ["CA VPC", "3C VPC"], "ext-test1": ["CCity VPC","HDC-DC VPC","SDC-DC VPC"] }
SUBNET_UUIDs = {'ext-test1': 'e1a7aad9-ef43-4ee5-b2f8-52c4ac7481fa','ext-test2': '1732650a-090f-46f3-b502-a76c0ccff6e9'}

#encoding the cred
credentials = f"{PC_PROVIDER_USERNAME}:{PC_PROVIDER_PASSWD}".encode("utf-8")
encoded_credentials = base64.b64encode(credentials).decode("utf-8")

headers = {
        'Content-Type': 'application/json', 
        'Accept': 'application/json', 
        'Authorization': f'Basic {encoded_credentials}'
        }

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
                resp2 = requests.get(url, headers=headers, verify=secure)

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

def get_route(api_server, headers, route_extId, route_table_etag, secure):
    url = f"https://{api_server}:9440/api/networking/v4.0/config/route-tables/{route_extId}/routes"
    resp = requests.get(url, headers=headers, verify=secure)
    if not(resp.ok):
        print("ROUTES  RETRIVE FAILED : {resp.status_code} : {resp.content}")
        exit()
    result = json.loads(resp.content)
    # print("=*"*200)
    # print(route_extId)
    # print(json.dumps(result))
    # print("="*200)
    # exit()
    for data in result["data"]:
        if data["routeTableReference"] == route_extId:
            r_extId = data["extId"]  # Extract the specific route ID
            url = f"https://{api_server}:9440/api/networking/v4.0/config/route-tables/{route_extId}/routes/{r_extId}"
            headers['NTNX-Request-Id'] = str(uuid.uuid4())
            headers['IF-Match'] = route_table_etag
            resp2 = requests.get(url, headers=headers, verify=secure)
            if resp2.ok:
                header = dict(resp2.headers)
                r_etag = header.get("Etag", None)
                # headers['IF-Match'] = header.get("Etag", None)
                resp2 = requests.delete(url, headers=headers, verify=secure)
                if not(resp2.ok):
                    print(f"ROUTE DELETE FAILED : {resp2.status_code} : {resp2.content}")
                    exit()
            result_route = json.loads(resp.content)
            # print("="*200)
            # print(f"ROUTE RETRIEVE SUCCESS : {resp2.status_code}")
            # print(route_extId)
            # print(json.dumps(result))
            # print("="*200)
            return data, r_etag, r_extId
            
def update_route(api_server, headers, payload, route_extId, route_etag, vpc_reference, route_table_reference, subnet_uuid, subnet_name, secure):
    url = f"https://{api_server}:9440/api/networking/v4.0/config/route-tables/{route_table_reference}/routes"
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
    resp = requests.post(url, headers=headers, json=payload, verify=secure)
    if not(resp.ok):
        print(f"ROUTE DELETE FAILED : {resp.status_code} : {resp.content}")
        exit()
    print("Route create successfully!!!")

            



def get_vpc_route_table(api_server, headers, vpc_extId, secure):
    url = f"https://{api_server}:9440/api/networking/v4.0/config/route-tables"
    resp = requests.get(url, headers=headers, verify=secure)
    if not( resp.ok ):
        print(f"GET VPC ROUTE LIST : {resp.status_code} : {resp.content}")
        exit()
    result = json.loads(resp.content)
    # print("="*200)
    # print(json.dumps(result))
    # print("="*200)
    for data in result["data"]:
        if data["vpcReference"] == vpc_extId:
            route_extId = data["extId"]
            url = f"https://{api_server}:9440/api/networking/v4.0/config/route-tables/{route_extId}"
            resp2 = requests.get(url, headers=headers, verify=secure)
            # resp2_res = json.loads(resp2.content)
            # print("="*200)
            # print(json.dumps(resp2_res))
            # print("="*200)
            if not (resp2.ok):
                print("GET VPC ROUTE : {resp2.status_code} : {resp2.content}")
            header = dict(resp2.headers)
            route_table_etag = header.get("Etag", None)
            print("Route table Etag is : ", route_table_etag)
            return route_extId, data, route_table_etag
        

def prism_flow_update_vpc(api_server, headers, vpc_name, subnet_uuid, subnet_name, secure=False):
    vpc_extId, vpc_data, vpc_etag = get_vpc(api_server, headers, vpc_name, secure=secure)
    route_extId, route_data, route_table_etag = get_vpc_route_table(api_server, headers, vpc_extId, secure=secure)

    # print("*"*300)
    # print(vpc_extId)
    # print(route_extId)
    # print("*"*300)
   
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
        payload, r_etag, r_extId = get_route(api_server, headers, route_extId, route_table_etag, secure)


        print('Updating VPC...')
        headers['NTNX-Request-Id'] = str(uuid.uuid4())
        headers['IF-Match'] = vpc_etag
        url = f'https://{api_server}:9440/api/networking/v4.0/config/vpcs/{vpc_extId}'
        resp = requests.put(url, headers=headers, json=vpc_data, verify=secure )
        print("*"*200)
        print(resp.status_code)
        print("*"*200)
        print('creating route entry...')
        update_route(api_server, headers, payload, r_extId, r_etag, vpc_extId, route_extId, subnet_uuid, subnet_name, secure=secure)
        sleep(5)

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