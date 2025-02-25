# user this script to get the list of overprovisioned vms
# author : amit.yadav@nutanix.com  
# version : 21/02/2025

import requests
import urllib3
import json
import time
from dataclasses import dataclass
from base64 import b64encode


@dataclass
class RequestParameters:
    '''Necessary code structure'''
    url: str
    username: str
    password: str
    payload: str

class RequestResponse:
    """Necessary code output"""
    def __init__(self):
        self.code=0
        self.message=""
        self.json=""
        self.details=""

class RESTClient:
    '''API calling module'''
    def __init__(self, parameter: RequestParameters):
        self.param = parameter

    def disable_warning(func):
        def wrapper(*args, **kwargs):
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            return func(*args, **kwargs)
        return wrapper

    @disable_warning
    def send_request(self):

        response = RequestResponse()

        url = self.param.url
        username = self.param.username
        password = self.param.password
        payload = self.param.payload
        encoded_credentials = b64encode(bytes(f"{username}:{password}", encoding="ascii")).decode("ascii")
        auth_header = f"Basic {encoded_credentials}"

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"{auth_header}",
            "cache-control": "no-cache",
        }

        try:
            resp = requests.post(url=self.param.url, headers=headers, verify=False, json=payload, timeout=10)

            response.code = resp.status_code
            response.json = resp.json()
            response.message = " request executed successfully."
            response.details = 'N/A'
        except requests.exceptions.ConnectTimeout:
            # timeout while connecting to the specified IP address or FQDN
            response.code = -99
            response.message = f"Connection has timed out."
            response.details = "Exception: requests.exceptions.ConnectTimeout"
        except urllib3.exceptions.ConnectTimeoutError:
            # timeout while connecting to the specified IP address or FQDN
            response.code = -99
            response.message = f"Connection has timed out."
            response.details = "urllib3.exceptions.ConnectTimeoutError"
        except requests.exceptions.MissingSchema:
            # potentially bad URL
            response.code = -99
            response.message = "Missing URL schema/bad URL."
            response.details = "N/A"
        except Exception as _e:
            """
            unhandled exception
            ... don't do this in production
            """
            response.code = -99
            response.message = "An unhandled exception has occurred."
            response.details = _e
            response.json = resp.json

        return response
    
#-----------------------------------------------------------------------------------------------------------------------------------------

url = f"https://10.136.136.10:9440/api/nutanix/v3/groups"
username = "an"
password = input(" enter your password...  \b ")

payload = {
  "entity_type": "mh_vm",
  "query_name": "",
  "grouping_attribute": " ",
  "group_count": 2000,
  "group_offset": 0,
  "group_attributes": [
    
  ],
  "group_member_sort_attribute": "vm_name",
  "group_member_sort_order": "ASCENDING",
  "group_member_attributes": [
    {
      "attribute": "vm_name"
    }
  ],
  "filter_criteria": "capacity%2Evm_overprovisioned_status==moderate"
}


#-----------------------------------------------------------------------------------------------------------------------------------------
parameters = RequestParameters(
    url = url,
    username= username,
    password= password,
    payload= payload
)

rest_client = RESTClient(parameter=parameters)
resp = rest_client.send_request()

if resp.code == 200:
    print(json.dumps((resp.json), indent=4))
else:
    print(f"error happened !!!{resp.json}")

        