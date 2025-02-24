# user this script to get the list of overprovisioned vms
# author : amit.yadav@nutanix.com  
# version : 21/02/2025

import requests
import urllib3
import json
import time
from dataclasses import dataclass
from base64 import b64encode

def disable_warning(func):
    def wrapper(*args, **kwargs):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return func(*args, **kwargs)
    return wrapper
    
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

    def send_request(self):

        response = RequestResponse()
        url = self.param.url
        username = self.param.username
        password = self.param.password
        encoded_credentials = b64encode(bytes(f"{username}:{password}", encoding="ascii")).decode("ascii")
        auth_header = f"Basic {encoded_credentials}"

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"{auth_header}",
            "cache-control": "no-cache",
        }

    