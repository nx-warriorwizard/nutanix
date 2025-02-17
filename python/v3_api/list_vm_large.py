
'''
v3 compatible code for creating a VM in AHV
author : amit yadav
version : 13-02-2025

list_vm_large.py - list all VMs in a large environment
reference taken from : https://github.com/nx-warriorwizard/nutanix/tree/main/python/v4_api/python/list_vm_v3_large

**STILL IN PROGRESS**
'''

from dataclasses import dataclass
import requests 
import urllib3
import argparse
import json
from base64 import b64encode
import yaml

@dataclass
class RequestParameters:
    """
    dataclass to hold the parameters of our API request
    this is not strictly required but can make
    our requests cleaner
    """
    url: str
    username: str
    password: str
    payload: str

class RequestResponse:
    """
    class to hold the response from our
    requests
    again, not strictly necessary but can
    make things cleaner later
    """
    def __init__(self):
        self.code = 0
        self.message = ""
        self.json = ""
        self.details = ""

class RESTClient:
    """
    the RESTClient class carries out the actual API request
    by 'packaging' these functions into a dedicated class,
    we can re-use instances of this class, resulting in removal
    of unnecessary code repetition and resources
    """

    def __init__(self, parameters: RequestParameters):
        """
        class constructor
        because this is a simple class, we only have a single
        instance variable, 'params', that holds the parameters
        relevant to this request
        """
        self.params = parameters    

    def send_request(self):
        """
        this is the main method that carries out the request
        basic exception handling is managed here, as well as
        returning the response (success or fail), as an instance
        of our RequestResponse dataclass
        """
        response = RequestResponse()
        """
        setup the HTTP Basic Authorization header based on the
        supplied username and password
        done this way so that passwords are not supplied on the command line
        """
        username = self.params.username
        password = self.params.password
        encoded_credentials = b64encode(
            bytes(f"{username}:{password}",encoding="ascii")
        ).decode("ascii")
        auth_header = f"Basic {encoded_credentials}"
        """
        """
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"{auth_header}",
            "cache-control": "no-cache",
        }
        try:
            api_request = requests.post(
                self.params.url,
                data=self.params.payload,
                headers=headers,
                verify=False,
                timeout=10,
            )
            response.code = api_request.status_code
            response.message = "Request submitted successfully"
            response.json = api_request.json()
            response.details = "N/A"
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

        return response