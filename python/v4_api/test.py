'''
Nutanix v4 api testing
version: 14-02-2025
author: amit.yadav@nutanix.com

Nutanix v4 requires Prism Central 2024.3 or later and AOS 7.0 or later
'''

import getpass
import argparse
import sys
import urllib3
import json

import ntnx_vmm_py_client
from ntnx_vmm_py_client import Configuration as VMMConfiguration
from ntnx_vmm_py_client import ApiClient as VMMClient
from ntnx_vmm_py_client import VmApi 
from ntnx_vmm_py_client.rest import ApiException
# from ntnx_vmm_py_client import vm_api_instance
# from ntnx_vmm_py_client import ApiException

# import ntnx_iam_py_client
# from ntnx_iam_py_client import Configuration as IAMConfiguration
# from ntnx_iam_py_client import ApiClient as IAMClient
# from ntnx_iam_py_client.rest import ApiException as IAMException
# from ntnx_iam_py_client import UsersApi, AuthorizationPoliciesApi
# from ntnx_iam_py_client import User, UserType, CreationType, UserStatusType
# from ntnx_iam_py_client import Key, KeyKind
# from ntnx_iam_py_client import AuthorizationPolicy, AuthorizationPolicyType
# from ntnx_iam_py_client import EntityFilter, IdentityFilter

config = VMMConfiguration()
config.host = '10.48.70.39' # IPv4/IPv6 address or FQDN of the cluster
config.port = 9440 # Port to which to connect to
config.username = 'admin' # UserName to connect to the cluster
config.password = 'nx2Tech123!' # Password to connect to the cluster
config.verify_ssl = False
api_client = VMMClient(configuration=config)
api_client.add_default_header(header_name='Accept-Encoding', header_value='gzip, deflate, br')
vm_api_instance = VmApi(api_client=api_client)

try:
    api_response = vm_api_instance.list_vms(
    # _page=page, # if page parameter is present
    _limit=10, # if limit parameter is present
    # _filter=_filter, # if filter parameter is present
    # _orderby=_orderby, # if orderby parameter is present
    # _select=select, # if select parameter is present
    # _expand=expand) # if expand parameter is present
    )
    print(api_response)
    # output= json.dumps(api_response)
    # print(json.loads(output))
except ApiException as e:
    print('exception occured')