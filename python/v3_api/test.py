import requests
import base64
def send_mail(api_server):
    url = f"https://10.136.136.10:9440/api/nutanix/v3/action_rules/trigger"

    token = base64.b64encode("an@blrgso.lab:Nutanix.123".encode("utf-8")).decode("utf-8")
    # auth = f"Basic {token}"
    auth = ("an@blrgso.lab", "Nutanix.123");
    # headers={
    # 'Content-Type': 'application/json',
    # 'Accept': 'application/json',
    # 'Authorization': 'Basic YW46TnV0YW5peC4xMjM='
    # }
    headers={
    'Content-Type': 'application/json',
    'Accept': 'application/json'
    }
    payload = {
    "trigger_type": "incoming_webhook_trigger",
    "trigger_instance_list": [{
        "webhook_id": "acb87c02-249a-43de-9923-0f237614c5dd",
        "string1" : "amit.yadav@nutanix.com",
        "string2" : "VM subnet update report",
        "string3" : "Hi, PFA VM subnet update report"
    }]
    }
    resp = requests.post(url, headers=headers, json=payload, auth=auth, verify=False)
    print("*"*200)
    print(resp.status_code)
    print(resp.content)


send_mail("10.136.136.10")