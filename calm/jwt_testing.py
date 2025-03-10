project_name = '@@{calm_project_name}@@'
jwt = '@@{calm_jwt}@@'

headers = {'Content-Type': 'application/json',  'Accept':'application/json', 'Authorization': 'Bearer {}'.format(jwt)}

baseUrl = "https://localhost:9440/api/nutanix/v3/"
url = baseUrl + "projects/list"
payload = {"kind":"project", "filter":"name=={}".format(project_name)}
method = "POST"
resp = process_request(url=url,method=method,user=None,password=None,payload=payload,headers=headers)
if resp.ok:
    project = json.loads(resp.content)["entities"][0]
else:
    print("Request failed!")
    print("status code: {}".format(resp.status_code))
    print("reason: {}".format(resp.reason))
    print("text: {}".format(resp.text))