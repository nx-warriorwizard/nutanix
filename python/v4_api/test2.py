
import ntnx_aiops_py_client
import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    # Configure the client
    config = ntnx_aiops_py_client.Configuration()
    # IPv4/IPv6 address or FQDN of the cluster
    config.host = "10.136.136.10"
    # Port to which to connect to
    config.port = 9440
    # Max retry attempts while reconnecting on a loss of connection
    config.max_retry_attempts = 3
    # Backoff factor to use during retry attempts
    config.backoff_factor = 3
    # UserName to connect to the cluster
    config.username = "admin"
    # Password to connect to the cluster
    config.password = "Nutanix@123"
    config.verify_ssl = False
    # Please add authorization information here if needed.
    client = ntnx_aiops_py_client.ApiClient(configuration=config)
    stats_api = ntnx_aiops_py_client.StatsApi(api_client=client)
    
    source_ext_id = "db293e8a-5770-c3c7-4213-85dbbc1d3679"
    ext_id = "686c821a-8091-4aef-8224-65b48019cd34"
    # Datetime needs to be in RFC3339 format
    start_time = datetime.datetime.now()
    # Datetime needs to be in RFC3339 format
    end_time = datetime.datetime.now()
    
    page = 0
    
    limit = 50
    
    sampling_interval = 1
    
    stat_type = "AVG"


    try:
        api_response = stats_api.get_entity_metrics_v4(sourceExtId=source_ext_id, extId=ext_id, _startTime=start_time, _endTime=end_time, _page=page, _limit=limit, _samplingInterval=sampling_interval, _statType=stat_type)
        print(api_response)
    except ntnx_aiops_py_client.rest.ApiException as e:
        print(e)

