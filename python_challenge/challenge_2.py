#!/usr/bin/env python3
# version 20251021
from datetime import datetime
import json
import time
import sys
from pathlib import Path
import requests
from requests.auth import HTTPBasicAuth
from crayons import *
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Locate the directory containing this file and the repository root.
# Temporarily add these directories to the system path so that we can import
# local files.
here = Path(__file__).parent.absolute()
repository_root = (here / ".." ).resolve()
sys.path.insert(0, str(repository_root))

import environment as env

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Constants
webex_token = env.WEBEX_TEAMS_ACCESS_TOKEN
step=1

print(yellow('\n##################################################',bold=True))
print(yellow('#  WELCOME TO THE SECURITY AUTOMATION CHALLENGE  #',bold=True))
print(yellow('#                                                #',bold=True))    
print(yellow('#       YOU HAVE TO COMPLETE THE WORKFLOW        #',bold=True))    
print(yellow('#                                                #',bold=True))       
print(yellow('##################################################',bold=True))
a=input('\nPress Enter to Continue and understand the context of this investigation :')
#TODO MISSION01: Assign the correct computer name to the cse_computer_name variable.
cse_computer_name = "Demo_AMP_Threat_Audit"
# Functions

def get_cse_computers(
    host=env.SECURE_ENDPOINT.get("host"),
    client_id=env.SECURE_ENDPOINT_CLIENT_ID,
    api_key=env.SECURE_ENDPOINT_API_KEY,
):
    """Get a list of computers from Cisco Secure Endpoint."""
    global step
    print(white(f"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nACTION ==> Step {str(step)} : Getting All computers and their details from Secure Endpoint",bold=True))
    step+=1
    # MISSION02: Construct the URL   
    url = f"https://{client_id}:{api_key}@{host}/v1/computers"
    if "MISSION02" in url:    
        print(yellow("MISSION02 : Construct the Correct URL API Endpoint",bold=True))    
        print(yellow("MISSION02 : from the Cisco Secure endpoint API documentation located at : https://developer.cisco.com/docs/secure-endpoint/overview/#overview",bold=True))
        print(yellow("MISSION02 : find the URL enpdoint that will give you the list of computers",bold=True))    
        print(yellow("MISSION02 : replace MISSION02 by the correct keyword in the URL above",bold=True))  
        env.print_missing_mission_warn(env.get_line())
    response = requests.get(url, verify=False)
    # Consider any status other than 2xx an error
    response.raise_for_status()

    computer_list = response.json()["data"]
    
    return computer_list


def get_cse_events(query_params="",
    host=env.SECURE_ENDPOINT.get("host"),
    client_id=env.SECURE_ENDPOINT_CLIENT_ID,
    api_key=env.SECURE_ENDPOINT_API_KEY,
):
    global step    
    print(white(f"\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nACTION ==> Step {str(step)} : Get a list of recent events from Cisco Secure Endpoint",bold=True))
    step+=1
    # MISSION04: Construct the URL
    url = f"https://{client_id}:{api_key}@{host}/v1/events"    
    if "MISSION04" in url:    
        print(yellow("MISSION04 : Construct the Correct URL API Endpoint",bold=True))    
        print(yellow("MISSION04 : from the Cisco Secure endpoint API documentation located at : https://developer.cisco.com/docs/secure-endpoint/overview/#overview",bold=True))
        print(yellow("MISSION04 : find the URL enpdoint that will give you the list of events on the investigated computer",bold=True))    
        print(yellow("MISSION04 : replace MISSION04 by the correct keyword in the URL above",bold=True))  
        env.print_missing_mission_warn(env.get_line())
    response = requests.get(url, params=query_params, verify=False)
    # Consider any status other than 2xx an error
    response.raise_for_status()

    events_list = response.json()["data"]
    
    return events_list

def cse_event_type_id(event_name_list,
    host=env.SECURE_ENDPOINT.get("host"),
    client_id=env.SECURE_ENDPOINT_CLIENT_ID,
    api_key=env.SECURE_ENDPOINT_API_KEY
):
    url = f"https://{client_id}:{api_key}@{host}/v1/event_types"
    response = requests.get(url, verify=False)
    response.raise_for_status()  
    data=response.json()['data']   
    id_list=[]
    for item in data:
        if item['name']=="Threat Detected" or item['name']=="Executed Malware":
            id_list.append(item['id'])
    return (id_list)
    
# method should be 'put', 'get' or 'delete'
def cse_isolation(method, computer_guid,
    host=env.SECURE_ENDPOINT.get("host"),
    client_id=env.SECURE_ENDPOINT_CLIENT_ID,
    api_key=env.SECURE_ENDPOINT_API_KEY,
):
    global step
    print(white(f"\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nRESPONSE ACTION ==> Step {str(step)} : Let's isolate the infected Endpoint in Secure Endpoint\n",bold=True))
    step+=1
    url = f"https://{client_id}:{api_key}@{host}/v1/computers/{computer_guid}/isolation"

    if method == 'get':
        response = requests.get(url, verify=False)
        response.raise_for_status()
    elif method == 'put':
        print(red("send put request for host isolation"))
        response = requests.put(url, verify=False)
        #json_response=json.loads(response)
        print(response.json())
        if response.status_code == 409:
            print(red("ATTENTION: The computer is already isolated."))
        else:
            response.raise_for_status()
    elif method == 'delete':
        response = requests.delete(url, verify=False)
        response.raise_for_status()
    else:
        print(red("ERROR: Unrecognized REST API Method. Please use 'get', 'put' or 'delete'."))
        sys.exit(1)    
    #isolation_status = response.json()["data"]   
    isolation_status={}
    print(isolation_status)
    return isolation_status


def malware_analytics_search_submissions(
    sha256,
    host=env.malware_analytics.get("host"),
    api_key=env.malware_analytics_API_KEY,
):
    """Search TreatGrid Submissions, by sha256.
    Args:
        sha256(str): Lookup this hash in malware_analytics Submissions.
        host(str): The malware_analytics host.
        api_key(str): Your malware_analytics API key.
    """
    global step
    print(white(f"\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nACTION ==> Step {str(step)} : Searching the Malware Analytics Submissions for sha256: {sha256}\n",bold=True))
    step+=1
    query_parameters = {
        "q": sha256,
        "api_key": api_key,
    }   
    response = requests.get(
        f"https://{host}/api/v2/search/submissions",
        params=query_parameters,
        verify=False
    )
    # MISSION06: Put proper function to consider any status other than 2xx an error     
    response_status=response.raise_for_status()
    if response_status==None:
        pass
    else:
        if 'MISSION06' in response_status:
            print(yellow("\nMISSION06 : let`s check here the result of the call. Did it work ?",bold=True))
            print(yellow("MISSION06 : replace MISSION06 by the correct function applyed to response",bold=True))   
            print(yellow("MISSION06 : have a look to other calls and search for things related to status",bold=True))        
            env.print_missing_mission_warn(env.get_line())  
    print(yellow(f"\n",bold=True))
    
    submission_info = response.json()["data"]["items"]

    if submission_info:
        print(cyan("\nRETURN ==> Ok We successfully retrieved data on the suspicious sha256 submission from Malware Analytics",bold=True))
    else:
        print(red("Unable to retrieve data on the sha256 submission",bold=True))
        sys.exit(1)

    return submission_info


def malware_analytics_get_domains(sample_id,
    host=env.malware_analytics.get("host"),
    api_key=env.malware_analytics_API_KEY,
):  
    if sample_id=="MISSION07":
        return("MISSION07")
    global step
    print(white(f"\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nACTION ==> Step {str(step)} : Let's get from Malware Analytics, domains that are associated with the Sample ID: {sample_id}",bold=True))
    step+=1
    url = f"https://{host}/api/v2/samples/feeds/domains"
    query_params = {
        "sample": sample_id,
        "after": "2019-01-01",
        "api_key": api_key,
    }    
    response = requests.get(
        url,
        params=query_params,
        verify=False
    )
    response.raise_for_status()
    
    domains_json = response.json()["data"]["items"]
    domains = []
    if domains_json:
        for item in domains_json:
            if item["domain"] not in domains:
                domains.append(item["domain"])
    else:
        print(red("Unable to retrieve domains on the sha256 submission. Extend timeframe and try again."))
        sys.exit(1)
    
    return domains


def get_umbrella_domain_status(domains,
    host=env.UMBRELLA.get("inv_url"),
    api_key=env.UMBRELLA_INVESTIGATE_KEY,
):
    global step
    
    print(cyan(f"\nRETURN ==> Ok Malware Analytics confirms that some domains are associated to the sha256\n",bold=True),white(f"\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nACTION ==> Step {str(step)} : Now let's query Umbrella Investigate in order to check all associated domains  to retreive their disposition",bold=True))     
    step+=1
    url = f"https://{host}/domains/categorization/{domains}?showLabels"  

    # MISSION09: Construct authentication headers for Umbrella Investigate     
    headers = { 'Authorization': 'Bearer ' + api_key}
    if headers== {'MISSION09':'MISSION09'}:
        print(yellow("\nMISSION09 : assign the correct value to the header variable ",bold=True))
        print(yellow("MISSION09 : replace MISSION09 by the correct value",bold=True))    
        env.print_missing_mission_warn(env.get_line())  

    print(yellow(f"\n",bold=True))    
    url0 = f"https://localhost:4000/v1/next"
    payload0="7"
    requests.post(url0, data=payload0, verify=False)
   
    response = requests.get(url, headers=headers,verify=False)
    response.raise_for_status()

    domains_status = response.json()
    
    return domains_status


def post_umbrella_events(blacklist_domains,
    host=env.UMBRELLA.get("en_url"),
    api_key=env.UMBRELLA_ENFORCEMENT_KEY,
):
    global step
    print(white(f"\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nRESPONSE ACTION ==> Step {str(step)} : Let's query the Umbrella Enforcement API for adding the domain found above to a custom domain blocking lists in Umbrella",bold=True))
    step+=1
    # MISSION11: Construct the API endpoint to post malware events to the Umbrella Enforcement API      
    url = f"https://{host}/1.0/events?customerKey={api_key}" 
    if 'MISSION11' in url:
        print(yellow("\nMISSION11 : build a correct url endpoint with api key value ",bold=True))
        print(yellow("MISSION11 : replace MISSION11 by the correct statement for passing the api key within the call above",bold=True))    
        env.print_missing_mission_warn(env.get_line())  

    print(yellow(f"\n",bold=True))
    headers={'Content-type': 'application/json', 'Accept': 'application/json'}

    # Time for AlertTime and EventTime when domains are added to Umbrella
    time = datetime.now().isoformat()
    data = []
    
    for domain in blacklist_domains:
        obj = {
            "alertTime": time + "Z",
            "deviceId": "ba6a59f4-e692-4724-ba36-c28132c761de",
            "deviceVersion": "13.7a",
            "dstDomain": domain,
            "dstUrl": "http://" + domain + "/",
            "eventTime": time + "Z",
            "protocolVersion": "1.0a",
            "providerName": "Security Platform"
        }
        data.append(obj)
    
    response = requests.post(url, data=json.dumps(data), headers=headers, verify=False)
    response.raise_for_status()

    id = response.json()["id"]
    #print(cyan("\nRETURN ==> OK Done, the Domain was succesfully added to the Umbrella Domain Blocking List",bold=True))     
    #id='4bf26c3d,fd2e,4def,b038-ee3778b3e6ba'
    return id, data
    
def umbrella_get_get_v2_api_token(host, client_id, client_secret):
    # documentation : https://developer.cisco.com/docs/cloud-security/umbrella-api-api-reference-auth-token-api-token-create-authorization-token/
    # copy the python code example and paste it here
    print(white("\n==> Ask a token to umbrella..."))
    url = f"https://{host}/auth/v2/token"
    payload = None
    headers = {"Content-Type": "application/x-www-form-urlencoded","Accept": "application/json"}
    response = requests.post(url, headers=headers, auth=(client_id, client_secret), data=payload, verify=False)
    response.raise_for_status()
    rep=json.loads(response.text.replace("'",'"'))
    #print(cyan(rep,bold=True))
    #print()
    #print(cyan(type(rep),bold=True))
    return rep["access_token"]
    
def umbrella_get_dns_activity(host,api_token,domain):
    print("OK let gets last DNS activity from Umbrella")
    print()
    headers = {'Authorization':'Bearer ' + api_token}
    ip_list=[]
    offset=0
    reporting_url=f'https://{host}/v2/activity/dns?from=-30days&to=now&limit=50&offset={offset}'
    print(reporting_url)
    response = requests.get(reporting_url, headers=headers,verify=False)
    resp=json.dumps(response.json())
    resp_text=json.dumps(response.json(),indent=4,sort_keys=True, separators=(',', ': '))
    data=response.json()['data'] # we extract only the data key/value from the response    
    print(yellow(data,bold=True))    
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True))
    print(yellow('#                   CHALLENGE                    #',bold=True))     
    print(yellow('#                                                #',bold=True))      
    print(yellow('#          Edit the script and fix it            #',bold=True))    
    print(yellow('#            to run the next steps               #',bold=True))       
    print(yellow('#                                                #',bold=True))      
    print(yellow('#        You have to parse the JSON result       #',bold=True))     
    print(yellow('#    above and put in a list the ip addresses    #',bold=True))    
    print(yellow('#    of the internal machines which connected    #',bold=True)) 
    print(yellow('#          to the malicious domain               #',bold=True))     
    print(yellow('#                                                #',bold=True)) 
    print(yellow('##################################################',bold=True))    
    print(red(f'Have a look to Line number : {str(env.get_line())} in the code ',bold=True)) 
    STOP_HERE=1
    if STOP_HERE:
        sys.exit() # this instruction stop the script .  remove it to move forward 
    else:
        # then we parse it here under
        for item in data:
            if item['domain'] == domain:
                ip_list.append(item['internalip'])
        #print('\nip_list : ',ip_list)
        return(ip_list)
    
def ctr_auth(
    host=env.THREATRESPONSE.get("host"),
    client_id=env.CTR_CLIENT_ID,
    api_key=env.CTR_API_KEY,
):
    print(white("\n==> Authenticating to Cisco XDR..."))
    url = f"https://{host}/iroh/oauth2/token"

    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json'}
    # MISSION12: Construct payload to pass in authentication request to Threat Response     
    payload = {'grant_type':'client_credentials'} 
    if 'MISSION12' in payload:
        print(yellow("\nMISSION12 : build a correct url endpoint with a correct payload value ",bold=True))
        print(yellow("\nMISSION12 : according to the sample there : https://developer.cisco.com/docs/cisco-xdr/oauth2-api-guide/#sample-code ",bold=True))
        print(yellow("\nMISSION12 : what is the value for the payload variable ?",bold=True))        
        print(yellow("MISSION12 : replace MISSION('MISSION12') by the correct statement within the payload assignment above",bold=True))    
        env.print_missing_mission_warn(env.get_line())  

    print(yellow(f"\n",bold=True))
    url0 = f"https://localhost:4000/v1/next"
    payload0="10"
    requests.post(url0, data=payload0, verify=False)

    response = requests.post(url, headers=headers, auth=(client_id, api_key), data=payload, verify=False)
    response.raise_for_status()

    access_token = response.json()["access_token"]

    return access_token


def ctr_inspect(access_token, arb_text,
    host=env.THREATRESPONSE.get("host"),
):
    print(white("\n==>XDR INSPECT API DEMO : Let's Take a block of arbitrary text which contains observables",bold=True))
    print(white("==> We use the XDR inspect API which extract observables from the text block, and return a list of formatted observables as a JSON object...\n",bold=True))    
    url = f"https://{host}/iroh/iroh-inspect/inspect"

    headers = {"Authorization":f"Bearer {access_token}", 'Content-Type':'application/json', 'Accept':'application/json'}

    inspect_payload = {'content':arb_text}

    inspect_payload = json.dumps(inspect_payload)
    #     response = requests.post(url, headers=headers, data=inspect_payload)
    # response = requests.post(url, headers=headers, data=inspect_payload, verifiy=False)
    response = requests.post(url, headers=headers, data=inspect_payload, verify=False)
    response.raise_for_status()

    observables = response.json()

    return observables
    
# MISSION14: Pass to the function properly formatted observables obtained in Step 7.
#env.print_missing_mission_warn(env.get_line()) # Delete this line when mission is complete.
def ctr_enrich_observe(access_token, ctr_observables,
    host=env.THREATRESPONSE.get("host"),
):
    
    url = f"https://{host}/iroh/iroh-enrich/observe/observables"

    headers = {"Authorization":f"Bearer {access_token}", 'Content-Type':'application/json', 'Accept':'application/json'}

    observe_payload = json.dumps(ctr_observables)
    #observe_payload = '[{"value": "b1380fd95bc5c0729738dcda2696aa0a7c6ee97a93d992931ce717a0df523967", "type": "sha256"}]'
    print()
    print(white('Here is the observable list found into the text : ')+cyan(observe_payload))
    global step
    print(white(f"\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nACTION ==> Step {str(step)} : Fetching Sightings about provided observables from Threat Response modules.",bold=True))
    step+=1
    response = requests.post(url, headers=headers, data=observe_payload, verify=False)
    response.raise_for_status()
    
    if "data" in response.json():
        data = response.json()["data"]
    else:
        print(red(response.json(),bold=True))
        sys.exit()
    print(cyan("RETURN ==> Sightings found in XDR are : \n",bold=True))         
    time.sleep(3)
    print(cyan(data,bold=True))
    
    url0 = f"https://localhost:4000/v1/next"
    payload0="14"
    requests.post(url0, data=payload0, verify=False)
    return data
    
def ctr_enrich_observe_original(access_token, observable,
    host=env.THREATRESPONSE.get("host"),
):
    if MISSION14=='MISSION14':
        return('MISSION14')
    print(white("\n==> Step 11 : Fetching Sightings about provided observables from Threat Response modules. Be patient, it may take time...",bold=True))
    
    url = f"https://{host}/iroh/iroh-enrich/observe/observables"

    headers = {"Authorization":f"Bearer {access_token}", 'Content-Type':'application/json', 'Accept':'application/json'}

    observe_payload = json.dumps(observable)
    #observe_payload = '[{"value": "b1380fd95bc5c0729738dcda2696aa0a7c6ee97a93d992931ce717a0df523967", "type": "sha256"}]'
    print()
    print(white('observable list : ')+red(observe_payload))
    print()
    response = requests.post(url, headers=headers, data=observe_payload)
    response.raise_for_status()
    
    if "data" in response.json():
        data = response.json()["data"]
    else:
        print(red(response.json(),bold=True))
        sys.exit()
    print(yellow(data,bold=True))
    
    print(red('WHOAW WE ARE AT MISSION 14 : And ctr_enrich_observe function was OK'))
    url0 = f"https://localhost:4000/v1/next"
    payload0="14"
    requests.post(url0, data=payload0, verify=False)
    return data

def ctr_enrich_print_scr_report(intel):
   
    print(white("\n==> Here is what XDR enrichment found. We got answsers from Threat Intell connected to XDR :\n"))

    for module in intel:
        #print(yellow(module,bold=True)) # Use for for troubleshooting :-)
        #print(white(f"\n==> Module: {module['module']} : {module['module-type']}"))
        print(cyan(f"\n==> Module: {module['module']} : {module['module_type_id']}",bold=True))
        if module["data"]:
            if module["module"] == "AMP for Endpoints":
                print(cyan(f"  ==> Count of Indicators: {module['data']['indicators']['count']} ",bold=True))
                for indicator in module["data"]["indicators"]["docs"]:
                    print(cyan(f"  ==> {indicator['description']} : {indicator['tags']}",bold=True))                
                print(cyan(f"  ==> Count of Sightings: {module['data']['sightings']['count']} ",bold=True))
                sighting = module['data']['sightings']['docs'][0]
                print(cyan(f"  ==> Most recent sighting: {sighting['description']}",bold=True))
                if sighting["targets"]:
                    print(cyan(f"  ==> Targets found: {len(sighting['targets'])}",bold=True))
                    target = sighting["targets"][0]
                    print(cyan(f"  ==> Most recent target: {target['type']} observed: {target['observed_time']['start_time']}",bold=True))
                    for observable in target["observables"]:
                        print(cyan(f"  ==> Target {observable['type']} : {observable['value']}",bold=True))
                    print(cyan(f"  ==> Target OS: {target['os']}",bold=True))
            elif module["module"] == "AMP File Reputation":
                for key in module["data"].keys():
                    print(cyan(f"  ==> Count of {key}: {module['data'][key]['count']}",bold=True))
            elif module["module"] == "VirusTotal":
                print(cyan("  ==> NO DATA FROM THIS INTEGRATION",bold=True))       
            elif module["module"] == "Stealthwatch Cloud":
                print(cyan("  ==> NO DATA FROM THIS INTEGRATION",bold=True))                    
            elif module["module"] == "AMP Global Intelligence":
                for key in module["data"].keys():
                    print(cyan(f"  ==> Count of {key}: {module['data'][key]['count']}",bold=True))
        else:
            print(cyan("  ==> NO DATA FROM THIS INTEGRATION",bold=True))
            
    url0 = f"https://localhost:4000/v1/next"
    payload0="16"
    requests.post(url0, data=payload0, verify=False)            

def ctr_response_actions(access_token,observables,
    host=env.THREATRESPONSE.get("host"),
):
    global step
    print(white(f"\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nACTION ==> Step {str(step)} : Fetching the list of available response actions and modules for given observables...",bold=True))
    step+=1
    url = f"https://{host}/iroh/iroh-response/respond/observables"
    payload = json.dumps(observables)
    headers = {"Authorization":f"Bearer {access_token}", 'Content-Type':'application/json', 'Accept':'application/json'}
    response = requests.post(url, headers=headers, data=payload, verify=False)    
    response.raise_for_status()
    #response_url = response.json()["data"][0]["url"]
    text_result=json.dumps(response.json(),sort_keys=True,indent=4, separators=(',', ': '))
    return text_result


def ctr_add_to_cse_scd(access_token, action_url,
    host=env.THREATRESPONSE.get("host"),
):
    global step
    print(white(f"\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nRESPONSE ACTION ==> Step {str(step)} : Adding a malicious sha256 to Secure Endpoint Simple Custom Detections list named Quarantine...",bold=True))
    step+=1
    url = f"https://{host}/iroh/iroh-response{action_url}"

    headers = {"Authorization":f"Bearer {access_token}", 'Content-Type':'application/json', 'Accept':'application/json'}

    #response = requests.post(url, headers=headers)
    response = requests.post(url, headers=headers, verify=False)
    response.raise_for_status()

    return response.status_code

def xdr_trigger_response_action(host,response_url):
    # this function is specific to this lab. For working sith the simulator. It is not the reality   
    argument_list=response_url.split('?')
    variables_list=argument_list[1].split('&')
    observable_type=variables_list[0].split('=')[1]
    observable_value=variables_list[1].split('=')[1]
    url = 'https://'+host+argument_list[0]
    print('base URL : ',url)  
    print('observable_type :',observable_type)    
    print('observable_value :',green(observable_value,bold=True))    
    payload = json.dumps({'value':observable_value,'type':observable_type })
    headers = { "Accept": "application/json" }
    response = requests.request('POST', url, headers=headers, data = payload, verify=False)
    #print('received response :',response.text.encode('utf8'))
    if '"status": "isolated"' in response.text:
        return({'status_code':200,'host_status':'isolated'})
    elif 'quarantine' in response.text:
        return({'status_code':200,'endpoint_status':'quarantined'})
    elif 'umbrella_ok' in response.text:
        result='adding retdemos.com to umbrella blocking list :\n'
        with open('./templates/13.json') as file:
            result=result+file.read()
        return result
    elif 'CSE_QUARANTINE_OK' in response.text:
        result='adding sha256 to CSE custom detection list :\n'
        with open('./templates/13.json') as file:
            result=result+file.read()
        return (200)
    else:
        return({'status_code':200,'status':'error'})
def MISSION05(text):
    return('MISSION05')
    
def MISSION06(text):
    return('MISSION06')
    
def MISSION(text):
    return(text)

        
# If this script is the "main" script, run...
if __name__ == "__main__":
    with open('./templates/isolation_status.txt','w') as file:
        file.write('0')
    print(cyan('\n##################################################',bold=True))
    print(cyan('#             HERE IS WHAT HAPPENED              #',bold=True))
    print(cyan('#  One of your users suspect a severe infection  #',bold=True))    
    print(cyan('#     He saw a Secure Endpoint Alert Popup       #',bold=True))    
    print(cyan('#     on his laptop ( Demo_AMP_Threat_Audit )    #',bold=True))     
    print(cyan('#  Just after having open a PDF file he received #',bold=True))       
    print(cyan('#                 in an email                    #',bold=True))     
    print(cyan('#                                                #',bold=True))     
    print(cyan('##################################################',bold=True))
    a=input('Press Enter to Continue')    
    print(cyan('\n##################################################',bold=True))
    print(cyan('#                                                #',bold=True))
    print(cyan('#        The Alert Popup was mentionning :       #',bold=True))    
    print(cyan('#                                                #',bold=True))    
    print(cyan('#     Threat Detected  and  Executed Malware     #',bold=True))       
    print(cyan('#                                                #',bold=True))     
    print(cyan('##################################################',bold=True))
    a=input('Press Enter to Continue')      
    '''
    Step 0. Set the computer name variable
    '''
    if cse_computer_name == "MISSION01":
        print()
        print(red(f"MISSION01 : cse_computer_name variable is a global variable, Assign to it the correct value",bold=True))
        sys.exit()
    else:
        print(green(f"\n",bold=True))
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True))
    print(yellow('#            We start with Secure Endpoint       #',bold=True))     
    print(yellow('#                                                #',bold=True))  
    print(yellow('##################################################',bold=True))    
    print(yellow('                                                  ',bold=True))    
    print(yellow('The alert is coming from Cisco Secure Endpoint ( CSE )\n',bold=True))     
    print(yellow(' - We need to gather CSE IDs of protected computers : we will need this later for host isolation',bold=True))      
    print(yellow('    Have a look to :\n     https://developer.cisco.com/docs/secure-endpoint/v1-api-reference-computer/\n',bold=True))   
    print(yellow(' - We need to : get IDs of events named : Threat Detected and Executed Malware because CSE don\'t use names in events but IDs',bold=True))      
    print(yellow('    Have a look to :\n     https://developer.cisco.com/docs/secure-endpoint/v1-api-reference-event-type/\n',bold=True))    
    print(yellow(' - Thanks to this we will be able to search for these events on the infected computer',bold=True))    
    print(yellow('   and the see the sha256 of the involved malware',bold=True))    
    print(yellow('    Have a look to :\n     https://developer.cisco.com/docs/secure-endpoint/v1-api-reference-event/\n',bold=True))     
    print(red(f'Line number : {str(env.get_line())}',bold=True))  
    a=input('\nPress Enter to continue :')
    cse_computer_list = get_cse_computers()

    print(cyan(f"RESULT ==> Secure Endpoint Computer List successfuly Fetched",bold=True))
    print(white(f"\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nACTION ==> Step {str(step)}. Let's get the GUID of the computer named {cse_computer_name}",bold=True))
    step+=1
    if not cse_computer_name:
        print()
        print(red(f"Wrong cse_computer_name in MISSION01. The variable is probably empty",bold=True))
        print()
        
    for computer in cse_computer_list:
        if computer["hostname"] == cse_computer_name:
            cse_computer_guid = computer["connector_guid"]

    print(cyan(f"\nRESULT ==> Secure Endpoint Computer name: {cse_computer_name}, GUID: {cse_computer_guid}",bold=True))
    print(white(f"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nACTION ==> Step {str(step)},Let's get, from Secure Endpoint, IDs of event named : 'Threat Detected','Executed Malware'",bold=True))
    step+=1
    event_name_list=['Threat Detected','Executed Malware']
    event_id_1=cse_event_type_id(event_name_list)
    print(cyan(f"RESULT ==> Found IDs are : {event_id_1}",bold=True))
    #print(white(f"\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nACTION ==> Let's get from Secure Endpoint the names of the threats with ID {event_id_1[0]}",bold=True))
    # MISSION03: Complete the Secure Endpoint query with correct event types to fetch event list   
    cse_query_params = f"connector_guid[]={cse_computer_guid}&&event_type[]=1107296272&event_type[]=1090519054&limit=100"
    if 'MISION03' in cse_query_params:
        print(yellow("MISSION03 : we want to display event related to event type : 1090519054 ( Threat Detected ) and 1107296272 ( Executed Malware )",bold=True))
        print(yellow("MISSION03 : write correct query parameter to send into the API call function get_cse_events()",bold=True))    
        env.print_missing_mission_warn(env.get_line())   
    print(yellow(f"\n",bold=True))        
    url0 = f"https://localhost:4000/v1/next"
    payload0="2"
    requests.post(url0, data=payload0, verify=False)
    
    cse_event_list = get_cse_events(query_params=cse_query_params)

    print(cyan(f"RESULT==> Secure Endpoint reports {len(cse_event_list)} events",bold=True))
    print(white(f"Let's investigate the most recent event this list"))
    cse_event = cse_event_list[0]
    
    print (green(f"\n   This First Event in the list is : {cse_event['event_type']} \
             \n   Detection: {cse_event['detection']} \
             \n   File name: {cse_event['file']['file_name']} \
             \n   File sha256: {cse_event['file']['identity']['sha256']}"))

    malicious_sha256 = cse_event["file"]["identity"]["sha256"]
    
    print(white(f"\nCOMPLETION 10 %"))
    print(yellow('\nCSE APIs allows us to isolate the endpoint...\n  Have a look to : https://developer.cisco.com/docs/secure-endpoint/endpoint-isolation/',bold=True))
    a=input(yellow('Do you want to isolate the Endpoint now ? Y/N :',bold=True))
    if a!='N' and a!='n':
        cse_computer_isolation = cse_isolation('put',cse_computer_guid)
        
        if cse_computer_isolation:
            print(green(f"Computer {cse_computer_name} (GUID {cse_computer_guid}) is {cse_computer_isolation['status']}"))

    print(white(f"\nCOMPLETION 20 %"))

    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True))
    print(yellow('#     We move forward with Malware Analytics     #',bold=True))     
    print(yellow('#                                                #',bold=True))  
    print(yellow('##################################################',bold=True))    
    print(yellow('                                                  ',bold=True))      
    print(yellow(' - We check in Malware Analytics for the sha256',bold=True))     
    print(yellow('   In order to have the confirmation that is is malicious',bold=True))  
    print(yellow('   and to check if know domains are attached to this sha256',bold=True))          
    print(red(f'Line number : {str(env.get_line())}',bold=True))  
    a=input('\nPress Enter to continue:')
    
    # MISSION05: Use the right function to find all samples, associated with malicious sha256     
    submission_info = malware_analytics_search_submissions(malicious_sha256)
    if 'MISSION05' in submission_info:
        print(yellow("\nMISSION05 : Call the correct python function in this script",bold=True))
        print(yellow("MISSION05 : replace MISSION05 by the correct function name in the call above",bold=True))    
        env.print_missing_mission_warn(env.get_line())  
   
    # HINT : compare the following print statement here under with similar print statements in this script
    print(yellow(f"\n",bold=True))            
    url0 = f"https://localhost:4000/v1/next"
    payload0="5"
    requests.post(url0, data=payload0, verify=False)
    malware_analytics_sample_id = submission_info[0]['item']['sample']

    print(green(f"Successfully retrieved Malware Analytics sample ID {malware_analytics_sample_id} for sha265 {malicious_sha256}"))


    print(white(f"\nCOMPLETION 35 %"))
    # MISSION07: Pass the right variable to achieve fetch all domains for a specific sample in Malware Analytics    
    malware_analytics_sample_domains = malware_analytics_get_domains(malware_analytics_sample_id)
    if 'MISSION07' in malware_analytics_sample_domains:
        print(yellow("\nMISSION07 : Pass the correct variable to the function",bold=True))
        print(yellow("MISSION07 : the variable that contains the sample ID",bold=True))    
        print(yellow("MISSION07 : replace MISSION07 variable name by the correct variable name",bold=True))
        env.print_missing_mission_warn(env.get_line())  
    url0 = f"https://localhost:4000/v1/next"
    payload0="6"
    requests.post(url0, data=payload0, verify=False)
    
    print(cyan(f"\nRETURN ==> Successfully retrieved domains on the sha256 submission: ",bold=True),red(malware_analytics_sample_domains,bold=True))

    print(yellow(f"\n",bold=True))    
    print(yellow(f"\nStep 5 - COMPLETION 40 %",bold=True))
     
    
    # MISSION08: Use the right function and pass the correct variable into it to retreive the status of the first domain associated with Treat Grid sample.     
    # Hint: Remember that numbering starts with 0 in most coding languages.
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True))
    print(yellow('#                Now we go to umbrella           #',bold=True))     
    print(yellow('#                                                #',bold=True))  
    print(yellow('##################################################',bold=True))    
    print(yellow('                                                 ',bold=True))      
    print(yellow(' - We check that Umbrella knows this domain as malicious ',bold=True))     
    print(yellow('   And Next as a challenge lab, we query umbrella to figure out',bold=True))  
    print(yellow('   which machines tried to connect to this risky domain',bold=True))     
    print(yellow('   ',bold=True))     
    print(yellow('   Actually, not every internal machines are protected by CSE !. Example : guests',bold=True)) 
    print(red(f'Line number : {str(env.get_line())}',bold=True))  
    a=input('\nPress Enter to continue:')    
    umbrella_domains_status = MISSION('MISSION08')
    umbrella_domains_status = get_umbrella_domain_status(malware_analytics_sample_domains)
    if 'MISSION08' in umbrella_domains_status:
        print(yellow("\nMISSION08 : Call the correct python function ",bold=True))
        print(yellow("\nMISSION08 : This function returns a list of domain status and it uses sample domains as input variable ",bold=True))
        print(yellow("MISSION08 : replace MISSION keyword by the correct function name and replace MISSION 08 by the correct input variable in the call above",bold=True))    
        env.print_missing_mission_warn(env.get_line())      
    print(yellow(f"\n",bold=True))        
    url0 = f"https://localhost:4000/v1/next"
    payload0="8"
    requests.post(url0, data=payload0, verify=False)
   
    umbrella_malicious_domains = []
   
    for key in umbrella_domains_status.keys():
        domain_status = umbrella_domains_status[key]['status']
        if domain_status == 1:
            print(green(f"The domain {key} is found CLEAN in Umbrella, domain status = 1"))
            env.print_missing_mission_warn(env.get_line()) # Delete this line when mission is complete.
        elif domain_status == -1:
            print(red(f"RETURN ==> The domain {key} is found MALICIOUS in Umbrella,, domain status = -1",bold=True))
            umbrella_malicious_domains.append(key)
        elif domain_status == 0:
            print(green(f"The domain {key} is found UNDEFINED in Umbrella,, domain status = 0"))

    url0 = f"https://localhost:4000/v1/next"
    payload0="9"
    requests.post(url0, data=payload0, verify=False)
    
    print(yellow(f"\nStep 6 - COMPLETION 50 %",bold=True))
    
    umbrella_event_id, umbrella_blacklist_enforcement = post_umbrella_events(umbrella_malicious_domains)

    #print(green(f"Domains {umbrella_malicious_domains} were accepted in the blocking list, Umbrella event id: {umbrella_event_id}",bold=True))
    
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True))
    print(yellow('#         Use umbrella V2 APIs to retrieve       #',bold=True))
    print(yellow('#        ip addresses of internal machines       #',bold=True))      
    print(yellow('#    which connected to the malicious domains    #',bold=True))        
    print(yellow('#                                                #',bold=True))  
    print(yellow('##################################################',bold=True))  
    a=input('\nPress enter to continue :')
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True))
    print(yellow('#        We need an umbrella Token First         #',bold=True))     
    print(yellow('#                                                #',bold=True))  
    print(yellow('##################################################',bold=True))     
    print(yellow('\nHave a look to :\n\nhttps://developer.cisco.com/docs/cloud-security/umbrella-api-api-reference-auth-token-api-token-create-authorization-token/\n',bold=True))     
    print(red(f'Line number : {str(env.get_line())}',bold=True))      
    a=input('\nPress Enter to Continue :')    
    umbrella_host_for_token=env.UMBRELLA_HOST_FOR_TOKEN   
    umbrella_client_id=env.UMBRELLA_CLIENT_ID
    umbrella_client_secret=env.UMBRELLA_CLIENT_SECRET    
    umbrella_token=umbrella_get_get_v2_api_token(umbrella_host_for_token, umbrella_client_id, umbrella_client_secret)
    print(cyan(umbrella_token,bold=True))
    print(green('\nPERFECT !!\n\n',bold=True))    
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True))
    print(yellow('#      Now get last Umbrella DNS Activities      #',bold=True))     
    print(yellow('#                                                #',bold=True))  
    print(yellow('##################################################',bold=True))    
    print(yellow('\nHave a look to :\n\nhttps://developer.cisco.com/docs/cloud-security/umbrella-api-api-reference-reports-reporting-api-activity-get-activity-dns/\n',bold=True))   
    print(red(f'Line number : {str(env.get_line())}',bold=True))  
    a=input('\nPress Enter to Continue :')     
    umbrella_report_host=env.UMBRELLA_REPORT_HOST
    domain='retdemos.com'
    infected_machine_list=umbrella_get_dns_activity(umbrella_report_host,umbrella_token,domain)    
    print('\n infected_machine_list : ',cyan(infected_machine_list,bold=True))    
    print(white('\n This is the list of the IP addresses of the internal endpoints which connected to the malicious domain',bold=True))
    print(yellow(f"\nStep 7 - COMPLETION 70 % - VERY GOOD !",bold=True))
    a=input(green('\nPERFECT !  Press enter to continue :',bold=True))    
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True))
    print(yellow('#            Now let\'s use XDR APIs              #',bold=True))     
    print(yellow('#                                                #',bold=True))  
    print(yellow('##################################################',bold=True))    
    print(yellow('                                                 ',bold=True))   
    print(white(f"\n==> Step {str(step)}  : Let's change the Approach !!!\n",bold=True))
    a=input('\nPress Enter to Continue :')    
    step+=1
    print(yellow(f"==> - In steps prior we used Secure Endpoint to detected a Threat",bold=True))
    print(yellow(f"==> - Secure Endpoint Fired Up an alert and indicated us an infected Endpoint by a malicious sha256",bold=True))    
    print(yellow(f"==> - This sha256 had a malicious behavior detected as a Threat",bold=True))           
    print(yellow(f"==> - Then we moved forward to an investigation",bold=True))      
    print(yellow(f"==> - We asked to Malware Analytics if the sha256 discovered by Secure Endpoint was known and has known bad domains associated to it",bold=True))  
    print(yellow(f"==> - Then we queried Umbrella Investigate to confirm that the domains found were malicious",bold=True))   
    print(yellow(f"==> - Then we queried Umbrella DNS activity to identify internal host which connected to the malicious domains",bold=True))       
    print(yellow(f"==>",bold=True))    
    print(yellow(f"==> - At that Point We know who is infected",bold=True))     
    print(white(f"==>",bold=True))       
    print(yellow(f"==> Let's accelerate. we are going to use only XDR to manage next operations",bold=True))    
    print(yellow(f"==> XDR can be the Unique Interface for us for all security operations",bold=True))    
    print(yellow(f"==> XDR was able to manage every operations we did prior as CSE, MA and Umbrella are integrated to XDR",bold=True))    
    print(yellow(f"==> XDR act as an API broker",bold=True))    
    print(white(f"\n",bold=True))      
    print(white(f"==>Let's go for it !\n",bold=True))   
    a=input('\nPress Enter to Continue :')    
    print(white(f"\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nACTION ==> Step {str(step)} : The first operation is to ask XDR for an API token\n",bold=True))    
    step+=1
    
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True))
    print(yellow('#              We Need an XDR API Token          #',bold=True))     
    print(yellow('#                                                #',bold=True))  
    print(yellow('##################################################',bold=True))    
    print(yellow('                          #                       ',bold=True))   
    print(yellow('\nHave a look to :\n\nhttps://developer.cisco.com/docs/cisco-xdr/generate-access-and-refresh-tokens/\n',bold=True))        
    print(white(f"\n==> Step {str(step)}  : ask for a token to XDR\n",bold=True))  
    step+=1    
    ctr_access_token = ctr_auth()

    print(cyan("RETURN ==> Received XDR access token :\n\n",bold=True),cyan(ctr_access_token,bold=True))
    print(green("\n bingo ! we got a token above \n",bold=True))
    a=input('\nType Enter to Continue :')       
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True))
    print(yellow('#   Let\'s use the sha256 we found but let\'s      #',bold=True))  
    print(yellow('#   include it into a text file which can be     #',bold=True))      
    print(yellow('#   any logs                                     #',bold=True))  
    print(yellow('#   Our goal is to introduce XDR Inspect API     #',bold=True))  
    print(yellow('#    which extract for us every observables      #',bold=True))
    print(yellow('#        contained into text like logs           #',bold=True))    
    print(yellow('#                                                #',bold=True))    
    print(yellow('#      Just to show that we can start our        #',bold=True)) 
    print(yellow('#     investigation from there and not from      #',bold=True))   
    print(yellow('#               and not CSE alerts               #',bold=True))    
    print(yellow('#                                                #',bold=True))    
    print(yellow('##################################################',bold=True))    
    print(yellow('                                                  ',bold=True))   
    ctr_arb_text = "some text stuff here to showcase the XDR inspect API capability \nb1380fd95bc5c0729738dcda2696aa0a7c6ee97a93d992931ce717a0df523967. \nSome additional text here after that can be very long"
    print('Here is the text : '+ctr_arb_text)
    print(yellow('\nHave a look to :\n\nhttps://developer.cisco.com/docs/cisco-xdr/find-observables/\n',bold=True))      
    print(white(f"\n==> Step {str(step)}  : extract observable from text with XDR inspect API \n",bold=True))     
    a=input('\nPress Enter to Continue :')     
    step+=1    
    # MISSION13: Pass free form arbitrary text that contains sha256 obtained in Step 1.
    # Hint: f"suspicious hash is {variable}"
    if 'MISSION13' in submission_info:
        print(yellow("\nMISSION13 : Pass any arbitrary text that contains the sha256 value obtained in Step 1",bold=True))
        print(yellow("\nMISSION13 : Edit environnment.py and update Use ARBITRARY_TEXT replace {replace_me_by_sha256} by the sha256 you found",bold=True))
        print(yellow("MISSION13 : replace MISSION13 by the env.ARBITRARY_TEXT variable name",bold=True))    
        env.print_missing_mission_warn(env.get_line()) 
        sys.exit()

    print(yellow(f"\n",bold=True))
    url0 = f"https://localhost:4000/v1/next"
    payload0="11"
    requests.post(url0, data=payload0, verify=False)
    #print(white(f"\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nACTION ==> Output result of the enrichment process",bold=True))    
    ctr_observables = ctr_inspect(ctr_access_token, ctr_arb_text)

    print(cyan(f"RETURN ==> Received formated list of observables. Observables found in text :\n {ctr_observables}",bold=True))
    a=input('\nPress Enter to Continue :')
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True))
    print(yellow('#     Let\'s run the XDR Enrichment process       #',bold=True))  
    print(yellow('#    in order to investigate the sh256 from      #',bold=True))      
    print(yellow('#       XDR Threat Intell and XDR events         #',bold=True))  
    print(yellow('#                                                #',bold=True))  
    print(yellow('#    Then we can see in XDR if this sha256       #',bold=True))
    print(yellow('#   had been seen in other events than only      #',bold=True))    
    print(yellow('#                CSE events in XDR               #',bold=True))    
    print(yellow('#                                                #',bold=True))    
    print(yellow('##################################################',bold=True))    
    print(yellow('                                                ',bold=True))   
    print(yellow('\nHave a look to :\n\nhttps://developer.cisco.com/docs/cisco-xdr/enrich-observables/\n',bold=True))      
    a=input('\nPress Enter to Continue :')     
    # MISSION14: Pass to the function properly formatted observables obtained in Step 7.
    # Hint: Check the function and put correct variable there too.
    ctr_intel = ctr_enrich_observe(ctr_access_token, ctr_observables)       
    if 'MISSION14' in ctr_intel:
        print(yellow("\nMISSION14 : 1-You have to fix the bug in the ctr_enrich_observe() function. Pass to it the correct variable and Make this function work !!",bold=True))  
        env.print_missing_mission_warn(env.get_line())  

    print(yellow(f"\n",bold=True))
    # print(red(ctr_intel)) # for debugging 
    url0 = f"https://localhost:4000/v1/next"
    payload0="14b"
    requests.post(url0, data=payload0, verify=False)
    print(cyan(f"Ok we Received several Sightings ( XDR Events ) related to this observable from XDR"))      
    time.sleep(3)
    print(green(f"Now we are going to display the details found in XDR son the infected machine"))    
    time.sleep(3)    
    #report_time = datetime.now().isoformat() # NOTICE : Windows does not allow the use of : in filenames
    report_time = datetime.now().strftime('%Y-%m-%dT%H-%M-%S')  # For windows machines
    ctr_report_path = here / f"ctr_report_{report_time}.json"
    print(white(f"\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nACTION ==> Step {str(step)}. indicators and sightings had been found in XDR. Saving result into : \n{ctr_report_path}",bold=True))
    step+=1
    with open(ctr_report_path, "w") as file:
        json.dump(ctr_intel, file, indent=2)

    url0 = f"https://localhost:4000/v1/next"
    payload0="15"
    requests.post(url0, data=payload0, verify=False)
    print(white(f"\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nACTION ==> Step {str(step)}. Let's get the result of XDR Enrichment",bold=True))
    step+=1
    ctr_enrich_print_scr_report(ctr_intel)
    
    print(yellow(f"\n- COMPLETION 95 % - WHOAW ALMOST DONE !",bold=True))
       
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True)) 
    print(yellow('#       Let\'s work now on response actions       #',bold=True))
    print(yellow('#                                                #',bold=True)) 
    print(yellow('# YOU HAVE TO :                                  #',bold=True)) 
    print(yellow('#                                                #',bold=True)) 
    print(yellow('# - Quarantine the infected machines             #',bold=True))      
    print(yellow('# - Block Malicious objects                      #',bold=True))
    print(yellow('#                                                #',bold=True))       
    print(yellow('##################################################',bold=True))  
    a=input('\nType Enter to Continue :')     
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True)) 
    print(yellow('#   Cisco XDR knows which response actions       #',bold=True))
    print(yellow('#        can be applied to observables           #',bold=True)) 
    print(yellow('#    from product Integrations and response      #',bold=True)) 
    print(yellow('#             workflows deployed                 #',bold=True)) 
    print(yellow('#                                                #',bold=True))       
    print(yellow('##################################################',bold=True))    
    print(yellow('\nHave a look to :\n\nhttps://developer.cisco.com/docs/cisco-xdr/list-available-actions-for-an-observable/\n',bold=True))       
    a=input('\nType Enter to Continue :')    
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True)) 
    print(yellow('#     Then we can query XDR to tell us what      #',bold=True))
    print(yellow('#   we can do for each observables and  even     #',bold=True)) 
    print(yellow('#    ask to XDR to trigger the response action   #',bold=True)) 
    print(yellow('#                                                #',bold=True))       
    print(yellow('##################################################',bold=True))    
    print(yellow('\nHave a look to :\n\nhttps://developer.cisco.com/docs/cisco-xdr/trigger-an-action/\n',bold=True))       
    a=input('\nType Enter to Continue :')     
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True)) 
    print(yellow('#                 Okay let\'s do it               #',bold=True))  
    print(yellow('#                                                #',bold=True))     
    print(yellow('##################################################',bold=True))       
    a=input('\nType Enter to Continue :')     
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True)) 
    print(yellow('#  First let\'s isolate the infected Endpoint     #',bold=True))
    print(yellow('#                                                #',bold=True))    
    print(yellow('# Let\'s trigger from XDR the CSE host isolation  #',bold=True))     
    print(yellow('#                                                #',bold=True))     
    print(yellow('##################################################',bold=True))  
    print(red(f'Line number : {str(env.get_line())}',bold=True))        
    a=input('\nType Enter to Continue :')        
    # MISSION15: assign function output to correct variable and pass it to function ctr_add_to_cse_scd to perform necessary action.
    # Hint: make sure to pass this variable to the function in validation section too!    
    print(red(f'Line number : {str(env.get_line())}',bold=True))     
    # here under let's get response action for hostnames
    ctr_observables={'value':'Demo_AMP_Threat_Audit','type':'hostname'}
    response_actions = ctr_response_actions(ctr_access_token,ctr_observables)
    print('available response actions are :\n',cyan(response_actions,bold=True))
    print(yellow('Okay, from the result above, we are interested in the workflow named :\n',bold=True),cyan(' W0080b - isolate endpoint from_hostname',bold=True))    
    print(yellow('We need to copy the URL :',bold=True),cyan('\n/respond/trigger/22g678f2-ad5e-4374-8708-a8fcc7861f6c/01HP8SN2BIX9I1IR4dI1b4l9q1DQVwziOKo?observable_type=hostname&observable_value=Demo_AMP_Threat_Audit&workflow_id=01HP8SN2BIX9I1IR4dI1b4l9q1DQVwziOKo',bold=True))     
    print(yellow('\nIMPORTANT NOTICE ! : In the URL have look to the observable_type and observable value',bold=True)) 
    print(yellow('\nNow we can use this URL to trigger the host isolation. It will be managed by Cisco XDR...',bold=True))    
    a=input('\nType Enter to Continue :')    
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True)) 
    print(yellow('#   Now let\'s trigger the CSE Host Isolation     #',bold=True))
    print(yellow('#                    from XDR                    #',bold=True))    
    print(yellow('#                                                #',bold=True))    
    print(yellow('##################################################',bold=True))  
    print(red(f'Line number : {str(env.get_line())}',bold=True))        
    a=input('\nType Enter to Continue :')    
    response_actions_url="/respond/trigger/22g678f2-ad5e-4374-8708-a8fcc7861f6c/01HP8SN2BIX9I1IR4dI1b4l9q1DQVwziOKo?observable_type=hostname&observable_value=Demo_AMP_Threat_Audit&workflow_id=01HP8SN2BIX9I1IR4dI1b4l9q1DQVwziOKo"
    result=xdr_trigger_response_action(env.XDR.get("host"),response_actions_url)
    print(green(result,bold=True))
    a=input('\nType Enter to Continue :')
    response_actions=''    
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True)) 
    print(yellow('#               Okay it\'s Your turn              #',bold=True))
    print(yellow('#                                                #',bold=True))    
    print(yellow('#       Search for the ISE ERS ANC Policy        #',bold=True)) 
    print(yellow('#               response action                  #',bold=True)) 
    print(yellow('#  Hint use only one ip address, it is enough    #',bold=True))     
    print(yellow('#                                                #',bold=True))        
    print(yellow('#   copy the URL of the response action which    #',bold=True))  
    print(yellow('#          isolate hosts thanks to ISE           #',bold=True))     
    print(yellow('#                                                #',bold=True))     
    print(yellow('##################################################',bold=True))  
       
    print(red(f'Line number : {str(env.get_line())}',bold=True))        
    a=input('\nType Enter to Continue :')    
    # PUT YOUR CODE HERE UNDER
    '''
    ip_address='1.2.3.4' # we use any valid ip address . the goal is to display available response actions
    ctr_observables={'value':ip_address,'type':'ip'}
    response_actions = ctr_response_actions(ctr_access_token,ctr_observables)
    print('available response actions are :\n',cyan(response_actions,bold=True))
    a=input('\nType Enter to Continue :')
    '''
    if response_actions=='':
        sys.exit()
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True)) 
    print(yellow('#  Let\'s use a loop to quarantine the hosts      #',bold=True))
    print(yellow('#                                                #',bold=True))    
    print(yellow('#    Have a look to the code an complete it      #',bold=True))  
    print(yellow('#                                                #',bold=True))     
    print(yellow('##################################################',bold=True))  

    print(red(f'Line number : {str(env.get_line())}',bold=True))        
    a=input('\nType Enter to Continue :')   
    result=''    
    # PUT YOUR CODE HERE UNDER
    '''
    for ip_address in infected_machine_list:
        response_actions_url=f"/xxxxxxxxxxxx/?observable_type=ip&observable_value={ip_address}&action-id=01YD3Z1A74H553WXOpHSOD0cJVN1fw1ik0T"
        result=xdr_trigger_response_action(env.XDR.get("host"),response_actions_url)
        print(green(result,bold=True))
    '''  
    if result=='':
        sys.exit()      
    a=input('\nType Enter to Continue :')    
    
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True)) 
    print(yellow('#   You have to do the same operation for the    #',bold=True))
    print(yellow('#     malicious domain. You have to block it     #',bold=True))         
    print(yellow('#                                                #',bold=True))     
    print(yellow('##################################################',bold=True))       
    print(red(f'Line number : {str(env.get_line())}',bold=True))        
    a=input('\nType Enter to Continue :')    
    result=''     
    # PUT YOUR CODE HERE UNDER
    '''
    ctr_observables={'value':'???????','type':'domain'}
    response_actions = ctr_response_actions(ctr_access_token,ctr_observables)
    print('available response actions are :\n',cyan(response_actions,bold=True))
    print(red(f'Line number : {str(env.get_line())}',bold=True))        
    a=input('\nType Enter to Continue :')    
    
    malicious_domain="??????????"
    response_actions_url=f"/xxxxxxxxxxxx/?observable_type=domain&observable_value={malicious_domain}"
    result=xdr_trigger_response_action(env.XDR.get("host"),response_actions_url)
    print(green(result,bold=True))    
    '''
    if result=='':
        sys.exit()     
    a=input('\nType Enter to Continue :')         
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True)) 
    print(yellow('#    finally quarantine the malicious sha256     #',bold=True))        
    print(yellow('#                                                #',bold=True))     
    print(yellow('##################################################',bold=True))  
       
    print(red(f'Line number : {str(env.get_line())}',bold=True))        
    a=input('\nType Enter to Continue :')    
    # PUT YOUR CODE HERE UNDER
    result=400
    '''
    ctr_observables={'value':'????????','type':'sha256'}
    response_actions = ctr_response_actions(ctr_access_token,ctr_observables)
    print('available response actions are :\n',cyan(response_actions,bold=True))
    a=input('\nType Enter to Continue :')  
    malicious_sha256="?????????"
    response_actions_url=f"/xxxxxxxxxxxx/?observable_type=sha256&observable_value={malicious_sha256}"
    result=xdr_trigger_response_action(env.XDR.get("host"),response_actions_url)
    '''
    if result == 200:
        print(green(f"RETURN ==> A malicious sha256 {malicious_sha256} is added to Secure Endpoint Simple Custom Detections list named Quarantine.",bold=True))    
    else:
        print(red('Error',bold=True))  
        sys.exit()
 
    print(yellow('\n                                        #########################################',bold=True))
    print(yellow('                                        # CONGRATUALTION! YOU COMPLETED AT 100% #',bold=True))
    print(yellow('                                        #########################################',bold=True))
    print(yellow('                                        #                                       #',bold=True))    
    print(yellow('                                        #               #### ####               #',bold=True)) 
    print(yellow('                                        #          ####  #######  ####          #',bold=True))
    print(yellow('                                        #         #    ###########    #         #',bold=True)) 
    print(yellow('                                        #        #    #############    #        #',bold=True)) 
    print(yellow('                                        #        #    #############    #        #',bold=True)) 
    print(yellow('                                        #         #    ###########    #         #',bold=True)) 
    print(yellow('                                        #           #   #########   #           #',bold=True)) 
    print(yellow('                                        #             #  #######  #             #',bold=True)) 
    print(yellow('                                        #               #########               #',bold=True)) 
    print(yellow('                                        #              ###########              #',bold=True)) 
    print(yellow('                                        #                                       #',bold=True))    
    print(yellow('                                        #########################################',bold=True))  
    a=input(yellow('\nCongratulation !!!!. ( actually we have a bonus lab ). Press Enter to continue :',bold=True))  
    print('\n\n\n')  
    print(yellow('\n##################################################',bold=True))
    print(yellow('#                 BONUS LAB                      #',bold=True))
    print(yellow('#   Now the question is about sending an alert   #',bold=True))
    print(yellow('# You have to send an alert into  the webex room #',bold=True))      
    print(yellow('#      With the list of infected  machines       #',bold=True))    
    print(yellow('#       And the list of malicious objects        #',bold=True))    
    print(yellow('#                IT\'S UP TO YOU                  #',bold=True))     
    print(yellow('#                                                #',bold=True))  
    print(yellow('##################################################',bold=True))         
    print(red(f'Line number : {str(env.get_line())}',bold=True))        
    a=input('\nType Enter to Continue :')    
    # PUT YOUR CODE HERE UNDER

    print(yellow('\n##################################################',bold=True))
    print(yellow('#                                                #',bold=True))
    print(yellow('#You have to call a Webex sending alert function #',bold=True))
    print(yellow('#                                                #',bold=True))  
    print(yellow('##################################################',bold=True))         
    print(red(f'Line number : {str(env.get_line())}',bold=True))        
    a=input('\nAdd your function call here under . Press Enter :')  
    # PUT YOUR CODE HERE UNDER
