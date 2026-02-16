#!/usr/bin/env python3
"""
Script Version 5.0 20260211
Python Mission: Create Threat Investigation & Response Automation Workflow
"""


from datetime import datetime
import json
import time
import sys
from pathlib import Path
import requests
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

print(yellow('\n##################################################',bold=True))
print(yellow('# WELCOME TO THE PYTHON THREAT HUNTING CHALLENGE #',bold=True))
print(yellow('# You have 15 Missions and several bugs to fix   #',bold=True))    
print(yellow('# Complete every challenges and Win this race    #',bold=True))    
print(yellow('#                ARE YOU READY !!!               #',bold=True))       
print(yellow('##################################################',bold=True))
a=input('Press Enter to Continue and understand the context of this investigation :')
print(cyan('\n##################################################',bold=True))
print(cyan('#             HERE IS WHAT HAPPENED              #',bold=True))
print(cyan('#  One of your users suspect a severe infection  #',bold=True))        
print(red('#  He openned a PDF received by mail and saw the #',bold=True)) 
print(red('#         Secure Endpoint Alert popup            #',bold=True))   
print(cyan('#     his laptop is ( Demo_AMP_Threat_Audit )    #',bold=True))    
print(cyan('#                                                #',bold=True))     
print(cyan('##################################################',bold=True))
a=input('Press Enter to Continue :')
#TODO MISSION01: Assign the correct computer name to the amp_computer_name variable.
print("\n-|-MISSION01-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|")
amp_computer_name = ""
if amp_computer_name=="":
    print(yellow('MISSION01 : what is the name of the computer on which we roll out the investigation ?',bold=True))
    env.print_missing_mission_warn(env.get_line()) # Delete this line when mission is complete.    
    # Hint: Refer to Step 1 of the Mission Overview in the lab guide.    
else:
    print(yellow(f"\n NICE LET'S CONTINUE !",bold=True))   
# Functions

def get_amp_computers(
    host=env.SECURE_ENDPOINT.get("host"),
    client_id=env.SECURE_ENDPOINT_CLIENT_ID,
    api_key=env.SECURE_ENDPOINT_API_KEY,
):
    """Get a list of computers from Cisco Secure Endpoint."""
    print(white("\n==> Step 1 : Getting All computers and their details from Secure Endpoint",bold=True))
    # MISSION02: Construct the URL
    print("\n-|-|-MISSION02-|-|-|-|-|-|-|-|-|-|-|-|-|-|") 
    url = f"https://{client_id}:{api_key}@{host}/v1/MISSION02"  
    if "MISSION02" in url:    
        print(yellow("MISSION02 : Construct the Correct URL API Endpoint",bold=True))    
        print(yellow("MISSION02 : from the Cisco Secure endpoint API documentation located at : https://developer.cisco.com/docs/secure-endpoint/overview/#overview",bold=True))
        print(yellow("MISSION02 : find the URL enpdoint that will give you the list of computers",bold=True))    
        print(yellow("MISSION02 : replace MISSION02 by the correct keyword in the URL above",bold=True))  
        env.print_missing_mission_warn(env.get_line())
    else:
        print(yellow(f"\n NICE LET'S CONTINUE !",bold=True))  
    response = requests.get(url, verify=False)
    # Consider any status other than 2xx an error
    response.raise_for_status()

    computer_list = response.json()["data"]
    
    return computer_list


def get_amp_events(query_params="",
    host=env.SECURE_ENDPOINT.get("host"),
    client_id=env.SECURE_ENDPOINT_CLIENT_ID,
    api_key=env.SECURE_ENDPOINT_API_KEY,
):
    """Get a list of recent events from Cisco Secure Endpoint."""
    print(white("\n==> Step 2 : Get a list of recent events from Cisco Secure Endpoint",bold=True))
    # MISSION04: Construct the URL
    print("\n-|-|-|-|-MISSION04-|-|-|-|-|-|-|-|-|-|-|-|")      
    url = f"https://{client_id}:{api_key}@{host}/v1/MISSION04"
    if "MISSION04" in url:    
        print(yellow("MISSION04 : Construct the Correct URL API Endpoint",bold=True))    
        print(yellow("MISSION04 : from the Cisco Secure endpoint API documentation located at : https://developer.cisco.com/docs/secure-endpoint/overview/#overview",bold=True))
        print(yellow("MISSION04 : find the /v1 URL enpdoint that will give you the list of events on the investigated computer",bold=True))    
        print(yellow("MISSION04 : replace MISSION04 by the correct keyword in the URL above",bold=True))  
        env.print_missing_mission_warn(env.get_line())
    response = requests.get(url, params=query_params, verify=False)
    # Consider any status other than 2xx an error
    response.raise_for_status()

    events_list = response.json()["data"]
    
    return events_list

# method should be 'put', 'get' or 'delete'
def amp_isolation(method, computer_guid,
    host=env.SECURE_ENDPOINT.get("host"),
    client_id=env.SECURE_ENDPOINT_CLIENT_ID,
    api_key=env.SECURE_ENDPOINT_API_KEY,
):
    print(white(f"\n==> Step 3 : Let's isolate the infected Endpoint in Secure Endpoint",bold=True))
    
    url = f"https://{client_id}:{api_key}@{host}/v1/computers/{computer_guid}/isolation"

    if method == 'get':
        response = requests.get(url, verify=False)
        response.raise_for_status()
    elif method == 'put':
        response = requests.put(url, verify=False)
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
    
    isolation_status = response.json()["data"]

    return isolation_status


def threatgrid_search_submissions(
    sha256,
    host=env.MALWARE_ANALYTICS.get("host"),
    api_key=env.MALWARE_ANALYTICS_API_KEY,
):
    """Search TreatGrid Submissions, by sha256.
    Args:
        sha256(str): Lookup this hash in MALWARE_ANALYTICS Submissions.
        host(str): The MALWARE_ANALYTICS host.
        api_key(str): Your MALWARE_ANALYTICS API key.
    """
    print(white(f"\n==> Step 4 : Searching the Malware Analytics Submissions for sha256: {sha256}\n",bold=True))
    query_parameters = {
        "q": sha256,
        "api_key": api_key,
    }
    print(red('Voluntary bug here after !... You must deactivate SSL certificate check in the request calls ( and in every https calls ! ). use the verify=False statement for this\nSearch for this statement in this code to see how to use it.',bold=True))
    a=input('\n Press Enter to continue')
    print()    
    print(red('line #'+str(env.get_line()),bold=True))      
    response = requests.get(
        f"https://{host}/api/v2/search/submissions",
        params=query_parameters,
    )  
    print(green('\nYeah !! :-) ',bold=True))
    # MISSION06: Put proper function to consider any status other than 2xx an error
    print("\n-|-|-|-|-|-|-MISSION06-|-|-|-|-|-|-|-|-|-|")      
    response_status=MISSION("MISSION06")
    if response_status==None:
        pass
    else:
        if 'MISSION06' in response_status:
            print(yellow("\nMISSION06 : let`s check here the result of the call. Did it work ?",bold=True))
            print(yellow("MISSION06 : replace MISSION06 by the correct function applyed to response",bold=True))   
            print(yellow("MISSION06 : have a look to other calls and search for things related to raise for status",bold=True))        
            env.print_missing_mission_warn(env.get_line())  
    print(yellow(f"\n NICE LET'S CONTINUE !",bold=True))
    
    submission_info = response.json()["data"]["items"]

    if submission_info:
        print(cyan("\nOk We successfully retrieved data on the suspicious sha256 submission from Malware Analytics",bold=True))
    else:
        print(red("Unable to retrieve data on the sha256 submission",bold=True))
        sys.exit(1)

    return submission_info


def threatgrid_get_domains(sample_id,
    host=env.MALWARE_ANALYTICS.get("host"),
    api_key=env.MALWARE_ANALYTICS_API_KEY,
):  
    if sample_id=="MISSION07":
        return("MISSION07")
    print(white(f"\n==> Step 5 : Let's get from Malware Analytics, domains that are associated with the Sample ID: {sample_id}",bold=True))

    url = f"https://{host}/api/v2/samples/feeds/domains"
    query_params = {
        "sample": sample_id,
        "after": "2019-01-01",
        "api_key": api_key,
    }
    print(red('Voluntary bug here after !... You must deactivate SSL certificate check in the request calls ( and in every https calls ! ). use the verify=False statement for this\nSearch for this statement in this code to see how to use it.',bold=True))
    a=input('\n Press Enter to continue')
    response = requests.get(
        url,
        params=query_params,
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
    print(white(f"\n==> Ok Malware Analytics confirmed us that some domains are associated to the sha256 and gave us the list\n\n==> Step 6 : Now let's query Umbrella Investigate in order to check all associated domains  to retreive their disposition",bold=True))
    print()
    print(red('Voluntary bug here after !...Easy to fix :-) ',bold=True))
    a=input('\n Press Enter to continue')   
    url = f"https://{host}/domains/categorization/{domain}?showLabels"
    print(yellow('\nYou Rock Man ! :-) ',bold=True))    

    # MISSION09: Construct authentication headers for Umbrella Investigate
    print("\n-|-|-|-|-|-|-|-|-|-MISSION09-|-|-|-|-|-|\n")   
    #headers = {'MISSION09':'MISSION09'}
    if headers== {'MISSION09':'MISSION09'}:
        print(yellow("\nMISSION09 : assign the correct value to the header variable ",bold=True))
        print(yellow("\nthis header must contain a bearer api_key assign to a key named Authorization  ",bold=True))           
        print(yellow("MISSION09 : replace MISSION09 by the correct value",bold=True))    
        print(yellow("\nYou can search for similar declaration for headers in this code, which contains a Bearer token  ",bold=True))         
        env.print_missing_mission_warn(env.get_line())  

    print(yellow(f"\n NICE LET'S CONTINUE !",bold=True))    
    url0 = f"https://localhost:4000/v1/next"
    payload0="7"
    requests.post(url0, data=payload0, verify=False)
    print(red('2 consecutive voluntary bugs are coming !...You should be able to fix it :-) based on what you have already seen',bold=True))  
    print('line #'+env.get_line()) 
    response = requests.get(url, headers=headers)
    response.raise_for_status()

    domains_status = response.json()
    
    return domains_status


def post_umbrella_events(blacklist_domains,
    host=env.UMBRELLA.get("en_url"),
    api_key=env.UMBRELLA_ENFORCEMENT_KEY,
):
    print(white(f"\n==> Step 7 : Let's query the Umbrella Enforcement API for adding the domain found above to a custom domain blocking lists in Umbrella",bold=True))
    a=input('\nPress Enter to continue :' )
    # MISSION11: Construct the API endpoint to post malware events to the Umbrella Enforcement API
    print("\n-|-|-|-|-|-|-|-|-|-|-|-MISSION11-|-|-|-|")      
    url = f"https://{host}/1.0/events?customerKey=MISSION11"  
    if 'MISSION11' in url:
        print(yellow("\nMISSION11 : build a correct url endpoint with api key value ",bold=True))
        print(yellow("MISSION11 : replace MISSION11 by the correct statement for passing the api key within the call above",bold=True))    
        env.print_missing_mission_warn(env.get_line())  

    print(yellow(f"\n NICE LET'S CONTINUE !",bold=True))
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
    print("\nOK Done, the Domain was succesfully added to the Umbrella Domain Blocking List")     
    #id='4bf26c3d,fd2e,4def,b038-ee3778b3e6ba'
    return id, data


def ctr_auth(
    host=env.THREATRESPONSE.get("host"),
    client_id=env.CTR_CLIENT_ID,
    api_key=env.CTR_API_KEY,
):
    print(white("\n==> Authenticating to Cisco XDR..."))
    url = f"https://{host}/iroh/oauth2/token"

    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json'}
    # MISSION12: Construct payload to pass in authentication request to Threat Response
    print("\n-|-|-|-|-|-|-|-|-|-|-|-|-MISSION12-|-|-|-|")      
    payload = MISSION('MISSION12') 
    if 'MISSION12' in payload:
        print(yellow("\nMISSION12 : build a correct url endpoint with a correct payload value ",bold=True))
        print(yellow("\nMISSION12 : according to the sample there : https://developer.cisco.com/docs/cisco-xdr/oauth2-api-guide/#sample-code ",bold=True))
        print(yellow("\nMISSION12 : what is the value for the payload variable ?",bold=True))        
        print(yellow("MISSION12 : replace MISSION('MISSION12') by the correct statement within the payload assignment above",bold=True))    
        env.print_missing_mission_warn(env.get_line())  

    print(yellow(f"\n NICE LET'S CONTINUE !",bold=True))
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
    print(white("\n==> Step 10 : Let's Take a block of arbitrary text which contains observables",bold=True))
    print(white("==> We use the XDR inspect API wich extract observables from the text block, and return a list of formatted observables as a JSON object...\n",bold=True))    
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
    print(white("\n==> Step 11 : Fetching Sightings about provided observables from XDR. Be patient, it may take time...",bold=True))
    
    url = f"https://{host}/iroh/iroh-enrich/observe/observables"

    headers = {"Authorization":f"Bearer {access_token}", 'Content-Type':'application/json', 'Accept':'application/json'}

    observe_payload = json.dumps(ctr_observables)
    #observe_payload = '[{"value": "b1380fd95bc5c0729738dcda2696aa0a7c6ee97a93d992931ce717a0df523967", "type": "sha256"}]'
    print()
    print(white('Here is the observable list found into the text : ')+cyan(observe_payload))
    print()
    response = requests.post(url, headers=headers, data=observe_payload, verify=False)
    response.raise_for_status()
    
    if "data" in response.json():
        data = response.json()["data"]
    else:
        print(red(response.json(),bold=True))
        sys.exit()
    print(cyan("Sightings found in XDR are : \n",bold=True))         
    time.sleep(3)
    print(yellow(data,bold=True))
    
    print(green('\nWHOAW MISSION 14 : ctr_enrich_observe function = OK',bold=True))
    url0 = f"https://localhost:4000/v1/next"
    payload0="14"
    requests.post(url0, data=payload0, verify=False)
    return data
    
def ctr_enrich_observe_original(access_token, MISSION14,
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
    
    print(red('HERE MISSION 14 : ctr_enrich_observe function OK'))
    url0 = f"https://localhost:4000/v1/next"
    payload0="14"
    requests.post(url0, data=payload0, verify=False)
    return data

def ctr_enrich_print_scr_report(intel):
    print(red('You are almost done !! but you have to fix that bug first :-) !',bold=True))
    print(red('HINT : the JSON result you got prior will definitely help !',bold=True))    
    print(white("\n==> Here is what XDR enrichment found. We got answsers from Threat Intell connected to XDR :\n"))

    for module in intel:
        #print(yellow(module,bold=True)) # Use for for troubleshooting :-)
        #print(white(f"\n==> Module: {module['module']} : {module['module-type']}"))
        print(cyan(f"\n==> Module: {module['module']} : {module['module_type_id']}",bold=True))
        if module["data"]:
            if module["module"] == "SECURE_ENDPOINT for Endpoints":
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
                    print(cyan(f"  ==> Target OS: {target['os']}"))
            elif module["module"] == "SECURE_ENDPOINT File Reputation":
                for key in module["data"].keys():
                    print(cyan(f"  ==> Count of {key}: {module['data'][key]['count']}",bold=True))
            elif module["module"] == "VirusTotal":
                print(cyan("  ==> NO DATA FROM THIS INTEGRATION",bold=True))       
            elif module["module"] == "Stealthwatch Cloud":
                print(cyan("  ==> NO DATA FROM THIS INTEGRATION",bold=True))                    
            elif module["module"] == "SECURE_ENDPOINT Global Intelligence":
                for key in module["data"].keys():
                    print(cyan(f"  ==> Count of {key}: {module['data'][key]['count']}",bold=True))
        else:
            print(cyan("  ==> NO DATA FROM THIS INTEGRATION",bold=True))
    print()
    print(green('PERFECT JOB !!!',bold=True))
    print()            
    url0 = f"https://localhost:4000/v1/next"
    payload0="16"
    requests.post(url0, data=payload0, verify=False)            


def ctr_response_actions(access_token,observables,
    host=env.THREATRESPONSE.get("host"),
):
    print(white("\n==> Step 12 : Fetching the list of available response actions and modules for given observable...",bold=True))
    print("\nobservables are :",observables)
    url = f"https://{host}/iroh/iroh-response/respond/observables"

    payload = json.dumps(observables)

    headers = {"Authorization":f"Bearer {access_token}", 'Content-Type':'application/json', 'Accept':'application/json'}
    #MISSION15 BUG TO FIX
    #response = requests.post(url, headers=headers, data=payload)
    response = requests.post(url, headers=headers, data=payload, verify=False)    
    response.raise_for_status()
    response_action_list=response.json()["data"]
    index=0
    print(yellow("\nList of available response actions for sha256 observables is : \n",bold=True))    
    ok=1
    while ok:
        for item in response_action_list:
            print(str(index)+' -',item["title"])
            index+=1
        a=input('\nSelect the index for the [Add SHA256 from custom detections File_Blacklist] response action : ')
        
        response_url = response.json()["data"][1]["url"]
        print(yellow("\nSelect response action url is :"+response_url,bold=True))
        if a=='1':
            ok=0
        else:
            print(red('Not the correct answer, try again',bold=True))
            index=0
    return response_url


def ctr_add_to_amp_scd(access_token, action_url,
    host=env.THREATRESPONSE.get("host"),
):
    print(white("\n==> Step 13 : Adding a malicious sha256 to Secure Endpoint Simple Custom Detections list named Quarantine...",bold=True))
    print('\naction_url :',action_url)
    print()
    response_action_url=action_url.split('/observable_type')[0]
    arguments0=action_url.split('/observable_type=')[1]
    arguments=arguments0.split('&')
    
    payload={'observable_type':arguments[0],'observable_value':arguments[1].replace('observable_value=','')}
    print('payload :',payload)
    url = f"https://{host}/iroh/iroh-response{response_action_url}"

    headers = {"Authorization":f"Bearer {access_token}", 'Content-Type':'application/json', 'Accept':'application/json'}

    #response = requests.post(url, headers=headers)
    response = requests.post(url, headers=headers, data=payload,verify=False)
    response.raise_for_status()

    return response.status_code

def MISSION05(text):
    return('MISSION05')
    
def MISSION06(text):
    return('MISSION06')
    
def MISSION(text):
    return(text)

# If this script is the "main" script, run...
if __name__ == "__main__":
    '''
    Step 0. Set the computer name variable
    '''
    if amp_computer_name == "MISSION01":
        print()
        print(red(f"Goto to line 51 and set the correct value for the amp_computer_name variable",bold=True))
        sys.exit()
    '''
    Step 1. In Secure Endpoint, get a list of all the events of "Threat Detected" and 
    "Executed Malware" types for a specific computer named `Demo_AMP_Threat_Audit`, 
    capture malicious sha256 associated with the first event.
    '''
    
    # Hint: If you get stuck at any point, try referring to your Postman solution! 

    #print(white(f"\nStep 1"))

    amp_computer_list = get_amp_computers()

    print(white(f"\nSecure Endpoint Computer List Fetched . Let's get the GUID of the computer named {amp_computer_name}"))
    
    if not amp_computer_name:
        print()
        print(red(f"Wrong amp_computer_name in MISSION01. The variable is probably empty",bold=True))
        print()
        
    for computer in amp_computer_list:
        if computer["hostname"] == amp_computer_name:
            amp_computer_guid = computer["connector_guid"]

    print(cyan(f"\nSecure Endpoint Computer name: {amp_computer_name}, GUID: {amp_computer_guid}",bold=True))

    print(white(f"==> Let's get from Secure Endpoint the names of the threats with IDs 1107296272 and 1090519054"))
    # MISSION03: Complete the Secure Endpoint query with correct event types to fetch event list
    # 
    print("\n-|-|-|-MISSION03-|-|-|-|-|-|-|-|-|-|-|-|-|")    
    amp_query_params = f"connector_guid[]={amp_computer_guid}&MISSION03"
    if 'MISSION03' in amp_query_params:
        print(yellow("MISSION03 : we want to display event related to event type : 1090519054 ( Threat Detected ) and 1107296272 ( Executed Malware )",bold=True))
        print(yellow("MISSION03 : write correct query parameter to send into the API call function get_amp_events()",bold=True))    
        env.print_missing_mission_warn(env.get_line())   
    print(yellow(f"\n NICE LET'S CONTINUE !",bold=True))        
    url0 = f"https://localhost:4000/v1/next"
    payload0="2"
    requests.post(url0, data=payload0, verify=False)
    
    amp_event_list = get_amp_events(query_params=amp_query_params)
    #print(cyan(amp_event_list,bold=True))
    print(cyan(f"\nWe Retrieved {len(amp_event_list)} events from Secure Endpoint",bold=True))

    amp_event = amp_event_list[0]
    
    print (green(f"\nThis First Event in the list is : {amp_event['event_type']} \
             \nDetection: {amp_event['detection']} \
             \nFile name: {amp_event['file']['file_name']} \
             \nFile sha256: {amp_event['file']['identity']['sha256']}"))

    threatgrid_sha = amp_event["file"]["identity"]["sha256"]

    """
    Step 2. Isolate infected Computer to perform further investigation 
    and make sure that the action was successful.
    """
    
    print(white(f"\nCOMPLETION 10 %"))

    amp_computer_isolation = amp_isolation('put',amp_computer_guid)
    
    if amp_computer_isolation:
        print(green(f"Computer {amp_computer_name} (GUID {amp_computer_guid}) is {amp_computer_isolation['status']}"))

    """
    In Malware Analytics, find all samples, associated with malicious sha256 that you have 
    captured in step 1 and look at analysis report for the first sample on the list.
    """

    print(white(f"\nCOMPLETION 20 %"))

    # MISSION05: Use the right function to find all samples, associated with malicious sha256
    print("\n-|-|-|-|-|-MISSION05-|-|-|-|-|-|-|-|-|-|-|")        
    submission_info = MISSION05(threatgrid_sha)
    if 'MISSION05' in submission_info:
        print(yellow("\nMISSION05 : Call the correct python function in this script",bold=True))
        print(yellow("\nThe function that Search TreatGrid Submissions, by sha256\n",bold=True))
        print(yellow("MISSION05 : replace MISSION05 by the correct function name in the call above",bold=True))    
        env.print_missing_mission_warn(env.get_line())  
    print(red('Voluntary bug here after !... Syntax is not good around line #'+str(env.get_line()),bold=True))
    a=input('\n Press Enter to continue')     
    print(yellow(f"\n NICE LET'S CONTINUE !",bold=true))        
    url0 = f"https://localhost:4000/v1/next"
    payload0="5"
    requests.post(url0, data=payload0, verify=False)
    threatgrid_sample_id = submission_info[0]['item']['sample']

    print(green(f"Successfully retrieved Malware Analytics sample ID {threatgrid_sample_id} for sha265 {threatgrid_sha}"))

    """
    Request all domains for a specific sample in Malware Analytics and store them in an array to get more data out of them.
    """
    print(white(f"\nCOMPLETION 35 %"))
    # MISSION07: Pass the right variable to achieve fetch all domains for a specific sample in Malware Analytics
    print("\n-|-|-|-|-|-|-|-MISSION07-|-|-|-|-|-|-|-|")      
    threatgrid_sample_domains = threatgrid_get_domains('MISSION07')
    if 'MISSION07' in threatgrid_sample_domains:
        print(yellow("\nMISSION07 : Pass the correct variable to the function",bold=True))
        print(yellow("MISSION07 : the variable that contains the sample ID",bold=True))    
        print(yellow("MISSION07 : replace MISSION07 variable name by the correct variable name",bold=True))
        env.print_missing_mission_warn(env.get_line())  
    url0 = f"https://localhost:4000/v1/next"
    payload0="6"
    requests.post(url0, data=payload0, verify=False)
    
    print(cyan(f"\nSuccessfully retrieved domains on the sha256 submission: {threatgrid_sample_domains}",bold=True))

    """
    Check all associated domains against Umbrella Investigate to retreive their status.
    """
    print(yellow(f"\n NICE LET'S CONTINUE !",bold=True))    
    print(yellow(f"\nStep 5 - COMPLETION 40 %",bold=True))
    # MISSION08: Use the right function and pass the correct variable into it to retreive the status of the first domain associated with Treat Grid sample.
    print("\n-|-|-|-|-|-|-|-|-MISSION08-|-|-|-|-|-|-|-|")    
    # Hint: Remember that numbering starts with 0 in most coding languages.
    umbrella_domains_status = MISSION('MISSION08')
    if 'MISSION08' in umbrella_domains_status:
        print(yellow("\nMISSION08 : Call the correct python function ",bold=True))
        print(yellow("\nMISSION08 : This function returns a list of domain status and it uses sample domains from Threatgrid as input variable ",bold=True))
        print(yellow("MISSION08 : replace MISSION08 by the correct function name with the correct input variable in the call above",bold=True))    
        env.print_missing_mission_warn(env.get_line())      
    print(yellow(f"\n NICE LET'S CONTINUE !",bold=True))        
    url0 = f"https://localhost:4000/v1/next"
    payload0="8"
    requests.post(url0, data=payload0, verify=False)
    if 'ERROR' in umbrella_domains_status:
        print(red(umbrella_domains_status,bold=True))
        print(red('Expected Token must be : Bearer <valid_umbrella_investigate_token>',bold=True))        
        print()
        sys.exit() 
    umbrella_malicious_domains = []
    print("\n-|-|-|-|-|-|-|-|-|-|-MISSION10-|-|-|-|-|")
    print()
    print(red('Easy to fix !',bold=True))
    print()    
    for key in umbrella_domains_status.keys():
        domain_status = umbrella_domains_status[key]['status']
        if domain_status == 1:
            print(green(f"The domain {key} is found CLEAN in Umbrella, domain status = 1"))
            env.print_missing_mission_warn(env.get_line()) # Delete this line when mission is complete.
        elif MISSION10: # MISSION10: Put correct condition check here with proper domain status value in order to catch Malicious domains only
            #elif domain_status == SOMETHING TO FIND:
            print(yellow('Yeah Man !',bold=True))
            print(cyan(f"The domain {key} is found MALICIOUS in Umbrella,, domain status = -1",bold=True))
            umbrella_malicious_domains.append(key)
        elif domain_status == 0:
            print(green(f"The domain {key} is found UNDEFINED in Umbrella,, domain status = 0"))

    url0 = f"https://localhost:4000/v1/next"
    payload0="9"
    requests.post(url0, data=payload0, verify=False)
    
    """
    Using Umbrella Enforcement, post malware events to the API for processing and optionally adding to a customer's domain lists.
    """
    
    print(yellow(f"\nStep 6 - COMPLETION 50 %",bold=True))
    
    umbrella_event_id, umbrella_blacklist_enforcement = post_umbrella_events(umbrella_malicious_domains)

    print(green(f"Domains {umbrella_malicious_domains} were accepted in the blocking list, Umbrella event id: {umbrella_event_id}",bold=True))

    print(yellow(f"\nStep 7 - COMPLETION 70 % - VERY GOOD !",bold=True))
    
    """
    Using XDR Threat Response, inspect if malicious sha256 has been found on our network. 
    Use response capabilities of Secure Endpoint module to block this malicious file from execution on all Computers in our network.
    """
    print(yellow(f"\n##########################################\n",bold=True))    
    print(white(f"\n==> Step 8 : Let's change the Approach !!!",bold=True))
    print(white(f"==> - In steps prior we used Secure Endpoint to detected a Threat",bold=True))
    print(white(f"==> - Secure Endpoint Fired Up an alert and indicated us an infected Endpoint by a malicious sha256",bold=True))    
    print(white(f"==> - This sha256 had a malicious behavior detected as a Threat",bold=True))    
    print(white(f"==> - Then we asked Secure Endpoint to preventively isolate the infected host",bold=True))        
    print(white(f"==> - Then we moved forward to an investigation",bold=True))      
    print(white(f"==> - We asked to Malware Analytics if the sha256 discovered by Secure Endpoint was known and has known bad domains associated to it",bold=True))  
    print(white(f"==> - Then we queried Umbrella Investigate to confirm that the domains found were malicious",bold=True))      
    print(white(f"==> - Then we added this domain to an Umbrella custom domain blocking List, in order to prevent other victims to connect to this domain",bold=True)) 
    print(white(f"==>",bold=True))    
    print(white(f"==> - At that Point JOB IS DONE",bold=True))     
    print(white(f"==>",bold=True))       
    print(yellow(f"==> Now we are going the change the approach, we are going to use XDR to manage all same operations",bold=True))    
    print(yellow(f"==> XDR can be the Unique Interface for us for all security operations",bold=True))    
    print(white(f"\n",bold=True))      
    print(white(f"==>Let's go for it !\n",bold=True))   
    a=input('Press Enter to Continue :')
    
    print(white(f"\n==> Step 9 : The first operation is to ask XDR for an API token\n",bold=True))    
    ctr_access_token = ctr_auth()

    print("Received XDR access token",cyan(ctr_access_token,bold=True))
    print(green("\n bingo ! we got a token above \n",bold=True))
    print("\n-|-|-|-|-|-|-|-|-|-|-|-|-|-MISSION13-|-|-|")
    # MISSION13: Pass free form arbitrary text that contains sha256 obtained in Step 1.
    # Hint: f"suspicious hash is {variable}"
    ctr_arb_text = "MISSION13"
    if 'MISSION13' in ctr_arb_text:
        print(yellow("\nMISSION13 : Pass any arbitrary text that contains the sha256 value obtained in Step 1",bold=True))
        print(yellow("\nMISSION13 : You can use the ARBITRARY_TEXT in environnment.py and insert into it any where the sha256",bold=True))
        print(yellow("MISSION13 : replace MISSION13 by the ARBITRARY_TEXT content",bold=True))    
        env.print_missing_mission_warn(env.get_line())  

    print(yellow(f"\n NICE LET'S CONTINUE !",bold=True))
    url0 = f"https://localhost:4000/v1/next"
    payload0="11"
    requests.post(url0, data=payload0, verify=False)
    
    ctr_observables = ctr_inspect(ctr_access_token, ctr_arb_text)

    print(cyan(f"Received formatted list of observables. Total observables: {len(ctr_observables)}",bold=True))

    # MISSION14: Pass to the function properly formatted observables obtained in Step 7.
    # Hint: Check the function and put correct variable there too.
    print("\n-|-|-|-|-|-|-|-|-|-|-|-|-|-|-MISSION14-|-|\n")
    #ctr_intel = ctr_enrich_observe(ctr_access_token, 'MISSION14')        
    if 'MISSION14' in ctr_intel:
        print(yellow("\nMISSION14 : 1-You have to fix the bug in the ctr_enrich_observe() function. Pass to it the correct variable and Make this function work !!",bold=True))  
        env.print_missing_mission_warn(env.get_line())  

    print(yellow(f"\n NICE LET'S CONTINUE !",bold=True))
    # print(red(ctr_intel)) # for debugging 
    url0 = f"https://localhost:4000/v1/next"
    payload0="14b"
    requests.post(url0, data=payload0, verify=False)
    print(green(f"Ok we Received several Sightings related to this observable from XDR"))    
    print()
    print(red('Windows users have to fix a bug here :-) !',bold=True))
    print('check line : '+str(env.get_line()))    
    report_time = datetime.now().isoformat() # NOTICE : Windows does not allow the use of : in filenames
    #report_time = datetime.now().strftime('%Y-%m-%dT%H-%M-%S')  # For windows machines
    ctr_report_path = here / f"ctr_report_{report_time}.json"
    print(cyan(f"\n==> indicators and sightings had been found in XDR. Saving result into : \n{ctr_report_path}",bold=True))
    
    with open(ctr_report_path, "w") as file:
        json.dump(ctr_intel, file, indent=2)

    url0 = f"https://localhost:4000/v1/next"
    payload0="15"
    requests.post(url0, data=payload0, verify=False)
    
    ctr_enrich_print_scr_report(ctr_intel)
    
    """
    Use response capabilities of Secure Endpoint module in CTR to block this malicious file from execution on all Computers in our network.
    """
    print(yellow(f"\nStep 8 - COMPLETION 95 % - WHOAW ALMOST DONE !",bold=True))
    # MISSION15: assign function output to correct variable and pass it to function ctr_add_to_amp_scd to perform necessary action.
    # Hint: make sure to pass this variable to the function in validation section too!
    print("\n-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-MISSION15-|")
    response_actions = MISSION('MISSION15')
    if 'MISSION15' in response_actions:
        print(yellow("\nMISSION15 : find the function which Fetch the list of available response actions and modules for a given observable",bold=True))
        print(yellow("MISSION15 : Then call it with the correct input variables ( API token first and second the observables variable name )",bold=True))
        print(yellow("MISSION15 : And assign the result to the variable named : response_actions",bold=True))        
        print(yellow("MISSION15 : replace MISSION15 string in the print statement bellow by the correct variable name",bold=True))    
        env.print_missing_mission_warn(env.get_line())         
    #print(cyan(f"Response Action URL response_action_url_list returned by ctr_response_actions() is : {MISSION15} "))        
    print(cyan(f"Response Action URL response_action_url_list returned by ctr_response_actions() is : {response_actions} "))  
    ctr_action_response = ctr_add_to_amp_scd(ctr_access_token, response_actions)
    if response_actions == 200:
        print(green(f"A malicious sha256 {threatgrid_sha} is added to Secure Endpoint Simple Custom Detections list named Quarantine."))
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
    host=env.SECURE_ENDPOINT.get("host")
    url = f"https://{host}/v1/disposition"

    try:
        user = get_user_details(webex_token)
    except:
        #print('NO USER')
        user={}
        user["id"]='no_user'
    response = requests.get(url, verify=False)
    Z=response.text+'*$'+threatgrid_sha+'**$'+threatgrid_sample_id+'***$'+threatgrid_sample_domains[0]+'****$'
    for item in umbrella_malicious_domains:
        Z=Z+item+'*****$' 
    for item_dict in umbrella_blacklist_enforcement:
        for item in item_dict.items():
            Z=Z+item[1]+'******$'
    for item_dict in ctr_observables:
        #print(item_dict)
        for item in item_dict.values():
            Z=Z+item+'********'             
    Z =Z+'$'+response_actions+'********$'+user["id"]
    print(yellow('\nYOUR MAGIC NUMBER IS :\n',bold=True))    
    print(Z)
