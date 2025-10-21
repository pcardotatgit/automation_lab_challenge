'''
    version 4.0 20251021

'''    
from flask import Flask
from flask import Flask, flash, redirect, render_template, request, session, abort
from flask_request_params import bind_request_params
from crayons import blue, green, yellow, white, red, cyan
from datetime import datetime, timedelta
import json
import os
import sys
 
app = Flask(__name__)

Umbrella_Investigate_Token='Bearer 31801821-b9a1-4ad3-82d9-dfe2c93ffake'
UMBRELLA_ENFORCEMENT_KEY = "12345678-b9a1-4ad3-82d9-dfe2c93ffffz"
CSE_CLIENT_ID = "defg26458064a05f1faz"
CSE_API_KEY = "12345678-4f95-43d5-908d-7a7d41ad385z"
CSE_AUTHORIZATION ="Basic ZGVmZzI2NDU4MDY0YTA1ZjFmYXo6MTIzNDU2NzgtNGY5NS00M2Q1LTkwOGQtN2E3ZDQxYWQzODV6"
THREATGRID_API_KEY = "Bearer Zjttqveo7g1doaszbc0n6qfzzz"
CTR_CLIENT_ID = "client-bbaad7e2-e5ff-413f-1234-0e21bc871zzz"
CTR_API_KEY = "ZezA_VszEcMTCzzzU0Wr5mQypXoxbjFNKDnLa0Mkw_O_ZZ4TND9mZZ"
CTR_TOKEN="Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkhqVW4yNlBPUGZlWFFxeDEtcEc3TFU1MnBNRTRVMVlySWlJa29fUTJMV0kifQ.eyJodHRwczovL3NjaGVtYXMuY2lzY28uY29tL2lyb2gvaWRlbnRpdHkvY2xhaW1zL3VzZXIvZW1haWwiOiJwY2FyZG90QGNpc2NvLmNvbSIsImh0dHBzOi8vc2NoZW1hcy5jaXNjby5jb20vaXJvaC9pZGVudGl0eS9jbGFpbXMvdXNlci9zY29wZXMiOlsiaW50ZWdyYXRpb24iLCJwcml2YXRlLWludGVsIiwiYWRtaW4iLCJwcm9maWxlIiwiaW5zcGVjdCIsInNzZSIsInJlZ2lzdHJ5IiwidXNlcnMiLCJjYXNlYm9vayIsIm9yYml0YWwiLCJlbnJpY2giLCJvYXV0aCIsImNvbGxlY3QiLCJyZXNwb25zZSIsInVpLXNldHRpbmdzIiwidGVsZW1ldHJ5OndyaXRlIiwib3BlbmlkIiwibm90aWZpY2F0aW9uIiwiZ2xvYmFsLWludGVsOnJlYWQiLCJhbyJdLCJodHRwczovL3NjaGVtYXMuY2lzY28uY29tL2lyb2gvaWRlbnRpdHkvY2xhaW1zL3VzZXIvaWRwL2lkIjoiaWRiLWFtcCIsImh0dHBzOi8vc2NoZW1hcy5jaXNjby5jb20vaXJvaC9pZGVudGl0eS9jbGFpbXMvdXNlci9uaWNrIjoiUGF0cmljayBDYXJkb3QiLCJlbWFpbCI6InBjYXJkb3RAY2lzY28uY29tIiwiYXVkIjoiY2xpZW50LWJiYWViN2UyLWU1YmItNDEzZi04NDY5LTBlMjFiYzg3MTJiYyIsImh0dHBzOi8vc2NoZW1hcy5jaXNjby5jb20vaXJvaC9pZGVudGl0eS9jbGFpbXMvdXNlci9yb2xlIjoiYWRtaW4iLCJzdWIiOiJiYjRjMDdkMy0zYjhjLTQxYTYtYjBlYS1hODZlNWY5NWQ3YTAiLCJpc3MiOiJJUk9IIEF1dGgiLCJodHRwczovL3NjaGVtYXMuY2lzY28uY29tL2lyb2gvaWRlbnRpdHkvY2xhaW1zL3Njb3BlcyI6WyJwcml2YXRlLWludGVsIiwiZW5yaWNoOnJlYWQiLCJjYXNlYm9vayIsImluc3BlY3Q6cmVhZCIsInJlc3BvbnNlIiwiZ2xvYmFsLWludGVsOnJlYWQiXSwiZXhwIjoxNjAxNDU5MTczLCJodHRwczovL3NjaGVtYXMuY2lzY28uY29tL2lyb2gvaWRlbnRpdHkvY2xhaW1zL29hdXRoL2NsaWVudC9uYW1lIjoicGF0cmlja19jdHJfYXBpX2tleSIsImh0dHBzOi8vc2NoZW1hcy5jaXNjby5jb20vaXJvaC9pZGVudGl0eS9jbGFpbXMvb2F1dGgvdXNlci9pZCI6ImJiNGMwN2QzLTNiOGMtNDFhNi1iMGVhLWE4NmU1Zjk1ZDdhMCIsImh0dHBzOi8vc2NoZW1hcy5jaXNjby5jb20vaXJvaC9pZGVudGl0eS9jbGFpbXMvb3JnL2lkIjoiNDE2MDM4MjYtNjA4ZS00YTRlLThiNjItYjE3ZjkwNjRmOWJkIiwiaHR0cHM6Ly9zY2hlbWFzLmNpc2NvLmNvbS9pcm9oL2lkZW50aXR5L2NsYWltcy9vYXV0aC9ncmFudCI6ImNsaWVudC1jcmVkcyIsImh0dHBzOi8vc2NoZW1hcy5jaXNjby5jb20vaXJvaC9pZGVudGl0eS9jbGFpbXMvb3JnL25hbWUiOiJDaXNjbyAtIHBjYXJkb3QiLCJqdGkiOiJ0b2tlbi05MDExZWJiNS0wZWQxLTQ3N2UtYTRhNS0yODc4N2Y3NjEwYmUiLCJuYmYiOjE2MDE0NTg1MTMsImh0dHBzOi8vc2NoZW1hcy5jaXNjby5jb20vaXJvaC9pZGVudGl0eS9jbGFpbXMvb2F1dGgvc2NvcGVzIjpbInByaXZhdGUtaW50ZWwiLCJlbnJpY2g6cmVhZCIsImNhc2Vib29rIiwiaW5zcGVjdDpyZWFkIiwicmVzcG9uc2UiLCJnbG9iYWwtaW50ZWw6cmVhZCJdLCJodHRwczovL3NjaGVtYXMuY2lzY28uY29tL2lyb2gvaWRlbnRpdHkvY2xhaW1zL3VzZXIvbmFtZSI6IlBhdHJpY2sgQ2FyZG90IiwiaHR0cHM6Ly9zY2hlbWFzLmNpc2NvLmNvbS9pcm9oL2lkZW50aXR5L2NsYWltcy91c2VyL2lkIjoiYmI0YzA3ZDMtM2I4Yy00MWE2LWIwZWEtYTg2ZTVmOTVkN2EwIiwiaHR0cHM6Ly9zY2hlbWFzLmNpc2NvLmNvbS9pcm9oL2lkZW50aXR5L2NsYWltcy9vYXV0aC9jbGllbnQvaWQiOiJjbGllbnQtYmJhZWI3ZTItZTViYi00MTNmLTg0NjktMGUyMWJjODcxMmJjIiwiaHR0cHM6Ly9zY2hlbWFzLmNpc2NvLmNvbS9pcm9oL2lkZW50aXR5L2NsYWltcy92ZXJzaW9uIjoidjEuMzkuMC1hNTBkMDllZWRmMWNkYzUwODBjYyIsImlhdCI6MTYwMTQ1ODU3MywiaHR0cHM6Ly9zY2hlbWFzLmNpc2NvLmNvbS9pcm9oL2lkZW50aXR5L2NsYWltcy9vYXV0aC9raW5kIjoiYWNjZXNzLXRva2VuIn0.pjQUsxKLn7kONHYJFaI7K5U4w3hs7n-3zLrwk13GBilgfaSQX10uSPAyWZ8nCQplx0gJ20Q9L7Z2XWeoI3VZKBYmWaJ8VvlQBNmie6klugGK54o1ysnf-YtgErgB5eo7lslu8nCMuCgxobXcCv5J4_hF0R9934UCGBH4NqqbogmPJe0lupsdyeXj9X1hf0Yx1fMDIJsaCU0QTTxzmZPj2wP_ywdyGFud4DagqGfFBUeOA6SaGh_iBtgcTF9No6VZLviLPde2UDrt4FcrTWmtlKF-BHvpusZZu1EAGs4ZpLwl9-QIouPOCdIou-umfMtEF_VLS71bjfiot4zUuojWQA"
UMBRELLA_TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMTktMDEtMDEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJ1bWJyZWxsYS1hdXRoei9hdXRoc3ZjIiwic3ViIjoib3JnLzE5NTMxMTUvdXNlci83ODg3OTk3IiwiZXhwIjoxNzYwNjQ5NDcyLCJuYmYiOjE3NjA2NDU4NzIsImlhdCI6MTc2MDY0NTg3Miwic2NvcGUiOiJyb2xlOnJvb3QtYWRtaW4iLCJhdXRoel9kb25lIjpmYWxzZX0.P9Lmb4nvcjjLhltk8aSjdT2vG1ITybsjAFaNgVprRZ-5lpQMkIG3Sbnc94GhEp2RKduFO2q3kgS9VUayjfqpZnRRFrFVvld5AnhAcA_m0PHz0Kdbq-OwjRmv7K4CuvCwxgJ1L03jKZY1zJQmU7QEjEMlT44d0ZODQAr19aRoMFRR8yCKOyaZZHOuJ5f8ghdeunVtXVhEEJtDKSw1aEORJQEsCCtR888qbjFd38BCy0ZpAI16JpL3r3RJQMbduVz1nNUi8dKnIrqcSqBCkWPMyutri0epQSgMLqOmVkA_Ts0oTlCl0eCmB4B5ac4mYdZ8tkNH7Ay5eJ3w_cWD_y9BYQ"

def t_():
    current_time = datetime.utcnow()
    current_time = current_time.strftime("$%Y%m%dW%H%M%S.%fZ")
    return(current_time)

def b_(t):
    with open('./templates/28b.json','a+') as file:
        file.write(t)
              

@app.route('/')
def index():
    headers = request.headers
    token = headers['Authorization']
    return "Sounds Good"

@app.route('/test')
def test():
    return render_template('check.html')
 
'''
    HERE UNDER CSE ROUTES
'''
@app.route("/v1/events", methods=['GET'])
def CSE1():
    """Get a list of recent events from Cisco CSE."""
    #?connector_guid[]=7eb09223-b9b3-4508-ac9f-d16fffbdafb0&event_type[]=1107296272&event_type[]=1090519054&limit=10
    #TO DEBUG
    #connector_guid=request.args.get('connector_guid')   
    b_('3')
    token = request.headers.get('Authorization')
    print()
    print(cyan('CSE GET All Events for a specific Computer',bold=True))
    print(cyan('received token :'+token,bold=True))     
    print()
    if token==CSE_AUTHORIZATION:
        return render_template('2.json')       
    else: 
        return '{"ERROR": {"error cause":"invalid Authentication Basic Token :'+token+' "}}'        

@app.route("/v1/computers", methods=['GET'])
def CSE2():
    token = request.headers.get('Authorization')   
    with open('./templates/28b.json','w') as file:
        file.write(t_())    
    b_('1')    
    print()
    print(cyan('CSE GET All Computers',bold=True))
    print(cyan('received token :'+token,bold=True))   
    print()
    #"""Get a list of computers from Cisco CSE."""
    if token==CSE_AUTHORIZATION:
        return render_template('1.json')       
    else: 
        return '{"ERROR": {"error cause":"invalid Authentication Basic Token :'+token+' "}}'    
 
@app.route("/v1/computers/fc2842aa-12a7-4e65-ab73-b4d8053a9d9d", methods=['GET','PUT','PATCH','DELETE'])
def CSE3b():
    token = request.headers.get('Authorization')
    print()
    print(cyan('received token :'+token,bold=True))   
    print()
    if token==CSE_AUTHORIZATION:
        if request.method == 'GET':
            print(cyan("/v1/computers/ ECHO: GET",bold=True))
            prtin()
            return render_template('3.json')
        elif request.method == 'PATCH':
            print(cyan("CSE PATCH Move Computer to new Group",bold=True))
            print()            
            return render_template('7-Move_Computer_to_new_Group.json')
        elif request.method == 'PUT':
            return "ECHO: PUT\n"           
    else: 
        return '{"ERROR": {"error cause":"invalid Authentication Basic Token :'+token+' "}}'  
 
@app.route("/v1/computers/7eb09223-b9b3-4508-ac9f-d16fffbdafb0", methods=['GET','PUT','PATCH','DELETE'])
def CSE3():
    token = request.headers.get('Authorization')
    print()
    print(cyan('received token :'+token,bold=True))   
    print()
    if token==CSE_AUTHORIZATION:
        if request.method == 'GET':
            print(cyan("/v1/computers/ ECHO: GET",bold=True))
            prtin()
            return render_template('3.json')
        elif request.method == 'PATCH':
            print(cyan("APMP PATCH Move Computer to new Group",bold=True))
            print()            
            return render_template('7-Move_Computer_to_new_Group.json')
        elif request.method == 'PUT':
            return "ECHO: PUT\n"           
    else: 
        return '{"ERROR": {"error cause":"invalid Authentication Basic Token :'+token+' "}}' 

@app.route("/v1/computers/7eb09223-b9b3-4508-ac9f-d16fffbdafb0/isolation", methods=['GET','PUT','PATCH','DELETE'])
def CSE4():
    token = request.headers.get('Authorization')
    print()
    print(cyan('received token :'+token,bold=True))   
    print()
    with open('./templates/isolation_status.txt','r') as file2:
        statut=file2.read()        
    if token==CSE_AUTHORIZATION:
        if request.method == 'GET':
            print(cyan("CSE GET Check status for Computer Isolation",bold=True)) 
            print(cyan(f"  current statut isolation is equal to {statut}",bold=True))
            if statut=='1':      
                b_('4')
                return render_template('10-Check_status_for_Computer_Isolation_isolated.json')
            else:
                return render_template('10b-Check_status_for_Computer_Isolation_isolated.json')
        elif request.method == 'PUT':
            print(cyan("CSE PUT : Isolate infected Computer",bold=True)) 
            print()
            if statut=='1': 
                print(cyan("Computer already isolated",bold=True)) 
                return render_template('21-Isolate_infected_Computer_error_409.json')
            else:
                with open('./templates/isolation_status.txt','w') as file2:
                    file2.write('1')              
                return render_template('8-Isolate_infected_Computer.json')    
        elif request.method == 'DELETE':
            print(cyan("CSE DELETE Delete Isolation of infected Computer",bold=True)) 
            print()
            with open('./templates/isolation_status.txt','w') as file2:
                file2.write('0')              
            return render_template('9-Delete_Isolation_of_infected_Computer.json')         
    else: 
        return '{"ERROR": {"error cause":"invalid Authentication Basic Token :'+token+' "}}'
        
@app.route("/v1/computers/fc2842aa-12a7-4e65-ab73-b4d8053a9d9d/isolation", methods=['GET','PUT','PATCH','DELETE'])
def CSE4b():
    token = request.headers.get('Authorization')
    print()
    print(cyan('received token :'+token,bold=True))   
    print()
    with open('./templates/isolation_status.txt','r') as file2:
        statut=file2.read()        
    if token==CSE_AUTHORIZATION:
        if request.method == 'GET':
            print(cyan("CSE GET Check status for Computer Isolation",bold=True)) 
            print(cyan(f"  current statut isolation is equal to {statut}",bold=True))
            if statut=='1':            
                return render_template('10-Check_status_for_Computer_Isolation_isolated.json')
            else:
                return render_template('10b-Check_status_for_Computer_Isolation_isolated.json')
        elif request.method == 'PUT':
            print(cyan("CSE PUT : Isolate infected Computer",bold=True)) 
            print()
            if statut=='1': 
                print(cyan("Computer already isolated",bold=True)) 
                return render_template('21-Isolate_infected_Computer_error_409.json')
            else:
                print(cyan("Computer NOT already isolated",bold=True))
                with open('./templates/isolation_status.txt','w') as file2:
                    file2.write('1')   
                with open('./templates/8-Isolate_infected_Computer.json') as file:
                    text_content=file.read()
                print(text_content)
                return render_template('8-Isolate_infected_Computer.json')    
        elif request.method == 'DELETE':
            print(cyan("CSE DELETE Delete Isolation of infected Computer",bold=True)) 
            print()
            with open('./templates/isolation_status.txt','w') as file2:
                file2.write('0')              
            return render_template('9-Delete_Isolation_of_infected_Computer.json')         
    else: 
        return '{"ERROR": {"error cause":"invalid Authentication Basic Token :'+token+' "}}'


@app.route("/v1/computers/fc2842aa-12a7-4e65-ab73-b4d8053a9d9d/vulnerabilities", methods=['GET'])
def CSE5():
    token = request.headers.get('Authorization')
    print()
    print(cyan("CSE GET All Vulnerabilities for a specific Computer",bold=True))
    print(cyan('received token :'+token,bold=True))   
    print()
    if token==CSE_AUTHORIZATION:
        return render_template('6-All_Vulnerabilities_for_a_specific_Computer.json')  
    else: 
        return '{"ERROR": {"error cause":"invalid Authentication Basic Token :'+token+' "}}'

@app.route("/v1/event_types", methods=['GET'])
def CSE6():
    token = request.headers.get('Authorization')
    print()
    print(cyan('CSE GET Event Types',bold=True))
    print(cyan('received token :'+token,bold=True))     
    print()
    if token==CSE_AUTHORIZATION:
        return render_template('1-get_event_type_id.json')        
    else: 
        return '{"ERROR": {"error cause":"invalid Authentication Basic Token :'+token+' "}}'  
        
        
@app.route("/v1/groups", methods=['GET'])
def CSE7():
    token = request.headers.get('Authorization')
    print()
    print(cyan('CSE GET All Groups',bold=True))
    print(cyan('received token :'+token,bold=True))     
    print()
    if token==CSE_AUTHORIZATION:
        return render_template('3-get_all_groups.json')       
    else: 
        return '{"ERROR": {"error cause":"invalid Authentication Basic Token :'+token+' "}}'      
    
@app.route("/v1/file_lists/simple_custom_detections", methods=['GET'])
def CSE8():
    token = request.headers.get('Authorization')
    print()
    print(cyan('CSE Get All Simple Custom Detections',bold=True))
    print(cyan('received token :'+token,bold=True))     
    print()
    if token==CSE_AUTHORIZATION:
        return render_template('4-get_all_simple_detection.json')      
    else: 
        return '{"ERROR": {"error cause":"invalid Authentication Basic Token :'+token+' "}}'     

@app.route("/v1/file_lists/10050bbc-cc0a-48b9-b8ce-71fbec2fba6c/files/b1380fd95bc5c0729738dcda2696aa0a7c6ee97a93d992931ce717a0df523967", 
methods=['POST'])
def CSE9():
    token = request.headers.get('Authorization')
    print()
    print(cyan('CSE Get All Simple Custom Detections',bold=True))
    print(cyan('received token :'+token,bold=True))     
    print()
    if token==CSE_AUTHORIZATION:
        return render_template('16-add_file_to_block_list.json')      
    else: 
        return '{"ERROR": {"error cause":"invalid Authentication Basic Token :'+token+' "}}'  

        
'''
    HERE UNDER MALWARE ANALYTICS ROUTES
'''
        
@app.route("/api/v2/search/submissions", methods=['GET'])
def TG1():
    sha=request.args['q']
    token = 'Bearer '+request.args['api_key']    
    print()
    print(cyan('ThreatGrid GET Sample Submissions Search',bold=True))
    print(cyan('received token :'+token,bold=True))  
    print(cyan('received sha :'+sha,bold=True))
    print()    
    if token==THREATGRID_API_KEY:
        if sha=='b1380fd95bc5c0729738dcda2696aa0a7c6ee97a93d992931ce717a0df523967':
            b_('4')
            return render_template('5.json')
        else: 
            return '{"ERROR": {"error cause":"this is not the expected sha256 '+sha+'"}}'          
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+' "}}'
    
@app.route("/api/v2/samples/feeds/domains", methods=['GET'])
def TG2():
    token = 'Bearer '+request.args['api_key']    
    sample = request.args['sample']  
    print()
    print(cyan('ThreatGrid GET Request Sample Domains',bold=True))
    print(cyan('received token :'+token,bold=True)) 
    print(cyan('received sample :'+sample,bold=True))    
    print()     
    if token==THREATGRID_API_KEY:
        if sample=='4d1e71bf3fa1a98b23fb7cb6e3ab2ad6':
            return render_template('6.json')
        elif sample=='d826d1eec635e7d77c1d9dd7abb0a8e5':
            return render_template('6.json')
        else: 
            return '{"ERROR": {"error cause":"this is not the expected sample_ID : '+sample+'"}}'      
    else: 
        return '{"ERROR": {"error cause":"invalid token **:'+token+'"}}'
        
    
@app.route("/api/v2/iocs/feeds/domains", methods=['GET'])
def TG3():
    token = 'Bearer '+request.args['api_key']       
    print()
    print(cyan('ThreatGrid GET IOC feeds',bold=True))
    print(cyan('received token :'+token,bold=True))     
    print()    
    if token==THREATGRID_API_KEY:
        if 'confidence' in request.args:
            return render_template('27.json')
        else:
            return render_template('1_IOC_Feeds.json')        
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+' "}}'

@app.route("/api/v3/feeds/dga-dns_2020-01-08.json", methods=['GET'])
def TG4():
    token = 'Bearer '+request.args['api_key']   
    print()
    print(cyan('ThreatGrid GET Feed in JSON format',bold=True))
    print(cyan('received token :'+token,bold=True))     
    print()     
    if token==THREATGRID_API_KEY:
            return render_template('2-Feed_in_JSON_format.json')        
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+' "}}'
        
@app.route("/api/v2/samples/d826d1eec635e7d77c1d9dd7abb0a8e5/analysis.json", methods=['GET'])
def TG5b():
    token = 'Bearer '+request.args['api_key']  
    print()
    print(cyan('ThreatGrid GET Request Sample Analysis Report',bold=True))
    print(cyan('received token :'+token,bold=True))     
    print()     
    if token==THREATGRID_API_KEY:
            return render_template('5-Request_Sample_Analysis_Report.json')        
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+' "}}' 
        
@app.route("/api/v2/samples/4d1e71bf3fa1a98b23fb7cb6e3ab2ad6/analysis.json", methods=['GET'])
def TG5():
    token = 'Bearer '+request.args['api_key']  
    print()
    print(cyan('ThreatGrid GET Request Sample Analysis Report',bold=True))
    print(cyan('received token :'+token,bold=True))     
    print()     
    if token==THREATGRID_API_KEY:
            return render_template('5-Request_Sample_Analysis_Report.json')        
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+' "}}' 
        
@app.route("/api/v3/feeds/ransomware-dns_2020-01-08.stix", methods=['GET'])
def TG6():
    token = 'Bearer '+request.args['api_key']  
    print()
    print(cyan('ThreatGrid GET Feed in STIX format',bold=True))
    print(cyan('received token :'+token,bold=True))     
    print()    
    if token==THREATGRID_API_KEY:
        return render_template('tg_stix.json')        
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+' "}}'
     
        
'''
    HERE UNDER UMBRELLA ROUTES
'''
@app.route("/domains/categorization", methods=['GET','POST'])
def Umbrella1():
    token = request.headers['Authorization']
    print()
    print(cyan('Umbrella GET Get Single Domain Status and Categorization',bold=True))
    print(cyan('received token :'+token,bold=True))   
    print()     
    if token==Umbrella_Investigate_Token:
        return render_template('7.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'
 
@app.route("/1.0/events", methods=['POST'])
def Umbrella2():
    headers = request.headers
    token = request.args['customerKey']
    print()
    print(cyan('Umbrella POST Enforce on bad Domains in Umbrella',bold=True))
    print()     
    if token==UMBRELLA_ENFORCEMENT_KEY:
        return render_template('14.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}' 
        
@app.route("/1.0/events?customerKey=12345678-b9a1-4ad3-82d9-dfe2c93ffffz", methods=['POST'])
def Umbrella2b():
    headers = request.headers
    token = request.args['customerKey']
    print()
    print(cyan('Umbrella POST Enforce on bad Domains in Umbrella',bold=True))
    print()     
    if token==UMBRELLA_ENFORCEMENT_KEY:
        b_('10')
        return render_template('14.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}' 

@app.route("/1.0/domains", methods=['GET'])
def umbrella3():
    #TO DEBUG
    headers = request.headers
    #token = headers['Authorization']
    token = request.args['customerKey']
    print()
    print(cyan('Umbrella POST Enforce on bad Domains in Umbrella',bold=True))
    print()     
    if token==UMBRELLA_ENFORCEMENT_KEY:
        return render_template('26-Get_all_domains_in_a_custom_Enforcement_List.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}' 
        
        
@app.route("/domains/categorization/retdemos.com", methods=['GET'])
def umbrella4():
    token = request.headers['Authorization']
    print()
    print(cyan('Umbrella GET Get Single Domain Status and Categorization',bold=True))
    print()       
    if token==Umbrella_Investigate_Token:
        return render_template('1-Get_Single_Domain_Status_and_Categorization.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'    
        
@app.route("/domains/categorization/['retdemos.com']", methods=['GET'])
def umbrella5():
    token = request.headers['Authorization']
    if token==Umbrella_Investigate_Token:
        return render_template('1-Get_Single_Domain_Status_and_Categorization.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'     

@app.route("/domains/categorization/%5B'retdemos.com',%20'retdemos.com',%20'retdemos.com'%5D", methods=['GET'])
def umbrella5b():
    token = request.headers['Authorization']
    if token==Umbrella_Investigate_Token:
        return render_template('1-Get_Single_Domain_Status_and_Categorization.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'          

@app.route("/pdns/domain/internetbadguys.com", methods=['GET'])
def umbrella6():
    token = request.headers['Authorization']
    print()
    print(cyan('Umbrella GET Get Historical Data on a Domain',bold=True))
    print()     
    if token==Umbrella_Investigate_Token:
        return render_template('2-Get_Historical_Data_on_a_Domain.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'   

@app.route("/recommendations/name/internetbadguys.com.json", methods=['GET'])
def umbrella7():
    token = request.headers['Authorization']
    print()
    print(cyan('Umbrella GET Co-Occurences for a Domain',bold=True))
    print()     
    if token==Umbrella_Investigate_Token:
        return render_template('Co-Occurences_for_a_Domain.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'   

@app.route("/links/name/example.com.json", methods=['GET'])
def umbrella8():
    token = request.headers['Authorization']
    print()
    print(cyan('Umbrella GET Related Domains for a Domain',bold=True))
    print()      
    if token==Umbrella_Investigate_Token:
        return render_template('4-Related_Domains_for_a_Domain.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'     

@app.route("/security/name/getmalware.com.json", methods=['GET'])
def umbrella9():
    token = request.headers['Authorization']
    print()
    print(cyan('Umbrella GET Get Security Report for domain',bold=True))
    print()      
    if token==Umbrella_Investigate_Token:
        return render_template('5-Get_Security_Report_for_domain.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'  

@app.route("/domains/risk-score/getmalware.com", methods=['GET'])
def umbrella10():
    token = request.headers['Authorization']
    print()
    print(cyan('Umbrella GET Get Risk Score for domain',bold=True))
    print()       
    if token==Umbrella_Investigate_Token:
        return render_template('6-Get_Risk_Score_for_domain.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'  

@app.route("/samples/getmalware.com", methods=['GET'])
def umbrella11():
    token = request.headers['Authorization']
    print()
    print(cyan('Umbrella GET Threat Grid Integration',bold=True))
    print()      
    if token==Umbrella_Investigate_Token:
        return render_template('7-Threat_Grid_Integration.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'      
        
@app.route("/1", methods=['GET']) #TO DEBUG
def umbrella12():
    token = request.headers['Authorization']
    print()
    print(cyan('Umbrella GET Enforce on bad Domains in Umbrella',bold=True))
    print()     
    if token==Umbrella_Investigate_Token:
        return render_template('15.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'  
        
@app.route('/auth/v2/token', methods = ['POST'])
def umbrella_token():
    with open('./templates/umbrella_token.json') as file:
        text_content=file.read()
    response=json.dumps(text_content)
    print(cyan(response,bold=True))
    #print(cyan(type(response),bold=True))  
    return render_template('umbrella_token.json')
    
@app.route('/v2/activity/dns', methods = ['GET'])
def umbrella_get_dns_activity():
    token = request.headers['Authorization']
    global UMBRELLA_TOKEN
    print('token : \n',cyan(token))
    print('Umbrella token : \n',cyan(UMBRELLA_TOKEN))    
    token = token.replace('Bearer ','')    
    if token!=UMBRELLA_TOKEN:
        print(red('Bad Token'))
        return ({})
    else:  
        return render_template('29_dns_activity.json')    
        
'''
    HERE UNDER XDR THREAT RESPONSES ROUTES
'''
       
@app.route("/iroh/oauth2/token", methods=['POST'])
def CTR1():
    payload=request.form['grant_type']
    print()
    print(cyan('Threat Response POST Auth',bold=True))    
    print(cyan("Received payload : "+payload,bold=True)) 
    print()
    token = 'OK'
    if payload=='client_credentials':
        return render_template('9.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}' 
        
@app.route("/iroh/iroh-inspect/inspect", methods=['GET','POST'])
def CTR2():
    token =request.headers['Authorization']
    print()
    print(cyan('Threat Response POST Inspect',bold=True))    
    #print(cyan("Received token : "+token,bold=True)) 
    print()    
    if token==CTR_TOKEN:
        b_('12')
        return render_template('10.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'         
        
@app.route("/iroh/iroh-enrich/observe/observables", methods=['POST'])
def CTR3():
    token =request.headers['Authorization']
    print()
    print(cyan('Threat Response POST Enrich - Observe',bold=True))         
    data = request.data  # TO DEBUG PATRICK
    #data = request.params['data']
    observable_str=''
    print(cyan("observe_payload: ",bold=True))      
    for item in data:
        observable_str+=chr(item)
    #observable=data[0]
    print(cyan(observable_str,bold=True))
    if token==CTR_TOKEN:
        if observable_str=='[{"value": "b1380fd95bc5c0729738dcda2696aa0a7c6ee97a93d992931ce717a0df523967", "type": "sha256"}]':
            b_('13')
            return render_template('11.json')
        else:
            b_('13b')
            return '{"ERROR": "wrong value for observe_payload "}'
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'       
        
@app.route("/iroh/iroh-response/respond/observables", methods=['POST'])
def CTR4():
    token =request.headers['Authorization']    
    print()
    print(cyan('Threat Response POST Response - Observables',bold=True))  
    print()
    data=json.loads(request.data)     
    observable_value=data['value']
    print()
    print('observable_value: ',observable_value)    
    observable_type=data['type']
    print()
    print('observable_type: ',observable_type)   
    if token==CTR_TOKEN:
        if observable_type=='hostname':
            return render_template('response_actions_for_hostnames.json')
        elif observable_type=='ip':
            return render_template('response_actions_for_ip.json')
        elif observable_type=='domain':
            return render_template('response_actions_for_domain.json')
        elif observable_type=='sha256':
            return render_template('response_actions_for_sha256.json')
        else:
            return ({})
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'      

@app.route("/iroh/iroh-response/respond/trigger/21bb0ed7-937c-4fc7-9338-34e05a8d6916/amp-add-sha256-scd", methods=['POST'])
def CTR5():
    token =request.headers['Authorization']
    print()
    print(cyan('Threat Response POST Response - Trigger action',bold=True))  
    print()    
    if token==CTR_TOKEN:
        b_('17')
        return render_template('13.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'  

@app.route("/iroh/iroh-response/respond/trigger/21bb0ed7-937c-4fc7-9338-34e05a8d6916/amp-remove-sha256-scd", methods=['POST'])
def CTR5b():
    token =request.headers['Authorization']
    print()
    print(cyan('Threat Response POST Response - Trigger action',bold=True))  
    print()    
    if token==CTR_TOKEN:
        b_('17')
        return render_template('13.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'     
        
        
        
@app.route("/iroh/iroh-enrich/deliberate/observables", methods=['POST'])
def CTRR():
    token =request.headers['Authorization']
    print()
    print(cyan('Threat Response POST Enrich - Deliberate',bold=True))    
    #print(cyan("Received token : "+token,bold=True)) 
    print()      
    if token==CTR_TOKEN:
        return render_template('3-Enrich_-_Deliberate.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'  
           
@app.route("/v1/disposition", methods=['GET'])
def CTR6():
    print()
    print(cyan('Threat Response POST Enrich - Deliberate',bold=True))    
    #print(cyan("Received token : "+token,bold=True)) 
    print()
    with open('./templates/28b.json','r') as file2:
        T='{'+file2.read()+'}'     
    return T          
        
@app.route("/iroh/iroh-enrich/refer/observables", methods=['POST'])
def CTR7():
    token =request.headers['Authorization']
    print()
    print(cyan('Threat Response POST Refer',bold=True))    
    #print(cyan("Received token : "+token,bold=True)) 
    print()    
    if token==CTR_TOKEN:
        return render_template('5-refer.json')
    else: 
        return '{"ERROR": {"error cause":"invalid token :'+token+'"}}'     

@app.route("/respond/trigger/22g678f2-ad5e-4374-8708-a8fcc7861f6c/01HP8SN2BIX9I1IR4dI1b4l9q1DQVwziOKo", methods=['POST'])
def CTR8():
    print(cyan("Trigger CSE host isolation workflow",bold=True)) 
    print()
    data=json.loads(request.data)     
    observable_value=data['value']
    print()
    print('observable_value: ',observable_value)    
    observable_type=data['type']
    print()
    print('observable_type: ',observable_type)     
    if observable_value=='Demo_AMP_Threat_Audit' and observable_type=='hostname':
        with open('./templates/isolation_status.txt','r') as file2:
            statut=file2.read()       
        if statut=='1': 
            print(cyan("Computer already isolated",bold=True)) 
            return render_template('21-Isolate_infected_Computer_error_409.json')
        else:
            with open('./templates/isolation_status.txt','w') as file2:
                file2.write('1')              
            return render_template('8-Isolate_infected_Computer.json')               
    else:
        return ('"status": "unknown"')
        
@app.route("/respond/trigger/9c99aefa-64be-4a3d-884e-d4f14e60eebc/01YD3Z1A74H553WXOpHSOD0cJVN1fw1ik0T", methods=['POST'])
def CTR9():
    print(cyan("Trigger ISE host Quarantine workflow",bold=True)) 
    print()
    data=json.loads(request.data)     
    observable_value=data['value']
    print()
    print('observable_value: ',observable_value)    
    observable_type=data['type']
    print()
    print('observable_type: ',observable_type)  
    infected_machine_list=['192.168.128.192', '192.168.128.181', '192.168.128.156']    
    if observable_type=='ip':   
        if observable_value in infected_machine_list and observable_type=='ip':            
            return ('"quarantine"')   
        else:
            return ('"status": "unknown"')            
    else:
        return ('"status": "unknown"')
        
@app.route("/respond/trigger/4b7a22cb-09a2-4b35-9b62-199bb55329c6/block", methods=['POST'])
def CTR10():
    print(cyan("Trigger adding domain to umbrella blocking list",bold=True)) 
    print()
    data=json.loads(request.data)     
    observable_value=data['value']
    print()
    print('observable_value: ',observable_value)    
    observable_type=data['type']
    print()
    print('observable_type: ',observable_type)     
    if observable_type=='domain':   
        if observable_value == "retdemos.com":            
            return ('umbrella_ok')   
        else:
            return ('"status": "unknown"')            
    else:
        return ('"status": "unknown"')
        
        
@app.route("/respond/trigger/9c99aefa-8b06-4df8-96f4-a89e3f2556ef/01GWHRNGESXD03H9ZF47jbf3ZzJKez1F0Ej", methods=['POST'])
def CTR11():
    print(cyan("Trigger adding domain to umbrella blocking list",bold=True)) 
    print()
    data=json.loads(request.data)     
    observable_value=data['value']
    print()
    print('observable_value: ',observable_value)    
    observable_type=data['type']
    print()
    print('observable_type: ',observable_type)     
    if observable_type=='sha256':   
        if observable_value == "b1380fd95bc5c0729738dcda2696aa0a7c6ee97a93d992931ce717a0df523967" :   
            print(green('QUARANTINE SHA256',bold=True))
            return ('CSE_QUARANTINE_OK')   
        else:
            print(red('ERROR 2',bold=True))
            return ('"status": "error"')            
    else:
        print(red('ERROR 1',bold=True))   
        return ('"status": "error"')
'''
        HERE UNDER JUST SOME EXAMPLES
'''
        
@app.route('/echo', methods = ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'])
def api_echo():
    # just example about how to handle method
    if request.method == 'GET':
        return "ECHO: GET\n"

    elif request.method == 'POST':
        return "ECHO: POST\n"

    elif request.method == 'PATCH':
        return "ECHO: PACTH\n"

    elif request.method == 'PUT':
        return "ECHO: PUT\n"

    elif request.method == 'DELETE':
        return "ECHO: DELETE"

@app.route('/v1/next', methods = ['POST'])
def next():
    t =request.data.decode("utf-8") 
    print("OK step :",t)
    with open('./templates/28b.json','a+') as file:
        file.write(t)
    return "1"
        
@app.route('/messages', methods = ['POST'])
def api_message():
    # just example
    if request.headers['Content-Type'] == 'text/plain':
        return "Text Message: " + request.data

    elif request.headers['Content-Type'] == 'application/json':
        return "JSON Message: " + json.dumps(request.json)

    elif request.headers['Content-Type'] == 'application/octet-stream':
        f = open('./binary', 'wb')
        f.write(request.data)
        f.close()
        return "Binary message written!"

    else:
        return "415 Unsupported Media Type ;)"  
        

    
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html'), 404 
    
    
if __name__ == "__main__":
    print()
    print(cyan("     Automation Lab Backend Simulator v4.0 "))
    print()
    with open('./templates/isolation_status.txt','w') as file2:
        file2.write('0')     
    app.secret_key = os.urandom(12)
    app.run(debug=False,host='0.0.0.0',port=4000,ssl_context='adhoc')
