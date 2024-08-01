import os
import subprocess
import configparser
import json
import shutil
import stat
import requests
import base64
from datetime import datetime
import uuid
import time 
import xml.etree.ElementTree as ET
import math

from services.svn_services import branch_list, repo_update, push_data

config = configparser.ConfigParser()
config.read("svn_config.ini")


def decode_base64(encoded_data):
    encoded_data = encoded_data.encode('utf-8')
    padding_needed = 4 - (len(encoded_data) % 4)
    if padding_needed != 4:
        encoded_data += b'=' * padding_needed
    decoded_data = base64.b64decode(encoded_data)
    return decoded_data

def custom_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()  # Serialize datetime as ISO format
    raise TypeError("Type not serializable")


def remove_readonly(func, path, _):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def count_calculation(data, url, tenant, branch, chunk_name):
    severity_counts = {
                    "LOW": 0,
                    "MEDIUM": 0,
                    "HIGH": 0
                }
    print(data[0])
    for file_info in data:
        # print(file_info["severity"])
        if file_info["severity"] == "CRITICAL":
            file_info["severity"] = "HIGH"
        elif file_info["severity"] == "INFORMATIONAL":
            file_info["severity"] = "LOW"
        severity = file_info["severity"]
        if severity in severity_counts:
            severity_counts[severity] += 1
    print(severity_counts)
    count_data = {}
    count_data['repository_url'] = url
    count_data['branch'] = branch
    count_data['chunk_name'] = chunk_name
    count_data['tenant_id'] = tenant
    count_data['count'] = severity_counts
    cert_file = str(config['LOCAL']['cert_file'])
    key_file = str(config['LOCAL']['key_file'])
    token = 'YOUR_TOKEN'
    headers = {
        'Authorization': f'Bearer {token}',
        'id' : f'{tenant}'     
    }
    base_url = config['LOCAL']['trustme_pmd_count_upload']
    response = requests.post(base_url, cert=(cert_file, key_file), headers=headers, data=count_data)
    print(response.text)
    
def nomalize_data(data, url, tenant, branch):
    file_name_chunk = uuid.uuid4()
    # print(data)
    total_violations = sum(len(file["violations"]) for file in data["data"]["files"])

    print("Total Violations:", total_violations)
    restructured_data = []

    for file_info in data['data']['files']:
        filename = file_info["filename"]
        for violation in file_info["violations"]:
            if violation["priority"] == 1:
                priority = "HIGH"
            elif violation["priority"] in [2,3]:
                priority =  "MEDIUM"
            else:
                priority =  "LOW"
            restructured_data.append({
                "url":data['url'],
                'batch_id' :str(file_name_chunk),
                'branch': branch,
                'created_at' :str(datetime.now()),
                'tenant_id' : decode_base64(data['tenant_id']).decode('utf-8'),
                "filename": filename,
                "beginline": violation["beginline"],
                "begincolumn": violation["begincolumn"],
                "endline": violation["endline"],
                "endcolumn": violation["endcolumn"],
                "description": violation["description"],
                "rule": violation["rule"],
                "ruleset": violation["ruleset"],
                "priority":  violation["priority"], 
                "severity" : priority,
                "externalInfoUrl": violation["externalInfoUrl"]
            })
    data["data"]["files"] = restructured_data
    print(data)




def pmd_scan(language):
    print('=================PMD Scan=====================')

    if language == 'JavaScript':
        RULESET = 'category/ecmascript/errorprone.xml, category/ecmascript/bestpractices.xml, category/ecmascript/codestyle.xml'

    elif language == 'Java':
        RULESET = 'category/java/security.xml, category/java/performance.xml, category/java/multithreading.xml, category/java/errorprone.xml, category/java/documentation.xml, category/java/codestyle.xml, category/java/bestpractices.xml'

    response_data =[]
    config = configparser.ConfigParser()
    config.read('svn_config.ini')

    accounts = config['LOCAL']['JAVA_REPO_LIST']
    svn_path = config['LOCAL']['SVN_PATH']
    print(accounts.split(','))
    
    for url in accounts.split(', '):
        url = url.strip()
        branches = branch_list(url)
        branch_count = len(branches)
        if branches != []:
            for branch in branches:
                print('==========>>>>>', branch)
                if url.endswith('/'):
                    folder_name = url.split('/')[-2]
                else:
                    folder_name = url.split('/')[-1]
                result_dict = {}
                response = repo_update(url)
                

                if response.returncode == 0:
                    print('Scanning started')
                    folder_name = folder_name +'/' + branch
                    pmd_scan_command = r"C:\pmd-bin-7.0.0-rc4\pmd-bin-7.0.0-rc4\bin\pmd.bat check -d %s -f json -R %s"  % (folder_name, RULESET)
                    print(pmd_scan_command)
                    result = subprocess.run(pmd_scan_command, shell=True, capture_output=True, text=True)
                    report = json.loads(result.stdout)
                    print(report)
                    print('==='*50)
                    if report['files'] != []:
                        result_dict['url'] = url
                        result_dict['data'] = report
                        result_dict['tenant_id'] = str(config['LOCAL']['TENANT_ID'])
                        nomalize_data(result_dict,  url, str(config['LOCAL']['TENANT_ID']), branch)
                    else:
                        print('No data')
                    
                else:
                    print('Unable to checkout the repository')
        else:
            if url.endswith('/'):
                folder_name = url.split('/')[-2]
            else:
                folder_name = url.split('/')[-1]
            result_dict = {}
            response_repo = repo_update(url)

            if response_repo.returncode == 0:
                print('Scanning started')

                pmd_scan_command = r"C:\pmd-bin-7.0.0-rc4\pmd-bin-7.0.0-rc4\bin\pmd.bat check -d %s -f json -R rulesets/java/quickstart.xml" %folder_name
                print(pmd_scan_command)
                result = subprocess.run(pmd_scan_command, shell=True, capture_output=True, text=True)
                report = json.loads(result.stdout)
                print('==='*50)
                if report['files'] != []:
                    result_dict['url'] = url
                    result_dict['data'] = report
                    result_dict['tenant_id'] = str(config['LOCAL']['TENANT_ID'])
                    nomalize_data(result_dict,  url, str(config['LOCAL']['TENANT_ID']), folder_name)
                else:
                    print('No data')
                
            else:
                print('Unable to checkout the repository')
# pmd_scan()
