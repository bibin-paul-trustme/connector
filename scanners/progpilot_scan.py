import csv
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

def search_csv(search_id):
    file_path = config['LOCAL']['cwe_data_file']
    with open(file_path, 'r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row['CWE-ID'] == search_id:
                return row['Name']
        return None

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
    base_url = config['LOCAL']['trustme_progpilot_count_upload']
    response = requests.post(base_url, cert=(cert_file, key_file), headers=headers, data=count_data)
    print(response.text)
    
def nomalize_data(data, url, tenant, branch):

    severity_mapping = {
        "CWE_79": "Medium",
        "CWE_98": "High",
        "CWE_95": "High",
        "CWE_78": "High",
        "CWE_90": "Medium",
        "CWE_89": "Medium",
        "CWE_285": "Medium",
        "CWE_1004": "Medium",
        "CWE_346": "Medium",
        "CWE_295": "High",
        "CWE_91": "Medium",
        "CWE_22": "Medium",
        "CWE_601": "Medium",
        "CWE_1333": "Medium"
    }
    vulnerabilities = []
    for report_result in data['report']:
        directory, filename = os.path.split(report_result.get('sink_file',''))
        line_number = report_result.get('sink_line', '1')
        filename = filename
        cwe_id = report_result.get('vuln_cwe')
        severity_str = severity_mapping.get(cwe_id, "Low")
        result_data = {
            'title': search_csv(str(cwe_id.split('_')[1])),
            'filename': filename,
            'line_number': line_number,
            'severity': severity_str.upper(),
            'category': report_result.get('vuln_name'),
            'description': report_result.get('vuln_type'),
            'details': '',
            'reference': f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
        }
        vulnerabilities.append(result_data)





def progpilot_scan():
    print('=================progpilot Scan=====================')
    response_data =[]
    config = configparser.ConfigParser()
    config.read('svn_config.ini')

    accounts = config['LOCAL']['PHP_REPO_LIST']
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
                    progpilot_scan_command = r"php .\\files\\progpilot_v1.1.0.phar %s" %folder_name
                    result = subprocess.run(progpilot_scan_command, shell=True, capture_output=True, text=True)
                    if result.returncode == 1:
                        lines = result.stdout.splitlines()

                        # Filter out lines starting with "Deprecated:"
                        filtered_lines = [line for line in lines if not line.startswith("Deprecated:")]

                        # Join the filtered lines back into a single string
                        filtered_output = "\n".join(filtered_lines)
                        report =   json.loads(filtered_output)
                    else:
                        report = []
                    print('==='*50)
                    if report != []:
                        result_dict['url'] = url
                        result_dict['report'] = report
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

                progpilot_scan_command = r"php .\\files\\progpilot_v1.1.0.phar %s" %folder_name
                print(progpilot_scan_command)
                result = subprocess.run(progpilot_scan_command, shell=True, capture_output=True, text=True)
                report = json.loads(result.stdout)
                print('==='*50)
                if report['files'] != []:
                    result_dict['url'] = url
                    result_dict['report'] = report
                    result_dict['tenant_id'] = str(config['LOCAL']['TENANT_ID'])
                    nomalize_data(result_dict,  url, str(config['LOCAL']['TENANT_ID']), folder_name)
                else:
                    print('No data')
                
            else:
                print('Unable to checkout the repository')
progpilot_scan()
