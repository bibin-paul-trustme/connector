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

def search_csv(search_id):
    file_path = 'files\cwe_data.csv'
    with open(file_path, 'r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row['CWE-ID'] == search_id:
                return row['Name']
        return None


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
    base_url = config['LOCAL']['trustme_ruff_count_upload']
    response = requests.post(base_url, cert=(cert_file, key_file), headers=headers, data=count_data)
    print(response.text)
    
def nomalize_data(data, url, tenant, branch):
    print(data)
    vulnerabilities = []
    for report_result in data['report'].get('Issues', []):
        # directory, filename = os.path.split(report_result.get('file'))
        line_number = report_result.get('line', '1')
        split_line_number = line_number.split("-")
        line_number = int(split_line_number[0])
        filename = report_result.get('file')
        severity_str = report_result.get('severity')
        result_data = {

                'title': report_result.get('details'),
                'filename': filename,
                'line_number': line_number,
                'severity': severity_str.upper(),
                'category': f"CWE-{report_result['cwe'].get('id')}",
                'description': search_csv(str(report_result['cwe'].get('id'))),
                'details': report_result.get('code'),
                'reference': f"https://cwe.mitre.org/data/definitions/{report_result['cwe'].get('id')}.html"
            }
        vulnerabilities.append(result_data)
    print('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
    print(vulnerabilities)
    
    
def gosec_scan():
    print('=================gosec Scan=====================')
    response_data =[]
    config = configparser.ConfigParser()
    config.read('svn_config.ini')

    accounts = config['LOCAL']['PYTHON_REPO_LIST']
    svn_path = config['LOCAL']['SVN_PATH']
    
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
                    # folder_name = folder_name + '\ ' + branch
                    folder_name = os.path.join(folder_name, branch).strip().replace(' ', '').replace('/', '\\')
                    folder_name = rf".\{folder_name}"
                    gosec_scan_command = ["gosec", "-exclude=G101", "-fmt=json", ".\\..."]
                    result = subprocess.run(gosec_scan_command, cwd=folder_name, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    print(result)
                    if result.returncode == 1:
                        report = json.loads(result.stdout)
                    else:
                        report = None
                    print('==='*50)
                    print(report)
                    if report:
                        result_dict['url'] = url
                        result_dict['report'] = report
                        result_dict['tenant_id'] = str(config['LOCAL']['TENANT_ID'])
                        nomalize_data(result_dict,  folder_name, str(config['LOCAL']['TENANT_ID']), branch)
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

                folder_name = os.path.join(folder_name, branch).strip().replace(' ', '').replace('/', '\\')
                folder_name = rf".\{folder_name}"
                gosec_scan_command = ["gosec", "-exclude=G101", "-fmt=json", ".\\..."]
                result = subprocess.run(gosec_scan_command, cwd=folder_name, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                print(result.stdout)

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
gosec_scan()
