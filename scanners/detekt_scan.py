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
    base_url = config['LOCAL']['trustme_detekt_count_upload']
    response = requests.post(base_url, cert=(cert_file, key_file), headers=headers, data=count_data)
    print(response.text)
    
def xml_file_to_json(xml_file_path):
    tree = ET.parse(xml_file_path)
    root = tree.getroot()
    report_dict = {
        'version': root.get('version'),
        'files': []
    }
    for file_element in root.findall('file'):
        file_report = {
            'name': file_element.get('name'),
            'errors': []
        }

        for error_element in file_element.findall('error'):
            error = {
                'line': error_element.get('line'),
                'column': error_element.get('column'),
                'severity': error_element.get('severity'),
                'message': error_element.get('message'),
                'source': error_element.get('source')
            }
            file_report['errors'].append(error)

        report_dict['files'].append(file_report)

    return report_dict

def nomalize_data(data, url, tenant, branch):
    print(data)
    report = []
    data = data['report']
    if data['files']:
        for file_info in data['files']:
            filename = file_info["name"]
            for violation in file_info["errors"]:
                if violation["severity"] in ['fatal', 'error']:
                    severity = 'HIGH'
                elif violation["severity"] in ['warning', 'maintainability']:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'

                rule = violation['source'].split('.')[1]
                violations = {
                    "filename": filename,
                    "begin_line": violation["line"],
                    "description": violation["message"],
                    "rule": rule,
                    "severity": severity,
                    "rule_set": rule,
                }
                report.append(violations)
    print(report)




def detekt_scan():
    print('=================detekt Scan=====================')
    response_data =[]
    config = configparser.ConfigParser()
    config.read('svn_config.ini')

    accounts = config['LOCAL']['KOTLIN_REPO_LIST']
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
                    detekt_scan_command = r"java -jar files\detekt-cli-1.23.6-all.jar --input %s --report xml:report_detekt.xml --all-rules" %folder_name
                    print(detekt_scan_command)
                    result = subprocess.run(detekt_scan_command, shell=True, capture_output=True, text=True)
                    report = xml_file_to_json('report_detekt.xml')
                    print(report)
                    print('==='*50)
                    if report['files'] != []:
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

                detekt_scan_command = r"java -jar files\detekt-cli-1.23.6-all.jar --input %s --report xml:report_detekt.xml --all-rules" %folder_name
                print(detekt_scan_command)
                result = subprocess.run(detekt_scan_command, shell=True, capture_output=True, text=True)
                report = xml_file_to_json('report_detekt.xml')
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
# detekt_scan()
