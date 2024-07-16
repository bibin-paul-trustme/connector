import configparser
import requests
import subprocess
import xmltodict
import json
import os
import xml.etree.ElementTree as ET
import re
import zipfile
import time
from datetime import datetime
import shutil
import math
import uuid
import base64

from services.svn_services import branch_list, repo_update, push_data

config = configparser.ConfigParser()
config.read("svn_config.ini")

def find_sln_files(directory):
    sln_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.sln'):
                sln_files.append(os.path.join(root, file))
    return sln_files

def decode_base64(encoded_data):
    encoded_data = encoded_data.encode('utf-8')
    padding_needed = 4 - (len(encoded_data) % 4)
    if padding_needed != 4:
        encoded_data += b'=' * padding_needed
    decoded_data = base64.b64decode(encoded_data)
    return decoded_data
def filter_data(html_content):
    first_p_content = re.search(r'<p>(.*?)</p>', html_content, re.DOTALL)

    # Print or use the extracted content
    if first_p_content:
        return first_p_content.group(1).strip()
    return None

def scan_and_push(folder_name, account, branch, file_name_chunk):
    sln_files_found = find_sln_files(folder_name)
    print(sln_files_found)
    sln_file_scan_data = []
    for sln_file in sln_files_found:
        print('===>>>>', sln_file)
        command = ['roslynator', 'analyze', sln_file]
        result = subprocess.run(command, capture_output=True, text=True)
        # print(result)

        if result.returncode != 2:
            result_data = result.stdout
            # with open('rrres.txt', 'r') as file:
            #     # Read the entire content of the file as a string
            #     result_data = file.read()
            # print(result_data)
            lines = result_data.split('\n')
            prefixes_to_match = ['Load solution', 'Loading solution', 'Done loading solution', 'Analyze solution', 'Analyze', 'No analyzers found to', 'Done analyzing solution', 'warning']
            excluded_lines = [line.strip() for line in result_data.split('\n') if
                            not any(line.strip().startswith(prefix) for prefix in prefixes_to_match) and (not line.strip() or not line.strip()[0].isdigit())]
            excluded_lines = list(filter(None, excluded_lines))
            pattern = r'(.*?\(\d+,\d+\)): (\w+ \w+): (.*)'
            
            for line in excluded_lines:
                print(line)
                match = re.match(pattern, line)
                if match:
                    file_location = match.group(1)
                    warning_code = match.group(2)
                    warning_description = match.group(3)
                    result = [file_location, warning_code, warning_description]
                    # print(result)
                sln_data = {}
                # parts = line.split(':')
                # print(parts)
                sln_data['filename'] = file_location.split('(')[0]
                sln_data['description'] = warning_description
                sln_data['severity'] = warning_code.split(' ')[1]
                sln_data['rule'] = warning_code.split(' ')[1]
                sln_data['beginline'] = file_location.split('(')[1].split(',')[0]
                sln_data['url'] = account
                sln_data['branch'] = branch
                # sln_data['data'] = branch_scan_data
                sln_data['tenant_id'] = str(config['LOCAL']['TENANT_ID'])
                if sln_data["severity"] == "error":
                    sln_data["severity"] = "HIGH"
                elif sln_data["severity"] == "warning":
                    sln_data["severity"] = "MEDIUM"
                else:
                    sln_data["severity"] = "LOW"

                sln_data['batch_id'] = str(file_name_chunk)
                sln_data['created_at'] = str(datetime.utcnow())
                sln_file_scan_data.append(sln_data)
    return sln_file_scan_data    


def rosylnator_scan():
    file_name_chunk = uuid.uuid4()
    accounts = config['LOCAL']['DOTNET_REPO_LIST']
    print(accounts)
    response_data =[]
    for account in  accounts.split(','):
        account = account.strip()
        branches = branch_list(account)
        if branches != []:
            for branch in branches:
                if account.endswith('/'):
                    folder_name = account.split('/')[-2]
                    account = account[:-1]
                else:
                    folder_name = account.split('/')[-1]
                if 'trunk' not in branches:
                    branches = branches + ['trunk']
                folder_name = folder_name +'/' + branch
                sln_data = scan_and_push(folder_name, account, branch, file_name_chunk)
                response_data.append(sln_data)
                push_data(response_data)
                
        else:
            if account.endswith('/'):
                folder_name = account.split('/')[-2]
                account = account[:-1]
            else:
                folder_name = account.split('/')[-1]
            sln_data = scan_and_push(folder_name, account, folder_name, file_name_chunk)
            response_data.append(sln_data)
            push_data(response_data)
rosylnator_scan()