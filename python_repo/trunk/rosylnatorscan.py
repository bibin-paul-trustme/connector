import configparser
import requests
import subprocess
import xmltodict
import json
import os
import xml.etree.ElementTree as ET
from logfile import setup_logger
import re
import zipfile
import time
from datetime import datetime
import shutil
import math
import uuid
import base64


script_path = os.path.abspath(__file__)
script_filename = os.path.basename(script_path)
logging = setup_logger()


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

def branch_list(account):
    svn_path = config['LOCAL']['SVN_PATH']
    if account.endswith('/'):
        account = account[:-1]
    
    base_url =  account+'/branches'
    branch_cmd = [svn_path, 'list', '--no-auth-cache', '--trust-server-cert', '--non-interactive', '--xml', base_url.strip()]
    branch_resp = subprocess.run(branch_cmd, capture_output=True, text=True)
    if branch_resp.returncode == 0:
        root = ET.fromstring(branch_resp.stdout)
        list_element = root.find('list')
        branches = [entry.find('name').text for entry in list_element.findall('entry')]
    else:
        branches = []
    branch_list = ['branches/'  + s for s in branches]
    base_url =  account+'/tags'
    tag_cmd = [svn_path, 'list',  '--no-auth-cache', '--trust-server-cert', '--non-interactive','--xml', base_url.strip()]
    tag_resp = subprocess.run(tag_cmd, capture_output=True, text=True)
    if tag_resp.returncode == 0:
        root = ET.fromstring(tag_resp.stdout)
        list_element = root.find('list')
        tags = [entry.find('name').text for entry in list_element.findall('entry')]
    else:
        tags = []
    tag_list = ['tags/'  + s for s in tags]
    branches = branch_list + tag_list
    base_url =account+'/trunk'
    trunk_cmd = [svn_path, 'info',  '--no-auth-cache', '--trust-server-cert', '--non-interactive','--xml', base_url.strip()]
    trunk_resp = subprocess.run(trunk_cmd, capture_output=True, text=True)
    if trunk_resp.returncode == 0:
        branches = branches + ['trunk']
    return branches

def push_data(data, file_name_chunk):

    total_violations = len(data)
    print("Total Violations:", total_violations)
    file_size = len(data) / 5000
    total_files = len(data)
    print(file_size)
    data_range_start = 0
    if file_size < 1 and file_size > 0:
        file_size = 1
    print('==============>>>>>>>>>>', math.ceil(file_size))
    # file_size = 2
    for i in range(0,math.ceil(file_size)):
        # print(i)
        data_range_end = data_range_start + 5000 
        json_result = json.dumps(data[data_range_start:data_range_end], indent=2)
        with open('rosylnator.json', 'w') as json_file:
            json_file.write(json_result)
        zip_file_name = 'rosylnator_zip_part_' +str(i)
        # print(zip_file_name)
        shutil.make_archive(zip_file_name, 'zip', '.', 'rosylnator.json')
        data_header = {'current_chunk': i, 'total_chunks': total_files, 'file_name_chunk':file_name_chunk, 'filename' :zip_file_name}
        cert_file = 'amtech.pem'
        key_file = 'amtech.key'
        token = 'YOUR_TOKEN'
        tenant = decode_base64(str(config['LOCAL']['TENANT_ID'])).decode('utf-8')
        headers = {
            'Authorization': f'Bearer {token}',
            'id' : f'{tenant}'     
        }
        base_url = config['LOCAL']['trustme_rosylnator_data_upload']
        with open(zip_file_name+'.zip', 'rb') as file:
            # Your file handling or request code here
            files = {'file': file}
            response = requests.post(base_url, cert=(cert_file, key_file), files=files, headers=headers, data=data_header)
            print(response.text)
        time.sleep(1)
        os.remove(zip_file_name+'.zip')
        os.remove('rosylnator.json')        
        data_range_start = data_range_end 
        # data_range_start = data_range_end +1
        if response.status_code == 200:
            logging.info(script_filename + ' - Successfully data pushed')
        else:
            logging.info(script_filename + ' - Data pushing failed')


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
    return sln_data    


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
                push_data(response_data, file_name_chunk)
                
        else:
            if account.endswith('/'):
                folder_name = account.split('/')[-2]
                account = account[:-1]
            else:
                folder_name = account.split('/')[-1]
            sln_data = scan_and_push(folder_name, account, folder_name, file_name_chunk)
            response_data.append(sln_data)
            push_data(response_data, file_name_chunk)
rosylnator_scan()