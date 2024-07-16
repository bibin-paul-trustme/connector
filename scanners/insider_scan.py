import os
import re 
import xml.etree.ElementTree as ET
import subprocess
from datetime import datetime
import uuid
import configparser
import requests
import time 
import math
import json
import shutil
import base64
import csv


from services.svn_services import branch_list, repo_update, push_data


script_path = os.path.abspath(__file__)
script_filename = os.path.basename(script_path)



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

def find_sln_files(directory):
    files_found = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.sln'):
                files_found.append(os.path.join(root, file))
    return files_found


def decode_base64(encoded_data):
    encoded_data = encoded_data.encode('utf-8')
    padding_needed = 4 - (len(encoded_data) % 4)
    if padding_needed != 4:
        encoded_data += b'=' * padding_needed
    decoded_data = base64.b64decode(encoded_data)
    return decoded_data


def insider_scan():
    print('started')
    file_name_chunk = uuid.uuid4()
    accounts = config['LOCAL']['DOTNET_REPO_LIST']
    response_data =[]
    for account in  accounts.split(','):
        account = account.strip()
        branches = branch_list(account)
        print('====>>>', account)
        response_repo = repo_update(account)
        if branches != []:
            for branch in branches:
                if account.endswith('/'):
                    folder_name = account.split('/')[-2]
                    account = account[:-1]
                else:
                    folder_name = account.split('/')[-1]
                folder_name = folder_name +'/' + branch
                command = ['insider','-tech','csharp','-target',folder_name,  '-exclude','.svn','-exclude','.ttf','-exclude','.zip','-exclude','.png','-exclude','.bmp','-exclude','.dll','-exclude','.TTF','-exclude','.sql','-exclude','.pdf','-exclude','.mdb','-exclude','.jpg']
                print(command)
                result = subprocess.run(command, capture_output=True, text=True)
                print(result)

                with open('report.json', 'r', encoding='utf-8') as f:
                    result_data = json.load(f)
                for data in result_data['vulnerabilities']:
                    # print(data)
                    sln_data = {}
                    parts = data['classMessage'].split(' (')
                    cwe_id = data.get('cwe',None)
                    if cwe_id:
                        cwe_id_res = str(cwe_id).split('-')[1]
                        cwe_data = search_csv(cwe_id_res)
                        sln_data['title'] = cwe_data
                    else:
                        data.get('method',None)
                    sln_data['filenmae'] = parts[0]
                    sln_data['description'] = data.get('description',None)
                    sln_data['details'] = data.get('recomendation',None)
                    sln_data['cweid'] = data.get('cwe',None)
                    sln_data['severity'] = data.get('cvss',None)
                    sln_data['cvss'] = data.get('cvss',None)
                    sln_data['category'] = data.get('cwe',None)
                    sln_data['beginline'] = data.get('line',None)
                    sln_data['url'] = account
                    sln_data['branch'] = branch
                    sln_data['refernces'] = f"https://cwe.mitre.org/data/definitions/{cwe_id_res}.html"
                    sln_data['tenant_id'] = str(config['LOCAL']['TENANT_ID'])
                    if sln_data["severity"] >= 9:
                        sln_data["severity"] = "CRITICAL"
                    elif sln_data["severity"] > 6 and sln_data["severity"] <9:
                        sln_data["severity"] = "HIGH"
                    elif sln_data["severity"] < 4:
                        sln_data["severity"] = "LOW"
                    else:
                        sln_data["severity"] = "MEDIUM"

                    sln_data['batch_id'] = str(file_name_chunk)
                    sln_data['created_at'] = str(datetime.utcnow())
                    response_data.append(sln_data)
            # print(response_data)
            push_data(response_data)
        else:
            if account.endswith('/'):
                folder_name = account.split('/')[-2]
                account = account[:-1]
            else:
                folder_name = account.split('/')[-1]
            # folder_name = folder_name +'/' + branch
            command = ['insider','-tech','csharp','-target',folder_name,  '-exclude','.svn','-exclude','.ttf','-exclude','.zip','-exclude','.png','-exclude','.bmp','-exclude','.dll','-exclude','.TTF','-exclude','.sql','-exclude','.pdf','-exclude','.mdb','-exclude','.jpg']
            print(command)
            result = subprocess.run(command, capture_output=True, text=True)
            # print(result)

            with open('report.json', 'r', encoding='utf-8') as f:
                result_data = json.load(f)
            for data in result_data['vulnerabilities']:
                # print(data)
                sln_data = {}
                parts = data['classMessage'].split(' (')
                cwe_id = data.get('cwe',None)
                if cwe_id:
                    cwe_id_res = str(cwe_id).split('-')[1]
                    cwe_data = search_csv(cwe_id_res)
                    sln_data['title'] = cwe_data
                else:
                    data.get('method',None)
                sln_data['filenmae'] = parts[0]
                sln_data['description'] = data.get('description',None)
                sln_data['details'] = data.get('recomendation',None)
                sln_data['cweid'] = data.get('cwe',None)
                sln_data['severity'] = data.get('cvss',None)
                sln_data['cvss'] = data.get('cvss',None)
                sln_data['category'] = data.get('cwe',None)
                sln_data['beginline'] = data.get('line',None)
                sln_data['url'] = account
                sln_data['branch'] = folder_name
                sln_data['refernces'] = f"https://cwe.mitre.org/data/definitions/{cwe_id_res}.html"
                sln_data['tenant_id'] = str(config['LOCAL']['TENANT_ID'])
                if sln_data["severity"] >= 9:
                    sln_data["severity"] = "CRITICAL"
                elif sln_data["severity"] > 6 and sln_data["severity"] <9:
                    sln_data["severity"] = "HIGH"
                elif sln_data["severity"] < 4:
                    sln_data["severity"] = "LOW"
                else:
                    sln_data["severity"] = "MEDIUM"

                sln_data['batch_id'] = str(file_name_chunk)
                sln_data['created_at'] = str(datetime.utcnow())
                response_data.append(sln_data)
        # print(response_data)
        push_data(response_data)




insider_scan()
