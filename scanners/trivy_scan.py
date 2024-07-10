import sys
sys.path.append('../')

import subprocess
import tempfile
import os
import configparser 
import json
import time
import stat
import requests
import zipfile 
import xml.etree.ElementTree as ET
from configurations.logfile import setup_logger
from services.svn_services import branch_list
from services.svn_services import repo_update

script_path = os.path.abspath(__file__)
script_filename = os.path.basename(script_path)
logging = setup_logger()


config = configparser.ConfigParser()
config.read("svn_config.ini")


def remove_readonly(func, path, _):
    os.chmod(path, stat.S_IWRITE)
    func(path)

def push_data(response_data):
    print(response_data)
    # logging.info(script_filename + ' - Pushing data to the portal')
    # json_result = json.dumps(response_data, indent=2)
    # with open('trivy.json', 'w') as json_file:
    #     json_file.write(json_result)
    # files = {'file': open('trivy.json', 'rb')}

    # with zipfile.ZipFile('trivy.zip', 'w') as zip_file:
    #     zip_file.write('trivy.json', arcname='file_inside_zip.txt')

    # # response = requests.post(url, files=files)
    # url = config['LOCAL']['trustme_trivy_data_upload']
    # headers = {
    #     'Authorization': 'Bearer ' + 'access_token'
    # }
    # cert_file = str(config['LOCAL']['cert_file'])
    # key_file = str(config['LOCAL']['key_file'])
    # files = {'file': open('trivy.zip', 'rb')}
    # print(url)
    # response = requests.post(url, cert=(cert_file, key_file),files=files, headers=headers)
    # print(response, response.text)
    # time.sleep(1)
    # files['file'].close()
    # # os.remove('trivy.json')
    # os.remove('trivy.zip')
    # if response.status_code == 200:
    #     logging.info(script_filename + ' - Successfully data pushed')
    # else:
    #     logging.info(script_filename + ' - Data pushing failed')
    

def scan_and_push(folder_name, branch):
    # directory_package = folder_name + 'package.json'
    # node_module_dir = folder_name +'/node_modules'
    # npm_command = f'npm install {directory_package}'
    # subprocess.run(npm_command, shell=True, capture_output=True, text=True, check=False)
    command = f'trivy fs --scanners vuln,secret,config,license --license-full {folder_name} --format json'
    result = subprocess.run(command, shell=True, capture_output=True, text=True, check=False)
    print(result)
    # os.remove(node_module_dir)
    if result.returncode == 0:
        report = json.loads(result.stdout)
        logging.info(script_filename + ' - Scanning Completed')
        severity_counts = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0
        }
        secret_severity_counts = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0
        }
        license_severity_counts = {
            "UNKNOWN": 0,
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0
        }
        for result in report["Results"]:
            for vulnerability in result.get("Vulnerabilities", []):
                if vulnerability["Severity"] == "CRITICAL":
                    vulnerability["Severity"] = "CRITICAL"
                elif vulnerability["Severity"] == "HIGH":
                    vulnerability["Severity"] = "HIGH"
                elif vulnerability["Severity"] == "MEDIUM":
                    vulnerability["Severity"] = "MEDIUM"
                elif vulnerability["Severity"] == "LOW":
                    vulnerability["Severity"] = "LOW"
                else:
                    vulnerability["Severity"] = "NO RISK"
                severity = vulnerability["Severity"]
                if severity in severity_counts:
                    severity_counts[severity] += 1
            secret_data = result.get("Secrets", [])
            if secret_data != []:
                for secret in secret_data:
                    if secret["Severity"] == "CRITICAL":
                        secret["Severity"] = "CRITICAL"
                    elif secret["Severity"] == "HIGH":
                        secret["Severity"] = "HIGH"
                    elif secret["Severity"] == "MEDIUM":
                        secret["Severity"] = "MEDIUM"
                    elif secret["Severity"] == "LOW":
                        secret["Severity"] = "LOW"
                    else:
                        secret["Severity"] = "NO RISK"
                    severity = secret["Severity"]
                    if severity in secret_severity_counts:
                        secret_severity_counts[severity] += 1
            license_data = result.get("Licenses", [])
            if license_data != []:
                for secret in result.get("Licenses", []):
                    if secret["Severity"] == "CRITICAL":
                        secret["Severity"] = "HIGH"
                    elif secret["Severity"] == "INFORMATIONAL":
                        secret["Severity"] = "LOW"
                    severity = secret["Severity"]
                    if severity in license_severity_counts:
                        license_severity_counts[severity] += 1
        report['secret_severity_data'] = secret_severity_counts
        report['severity_data'] = severity_counts
        report['licenses_severity_data'] = license_severity_counts
        return report
    else:
        logging.info(script_filename + ' - Unable to checkout the repository')
        print('Unable to checkout the repository')


def trivy_scan():
    logging.info(script_filename + ' - Trivy scan started')
    print('=================Trivy Scan=====================')
    response_data =[]
    config = configparser.ConfigParser()
    config.read('svn_config.ini')
    print(config)
    accounts = config['LOCAL']['REPO_LIST']
    svn_path = config['LOCAL']['SVN_PATH']
    for url in accounts.split(', '):
        print(url)
        url = url.strip()
        branches = branch_list(url)
        branch_count = len(branches)
        if url.endswith('/'):
            folder_name = url.split('/')[-2]
            url = url.rstrip('/')
        else:
            folder_name = url.split('/')[-1]
        
        response_repo = repo_update(url)
        if branches != []:
            for branch in branches:
                print('==========>>>>>', branch)
                logging.info(f'Scanning Started for branch: {branch} - { len(branches) - branch_count} / {len(branches)}' )
                result_dict = {}
                if response_repo.returncode == 0:
                    repo_name = folder_name +'/' + branch
                    report = scan_and_push(repo_name, branch)
                    result_dict['url'] = url
                    result_dict['branch'] = branch
                    result_dict['data'] = report
                    result_dict['tenant_id'] = str(config['LOCAL']['TENANT_ID'])
                    response_data.append(result_dict)
                    push_data(response_data)
                    
        else:
            result_dict = {}
            report = scan_and_push(folder_name, folder_name)
            result_dict['url'] = url
            result_dict['branch'] = folder_name
            result_dict['data'] = report
            result_dict['tenant_id'] = str(config['LOCAL']['TENANT_ID'])
            response_data.append(result_dict)
            push_data(response_data)

trivy_scan()
