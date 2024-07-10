import os
import re
import json
import subprocess

from datetime import datetime

from ct_backend.db_connection import get_db_connection
from services.insider.insider_scan import search_csv
from .gosec_scan import GoSecScanner

# local
from .npm_action import NPMInstallAction
from .ruff_scan import RuffScanner
from .sfdx_scan import SFDXScanner
from .bandit_scan import BanditScanner
from .pmd_scan import PMDJavaScriptScanner, PMDJavaScanner
from .rosylnator_scan import RosylnatorScanner
from .insider_scan import InsiderJavaScriptScanner, InsiderJavaScanner, InsiderCSharpScanner, InsiderKotlinScanner, InsiderIosScanner, InsiderKotlinScanner
from .trivy_scan import TrivyLicensesScanner, TrivySecretScanner, TrivyVulnerabilitiesScanner
from .phpmd_scan import PHPMDScanner
from .progpilot_scan import ProgPilotScanner
from .rubocop_scan import RuboCopScanner
from .detekt_scan import DetektScanner

SCANNER_MAPPING = {
    'Python': [
        RuffScanner,
        BanditScanner,
        TrivySecretScanner,
        TrivyVulnerabilitiesScanner,
        TrivyLicensesScanner,
    ],
    'Apex': [
        SFDXScanner,
        TrivySecretScanner,
        TrivyVulnerabilitiesScanner,
        TrivyLicensesScanner,
    ],
    'JavaScript': [
        NPMInstallAction,
        TrivySecretScanner,
        TrivyVulnerabilitiesScanner,
        TrivyLicensesScanner,
        InsiderJavaScriptScanner,
        PMDJavaScriptScanner,
    ],
    '.NET': [
        TrivySecretScanner,
        TrivyVulnerabilitiesScanner,
        TrivyLicensesScanner,
        InsiderCSharpScanner,
        RosylnatorScanner,
    ],
    'Typescript': [
        TrivySecretScanner,
        TrivyVulnerabilitiesScanner,
        TrivyLicensesScanner,
        InsiderJavaScriptScanner,
        PMDJavaScriptScanner,
    ],
    'Java': [
        TrivySecretScanner,
        TrivyVulnerabilitiesScanner,
        TrivyLicensesScanner,
        InsiderJavaScanner,
        PMDJavaScanner,
    ],
    'Go': [
        TrivySecretScanner,
        TrivyVulnerabilitiesScanner,
        TrivyLicensesScanner,
        GoSecScanner,
    ]
    ,
    'PHP': [
        TrivySecretScanner,
        TrivyVulnerabilitiesScanner,
        TrivyLicensesScanner,
        PHPMDScanner,
        ProgPilotScanner,
    ],
    'Ruby': [
        TrivySecretScanner,
        TrivyVulnerabilitiesScanner,
        TrivyLicensesScanner,
        RuboCopScanner,
    ],
    'Kotlin': [
        TrivySecretScanner,
        TrivyVulnerabilitiesScanner,
        TrivyLicensesScanner,
        InsiderKotlinScanner,
        DetektScanner,
    ]
}


def remove_existing_scan_result(collection, repo_url, tenant_id, branch_name):
    filter_query = {
        'tenant_id': tenant_id,
        'url': repo_url,
        'branch': branch_name
    }
    resp = collection.find(filter_query)
    print('*****************', list(resp))
    # remove previous records
    collection.delete_many(filter_query)
    print("****Existing result removed****")
    return


def initiate_bandit_scan(repo_url, branch_name, tenant_id, directory):
    try:
        response_data = []
        client, ct_db = get_db_connection()
        report_collection = ct_db['bandit_scan_report']
        command = ['bandit', directory, '-r', '-f', 'json', '--silent']
        result = subprocess.run(command,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
        print("Bandit ====> ", result.returncode)
        if result.returncode != 1:
            print("Bandit return code======>", result.returncode)
            return
        report = json.loads(result.stdout)
        if 'results' in report:
            for report_result in report['results']:
                result_data = {}
                # print(report_result)
                result_data['title'] = report_result.get('test_name')
                result_data['filename'] = report_result.get('filename')
                result_data['created_at'] = datetime.now()
                result_data['description'] = ''
                result_data['details'] = ''
                issue_cwe_data = report_result.get('issue_cwe')
                if issue_cwe_data:
                    issue_cwe_id = issue_cwe_data.get('id')
                    issue_cwe_link = issue_cwe_data.get('link')
                    cwe_data = search_csv(issue_cwe_id)
                    print(cwe_data)
                    result_data['title'] = cwe_data
                else:
                    issue_cwe_id = ''
                    issue_cwe_link = ''
                    result_data['title'] = ''
                result_data['cweid'] = issue_cwe_id
                result_data['severity'] = report_result.get(
                    'issue_severity', None)
                result_data['cvss'] = ''
                result_data['category'] = "CWE-" + str(result_data['cweid'])
                result_data['beginline'] = report_result.get(
                    'line_number', None)
                result_data['url'] = repo_url
                result_data['branch'] = branch_name
                result_data['references'] = issue_cwe_link
                result_data['tenant_id'] = tenant_id
                result_data['more_details'] = report_result
                response_data.append(result_data)
            remove_existing_scan_result(report_collection, repo_url,
                                        branch_name, tenant_id)
            # Insert the report into MongoDB
            report_collection.insert_many(response_data)
        return
    except Exception as e:
        print("Bandit exception ==========> ", str(e))
        return


def initiate_ruff_scan(repo_url, branch_name, tenant_id, directory):
    try:
        report_data = []
        client, ct_db = get_db_connection()
        report_collection = ct_db['ruff_scan_report']
        command = ['ruff', 'check', directory]
        result = subprocess.run(command,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
        print("Ruff initiated ==========> ", result.returncode)
        if result.returncode != 1:
            return
        output = result.stdout
        lines = output.split("\n")

        for line in lines:
            parts = line.split(":")
            if len(parts) >= 2:
                filename = parts[0]
                line_number, column_number, description = parts[1], parts[
                    2], ":".join(parts[3:])
                result_data = {
                    'filename': filename.strip(),
                    'rule': filename.strip(),
                    'severity': 'LOW',
                    'beginline': line_number.strip(),
                    'column': column_number.strip(),
                    'details': description,
                    'branch': branch_name,
                    'url': repo_url,
                    'created_at': datetime.now()
                }
                if description:
                    # Splitting the description into two parts based on the first space
                    split_description = description.split(" ")

                    # Extracting the error code and the description
                    error_code = split_description[1].strip()
                    desc = " ".join(split_description[2:]).strip()
                    if "[*]" in desc:
                        desc = desc.replace("[*]", "").strip()
                    result_data['rule'] = error_code
                    result_data['description'] = desc
                report_data.append(result_data)
        remove_existing_scan_result(report_collection, repo_url, branch_name,
                                    tenant_id)
        # Insert the report into MongoDB
        report_collection.insert_many(report_data)
        return
    except Exception as e:
        print("Ruff exception ==========> ", str(e))
        return


def find_sln_files(directory):
    sln_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.sln'):
                sln_files.append(os.path.join(root, file))
    return sln_files


def initiate_roslynator_scan(repo_url, branch_name, tenant_id, directory):
    try:
        sln_file_scan_data = []
        sln_files_found = find_sln_files(directory)
        client, ct_db = get_db_connection()
        report_collection = ct_db['rosylnator_scan_report']
        for sln_file in sln_files_found:
            print('===>>>>', sln_file)
            command = ['roslynator', 'analyze', directory]
            result = subprocess.run(command,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True)
            print("Rosylnator initiated ==========> ", result.returncode)
            if result.returncode != 1:
                return

            result_data = result.stdout
            # lines = result_data.split("\n")

            prefixes_to_match = [
                'Load solution', 'Loading solution', 'Done loading solution',
                'Analyze solution', 'Analyze', 'No analyzers found to',
                'Done analyzing solution', 'warning'
            ]
            excluded_lines = [
                line.strip() for line in result_data.split('\n')
                if not any(line.strip().startswith(prefix)
                           for prefix in prefixes_to_match) and
                (not line.strip() or not line.strip()[0].isdigit())
            ]
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
                sln_data['beginline'] = file_location.split('(')[1].split(
                    ',')[0]
                sln_data['url'] = repo_url
                sln_data['branch'] = branch_name
                # sln_data['data'] = branch_scan_data
                sln_data['tenant_id'] = tenant_id
                if sln_data["severity"] == "error":
                    sln_data["severity"] = "HIGH"
                elif sln_data["severity"] == "warning":
                    sln_data["severity"] = "MEDIUM"
                else:
                    sln_data["severity"] = "LOW"

                # sln_data['batch_id'] = str(file_name_chunk)
                sln_data['created_at'] = str(datetime.utcnow())
                sln_file_scan_data.append(sln_data)

        remove_existing_scan_result(report_collection, repo_url, branch_name,
                                    tenant_id)
        # Insert the report into MongoDB
        report_collection.insert_many(sln_file_scan_data)
        return
    except Exception as e:
        print("Rosylnator exception ==========> ", str(e))
        return


def initiate_pmd_scan(repo_url, branch_name, tenant_id, directory):
    print('pmd')
    try:
        report_data = []
        client, ct_db = get_db_connection()
        report_collection = ct_db['pmd_scan_report']
        pmd_scan_command = r"pmd check -d %s -f json -R rulesets/java/quickstart.xml" % directory
        print(pmd_scan_command)
        result = subprocess.run(pmd_scan_command,
                                shell=True,
                                capture_output=True,
                                text=True)
        report = json.loads(result.stdout)
        result_dict = {}
        if report['files'] != []:
            result_dict['url'] = repo_url
            result_dict['branch'] = branch_name
            result_dict['tenant_id'] = tenant_id
            result_dict['created_at'] = datetime.utcnow()
            result_dict['report'] = report
            # remove_existing_scan_result(report_collection, repo_url, branch_name, tenant_id)
            # # Insert the report into MongoDB
            restructured_data = []

            for file_info in result_dict['report']['files']:
                filename = file_info["filename"]
                for violation in file_info["violations"]:
                    if violation["priority"] == 1:
                        priority = "HIGH"
                    elif violation["priority"] in [2, 3]:
                        priority = "MEDIUM"
                    else:
                        priority = "LOW"
                    restructured_data.append({
                        "url":
                        repo_url,
                        'branch':
                        branch_name,
                        'created_at':
                        str(datetime.now()),
                        'tenant_id':
                        tenant_id,
                        "filename":
                        filename,
                        "beginline":
                        violation["beginline"],
                        "begincolumn":
                        violation["begincolumn"],
                        "endline":
                        violation["endline"],
                        "endcolumn":
                        violation["endcolumn"],
                        "description":
                        violation["description"],
                        "rule":
                        violation["rule"],
                        "ruleset":
                        violation["ruleset"],
                        "priority":
                        violation["priority"],
                        "severity":
                        priority,
                        "externalInfoUrl":
                        violation["externalInfoUrl"]
                    })
            result_dict["report"] = restructured_data
            print('=========', result_dict)
            report_collection.insert_many(result_dict["report"])
        return
    except Exception as e:
        print("PMD exception ==========> ", str(e))
        return
