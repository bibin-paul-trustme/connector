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
def filter_data(html_content):
    first_p_content = re.search(r'<p>(.*?)</p>', html_content, re.DOTALL)

    # Print or use the extracted content
    if first_p_content:
        return first_p_content.group(1).strip()
    return None



def spotbugs_scan():
    file_name_chunk = uuid.uuid4()
    repo_list  = config['LOCAL']['JAVA_REPO_LIST']

    for repo in repo_list.split(','):
        if repo.endswith('/'):      
            repo = repo[:-1]
        folder_name = config['LOCAL']['java_repo']
        print('======', folder_name)
        dir_list = [f for f in os.listdir(folder_name) if os.path.isdir(os.path.join(folder_name, f))]
        print(dir_list)
        for branch in dir_list:
            scan_location = folder_name + '/' + branch
            spotbugs_scan_command = r"spotbugs.bat -textui -pluginList java_plugin\findsecbugs-plugin-1.12.0.jar -xml:withMessages %s" %scan_location
            print(spotbugs_scan_command)
            result = subprocess.run(spotbugs_scan_command, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                response = result.stdout.encode('utf-8').decode('utf-8')
                xml_dict = xmltodict.parse(response)
                xml_string = xmltodict.unparse(xml_dict, pretty=True)

                # Specify the file path where you want to save the XML data
                xml_file_path = 'output.xml'

                # Write the XML string to the file
                with open(xml_file_path, 'w', encoding='utf-8') as xml_file:
                    xml_file.write(xml_string)
                # print('..................', xml_dict)

                result_data = []
                for data in xml_dict['BugCollection']['BugInstance']:

                    # data = {'@type': 'DE_MIGHT_IGNORE', '@priority': '2', '@rank': '16', '@abbrev': 'DE', '@category': 'BAD_PRACTICE', '@instanceHash': '14803200ed45a6438f67befc52dbcf3e', '@instanceOccurrenceNum': '0', '@instanceOccurrenceMax': '0', '@cweid': '391', 'ShortMessage': 'Method might ignore exception', 'LongMessage': 'alliancetechnical.ejb3.estimating.EstimatingResultSet.addResult(EstimatingResult) might ignore java.lang.Exception', 'Class': [{'@classname': 'alliancetechnical.ejb3.estimating.EstimatingResultSet', '@primary': 'true', 'SourceLine': {'@classname': 'alliancetechnical.ejb3.estimating.EstimatingResultSet', '@start': '20', '@end': '476', '@sourcefile': 'EstimatingResultSet.java', '@sourcepath': 'alliancetechnical/ejb3/estimating/EstimatingResultSet.java', 'Message': 'At EstimatingResultSet.java:[lines 20-476]'}, 'Message': 'In class alliancetechnical.ejb3.estimating.EstimatingResultSet'}, {'@classname': 'java.lang.Exception', '@role': 'CLASS_EXCEPTION', 'SourceLine': {'@classname': 'java.lang.Exception', '@start': '55', '@end': '124', '@sourcefile': 'Exception.java', '@sourcepath': 'java/lang/Exception.java', 'Message': 'At Exception.java:[lines 55-124]'}, 'Message': 'Exception class java.lang.Exception'}], 'Method': {'@classname': 'alliancetechnical.ejb3.estimating.EstimatingResultSet', '@name': 'addResult', '@signature': '(Lalliancetechnical/ejb3/estimating/EstimatingResult;)V', '@isStatic': 'false', '@primary': 'true', 'SourceLine': {'@classname': 'alliancetechnical.ejb3.estimating.EstimatingResultSet', '@start': '35', '@end': '72', '@startBytecode': '0', '@endBytecode': '726', '@sourcefile': 'EstimatingResultSet.java', '@sourcepath': 'alliancetechnical/ejb3/estimating/EstimatingResultSet.java'}, 'Message': 'In method alliancetechnical.ejb3.estimating.EstimatingResultSet.addResult(EstimatingResult)'}, 'SourceLine': [{'@classname': 'alliancetechnical.ejb3.estimating.EstimatingResultSet', '@primary': 'true', '@start': '69', '@end': '69', '@startBytecode': '364', '@endBytecode': '364', '@sourcefile': 'EstimatingResultSet.java', '@sourcepath': 'alliancetechnical/ejb3/estimating/EstimatingResultSet.java', 'Message': 'At EstimatingResultSet.java:[line 69]'}, {'@classname': 'alliancetechnical.ejb3.estimating.EstimatingResultSet', '@primary': 'true', '@start': '69', '@end': '69', '@startBytecode': '364', '@endBytecode': '364', '@sourcefile': 'EstimatingResultSet.java', '@sourcepath': 'alliancetechnical/ejb3/estimating/EstimatingResultSet.java', 'Message': 'At EstimatingResultSet.java:[line 69]'}]}
                    # print('======', data)
                    temp_data = {}
                    temp_data.setdefault('details', '')

                    
                    temp_data['title'] = data.get('ShortMessage', None)
                    temp_data['description'] = data.get('LongMessage', None)
                    temp_data['priority'] = data.get('@priority', None)
                    if data['@priority'] == '1':
                        temp_data['severity'] = "HIGH"
                    elif data['@priority'] == '2':
                        temp_data['severity'] = "MEDIUM"
                    else:
                        temp_data['severity'] = "LOW"
                    
                    temp_data['category'] = data.get('@category', None)
                    if isinstance(data['Class'], list):
                        print('=====list')
                        for class_data in data['Class']:
                            temp_data['beginline'] = class_data.get('SourceLine', {}).get('@start', None)
                    
                            temp_data['filename'] = class_data.get('SourceLine', {}).get('@sourcefile', None)
                            temp_data['cweid'] = ''
                            pattern_data = xml_dict['BugCollection']['BugPattern']
                            for pattern in pattern_data:
                                # print('**********', pattern['Details'])
                                if data.get('@type', None) == pattern['@type']:
                                    temp_data['details'] = pattern['Details']
                                    
                                    references_match = re.search(r'<b>References<\/b><br\/>(.*?)<\/p>', pattern['Details'], re.DOTALL)
                                    if references_match:
                                        references_content = references_match.group(1)
                                        references_list = re.findall(r'<a href="(.*?)">(.*?)<\/a>', references_content)
                                        if references_list:
                                            web_addresses = [url for url, _ in references_list]
                                            temp_data['references'] = web_addresses
                                        else:
                                            temp_data['references'] = []
                                    # solution_match = re.search(r'<b>Solution:<\/b><br\/>(.*?)<br\/>', pattern['Details'], re.DOTALL)
                                    # if solution_match:
                                    #     solution_content = solution_match.group(1)
                                    #     cleaned_string = re.sub(r'<[^>]+>', '', solution_content)
                                    #     print(cleaned_string)
                                    #     if cleaned_string:
                                    #         print('okkkkkkk')
                                    #         if temp_data['details']:
                                    #             temp_data['details'] = temp_data['details'] + ' Solution: ' +cleaned_string.replace('\n', '').strip()
                                    #         else:
                                    #             temp_data['details'] ='Solution: ' +cleaned_string
                                    #     print(temp_data['details'])    

                            for pattern in pattern_data:
                                if '@cweid' in pattern:
                                    if data.get('@cweid', None) == pattern['@cweid']:
                                        # print(pattern['Details'])
                                        cwe_match = re.search(r'CWE-\d+', pattern['Details'])
                                        if cwe_match:
                                            cwe_value = cwe_match.group()
                                            temp_data['cweid'] = cwe_value
                                            break
                                else:
                                    temp_data['refernces'] = ''
                            temp_data['repository_url'] = repo
                            temp_data['branch'] = branch
                            temp_data['created_at'] = str(datetime.now())
                            temp_data['tenant_id'] = str(config['LOCAL']['TENANT_ID'])
                            result_data.append(temp_data)
                    else:
                        print('int he ekse')
                        temp_data['beginline'] = data.get('Class', {}).get('SourceLine', {}).get('@start', None)
                        
                        temp_data['filename'] = data.get('Class', {}).get('SourceLine', {}).get('@sourcefile', None)
                        temp_data['cweid'] = ''
                        pattern_data = xml_dict['BugCollection']['BugPattern']
                        # print('--'*50)

                        for pattern in pattern_data:
                            
                            
                            if data.get('@type', None) == pattern['@type']:
                                all_p_content = filter_data(pattern['Details'])
                                characters_to_replace = ["&nbsp;", "\n"]
                                if all_p_content:
                                    modified_content = all_p_content.strip()
                                    for char_to_replace in characters_to_replace:
                                        modified_content = modified_content.replace(char_to_replace, "")
                                        cleaned_string = re.sub(r'<[^>]+>', '', pattern['Details'])
                                    temp_data['details'] = cleaned_string
                                else:
                                    temp_data['details'] = ''
                                references_match = re.search(r'<b>References<\/b><br\/>(.*?)<\/p>', pattern['Details'], re.DOTALL)
                                if references_match:
                                    references_content = references_match.group(1)
                                    references_list = re.findall(r'<a href="(.*?)">(.*?)<\/a>', references_content)
                                    if references_list:
                                        web_addresses = [url for url, _ in references_list]
                                        temp_data['references'] = web_addresses
                                        break
                                    else:
                                        temp_data['references'] = []
                                # print('========details=========', pattern['Details'])
                                solution_match = re.search(r'<b>Solution:<\/b><br\/>(.*?)<br\/>', pattern['Details'], re.DOTALL)
                                if solution_match:
                                    solution_content = solution_match.group(1)
                                    cleaned_string = re.sub(r'<[^>]+>', '', solution_content)
                                    print(cleaned_string)
                                    if cleaned_string:
                                        print('okkkkkkk')
                                        if temp_data['details']:
                                            temp_data['details'] = temp_data['details'] + ' Solution: ' +cleaned_string.replace('\n', '')
                                        else:
                                            temp_data['details'] ='Solution: ' +cleaned_string
                                    print(temp_data['details'])
                        for pattern in pattern_data:
                            if '@cweid' in pattern:
                                if data.get('@cweid', None) == pattern['@cweid']:
                                    cwe_match = re.search(r'CWE-\d+', pattern['Details'])
                                    if cwe_match:
                                        cwe_value = cwe_match.group()
                                        temp_data['cweid'] = cwe_value
                                        break
                            else:
                                temp_data['refernces'] = ''
                        temp_data['url'] = repo
                        temp_data['branch'] = branch
                        temp_data['batch_id'] = str(file_name_chunk)
                        temp_data['created_at'] = str(datetime.now())
                        temp_data['tenant_id'] = str(config['LOCAL']['TENANT_ID'])
                        result_data.append(temp_data)

                push_data(result_data)
spotbugs_scan()