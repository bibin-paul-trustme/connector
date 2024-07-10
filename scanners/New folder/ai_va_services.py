from ..models import VulnerablePackage, CredentialExposure, CodeLevelVulnerability
import requests
import json
from itertools import chain

def split_array(arr, max_length=15):
    return [arr[i:i + max_length] for i in range(0, len(arr), max_length)]


def get_vulnerabilities_recommendation_cost(scan_issue, recommendation_type):
    url = "https://codeiris.eng.trustme.ai/api/v1/ai/integration/recommend"
    vulnerabilities = list(VulnerablePackage.objects.filter(scan=scan_issue).exclude(vulnerability_id=None).exclude(vulnerability_id="").values_list('vulnerability_id'))
    credential_exposures = ['CWE-312',]
    codelevel_vulnerabilities = list(CodeLevelVulnerability.objects.filter(scan=scan_issue).exclude(cwe_id=None).exclude(cwe_id="").values_list('cwe_id'))
    cwe_list = list(set(vulnerabilities+credential_exposures+codelevel_vulnerabilities))
    cwe_list = list(chain(*cwe_list))

    payload = json.dumps({
        "issueId": str(scan_issue.id),
        "cweList": cwe_list,
        "cvssList": [],
        "recommendationType": recommendation_type,
        "description": "This issue has several problem"
    })
    headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Basic dHJ1c3RtZTo4NDgxYzE2MDg3OTBlYzM1MWQ0Mzg4ZmFmNTA5NzM2MQ=='
    }
    html_response = ''
    response = requests.request("POST", url, headers=headers, data=payload)
    html_response = json.loads(response.text)["resultObject"]["htmlResponse"]
    return html_response

def get_vulnerabilities_rank(scan):
    print("scan = ",scan)
    url = "https://codeiris.eng.trustme.ai/api/v1/ai/integration/rank"
    vulnerabilities = VulnerablePackage.objects.filter(scan=scan)
    credential_exposures = CredentialExposure.objects.filter(scan=scan)
    codelevel_vulnerabilities = CodeLevelVulnerability.objects.filter(scan=scan)
    rank_body = []
    for vulnerability in vulnerabilities:
        vulnerabilities_obj = {}
        if not vulnerability.vulnerability_id == None and not vulnerability.vulnerability_id == '':
            vulnerabilities_obj["issueId"] = str(vulnerability.id)
            vulnerabilities_obj["cweList"] = [vulnerability.vulnerability_id]
            vulnerabilities_obj["description"] = vulnerability.description
            rank_body.append(vulnerabilities_obj)

    for vulnerability in codelevel_vulnerabilities:
        vulnerabilities_obj = {}
        if not vulnerability.cwe_id == None and not vulnerability.cwe_id == '':
            vulnerabilities_obj["issueId"] = str(vulnerability.id)
            vulnerabilities_obj["cweList"] = [vulnerability.cwe_id]
            vulnerabilities_obj["description"] = vulnerability.description
            rank_body.append(vulnerabilities_obj)

    for vulnerability in credential_exposures:
        vulnerabilities_obj = {}
        vulnerabilities_obj["issueId"] = str(vulnerability.id)
        vulnerabilities_obj["cweList"] = ['CWE-312']
        vulnerabilities_obj["description"] = ''
        rank_body.append(vulnerabilities_obj)
    headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Basic dHJ1c3RtZTo4NDgxYzE2MDg3OTBlYzM1MWQ0Mzg4ZmFmNTA5NzM2MQ=='
    }
    rank_bodies = split_array(rank_body)
    html_response = ''
    for rank_body in rank_bodies:
        response = requests.request("POST", url, headers=headers, data=json.dumps(rank_body))
        print(response.text)
        html_response = json.loads(response.text)["resultObject"]["htmlResponse"]
        
    return html_response

