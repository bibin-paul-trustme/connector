from datetime import datetime
import subprocess
from urllib.parse import urlparse, urlunparse

# services
from apps.sanitization_functions import sanitize_request

# third party
import requests
import tldextract
import xmltodict
from bson.objectid import ObjectId
from rest_framework import status
from zapv2 import ZAPv2
import json
from django.db import connections
from django_tenants.utils import get_tenant_database_alias
from apps.scanner.models.zap_models import ZAPReportsList, ZAPReport, SeverityKind
from apps.core.models.tenant import Tenant

# from apps.zap_integration.zap_services import html_to_pdfconversion
from .generate_token import get_tokens_for_user
from apps.users.models import User
from config import s3_config as s3_config
import boto3
from rest_framework.exceptions import NotFound
import configparser
from constants.server_config import SERVER_TYPE

config = configparser.ConfigParser()
config.read("cognito_constants.ini")
DOMAIN = config[SERVER_TYPE]["DOMAIN"]
from constants.response_messages import *


def extract_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if domain.startswith("www."):
        domain = domain[4:]
    try:
        url = domain.split(".")[-2]
        return url.capitalize()
    except:
        return None


def is_valid_url(url):
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme or parsed_url.scheme not in ["http", "https"]:
            return False
        ext = tldextract.extract(parsed_url.netloc)
        return bool(ext.domain) and bool(ext.suffix)
    except ValueError:
        return False


def is_request_url(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:55.0) Gecko/20100101 Firefox/55.0",
        }
        response = sanitize_request(url, headers=headers)
        return 200 <= response.status_code <= 299
    except requests.exceptions.RequestException:
        return False


def normalize(restructured_data, obj_id, file_name, user, tenant_id):
    from apps.scanner.tasks import pdf_generation

    print("obj_id ======= ", obj_id)
    zap_report = ZAPReportsList.objects.get(id=obj_id)
    baseurl = zap_report.base_url
    ZAPReport.objects.filter(zap_id__base_url=baseurl).delete()
    count = 1
    for data in restructured_data:
        if "instances" in data:
            instances_data = data.pop("instances")
            data.update(instances_data)
        data["url"] = data["uri"]
        if data["desc"] is not None:
            data["description"] = data["desc"].replace("<p>", "")
        if data["solution"] is not None:
            data["solution"] = data["solution"].replace("<p>", "")
        if data["riskdesc"] is not None:
            data["risk"] = data["riskdesc"].split(" (")[0]
        if data["reference"] is not None:
            data["reference"] = data.get("reference", "").replace("<p>", "")
        data["id"] = count
        count += 1
        del data["uri"]
        ZAPReport.objects.get_or_create(
            zap=zap_report,
            name=data["name"],
            risk=SeverityKind[data["risk"].upper()],
            description=data["description"],
            instances=data["count"],
            url=data["url"],
            method=data["method"],
            attack=data["attack"],
            evidence=data["evidence"],
            solution=data["solution"],
            reference=data["reference"],
            cwe_id=data["cweid"],
            wasc_id=data["wascid"],
            plugin_id=data["pluginid"],
        )

    token, user_id = get_tokens_for_user(user, tenant_id)
    # html_to_pdfconversion(user_id, token, baseurl, file_name, obj_id)
    pdf_generation(user_id, token, baseurl, file_name, str(obj_id), tenant_id, DOMAIN)


def zap_scanning_async(baseurl, user, tenant):
    # local
    # from .zap_services import zap_report_database
    from datetime import datetime

    print("Inside the zap scanning", baseurl)
    file_name = "Web_Scanning_Reports_" + str(datetime.now()) + ".pdf"

    connection = connections[get_tenant_database_alias()]
    connection.set_schema_to_public()
    tenant = Tenant.objects.get(uid=tenant)
    connection.set_tenant(tenant)
    user = User.objects.get(id=user)
    zap_report = ZAPReportsList.objects.create(
        is_ready=False, file_name=file_name, base_url=baseurl
    )
    obj_id = zap_report.id
    command = f"java -jar /scan/zap/zap-2.15.0.jar -cmd -quickurl {baseurl} "
    # command = f'java -jar ZAP_2.15.0_Linux/ZAP_2.15.0/zap-2.15.0.jar -cmd -quickurl {baseurl}'
    # command = f'java -jar ZAP_2.15.0_Linux/ZAP_2.15.0/zap-2.15.0.jar -cmd -quickurl https://qa.trustme.ai'
    print("command = ", command)
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    print("result = ", result.returncode)

    json_string = []
    if result.returncode == 0:
        print("*********************")
        xml_string = "\n".join(result.stdout.split("\n")[1:])
        start_index = xml_string.find("<?xml")
        if start_index != -1:
            xml_string = xml_string[start_index:]
        json_data = xmltodict.parse(xml_string.strip())
        json_string = json.dumps(json_data, indent=4)
        data = json.loads(json_string)
        restructured_data = []
        try:
            for alertitem in data["OWASPZAPReport"]["site"]["alerts"]["alertitem"]:
                instances = alertitem["instances"]["instance"]
                if isinstance(instances, list):
                    for instance in instances:
                        alert_copy = alertitem.copy()
                        alert_copy["instances"] = instance
                        restructured_data.append(alert_copy)
                else:
                    alertitem["instances"] = instances
                    restructured_data.append(alertitem)
        except Exception as e:
            site_data = data["OWASPZAPReport"]["site"]
            restructured_data = []
            for site in site_data:
                alerts = site["alerts"]["alertitem"]
                if not isinstance(alerts, list):
                    alerts = [alerts]
                for alert in alerts:
                    instances = alert["instances"]["instance"]
                    if not isinstance(instances, list):
                        instances = [instances]
                    alert_copy = alert.copy()
                    del alert_copy["instances"]
                    for instance in instances:
                        instance_data = {**alert_copy, **instance}
                        restructured_data.append(instance_data)
        normalize(restructured_data, obj_id, file_name, user, connection.tenant.uid)
        # print('=====================================')
    return json_string


def remove_duplicates(data):
    try:
        # print('sssssss', data)
        unique_data = {}
        for item in data:
            # description = item["description"]
            url = item["url"]
            severity = item["risk"]
            name = item["name"]
            key = (url, name, severity)
            if key not in unique_data:
                unique_data[key] = {"data": [], "instances": 0}
            unique_data[key]["data"].append(item)
            unique_data[key]["instances"] += 1
        deduplicated_data = []

        for description, item_info in unique_data.items():
            items = item_info["data"]
            occurrences = item_info["instances"]
            item = items[0]
            item["instances"] = occurrences
            deduplicated_data.append(item)
        print("mmmmmm = ", len(deduplicated_data))
        return deduplicated_data
    except Exception as e:
        print(str(e))
        return []


def get_dast_report_url(file_name, tenant_id):
    file_folder = s3_config.ZAP_FOLDER_PATH + tenant_id + "/"
    s3_client = boto3.client("s3", endpoint_url=s3_config.S3_BUCKET_ENDPOINT_URL)
    print(file_name, s3_config.REPORT_BUCKET_NAME, s3_config.PMD_REPORT_FOLDER_PATH)
    file_view_url = s3_client.generate_presigned_url(
        "get_object",
        Params={
            "Bucket": s3_config.REPORT_BUCKET_NAME,
            "Key": file_folder + file_name,
            "ResponseContentType": "application/pdf",
        },
        ExpiresIn=300,
    )
    file_download_url = s3_client.generate_presigned_url(
        "get_object",
        Params={"Bucket": s3_config.REPORT_BUCKET_NAME, "Key": file_folder + file_name},
        ExpiresIn=300,
    )
    print(file_view_url, file_download_url)
    if file_download_url:
        response = {"view_url": file_view_url, "download_url": file_download_url}
        return response
    raise NotFound(FILE_NOT_FOUND)
