from apps.reports.tasks import convert_html_to_pdf
from asgiref.sync import sync_to_async
from ..models.scqa_report import SCQAReport
from django_tenants.utils import get_tenant_database_alias
from django.db import connections
from apps.core.models.tenant import Tenant
# builtins
import asyncio
import io
import json
import tempfile

# third party
import boto3
from pyppeteer import launch

from config import s3_config
from rest_framework.exceptions import NotFound
from constants.response_messages import *

def generate_pmd_parameter(repo_url, branch):
    url_params = ''
    url_params = url_params + 'repository_url=' + repo_url + '&branch=' + branch
    return url_params


@sync_to_async
def scqa_report_collection_update(obj_id, user_id=None, schema_name=None):
    connection = connections[get_tenant_database_alias()]
    tenant = Tenant.objects.get(schema_name=schema_name)
    connection.set_schema_to_public()
    connection.set_tenant(tenant)
    SCQAReport.objects.filter(id=obj_id).update(report_status=True)

async def convert_html_to_pdf(
    file_name, tenant_id, user_id, obj_id, token, base_url, repo_url, branch, url_params, repo_name, schema_name=None
):
    with tempfile.TemporaryFile() as fp:
        # print("trivy-report-file-name ", type(file_name))
        browser = await launch(
            handleSIGINT=False,
            handleSIGTERM=False,
            handleSIGHUP=False,
            headless=True,
            # userDataDir='/tmp/pyppeteer_userdata'
            userDataDir=fp,
            # executablePath="C:\Program Files\Google\Chrome\Application\chrome.exe",
            executablePath='/home/sbx_user1051/headless-chromium',
            args=[
                '--no-sandbox',
                '--single-process',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--no-zygote',
            ],
        )

        print('browser - ', browser)
        page = await browser.newPage()
        width, height = 1280, 689  # You can adjust these values
        await page.setViewport({'width': width, 'height': height})
        print('page', page)
        # print(domain, token)
        print('####REPO#####', repo_url, repo_url)
        if repo_url:
            url = (
                base_url
                + '/#/security-analysis-report?page=source-code-report&token='
                + token
                + '&repo='
                + repo_url
                + '&repository_url='
                + repo_url
                + '&branch='
                + branch
                + '&domain_url='
                + base_url
            )
        else:
            url = base_url + '/#/security-analysis-report?page=source-code-report&token=' + token
        print('url ==> ', url)
        await page.goto(url)
        await asyncio.sleep(120)
        pdf = await page.pdf(
            {
                'format': 'A4',
                'margin': {'top': '5mm', 'right': '5mm', 'bottom': '5mm', 'left': '5mm'},
                'printBackground': 'true',
            },
        )
        await browser.close()
        print('------> ', s3_config.PMD_REPORT_FOLDER_PATH)
        s3_key = s3_config.PMD_REPORT_FOLDER_PATH + tenant_id + '/' + file_name
        print('s3_key', s3_key)
        print('s3_key', s3_config.REPORT_BUCKET_NAME)
        s3 = boto3.client('s3')
        s3 = s3.put_object(Bucket=s3_config.REPORT_BUCKET_NAME, Key=s3_key, Body=pdf)
        await scqa_report_collection_update(obj_id=obj_id, schema_name=schema_name)


def generate_report_web_page(
    file_name, tenant_id, user_id, obj_id, token, base_url, repo_url, branch, url_params, repo_name, schema_name=None
):
    print('==========================START===========================')
    loop = asyncio.new_event_loop()
    result = loop.run_until_complete(
        convert_html_to_pdf(
            file_name, tenant_id, user_id, obj_id, token, base_url, repo_url, branch, url_params, repo_name, schema_name=schema_name,
        )
    )


def get_scqa_report_url(file_name, tenant_id):

    file_folder = s3_config.PMD_REPORT_FOLDER_PATH + tenant_id + '/'
    s3_client = boto3.client('s3', endpoint_url=s3_config.S3_BUCKET_ENDPOINT_URL)
    print(file_name, s3_config.REPORT_BUCKET_NAME, s3_config.PMD_REPORT_FOLDER_PATH)
    file_view_url = s3_client.generate_presigned_url(
        'get_object',
        Params={
            'Bucket': s3_config.REPORT_BUCKET_NAME,
            'Key': file_folder + file_name,
            'ResponseContentType': 'application/pdf',
        },
        ExpiresIn=300,
    )
    file_download_url = s3_client.generate_presigned_url(
        'get_object', Params={'Bucket': s3_config.REPORT_BUCKET_NAME, 'Key': file_folder + file_name}, ExpiresIn=300
    )
    print(file_view_url, file_download_url)
    if file_download_url:
        response = {'view_url': file_view_url, 'download_url': file_download_url}
        return response
    raise NotFound(FILE_NOT_FOUND)