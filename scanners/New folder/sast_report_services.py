from ..models.sast_report import SASTReport
# django
from django.utils import timezone

from asgiref.sync import sync_to_async
from django_tenants.utils import get_tenant_database_alias
from django.db import connections
from apps.core.models.tenant import Tenant
from config import s3_config as s3_config
import boto3
from constants.response_messages import *
from rest_framework.exceptions import NotFound



@sync_to_async
def trivy_scan_report_pdf_update(obj_id, file_name, schema_name):
    print('123 =q=======> ', obj_id, file_name)
    connection = connections[get_tenant_database_alias()]
    tenant = Tenant.objects.get(schema_name=schema_name)
    connection.set_schema_to_public()
    connection.set_tenant(tenant)
    # qs = BitbucketScanReport.objects.filter(_id=ObjectId(obj_id))
    qs = SASTReport.objects.filter(id=obj_id)
    print('qs====================>>>>', qs)
    # report_generated_local_time = timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z')
    # if qs[0].time_zone:
    #     time_zone = qs[0].time_zone
    #     report_generated_local_time = convert_utc_to_local(time_zone)
    update_obj = qs.update(
        report_status=True,
        # file_name=file_name,
        # report_generated_at=timezone.now(),
    )
    print('update_obj ===========> ', update_obj)


def get_sast_report_url(file_name, tenant_id):

    file_folder = s3_config.TRIVY_REPORT_FOLDER_PATH + tenant_id + '/'
    s3_client = boto3.client('s3', endpoint_url=s3_config.S3_BUCKET_ENDPOINT_URL)
    print(file_name, s3_config.REPORT_BUCKET_NAME, s3_config.REPORT_FOLDER_PATH)
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
