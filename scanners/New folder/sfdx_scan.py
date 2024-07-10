import subprocess

from datetime import datetime

from .base import BaseScanner
from ..choices import ScanKind
from ..models import CodeLevelVulnerability, SeverityKind
import json
from pathlib import Path


class SFDXScanner(BaseScanner):
    SCAN_KIND = ScanKind.SFDX


    def run(self):
        command = f'sf scanner run --target {self.path} --category Security --format json'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        data1 = json.loads(result.stdout) if result.returncode == 0 else []

        command = f'sf scanner run dfa --target {self.path} --category Security --format=json'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            message, json_string = result.stdout.split('\n', 1)
            data2 = json.loads(json_string)
        else:
            data2 = []
        return data1 + data2

    def normalize(self, results):
        report = results
        for report_result in report:
            result_data = {}
            filename = report_result.get('fileName')
            if self.path in filename:
                filename = Path(filename).relative_to(self.path)
            violations = report_result['violations']
            result_data['scan'] = self.scan
            for violation in violations:
                result_data['filename'] = filename
                result_data['title'] = violation['message'].strip().split('.')[0]

                if violation['severity'] == 1:
                    result_data['severity'] = SeverityKind.HIGH
                elif violation['severity'] == 2:
                    result_data['severity'] = SeverityKind.MEDIUM
                else:
                    result_data['severity'] = SeverityKind.LOW

                result_data['line_number'] = violation.get('line', '1')
                result_data['category'] = violation.get('category')
                result_data['description'] = violation['message'].strip()
                # result_data['scm_link'] = violation['cweid']
                result_data['reference'] = violation.get('url')
                result_data['details'] = violation.get('details')

                scm_link = self.get_scm_link(
                    filename=filename,
                    line_number=result_data['line_number'],
                )
                result_data['scm_link'] = scm_link
                
                CodeLevelVulnerability.objects.create(**result_data)
        return
