import os
import json
import subprocess
from pathlib import Path

from apps.core.exception import ScanningFailedError

from .base import BaseScanner
from ..choices import ScanKind
from ..models import CodeLevelVulnerability, SeverityKind
from services.gosec_scanner.gosec_scan import search_csv


class GoSecScanner(BaseScanner):
    SCAN_KIND = ScanKind.GO_SEC

    def run(self):
        command = f"/scan/gosec -exclude=G101 -fmt=json {self.path}/./..."
        result = subprocess.run(command,
                                shell=True,
                                capture_output=True,
                                text=True)

        print(result.returncode)
        if result.returncode != 1:
            raise ScanningFailedError
        return json.loads(result.stdout)

    def normalize(self, results):
        vulnerabilities = []

        for report_result in results.get('Issues', []):
            # directory, filename = os.path.split(report_result.get('file'))
            line_number = report_result.get('line', '1')
            split_line_number = line_number.split("-")
            line_number = int(split_line_number[0])
            filename = report_result.get('file')
            if self.path in filename:
                filename = Path(filename).relative_to(self.path)
            severity_str = report_result.get('severity')

            scm_link = self.get_scm_link(
                filename=filename,
                line_number=line_number,
            )
            result_data = {
                'scan': self.scan,
                'title': report_result.get('details'),
                'filename': filename,
                'line_number': line_number,
                'severity': getattr(SeverityKind, severity_str.upper()),
                'category': f"CWE-{report_result['cwe'].get('id')}",
                'scm_link': scm_link,
                'description': search_csv(str(report_result['cwe'].get('id'))),
                'details': report_result.get('code'),
                'reference': f"https://cwe.mitre.org/data/definitions/{report_result['cwe'].get('id')}.html"
            }

            CodeLevelVulnerability.objects.create(**result_data)
