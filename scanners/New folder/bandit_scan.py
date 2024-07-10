import json
import subprocess
from pathlib import Path

from apps.core.exception import ScanningFailedError

from .base import BaseScanner
from ..choices import ScanKind
from ..models import CodeLevelVulnerability, SeverityKind


class BanditScanner(BaseScanner):
    SCAN_KIND = ScanKind.BANDIT

    def run(self):
        command = ['bandit', self.path, '-r', '-f', 'json', '--silent']
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 1:
            raise ScanningFailedError
        return json.loads(result.stdout)

    def normalize(self, results):
        vulnerabilities = []
        for report_result in results.get('results', []):
            severity_str = report_result.get('issue_severity', '')
            line_number = report_result.get('line_number', 1)

            filename = report_result.get('filename')
            filename = Path(filename).relative_to(self.path)
            description = report_result.get('issue_text', None)
            details = report_result.get('code', None)
            reference = report_result.get('more_info', None)

            scm_link = self.get_scm_link(
                filename=filename,
                line_number=line_number,
            )

            result_data = {
                'scan': self.scan,
                'title': report_result.get('test_name'),
                'filename': filename,
                'line_number': line_number,
                'severity': getattr(SeverityKind, severity_str.upper()),
                'category': f"CWE-{report_result['issue_cwe']['id']}",
                'scm_link': scm_link,
                'description': description,
                'details': details,
                'reference': reference
            }
            vulnerabilities.append(CodeLevelVulnerability(**result_data))

        CodeLevelVulnerability.objects.bulk_create(vulnerabilities)
