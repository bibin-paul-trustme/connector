import os
import json
import subprocess
from pathlib import Path

from apps.core.exception import ScanningFailedError

from .base import BaseScanner
from ..choices import ScanKind
from ..models import CodeLevelVulnerability, SeverityKind
from services.gosec_scanner.gosec_scan import search_csv


class ProgPilotScanner(BaseScanner):
    SCAN_KIND = ScanKind.PROGPIOLET

    def run(self):
        command = f"progpilot {self.path}"
        result = subprocess.run(command,
                                shell=True,
                                capture_output=True,
                                text=True)

        print(result.returncode)
        if result.returncode != 1:
            raise ScanningFailedError
        return json.loads(result.stdout)

    def normalize(self, results):
        # severity_mapping = {
        #     "CWE_79": "High",
        #     "CWE_98": "Critical",
        #     "CWE_95": "Critical",
        #     "CWE_78": "Critical",
        #     "CWE_90": "High",
        #     "CWE_89": "High",
        #     "CWE_285": "High",
        #     "CWE_1004": "High",
        #     "CWE_346": "High",
        #     "CWE_295": "Critical",
        #     "CWE_91": "High",
        #     "CWE_22": "High",
        #     "CWE_601": "High",
        #     }

        severity_mapping = {
        "CWE_79": "Medium",
        "CWE_98": "High",
        "CWE_95": "High",
        "CWE_78": "High",
        "CWE_90": "Medium",
        "CWE_89": "Medium",
        "CWE_285": "Medium",
        "CWE_1004": "Medium",
        "CWE_346": "Medium",
        "CWE_295": "High",
        "CWE_91": "Medium",
        "CWE_22": "Medium",
        "CWE_601": "Medium",
        "CWE_1333": "Medium"
}
        vulnerabilities = []

        for report_result in results:
            directory, filename = os.path.split(report_result.get('sink_file',''))
            line_number = report_result.get('sink_line', '1')
            filename = filename
            if self.path in filename:
                filename = Path(filename).relative_to(self.path)
            cwe_id = report_result.get('vuln_cwe')
            severity_str = severity_mapping.get(cwe_id, "Low")

            scm_link = self.get_scm_link(
                filename=filename,
                line_number=line_number,
            )
            result_data = {
                'scan': self.scan,
                'title': search_csv(str(cwe_id.split('_')[1])),
                'filename': filename,
                'line_number': line_number,
                'severity': getattr(SeverityKind, severity_str.upper()),
                'category': report_result.get('vuln_name'),
                'scm_link': scm_link,
                'description': report_result.get('vuln_type'),
                'details': '',
                'reference': f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
            }

            CodeLevelVulnerability.objects.create(**result_data)
