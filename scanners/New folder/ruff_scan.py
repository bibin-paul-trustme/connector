import subprocess

from datetime import datetime
from pathlib import Path
from .base import BaseScanner
from ..choices import ScanKind
from ..models import SeverityKind, CodeQualityAnalyserScanAlerts


class RuffScanner(BaseScanner):
    SCAN_KIND = ScanKind.RUFF

    def run(self):
        command = ['ruff', 'check', self.path]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 1:
            return {"error_code": result.returncode}
        return {'result': result.stdout}

    def normalize(self, results):
        # branch
        branch_name = self.scan.branch
        # repo-url
        repo_url = self.scan.repo.url
        output = results['result']
        report_data = []
        lines = output.split("\n")

        for line in lines:
            parts = line.split(":")
            if len(parts) >= 2:
                filename = parts[0]
                line_number, column_number, description = parts[1], parts[2], ":".join(parts[3:])
                if self.path in filename:
                    filename = Path(filename).relative_to(self.path)
                result_data = {'filename': filename, 'severity': SeverityKind.LOW,
                               'begin_line': line_number.strip(), 'begin_column': column_number.strip(),
                               'details': description,'scan':self.scan}
                if description:
                    # Splitting the description into two parts based on the first space
                    split_description = description.split(" ")

                    # Extracting the error code and the description
                    error_code = split_description[1].strip()
                    desc = " ".join(split_description[2:]).strip()
                    if "[*]" in desc:
                        desc = desc.replace("[*]", "").strip()
                    result_data['rule_set'] = error_code
                    result_data['rule'] = error_code
                    result_data['description'] = desc
                scm_link = self.get_scm_link(
                    filename=filename,
                    line_number=result_data["begin_line"],
                )
                result_data['scm_link'] = scm_link
                CodeQualityAnalyserScanAlerts.objects.create(**result_data)
        return
