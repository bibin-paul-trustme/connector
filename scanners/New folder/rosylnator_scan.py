import re
import json
import subprocess

from .base import BaseScanner
from ..choices import ScanKind
from ..models import CodeQualityAnalyserScanAlerts, SeverityKind
from apps.core.exception import ScanningFailedError
import os
from pathlib import Path



class RosylnatorScanner(BaseScanner):
    SCAN_KIND = ScanKind.ROSLYNATOR

    def run(self):
        sln_files = []
        for root, dirs, files in os.walk(self.path):
            for file in files:
                if file.endswith('.sln'):
                    sln_files.append(os.path.join(root, file))
        command = ['roslynator', 'analyze', sln_files[0]]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 1:
            raise ScanningFailedError
        return result.stdout

    def normalize(self, results):
        try:
            prefixes_to_match = ['Load solution', 'Loading solution', 'Done loading solution', 'Analyze solution',
                                'Analyze', 'No analyzers found to', 'Done analyzing solution', 'warning']
            excluded_lines = [line.strip() for line in results.split('\n') if
                            not any(line.strip().startswith(prefix) for prefix in prefixes_to_match) and (
                                        not line.strip() or not line.strip()[0].isdigit())]
            excluded_lines = list(filter(None, excluded_lines))
            pattern = r'(.*?\(\d+,\d+\)): (\w+ \w+): (.*)'
            for line in excluded_lines:
                match = re.match(pattern, line)
                if match:
                    file_location = match.group(1)
                    warning_code = match.group(2)
                    warning_description = match.group(3)
                    result = [file_location, warning_code, warning_description]
                result_data = {}
                filename = file_location.split('(')[0]
                if self.path in filename:
                    filename = Path(filename).relative_to(self.path)
                result_data['filename'] = filename
                result_data['description'] = warning_description
                result_data['severity'] = warning_code.split(' ')[1]
                result_data['rule'] = warning_code.split(' ')[1]
                result_data['rule_set'] = warning_code.split(' ')[1]
                result_data['begin_line'] = file_location.split('(')[1].split(',')[0]
                result_data['scan'] = self.scan

                if result_data["severity"] == "error":
                    result_data["severity"] = SeverityKind.HIGH
                elif result_data["severity"] == "warning":
                    result_data["severity"] = SeverityKind.MEDIUM
                else:
                    result_data["severity"] = SeverityKind.LOW

                scm_link = self.get_scm_link(
                    filename=filename,
                    line_number=result_data['begin_line'],
                )
                result_data['scm_link'] = scm_link
                CodeQualityAnalyserScanAlerts.objects.create(**result_data)
            return
        except Exception as e:
            print("e = ",e)
            return
