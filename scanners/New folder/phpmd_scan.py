import json
import os
from pathlib import Path
import subprocess

from .base import BaseScanner
from ..choices import ScanKind
from ..models import CodeQualityAnalyserScanAlerts, SeverityKind


class PHPMDScanner(BaseScanner):
    SCAN_KIND = ScanKind.PMD

    def run(self):
        command = r"phpmd %s json codesize,naming" % self.path
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return json.loads(result.stdout)
    
    def strip_current_directory(file_path):
        abs_path = os.path.abspath(file_path)
        current_directory = os.getcwd()
        if abs_path.startswith(current_directory):
            stripped_path = abs_path[len(current_directory):]
            if stripped_path.startswith(os.sep):
                stripped_path = stripped_path[len(os.sep):]
            return stripped_path
        else:
            return file_path

    def normalize(self, results):
        try:
            if results['files']:
                for file_info in results['files']:
                    filename = file_info["file"]
                    if self.path in filename:
                        filename = Path(filename).relative_to(self.path)
                    for violation in file_info["violations"]:
                        if violation["priority"] == 1:
                            severity = SeverityKind.HIGH
                        elif violation["priority"] in [2, 3]:
                            severity = SeverityKind.MEDIUM
                        else:
                            severity = SeverityKind.LOW

                        scm_link = self.get_scm_link(
                            filename=filename,
                            line_number=violation["beginLine"],
                        )

                        violations = {
                            "filename": filename,
                            "begin_line": violation["beginLine"],
                            "description": violation["description"],
                            "rule": violation["rule"],
                            "severity": severity,
                            "rule_set": violation["ruleSet"],
                            "scan": self.scan,
                            "scm_link": scm_link,
                        }
                        resp = CodeQualityAnalyserScanAlerts.objects.create(**violations)
                        
        except Exception as e:
            print(e)
        return
