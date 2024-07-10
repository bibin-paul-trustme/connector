import json
import os
from pathlib import Path
import subprocess

from .base import BaseScanner
from ..choices import ScanKind
from ..models import CodeQualityAnalyserScanAlerts, SeverityKind


class RuboCopScanner(BaseScanner):
    SCAN_KIND = ScanKind.RUBOCOP

    def run(self):
        command = r"rubocop %s --format json" % self.path
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return json.loads(result.stdout)

    def normalize(self, results):
        try:
            if results['files']:
                for file_data in results["files"]:
                    file_path = file_data["path"]
                    if self.path in file_path:
                        file_path = Path(file_path).relative_to(self.path)
                        for offense in file_data["offenses"]:
                            if offense["severity"] in ['fatal', 'error','warning']:
                                severity = SeverityKind.HIGH
                            elif offense["severity"] in ['convention']:
                                severity = SeverityKind.MEDIUM
                            else:
                                severity = SeverityKind.LOW
                            violations = {
                                "filename": file_path,
                                "description": offense["message"],
                                "severity": severity,
                                "rule": offense["cop_name"],
                                "rule_set": offense["cop_name"],
                                "begin_line": offense["location"]["start_line"],
                                "scan": self.scan
                            }
                            resp = CodeQualityAnalyserScanAlerts.objects.create(**violations)
        except Exception as e:
            print(e)
        return
