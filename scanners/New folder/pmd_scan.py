import json
import subprocess
from pathlib import Path

from .base import BaseScanner
from ..choices import ScanKind
from ..models import CodeQualityAnalyserScanAlerts, SeverityKind


class PMDScanner(BaseScanner):
    SCAN_KIND = ScanKind.PMD

    def run(self):
        command = f"pmd check -d {self.path} -f json -R {self.RULESET}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return json.loads(result.stdout)

    def normalize(self, results):
        try:
            if results['files']:
                for file_info in results['files']:
                    filename = file_info["filename"]
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
                            line_number=violation["beginline"],
                        )

                        violations = {
                            "filename": filename,
                            "begin_line": violation["beginline"],
                            "description": violation["description"],
                            "rule": violation["rule"],
                            "severity": severity,
                            "rule_set": violation["ruleset"],
                            "scan": self.scan,
                            "scm_link": scm_link,
                        }
                        CodeQualityAnalyserScanAlerts.objects.create(**violations)
        except Exception as e:
            print(e)
        return


class PMDJavaScanner(PMDScanner):
    RULESET = 'category/ecmascript/errorprone.xml, category/ecmascript/bestpractices.xml'


class PMDJavaScriptScanner(PMDScanner):
    RULESET = 'category/java/security.xml, category/java/performance.xml, category/java/multithreading.xml, category/java/errorprone.xml, category/java/documentation.xml, category/java/codestyle.xml, category/java/bestpractices.xml'
