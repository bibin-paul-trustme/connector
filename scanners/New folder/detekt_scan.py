import json
import subprocess
from pathlib import Path

from .base import BaseScanner
from ..choices import ScanKind
from ..models import CodeQualityAnalyserScanAlerts, SeverityKind
import xml.etree.ElementTree as ET


def xml_file_to_json(xml_file_path):
    tree = ET.parse(xml_file_path)
    root = tree.getroot()
    report_dict = {
        'version': root.get('version'),
        'files': []
    }
    for file_element in root.findall('file'):
        file_report = {
            'name': file_element.get('name'),
            'errors': []
        }

        for error_element in file_element.findall('error'):
            error = {
                'line': error_element.get('line'),
                'column': error_element.get('column'),
                'severity': error_element.get('severity'),
                'message': error_element.get('message'),
                'source': error_element.get('source')
            }
            file_report['errors'].append(error)

        report_dict['files'].append(file_report)

    return report_dict

class DetektScanner(BaseScanner):
    SCAN_KIND = ScanKind.DETEKT

    def run(self):
        command = f"java -jar /scan/detekt/lib/detekt-cli-1.23.3-all.jar --input {self.path} --report xml:report_detekt.xml --all-rules"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return xml_file_to_json('report_detekt.xml')

    def normalize(self, results):
        try:
            if results['files']:
                for file_info in results['files']:
                    filename = file_info["name"]
                    if self.path in filename:
                        filename = Path(filename).relative_to(self.path)
                    for violation in file_info["errors"]:
                        if violation["severity"] in ['fatal', 'error']:
                            severity = SeverityKind.HIGH
                        elif violation["severity"] in ['warning', 'maintainability']:
                            severity = SeverityKind.MEDIUM
                        else:
                            severity = SeverityKind.LOW

                        scm_link = self.get_scm_link(
                            filename=filename,
                            line_number=violation["line"],
                        )
                        rule = violation['source'].split('.')[1]
                        violations = {
                            "filename": filename,
                            "begin_line": violation["line"],
                            "description": violation["message"],
                            "rule": rule,
                            "severity": severity,
                            "rule_set": rule,
                            "scan": self.scan,
                            "scm_link": scm_link,
                        }
                        CodeQualityAnalyserScanAlerts.objects.create(**violations)
        except Exception as e:
            print(e)
        return
