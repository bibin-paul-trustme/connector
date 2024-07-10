import json
import subprocess

from apps.core.exception import ScanningFailedError
from apps.scanner.models import CredentialExposure, LicenseExposure, SeverityKind, VulnerablePackage
from .base import BaseScanner
from ..choices import ScanKind
from pathlib import Path



class TrivySecretScanner(BaseScanner):
    SCAN_KIND = ScanKind.TRIVY_SECRET
    COMMAND = 'secret'
    RESULT_KEY = 'Secrets'

    def run(self):
        command = f'trivy fs --scanners {self.COMMAND} --license-full --format json --secret-config /home/sbx_user1051/trivy.yaml {self.path}'
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            # stdout=subprocess.PIPE,
            # stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            raise ScanningFailedError(result)
        return json.loads(result.stdout)

    def normalize(self, results):
        already_found = set()
        unique_secret = []
        for result in results.get('Results', []):
            for secret in result.get(self.RESULT_KEY, []):
                filename = result["Target"]
                if self.RESULT_KEY == 'Licenses':
                    filename = secret.get("FilePath")
                if self.path in filename:
                    filename = Path(filename).relative_to(self.path)
                secret["filename"] = filename
                if secret['Severity'] == 'CRITICAL':
                    secret['Severity'] = 'HIGH'
                if secret['Severity'] == 'INFORMATIONAL':
                    secret['Severity'] = 'LOW'
                severity = secret['Severity']

                secret['StartLine'] = secret.get('StartLine', 1)
                pkgname = secret.get('PkgName', 'default')
                # Is this a duplicate?
                k = (secret['StartLine'], result['Target'], severity, pkgname)
                if self.RESULT_KEY == 'Licenses': 
                    k = (secret['StartLine'], filename, severity, pkgname)
                if k in already_found:
                    continue
                already_found.add(k)

                unique_secret.append(secret)

        self.save_to_db(items=unique_secret)

    def save_to_db(self, items):
        for item in items:
            severity_str = item.get('Severity', '')
            scm_link = self.get_scm_link(
                filename=item["filename"],
                line_number=item['StartLine'],
            )
            CredentialExposure.objects.get_or_create(
                scan=self.scan,
                filename=item["filename"],
                title=item['Title'].split('.')[0],
                rule=item['RuleID'],
                severity=getattr(SeverityKind, severity_str.upper()),
                category=item['Category'],
                begin_line=item['StartLine'],
                end_line=item['EndLine'],
                content=item['Match'],
                scm_link=scm_link,
            )


class TrivyVulnerabilitiesScanner(TrivySecretScanner):
    SCAN_KIND = ScanKind.TRIVY_VULNERABILITY
    COMMAND = 'vuln,misconfig'
    RESULT_KEY = 'Vulnerabilities'
    RESULT_KEY_MISCONFIG = 'Misconfigurations'

    def normalize(self, results):
        unique_secret = []
        for result in results.get('Results', []):
            for secret in result.get(self.RESULT_KEY, []):
                secret["filename"] = result["Target"]
                if secret['Severity'] == 'CRITICAL':
                    secret['Severity'] = 'HIGH'

                if secret['Severity'] == 'INFORMATIONAL':
                    secret['Severity'] = 'LOW'

                secret['StartLine'] = secret.get('StartLine', 1)

                unique_secret.append(secret)

            for secret in result.get(self.RESULT_KEY_MISCONFIG, []):
                secret["filename"] = result["Target"]
                if secret['Severity'] == 'CRITICAL':
                    secret['Severity'] = 'HIGH'
                if secret['Severity'] == 'INFORMATIONAL':
                    secret['Severity'] = 'LOW'

                secret['StartLine'] = secret.get('StartLine', 1)

                unique_secret.append(secret)

        self.save_to_db(items=unique_secret)

    def save_to_db(self, items):
        for item in items:
            severity_str = item.get('Severity', '')
            VulnerablePackage.objects.get_or_create(
                scan=self.scan,
                title=item['Title'].split('.')[0],
                description=item['Description'],
                file=item['filename'],
                severity=getattr(SeverityKind, severity_str.upper()),
                installed_version=item.get('InstalledVersion', '')[:100],
                fixed_version=item.get('FixedVersion', '')[:100],
                library=item.get('PkgName', ''),
                vulnerability_id=item.get("VulnerabilityID", ''),
                scm_link="",
                reference=item.get('References', ''),
            )


class TrivyLicensesScanner(TrivySecretScanner):
    SCAN_KIND = ScanKind.TRIVY_LICENSE
    COMMAND = 'license'
    RESULT_KEY = 'Licenses'

    def save_to_db(self, items):
        for item in items:
            severity_str = item.get('Severity', '')
            LicenseExposure.objects.get_or_create(
                scan=self.scan,
                filename=item.get('filename', ''),
                severity=getattr(SeverityKind, severity_str.upper()),
                package=item.get("PkgName", ''),
                license=item.get("Name", ''),
                classification=item.get("Category", '')
            )
