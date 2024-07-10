import json
import subprocess

from services.insider.insider_scan import search_csv
from .base import BaseScanner
from ..choices import ScanKind
from ..models import CodeLevelVulnerability, SeverityKind
from .get_extensions import get_extensions_in_tree
from pathlib import Path



class BaseInsiderScanner(BaseScanner):
    SCAN_KIND = ScanKind.INSIDER
    # COMMAND = 'javascript'
    EXTENSIONS_TO_SCAN = [
        '.js',     # JavaScript
        '.ts',     # TypeScript
        '.java',
        '.kt',     # Kotlin
        '.cs',     # C#
        '.cshtml', # C# HTML
        '.aspx',   # Active Server Page, Extended (a .NET web form)
    ]

    def run(self):
        # We don't want insider to scan .md or .png files, for example.

        exclude_extensions = get_extensions_in_tree(self.path)
        # Don't exclude the extensions we want to scan.
        exclude_extensions.difference_update(self.EXTENSIONS_TO_SCAN)

        if exclude_extensions:
            print('Will not scan these extensions: ', exclude_extensions)

        # Change each extension into a regular expression
        exclude_regexps = ['\\{}$'.format(ext) for ext in exclude_extensions]

        # If the tree has a ridiculous number of extensions, trim the list

        sum_of_lengths = sum(map(len, exclude_regexps))
        LIMIT = 1000  # Arbitrary
        while sum_of_lengths > LIMIT:
            last = exclude_regexps.pop()
            sum_of_lengths -= len(last)

        exclude_regexps.extend(['/test/', '/LICENSE$'])
        exclude_options = ['-exclude \'{}\''.format(regexp) for regexp in exclude_regexps]
        exclude_options = ' '.join(exclude_options)

        command = f"/scan/insider --tech {self.COMMAND} -quiet --target {self.path} -no-html {exclude_options} > /dev/null 2>&1 && cat report.json"
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(result.stdout)

        # removing duplicates in the result
        unique_vulnerabilities = set()
        unique_vul_list = []

        for vuln in data.get('vulnerabilities', []):
            vuln_tuple = (vuln.get('cvss'), vuln.get('cwe'), vuln.get('line'), vuln.get('class'), vuln.get('vul_id'), vuln.get('column'), vuln.get('description'), vuln.get('classMessage'))
            if vuln_tuple not in unique_vulnerabilities:
                unique_vulnerabilities.add(vuln_tuple)
                unique_vul_list.append(vuln)

        unique_data = {'vulnerabilities': unique_vul_list}
        unique_json_str = json.dumps(unique_data, indent=2)
        if result.returncode != 0:
            return {'error_code': result.returncode}
        return json.loads(unique_json_str)


    def normalize(self, results):
        scan_result = results.get('vulnerabilities', [])
        for data in scan_result:
            result_data = {}
            parts = data['classMessage'].split(' (')
            cwe_id = data.get('cwe', None)
            if cwe_id:
                cwe_id_res = str(cwe_id).split('-')[1]
                cwe_data = search_csv(cwe_id_res)
                result_data['description'] = cwe_data
                result_data['title'] = data.get('description', None).split(".")[0]
            else:
                result_data['title'] = data.get('method', '')
                result_data['description'] = data.get('description', None)

            result_data['category'] = data.get('cwe', None)
            result_data['severity'] = data.get('cvss', None)
            if result_data["severity"] > 6:
                result_data["severity"] = SeverityKind.HIGH
            elif result_data["severity"] < 4:
                result_data["severity"] = SeverityKind.LOW
            else:
                result_data["severity"] = SeverityKind.MEDIUM
            filename = parts[0]
            if self.path in filename:
                filename = Path(filename).relative_to(self.path)
            # result_data["severity"] = 1
            result_data['filename'] = filename
            result_data['line_number'] = data.get('line', None)
            result_data['reference'] = [
                f"https://cwe.mitre.org/data/definitions/{cwe_id_res}.html"
            ]
            result_data['details'] = data.get('recomendation', None)
            result_data['cwe_id'] = data.get('cwe', None)
            result_data['cvss'] = data.get('cvss', 0)
            result_data['scan'] = self.scan
            scm_link = self.get_scm_link(
                filename=filename,
                line_number=result_data['line_number'],
            )
            result_data['scm_link'] = scm_link

            CodeLevelVulnerability.objects.get_or_create(**result_data)


class InsiderJavaScriptScanner(BaseInsiderScanner):
    COMMAND = 'javascript'


class InsiderJavaScanner(BaseInsiderScanner):
    COMMAND = 'java'


class InsiderCSharpScanner(BaseInsiderScanner):
    COMMAND = 'csharp'


class InsiderKotlinScanner(BaseInsiderScanner):
    COMMAND = 'android'


class InsiderIosScanner(BaseInsiderScanner):
    COMMAND = 'ios'
