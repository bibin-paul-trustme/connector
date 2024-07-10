import pygit2

from constants.scan_issues_categories import CODE_VULNERABILITY, CODE_QUALITY, LANG_PKGS, LICENSE, CREDENTIAL
from ..models import (
    CodeLevelVulnerability,
    CodeQualityAnalyserScanAlerts,
    CredentialExposure,
    LicenseExposure,
    VulnerablePackage,
    SeverityKind,
)
from django.db.models import F, IntegerField, Value, When, Case, CharField


def get_scan_issues_list(scan_obj):
    scan = scan_obj

    # Get vulnerabilities related to the scan
    code_vulnerabilities = CodeLevelVulnerability.objects.filter(scan=scan).annotate(
        line=F('line_number'),
        severity_level=F('severity'),
        file_name=F('filename'),
        issue_category=Value(CODE_VULNERABILITY, output_field=CharField())
    ).values('line', 'severity_level', 'file_name', 'issue_category')

    # Get alerts related to the scan
    code_alerts = CodeQualityAnalyserScanAlerts.objects.filter(scan=scan).annotate(
        line=F('begin_line'),
        severity_level=F('severity'),
        file_name=F('filename'),
        issue_category=Value(CODE_QUALITY, output_field=CharField())
    ).values('line', 'severity_level', 'file_name', 'issue_category')

    # Get credential exposures related to the scan
    credential_exposures = CredentialExposure.objects.filter(scan=scan).annotate(
        line=F('begin_line'),
        severity_level=F('severity'),
        file_name=F('filename'),
        issue_category=Value(CREDENTIAL, output_field=CharField())
    ).values('line', 'severity_level', 'file_name', 'issue_category')

    # Get vulnerable packages related to the scan
    vulnerable_packages = VulnerablePackage.objects.filter(scan=scan).annotate(
        line=Case(
            When(file__isnull=True, then=Value(1)),
            default=Value(1),
            output_field=IntegerField()
        ),
        severity_level=F('severity'),
        file_name=F('file'),
        issue_category=Value(LANG_PKGS, output_field=CharField())
    ).values('line', 'severity_level', 'file_name', 'issue_category')

    # Get license exposures related to the scan
    license_exposures = LicenseExposure.objects.filter(scan=scan).annotate(
        line=Case(
            When(filename__isnull=True, then=Value(1)),
            default=Value(1),
            output_field=IntegerField()
        ),
        severity_level=F('severity'),
        file_name=F('filename'),
        issue_category=Value(LICENSE, output_field=CharField())
    ).values('line', 'severity_level', 'file_name', 'issue_category')

    # Combine results
    combined_results = list(code_vulnerabilities) + list(code_alerts) + list(credential_exposures) + list(vulnerable_packages) + list(license_exposures)

    # Severity kind choices mapping
    severity_labels = dict(SeverityKind.choices)

    # Initialize a dictionary to store the highest severity result for each file and line
    unique_results = {}

    for result in combined_results:
        # Apply severity labels
        result['severity'] = result['severity_level']
        result['category'] = result['issue_category']

        result.pop('severity_level')
        result.pop('issue_category')
        
        # Generate the key for unique results
        key = (result['file_name'], result['line'])
        
        # If the key is not in unique_results or the current result has higher severity, update the dictionary
        if key not in unique_results or result['severity'] > unique_results[key]['severity']:
            # print("key-----", key)
            unique_results[key] = result

    # Convert the dictionary back into a list
    filtered_results = list(unique_results.values())
    return filtered_results


def get_line_author(repo_path, file_path, line_number):
    """
    Get the author of the last edit for a specific line in a file.

    :param repo_path: Path to the Git repository.
    :param file_path: Path to the file within the repository.
    :param line_number: Line number to check (1-based index).
    :return: Author name of the last edit.
    """
    try:
        # Ensure the line number is 1-based index
        line_number -= 1

        # Open the repository
        repo = pygit2.Repository(repo_path)

        # Get the blame object for the file
        blame = repo.blame(file_path)

        # Get the hunk for the specified line
        hunk = blame.for_line(line_number)
        print(hunk.final_committer)
        # Get the author of the hunk
        author = hunk.final_committer.name

        return author
    except Exception as e:
        return ""
