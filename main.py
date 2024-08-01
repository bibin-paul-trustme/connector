import os
import configparser
from services.svn_services import repo_update
from services.language_detection import detect_frameworks_in_directory

from scanners.trivy_scan import trivy_scan
from scanners.insider_scan import insider_scan
from scanners.pmd_scan import pmd_scan
from scanners.roslynator_scan import rosylnator_scan
from scanners.ruff_scan import ruff_scan
from scanners.bandit_scan import bandit_scan
from scanners.rubocop_scan import rubocop_scan
from scanners.detekt_scan import detekt_scan
from scanners.phpmd_scan import phpmd_scan
from scanners.gosec_scan import gosec_scan
from scanners.progpilot_scan import progpilot_scan
from scanners.sfdx import sfdx_scan

def RuffScanner():
    ruff_scan()
    print("Running RuffScanner...")

def BanditScanner():
    bandit_scan()
    print("Running BanditScanner...")

def TrivyScanner():
    print("Running TrivyScanner...")
    trivy_scan()

def RosylnatorScanner():
    print("Running RosylnatorScanner...")
    rosylnator_scan()

def RuboCopScanner():
    print("Running RosylnatorScanner...")
    rubocop_scan()

def RosylnatorScanner():
    print("Running RosylnatorScanner...")
    rosylnator_scan()

def GoSecScanner():
    print("Running GoSecScanner...")
    gosec_scan()

def PHPMDScanner():
    print("Running PHPMDScanner...")
    phpmd_scan()

def DetektScanner():
    print("Running DetektScanner...")
    detekt_scan()

def ProgPilotScanner():
    print("Running ProgPilotScanner...")
    progpilot_scan()

def DetektScanner():
    print("Running DetektScanner...")
    detekt_scan()

def InsiderJavaScriptScanner():
    print("Running InsiderJavaScriptScanner...")
    insider_scan('JavaScript')

def InsiderCSharpScanner():
    print("Running InsiderCSharpScanner...")
    insider_scan('CSharp')

def InsiderKotlinScanner():
    print("Running InsiderKotlinScanner...")
    insider_scan('Kotlin')

def InsiderJavaScanner():
    print("Running InsiderJavaScanner...")
    insider_scan('Java')

def PMDJavaScriptScanner():
    print("Running PMDJavaScriptScanner...")
    pmd_scan('JavaScript')

def PMDJavaScanner():
    print("Running PMDJavaScanner...")
    pmd_scan('Java')

def SFDXScanner():
    print("Running SFDXScanner...")
    sfdx_scan()


config = configparser.ConfigParser()
config.read('svn_config.ini')

SCANNER_MAPPING = {
    'Python': [
        RuffScanner,
        BanditScanner,
        TrivyScanner,
    ],
    'Apex': [
        SFDXScanner,
        TrivyScanner,
    ],
    'JavaScript': [
        TrivyScanner,
        InsiderJavaScriptScanner,
        PMDJavaScriptScanner,
    ],
    '.NET': [
        TrivyScanner,
        InsiderCSharpScanner,
        RosylnatorScanner,
    ],
    'TypeScript': [
        TrivyScanner,
        InsiderJavaScriptScanner,
        PMDJavaScriptScanner,
    ],
    'Java': [
        TrivyScanner,
        InsiderJavaScanner,
        PMDJavaScanner,
    ],
    'Go': [
        TrivyScanner,
        GoSecScanner,
    ]
    ,
    'PHP': [
        TrivyScanner,
        PHPMDScanner,
        ProgPilotScanner,
    ],
    'Ruby': [
        TrivyScanner,
        RuboCopScanner,
    ],
    'Kotlin': [
        TrivyScanner,
        InsiderKotlinScanner,
        DetektScanner,
    ]
}


def run_scanners(language):
    if language in SCANNER_MAPPING:
        scanners = SCANNER_MAPPING[language]
        for scanner in scanners:
            scanner()
    else:
        print(f"No scanners available for the language: {language}")

repo_list = config.get('LOCAL', 'repo_list').split(', ')
repo_list = ['https://DESKTOP-U5QL7TU/svn/python_repo']
for repo in repo_list:
    repo_update(repo)
    frame_wroks = detect_frameworks_in_directory(repo)
    for framework in frame_wroks:
        run_scanners(framework)
