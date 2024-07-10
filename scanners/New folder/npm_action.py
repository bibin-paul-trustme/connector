import os
import subprocess

from .base import BaseScanner
from ..choices import ScanKind


class NPMInstallAction(BaseScanner):
    # TODO figure out a what type a action should be
    SCAN_KIND = ScanKind.INSIDER
    COMMAND = 'javascript'

    def run(self):
        if os.path.exists(os.path.join(self.path, 'package.json')):
            npm_command = f'cd {self.path} && npm install package.json'
            result = subprocess.run(
                npm_command,
                shell=True,
                capture_output=True,
                text=True,
                check=False,
            )

            if result.returncode != 0:
                return {'error_code': result.returncode}
        return {}

    def normalize(self, results):
        pass
