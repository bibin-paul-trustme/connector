from apps.core.exception import ScanningFailedError
from ..models import ScanRawResult, Scan


class BaseScanner:
    SCAN_KIND = None

    def __init__(self, path: str, scan: Scan) -> None:
        self.path = path
        self.scan = scan

    def run(self):
        raise NotImplementedError

    def normalize(self, results):
        raise NotImplementedError

    def get_scm_link(self, filename, line_number):
        repo_url = self.scan.repo.url
        return self.scan.repo.credential.get_scm_link(
            repo_url=repo_url[:-4],
            branch=self.scan.branch,
            commit=self.scan.commit,
            filename=filename,
            line_number=line_number,
        )

    # @shared_task
    def dispatch(self):
        try:
            results = self.run()
        except ScanningFailedError as e:
            results = {"called_process_error": str(e)}

        ScanRawResult.objects.create(
            scan=self.scan,
            results=results,
            kind=self.SCAN_KIND,
        )

        if 'called_process_error' not in results:
            self.normalize(results=results)
