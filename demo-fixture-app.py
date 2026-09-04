"""Demo fixture for SecurityAgent's hackathon PR-review demo - intentionally
vulnerable, not real application code."""

import subprocess
import sys


def run_backup(filename):
    subprocess.run(f"tar -czf backup.tar.gz {filename}", shell=True)


if __name__ == "__main__":
    run_backup(sys.argv[1])
