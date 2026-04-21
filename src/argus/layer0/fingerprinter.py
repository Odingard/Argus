import subprocess
import json
import re
from typing import Dict

class VersionFingerprinter:
    """Layer 0: Identifies target versioning to prevent false positives."""

    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    def get_constraints(self) -> Dict[str, str]:
        """Logs and returns version metadata from the target."""
        constraints = {}
        # 1. Check pyproject.toml / requirements.txt
        try:
            with open(f"{self.repo_path}/pyproject.toml", 'r') as f:
                content = f.read()
                version = re.search(r'version = "(.*?)"', content)
                if version:
                    constraints['framework_version'] = version.group(1)
        except FileNotFoundError:
            constraints['framework_version'] = "unknown"

        # 2. Check Git Tags (2026 standard for release tracking). Tight
        # exception list: the only failures we expect are (a) git binary not
        # installed (FileNotFoundError), (b) path is not a git repo or has no
        # tags (CalledProcessError). Anything else bubbles up.
        try:
            tag = subprocess.check_output(
                ["git", "-C", self.repo_path, "describe", "--tags"],
                stderr=subprocess.STDOUT,
                timeout=5,
            ).decode().strip()
            constraints['git_tag'] = tag
        except FileNotFoundError:
            constraints['git_tag'] = "git_not_installed"
        except subprocess.CalledProcessError:
            constraints['git_tag'] = "no_tags"
        except subprocess.TimeoutExpired:
            constraints['git_tag'] = "git_timeout"

        print(f"[LAYER 0] Fingerprint Captured: {json.dumps(constraints)}")
        return constraints
