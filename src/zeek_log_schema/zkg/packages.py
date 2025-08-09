import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from git import Repo

ZKG_TMP_WORKING_DIR = Path(tempfile.gettempdir()) / 'zeek-log-schema-zkg'


def build_package_index(zkg_repo: str = "https://github.com/zeek/packages.git"):
    # Create working directory and clean if already exists
    if ZKG_TMP_WORKING_DIR.is_dir() and len(list(ZKG_TMP_WORKING_DIR.glob("*"))) > 0:
        shutil.rmtree(ZKG_TMP_WORKING_DIR)

    ZKG_TMP_WORKING_DIR.mkdir(parents=True, exist_ok=True)
    if not ZKG_TMP_WORKING_DIR.exists():
        raise RuntimeError(f"Temporary working directory {ZKG_TMP_WORKING_DIR} could not be created")

    # Clone repository (incl. shallow checkout because we need to read the zkg.index files)
    repo = Repo.clone_from(zkg_repo, ZKG_TMP_WORKING_DIR, depth=1)

    # Extract repositories from zkg.index files
    package_repos = {}
    for zkg_index_file in ZKG_TMP_WORKING_DIR.glob('**/zkg.index'):
        with zkg_index_file.open('r') as f:
            package_repos |= parse_zkg_index(f.readlines())

    # Clean up temp dir
    shutil.rmtree(ZKG_TMP_WORKING_DIR)

    return package_repos


def parse_zkg_index(zkg_index_lines: list[str]) -> dict[str, str]:
    repos = {}

    for line in zkg_index_lines:
        repo_url = line.strip()
        try:
            # Use urlparse instead of removeprefix (to support other platforms besides GitHub in the future) and regex (because of possible query params/fragments in URL)
            package_name = urlparse(repo_url).path.removeprefix('/')
            repos[package_name] = repo_url
        except KeyboardInterrupt:
            pass
        except:
            raise ValueError(f"Could not parse repository from zkg.index: {line}")

    return repos
