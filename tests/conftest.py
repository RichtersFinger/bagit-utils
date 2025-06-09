from pathlib import Path
from shutil import rmtree

import pytest


@pytest.fixture(name="tmp", scope="session")
def _tmp():
    return Path("tests/tmp")


def _tmp_cleanup(target):
    if target.is_dir():
        rmtree(target)


@pytest.fixture(scope="session", autouse=True)
def tmp_setup(tmp):
    """Set up tmp"""
    _tmp_cleanup(tmp)
    tmp.mkdir()


@pytest.fixture(scope="session", autouse=True)
def tmp_cleanup(request, tmp):
    """Clean up tmp"""
    request.addfinalizer(lambda: _tmp_cleanup(tmp))
