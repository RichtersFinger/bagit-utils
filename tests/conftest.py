"""Common test fixtures."""

from uuid import uuid4

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


@pytest.fixture(name="src")
def _src(tmp):
    src = tmp / str(uuid4())
    src.mkdir()
    (src / "data").mkdir()
    (src / "data" / "payload.txt").write_bytes(b"data")
    return src


@pytest.fixture(name="dst")
def _dst(tmp):
    return tmp / str(uuid4())
