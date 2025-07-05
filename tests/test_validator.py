"""Test module for `validator.py`."""

import pytest

from bagit_utils import BagItProfileValidator, Bag, BagValidator


def create_test_bag(src, dst, baginfo=None, algorithms=None) -> Bag:
    """Creates and returns minimal `Bag`."""
    return Bag.build_from(
        src,
        dst,
        baginfo or {},
        algorithms,
        validate=False,
    )


@pytest.mark.parametrize(
    ("profile", "ok"),
    [
        (
            0,
            False,
        ),
        (
            {},
            True,
        ),
        (
            {"unknown": None},
            False,
        ),
        (
            {
                "Bag-Info": {
                    "a": {
                        "required": True,
                        "repeatable": True,
                        "description": "a",
                        "values": ["a"],
                    }
                }
            },
            True,
        ),
        (
            {
                "Bag-Info": {
                    "a": {
                        "required": True,
                        "repeatable": True,
                        "description": "a",
                        "regex": "a",
                    }
                }
            },
            True,
        ),
        ({"Bag-Info": {"a": {"values": ["a"], "regex": "a"}}}, False),
        ({"Bag-Info": {"a": {"required": None}}}, False),
        ({"Bag-Info": {"a": {"repeatable": None}}}, False),
        ({"Bag-Info": {"a": {"description": None}}}, False),
        ({"Bag-Info": {"a": {"values": None}}}, False),
        ({"Bag-Info": {"a": {"values": [None]}}}, False),
        ({"Bag-Info": {"a": {"regex": None}}}, False),
        ({"Bag-Info": {"a": {"regex": r"("}}}, False),
        ({"Bag-Info": {"a": {"unknown": None}}}, False),
        ({"Manifests-Required": ["md5"], "Manifests-Allowed": ["md5"]}, True),
        ({"Manifests-Required": None}, False),
        ({"Manifests-Allowed": None}, False),
        ({"Manifests-Required": []}, True),
        ({"Manifests-Allowed": []}, True),
        ({"Manifests-Required": ["unknown"]}, True),
        ({"Manifests-Required": ["md5"], "Manifests-Allowed": []}, False),
        ({"Manifests-Required": [], "Manifests-Allowed": ["md5"]}, True),
        ({"Allow-Fetch.txt": True}, True),
        ({"Fetch.txt-Required": True}, True),
        ({"Allow-Fetch.txt": None}, False),
        ({"Fetch.txt-Required": None}, False),
        ({"Allow-Fetch.txt": False, "Fetch.txt-Required": True}, False),
        ({"Data-Empty": False}, True),
        ({"Data-Empty": None}, False),
        ({"Serialization": "forbidden"}, True),
        ({"Serialization": None}, False),
        ({"Serialization": "a"}, False),
        ({"Accept-Serialization": ["application/zip"]}, True),
        ({"Accept-Serialization": [None]}, False),
        ({"Accept-Serialization": None}, False),
        ({"Accept-BagIt-Version": None}, False),
        ({"Accept-BagIt-Version": []}, False),
        ({"Accept-BagIt-Version": ["0.93", "1.0"]}, True),
        (
            {
                "Tag-Manifests-Required": ["md5"],
                "Tag-Manifests-Allowed": ["md5"],
            },
            True,
        ),
        ({"Tag-Manifests-Required": None}, False),
        ({"Tag-Manifests-Allowed": None}, False),
        ({"Tag-Manifests-Required": []}, True),
        ({"Tag-Manifests-Allowed": []}, True),
        ({"Tag-Manifests-Required": ["unknown"]}, True),
        (
            {"Tag-Manifests-Required": ["md5"], "Tag-Manifests-Allowed": []},
            False,
        ),
        (
            {"Tag-Manifests-Required": [], "Tag-Manifests-Allowed": ["md5"]},
            True,
        ),
        ({"Tag-Files-Required": None}, False),
        ({"Tag-Files-Allowed": None}, False),
        ({"Tag-Files-Required": []}, True),
        ({"Tag-Files-Allowed": []}, True),
        ({"Tag-Files-Required": ["any/file"]}, True),
        ({"Tag-Files-Required": ["any/file"], "Tag-Files-Allowed": []}, False),
        (
            {"Tag-Files-Required": ["any/file"], "Tag-Files-Allowed": ["*"]},
            True,
        ),
        (
            {
                "Tag-Files-Required": ["any/file"],
                "Tag-Files-Allowed": ["**/*"],
            },
            True,
        ),
        (
            {
                "Tag-Files-Required": ["any/file"],
                "Tag-Files-Allowed": ["meta/*"],
            },
            False,
        ),
        ({"Payload-Files-Required": None}, False),
        ({"Payload-Files-Allowed": None}, False),
        ({"Payload-Files-Required": []}, True),
        ({"Payload-Files-Allowed": []}, True),
        ({"Payload-Files-Required": ["any/file"]}, True),
        (
            {
                "Payload-Files-Required": ["any/file"],
                "Payload-Files-Allowed": [],
            },
            False,
        ),
        (
            {
                "Payload-Files-Required": ["any/file"],
                "Payload-Files-Allowed": ["*"],
            },
            True,
        ),
        (
            {
                "Payload-Files-Required": ["any/file"],
                "Payload-Files-Allowed": ["**/*"],
            },
            True,
        ),
        (
            {
                "Payload-Files-Required": ["any/file"],
                "Payload-Files-Allowed": ["meta/*"],
            },
            False,
        ),
    ],
)
def test_profile_validator(profile, ok):
    """Test profile-validation via `BagItProfileValidator`."""
    if ok:
        BagItProfileValidator.load_profile(profile)
        return
    with pytest.raises(ValueError) as exc_info:
        BagItProfileValidator.load_profile(profile)
    print(exc_info.value)


@pytest.mark.parametrize(
    ("profile", "ok"),
    [
        ({"Manifests-Required": ["md5"]}, True),
        ({"Manifests-Required": ["sha1"]}, False),
        ({"Manifests-Allowed": ["md5"]}, True),
        ({"Manifests-Allowed": ["sha1"]}, False),
    ],
)
def test_bag_validator_manifest_files(src, dst, profile, ok):
    """Test validation for manifest files."""
    bag: Bag = create_test_bag(src, dst, algorithms=["md5"])

    assert (
        report := BagValidator.validate_once(bag, profile=profile)
    ).valid is ok
    if not ok:
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")


@pytest.mark.parametrize(
    ("profile", "ok"),
    [
        ({}, True),
        ({"Allow-Fetch.txt": True}, True),
        ({"Allow-Fetch.txt": False}, True),
        ({"Fetch.txt-Required": True}, False),
        ({"Fetch.txt-Required": False}, True),
    ],
)
def test_bag_validator_fetch_txt_file_does_not_exist(src, dst, profile, ok):
    """Test validation for fetch.txt files."""
    bag: Bag = create_test_bag(src, dst)

    assert (
        report := BagValidator.validate_once(bag, profile=profile)
    ).valid is ok
    if not ok:
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")


@pytest.mark.parametrize(
    ("profile", "ok"),
    [
        ({}, True),
        ({"Allow-Fetch.txt": True}, True),
        ({"Allow-Fetch.txt": False}, False),
        ({"Fetch.txt-Required": True}, True),
        ({"Fetch.txt-Required": False}, True),
    ],
)
def test_bag_validator_fetch_txt_file_does_exist(src, dst, profile, ok):
    """Test validation for fetch.txt files."""
    bag: Bag = create_test_bag(src, dst)
    (bag.path / "fetch.txt").touch()

    assert (
        report := BagValidator.validate_once(bag, profile=profile)
    ).valid is ok
    if not ok:
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")


@pytest.mark.parametrize(
    ("profile", "callback", "ok"),
    [
        (
            {"Data-Empty": True},
            lambda bag: (bag.path / "data" / "payload.txt").write_bytes(b""),
            True,
        ),
        (
            {"Data-Empty": True},
            lambda bag: (bag.path / "data" / "payload1.txt").touch(),
            False,
        ),
        (
            {"Data-Empty": True},
            lambda bag: (bag.path / "data" / "payload.txt").write_bytes(
                b"data"
            ),
            False,
        ),
        (
            {"Data-Empty": False},
            lambda bag: (bag.path / "data" / "payload.txt").write_bytes(
                b"data"
            ),
            True,
        ),
    ],
)
def test_bag_validator_data_empty(src, dst, profile, callback, ok):
    """Test validation for data-empty."""
    bag: Bag = create_test_bag(src, dst)
    callback(bag)

    assert (
        report := BagValidator.validate_once(bag, profile=profile)
    ).valid is ok
    if not ok:
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")


@pytest.mark.parametrize(
    ("profile", "ok"),
    [
        (
            {"Accept-BagIt-Version": ["1.0"]},
            True,
        ),
        (
            {"Accept-BagIt-Version": ["0.97"]},
            False,
        ),
    ],
)
def test_bag_validator_accept_bagit_version(src, dst, profile, ok):
    """Test validation for accepted BagIt-version."""
    bag: Bag = create_test_bag(src, dst)

    assert (
        report := BagValidator.validate_once(bag, profile=profile)
    ).valid is ok
    if not ok:
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")


@pytest.mark.parametrize(
    ("profile", "ok"),
    [
        ({"Tag-Manifests-Required": ["md5"]}, True),
        ({"Tag-Manifests-Required": ["sha1"]}, False),
        ({"Tag-Manifests-Allowed": ["md5"]}, True),
        ({"Tag-Manifests-Allowed": ["sha1"]}, False),
    ],
)
def test_bag_validator_tag_manifest_files(src, dst, profile, ok):
    """Test validation for tag-manifest files."""
    bag: Bag = create_test_bag(src, dst, algorithms=["md5"])

    assert (
        report := BagValidator.validate_once(bag, profile=profile)
    ).valid is ok
    if not ok:
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")


@pytest.mark.parametrize(
    ("profile", "callback", "ok"),
    [
        (
            {"Tag-Files-Required": []},
            lambda bag: None,
            True,
        ),
        (
            {"Tag-Files-Required": ["metadata.xml"]},
            lambda bag: None,
            False,
        ),
        (
            {"Tag-Files-Required": ["metadata.xml"]},
            lambda bag: (bag.path / "metadata.xml").touch(),
            True,
        ),
    ],
)
def test_bag_validator_tag_files_required(src, dst, profile, callback, ok):
    """Test validation for required tag-files."""
    bag: Bag = create_test_bag(src, dst)
    callback(bag)

    assert (
        report := BagValidator.validate_once(bag, profile=profile)
    ).valid is ok
    if not ok:
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")


@pytest.mark.parametrize(
    ("profile", "callback", "ok"),
    [
        (
            {"Tag-Files-Allowed": []},
            lambda bag: None,
            True,
        ),
        (
            {"Tag-Files-Allowed": []},
            lambda bag: [
                (bag.path / "metadata.xml").touch(),
                (bag.path / "meta").mkdir(),
                (bag.path / "meta" / "metadata.xml").touch(),
            ],
            False,
        ),
        (
            {"Tag-Files-Allowed": ["**/metadata.xml"]},
            lambda bag: [
                (bag.path / "metadata.xml").touch(),
                (bag.path / "meta").mkdir(),
                (bag.path / "meta" / "metadata.xml").touch(),
            ],
            False,
        ),
        (
            {"Tag-Files-Allowed": ["**/metadata.xml"]},
            lambda bag: [
                (bag.path / "meta").mkdir(),
                (bag.path / "meta" / "metadata.xml").touch(),
            ],
            True,
        ),
    ],
)
def test_bag_validator_tag_files_allowed(src, dst, profile, callback, ok):
    """Test validation for allowed tag-files."""
    bag: Bag = create_test_bag(src, dst)
    callback(bag)

    assert (
        report := BagValidator.validate_once(bag, profile=profile)
    ).valid is ok
    if not ok:
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")


@pytest.mark.parametrize(
    ("profile", "callback", "ok"),
    [
        (
            {"Payload-Files-Required": []},
            lambda bag: None,
            True,
        ),
        (
            {"Payload-Files-Required": ["data/payload1.txt"]},
            lambda bag: None,
            False,
        ),
        (
            {"Payload-Files-Required": ["data/payload1.txt"]},
            lambda bag: (bag.path / "data" / "payload1.txt").touch(),
            True,
        ),
    ],
)
def test_bag_validator_payload_files_required(src, dst, profile, callback, ok):
    """Test validation for required payload-files."""
    bag: Bag = create_test_bag(src, dst)
    callback(bag)

    assert (
        report := BagValidator.validate_once(bag, profile=profile)
    ).valid is ok
    if not ok:
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")


@pytest.mark.parametrize(
    ("profile", "callback", "ok"),
    [
        (
            {"Payload-Files-Allowed": []},
            lambda bag: None,
            False,
        ),
        (
            {"Payload-Files-Allowed": ["data/*"]},
            lambda bag: None,
            True,
        ),
        (
            {"Payload-Files-Allowed": ["**/*"]},
            lambda bag: [
                (bag.path / "data" / "payload1.txt").touch(),
                (bag.path / "data" / "data1").mkdir(),
                (bag.path / "data" / "data1" / "payload2.txt").touch(),
            ],
            True,
        ),
        (
            {"Payload-Files-Allowed": ["data/*"]},
            lambda bag: [
                (bag.path / "data" / "payload1.txt").touch(),
                (bag.path / "data" / "data1").mkdir(),
                (bag.path / "data" / "data1" / "payload2.txt").touch(),
            ],
            False,
        ),
    ],
)
def test_bag_validator_payload_files_allowed(src, dst, profile, callback, ok):
    """Test validation for allowed payload-files."""
    bag: Bag = create_test_bag(src, dst)
    callback(bag)

    assert (
        report := BagValidator.validate_once(bag, profile=profile)
    ).valid is ok
    if not ok:
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")


@pytest.mark.parametrize(
    ("profile", "callback", "ok"),
    [
        (
            {},
            lambda bag: None,
            True,
        ),
        (
            {"Bag-Info": {"a": {"required": True}}},
            lambda bag: None,
            False,
        ),
        (
            {"Bag-Info": {"a": {"required": False}}},
            lambda bag: None,
            True,
        ),
        (
            {"Bag-Info": {"a": {}}},  # default
            lambda bag: bag.set_baginfo(bag.baginfo | {"a": ["value"]}, False),
            True,
        ),
        (
            {"Bag-Info": {"a": {"required": True}}},
            lambda bag: bag.set_baginfo(bag.baginfo | {"a": ["value"]}, False),
            True,
        ),
        (
            {"Bag-Info": {"a": {"repeatable": True}}},
            lambda bag: None,
            True,
        ),
        (
            {"Bag-Info": {"a": {"repeatable": False}}},
            lambda bag: bag.set_baginfo(
                bag.baginfo | {"a": ["value0", "value1"]}, False
            ),
            False,
        ),
        (
            {"Bag-Info": {"a": {}}},  # default
            lambda bag: bag.set_baginfo(
                bag.baginfo | {"a": ["value0", "value1"]}, False
            ),
            True,
        ),
        (
            {"Bag-Info": {"a": {"repeatable": True}}},
            lambda bag: bag.set_baginfo(
                bag.baginfo | {"a": ["value0", "value1"]}, False
            ),
            True,
        ),
        (
            {"Bag-Info": {"a": {"values": []}}},
            lambda bag: None,
            True,
        ),
        (
            {"Bag-Info": {"a": {"values": ["value0"]}}},
            lambda bag: bag.set_baginfo(
                bag.baginfo | {"a": ["value1"]}, False
            ),
            False,
        ),
        (
            {"Bag-Info": {"a": {"values": ["value0"]}}},
            lambda bag: bag.set_baginfo(
                bag.baginfo | {"a": ["value0"]}, False
            ),
            True,
        ),
        (
            {"Bag-Info": {"a": {"regex": r"value[0-9]"}}},
            lambda bag: None,
            True,
        ),
        (
            {"Bag-Info": {"a": {"regex": r"value[0-9]"}}},
            lambda bag: bag.set_baginfo(
                bag.baginfo | {"a": ["value0"]}, False
            ),
            True,
        ),
        (
            {"Bag-Info": {"a": {"regex": r"value[0-9]"}}},
            lambda bag: bag.set_baginfo(
                bag.baginfo | {"a": ["valueA"]}, False
            ),
            False,
        ),
        (
            {"Bag-Info": {"a": {"regex": r"value[0-9]"}}},
            lambda bag: bag.set_baginfo(
                bag.baginfo | {"a": ["-value0-"]}, False
            ),
            False,
        ),
        (
            {"Bag-Info": {"a": {"repeatable": False, "regex": r"value[0-9]"}}},
            lambda bag: bag.set_baginfo(
                bag.baginfo | {"a": ["value0", "-value1-"]}, False
            ),
            False,
        ),
        (  # unknown-tag warning
            {"Bag-Info": {"a": {"values": []}}},
            lambda bag: bag.set_baginfo(
                bag.baginfo | {"a": ["value0"], "b": ["value1"]}, False
            ),
            False,
        ),
    ],
)
def test_bag_validator_bag_info(src, dst, profile, callback, ok):
    """Test validation for Bag-Info-section."""
    bag: Bag = create_test_bag(src, dst)
    callback(bag)

    assert (
        report := BagValidator.validate_once(bag, profile=profile)
    ).valid is ok
    if not ok:
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")
