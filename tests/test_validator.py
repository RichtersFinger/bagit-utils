"""Test module for `validator.py`."""

import tempfile
from pathlib import Path
from unittest import TestCase

from bagit_utils import BagItProfileValidator, Bag, BagValidator


def get_default_directories(tmp: Path) -> Path:
    """Returns default (sub-)directories 'src' and 'dst'."""
    src, dst = Path(tmp) / "src", Path(tmp) / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "data").mkdir()
    (src / "data" / "payload.txt").write_bytes(b"payload content")
    return src, dst


def create_test_bag(src, dst, baginfo=None, algorithms=None) -> Bag:
    """Creates and returns minimal `Bag`."""
    return Bag.build_from(
        src,
        dst,
        baginfo or {},
        algorithms,
        validate=False,
    )


class TestBagItProfileValidatorLoadProfile(TestCase):
    """Test `BagItProfileValidator.load_profile`."""

    def test_validation(self):
        """Test profile-validation."""
        cases = [
            (0, False),
            ({}, True),
            ({"unknown": None}, False),
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
            (
                {"Manifests-Required": ["md5"], "Manifests-Allowed": ["md5"]},
                True,
            ),
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
                {
                    "Tag-Manifests-Required": ["md5"],
                    "Tag-Manifests-Allowed": [],
                },
                False,
            ),
            (
                {
                    "Tag-Manifests-Required": [],
                    "Tag-Manifests-Allowed": ["md5"],
                },
                True,
            ),
            ({"Tag-Files-Required": None}, False),
            ({"Tag-Files-Allowed": None}, False),
            ({"Tag-Files-Required": []}, True),
            ({"Tag-Files-Allowed": []}, True),
            ({"Tag-Files-Required": ["any/file"]}, True),
            (
                {"Tag-Files-Required": ["any/file"], "Tag-Files-Allowed": []},
                False,
            ),
            (
                {
                    "Tag-Files-Required": ["any/file"],
                    "Tag-Files-Allowed": ["*"],
                },
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
            (
                {
                    "Tag-Files-Required": ["meta/dir/"],
                    "Tag-Files-Allowed": ["meta/dir/*"],
                },
                True,
            ),
            (
                {
                    "Tag-Files-Required": ["meta/dir/"],
                    "Tag-Files-Allowed": ["meta/dir/**"],
                },
                True,
            ),
            (
                {
                    "Tag-Files-Required": ["meta/dir/"],
                    "Tag-Files-Allowed": ["meta/dir/a/*"],
                },
                True,
            ),
            (
                {
                    "Tag-Files-Required": ["meta/dir/0"],
                    "Tag-Files-Allowed": ["meta/dir/[0-9]"],
                },
                True,
            ),
            (
                {
                    "Tag-Files-Required": ["meta/dir/a"],
                    "Tag-Files-Allowed": ["meta/dir/[0-9]"],
                },
                False,
            ),
            (
                {
                    "Tag-Files-Required": ["meta/a"],
                    "Tag-Files-Allowed": ["meta/*/*"],
                },
                False,
            ),
            (
                {
                    "Tag-Files-Required": ["meta/a/b"],
                    "Tag-Files-Allowed": ["meta/*/*"],
                },
                True,
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
                    "Payload-Files-Allowed": ["data/*"],
                },
                False,
            ),
            (
                {
                    "Payload-Files-Required": ["data/dir/"],
                    "Payload-Files-Allowed": ["data/dir/*"],
                },
                True,
            ),
            (
                {
                    "Payload-Files-Required": ["data/dir/"],
                    "Payload-Files-Allowed": ["data/dir/**"],
                },
                True,
            ),
            (
                {
                    "Payload-Files-Required": ["data/dir/"],
                    "Payload-Files-Allowed": ["data/dir/a/*"],
                },
                True,
            ),
            (
                {
                    "Payload-Files-Required": ["data/dir/"],
                    "Payload-Files-Allowed": ["data/dir/[0-9]"],
                },
                True,
            ),
            (
                {
                    "Payload-Files-Required": ["data/dir/0"],
                    "Payload-Files-Allowed": ["data/dir/[0-9]"],
                },
                True,
            ),
            (
                {
                    "Payload-Files-Required": ["data/dir/a"],
                    "Payload-Files-Allowed": ["data/dir/[0-9]"],
                },
                False,
            ),
            (
                {
                    "Payload-Files-Required": ["data/a"],
                    "Payload-Files-Allowed": ["data/*/*"],
                },
                False,
            ),
            (
                {
                    "Payload-Files-Required": ["data/a/b"],
                    "Payload-Files-Allowed": ["data/*/*"],
                },
                True,
            ),
        ]

        for profile, ok in cases:
            with self.subTest(profile=profile, ok=ok):
                if ok:
                    BagItProfileValidator.load_profile(profile)
                else:
                    with self.assertRaises(ValueError) as exc_info:
                        BagItProfileValidator.load_profile(profile)
                    print(exc_info.exception)


class TestBagValidatorManifestFiles(TestCase):
    """Test `BagValidator` manifest files."""

    def test_validation(self):
        """Test validation."""
        cases = [
            ({"Manifests-Required": ["md5"]}, True),
            ({"Manifests-Required": ["sha1"]}, False),
            ({"Manifests-Allowed": ["md5"]}, True),
            ({"Manifests-Allowed": ["sha1"]}, False),
        ]

        for profile, ok in cases:
            with self.subTest(profile=profile, ok=ok):
                with tempfile.TemporaryDirectory() as td:
                    src, dst = get_default_directories(Path(td))

                    bag: Bag = create_test_bag(src, dst, algorithms=["md5"])
                    report = BagValidator.validate_once(bag, profile=profile)

                    if ok:
                        self.assertTrue(report.valid)
                    else:
                        self.assertFalse(report.valid)
                        for issue in report.issues:
                            print(f"{issue.level}: {issue.message}")


class TestBagValidatorFetchTxt(TestCase):
    """Test `BagValidator` fetch.txt files."""

    def test_file_does_not_exist(self):
        """Test missing file."""
        cases = [
            ({}, True),
            ({"Allow-Fetch.txt": True}, True),
            ({"Allow-Fetch.txt": False}, True),
            ({"Fetch.txt-Required": True}, False),
            ({"Fetch.txt-Required": False}, True),
        ]

        for profile, ok in cases:
            with self.subTest(profile=profile, ok=ok):
                with tempfile.TemporaryDirectory() as td:
                    src, dst = get_default_directories(Path(td))

                    bag: Bag = create_test_bag(src, dst)
                    report = BagValidator.validate_once(bag, profile=profile)

                    if ok:
                        self.assertTrue(report.valid)
                    else:
                        self.assertFalse(report.valid)
                        for issue in report.issues:
                            print(f"{issue.level}: {issue.message}")

    def test_file_does_exist(self):
        """Test existing file."""
        cases = [
            ({}, True),
            ({"Allow-Fetch.txt": True}, True),
            ({"Allow-Fetch.txt": False}, False),
            ({"Fetch.txt-Required": True}, True),
            ({"Fetch.txt-Required": False}, True),
        ]

        for profile, ok in cases:
            with self.subTest(profile=profile, ok=ok):
                with tempfile.TemporaryDirectory() as td:
                    src, dst = get_default_directories(Path(td))

                    bag: Bag = create_test_bag(src, dst)
                    (bag.path / "fetch.txt").touch()
                    report = BagValidator.validate_once(bag, profile=profile)

                    if ok:
                        self.assertTrue(report.valid)
                    else:
                        self.assertFalse(report.valid)
                        for issue in report.issues:
                            print(f"{issue.level}: {issue.message}")


class TestBagValidatorDataEmpty(TestCase):
    """Test `BagValidator` data-empty."""

    def test_validation(self):
        """Test validation."""
        cases = [
            (
                {"Data-Empty": True},
                lambda bag: (bag.path / "data" / "payload.txt").write_bytes(
                    b""
                ),
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
        ]

        for profile, callback, ok in cases:
            with self.subTest(profile=profile, ok=ok):
                with tempfile.TemporaryDirectory() as td:
                    src, dst = get_default_directories(Path(td))

                    bag: Bag = create_test_bag(src, dst)
                    callback(bag)
                    report = BagValidator.validate_once(bag, profile=profile)

                    if ok:
                        self.assertTrue(report.valid)
                    else:
                        self.assertFalse(report.valid)
                        for issue in report.issues:
                            print(f"{issue.level}: {issue.message}")


class TestBagValidatorAcceptBagitVersion(TestCase):
    """Test `BagValidator` accepted BagIt-version."""

    def test_validation(self):
        """Test validation."""
        cases = [
            (
                {"Accept-BagIt-Version": ["1.0"]},
                True,
            ),
            (
                {"Accept-BagIt-Version": ["0.97"]},
                False,
            ),
        ]

        for profile, ok in cases:
            with self.subTest(profile=profile, ok=ok):
                with tempfile.TemporaryDirectory() as td:
                    src, dst = get_default_directories(Path(td))

                    bag: Bag = create_test_bag(src, dst)
                    report = BagValidator.validate_once(bag, profile=profile)

                    if ok:
                        self.assertTrue(report.valid)
                    else:
                        self.assertFalse(report.valid)
                        for issue in report.issues:
                            print(f"{issue.level}: {issue.message}")


class TestBagValidatorTagManifestFiles(TestCase):
    """Test `BagValidator` tag-manifest files."""

    def test_validation(self):
        """Test validation."""
        cases = [
            ({"Tag-Manifests-Required": ["md5"]}, True),
            ({"Tag-Manifests-Required": ["sha1"]}, False),
            ({"Tag-Manifests-Allowed": ["md5"]}, True),
            ({"Tag-Manifests-Allowed": ["sha1"]}, False),
        ]

        for profile, ok in cases:
            with self.subTest(profile=profile, ok=ok):
                with tempfile.TemporaryDirectory() as td:
                    src, dst = get_default_directories(Path(td))

                    bag: Bag = create_test_bag(src, dst, algorithms=["md5"])
                    report = BagValidator.validate_once(bag, profile=profile)

                    if ok:
                        self.assertTrue(report.valid)
                    else:
                        self.assertFalse(report.valid)
                        for issue in report.issues:
                            print(f"{issue.level}: {issue.message}")


class TestBagValidatorTagFiles(TestCase):
    """Test `BagValidator` tag-files constraints."""

    def test_required(self):
        """Test required tag-files."""
        cases = [
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
        ]

        for profile, callback, ok in cases:
            with self.subTest(profile=profile, ok=ok):
                with tempfile.TemporaryDirectory() as td:
                    src, dst = get_default_directories(Path(td))

                    bag: Bag = create_test_bag(src, dst)
                    callback(bag)
                    report = BagValidator.validate_once(bag, profile=profile)

                    if ok:
                        self.assertTrue(report.valid)
                    else:
                        self.assertFalse(report.valid)
                        for issue in report.issues:
                            print(f"{issue.level}: {issue.message}")

    def test_allowed(self):
        """Test allowed tag-files."""
        cases = [
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
        ]

        for profile, callback, ok in cases:
            with self.subTest(profile=profile, ok=ok):
                with tempfile.TemporaryDirectory() as td:
                    src, dst = get_default_directories(Path(td))

                    bag: Bag = create_test_bag(src, dst)
                    callback(bag)
                    report = BagValidator.validate_once(bag, profile=profile)

                    if ok:
                        self.assertTrue(report.valid)
                    else:
                        self.assertFalse(report.valid)
                        for issue in report.issues:
                            print(f"{issue.level}: {issue.message}")


class TestBagValidatorPayloadFiles(TestCase):
    """Test `BagValidator` payload-files constraints."""

    def test_required(self):
        """Test required payload-files."""
        cases = [
            (
                {"Payload-Files-Required": []},
                lambda bag: None,
                True,
            ),
            (  # file required
                {"Payload-Files-Required": ["data/payload1.txt"]},
                lambda bag: None,
                False,
            ),
            (
                {"Payload-Files-Required": ["data/payload1.txt"]},
                lambda bag: (bag.path / "data" / "payload1.txt").touch(),
                True,
            ),
            (  # directory required
                {"Payload-Files-Required": ["data/dir/"]},
                lambda bag: None,
                False,
            ),
            (
                {"Payload-Files-Required": ["data/dir/"]},
                lambda bag: (bag.path / "data" / "dir").mkdir(),
                False,
            ),
            (
                {"Payload-Files-Required": ["data/dir/"]},
                lambda bag: [
                    (bag.path / "data" / "dir").mkdir(),
                    (bag.path / "data" / "dir" / ".keep").touch(),
                ],
                True,
            ),
            (
                {"Payload-Files-Required": ["data/dir/"]},
                lambda bag: [
                    (bag.path / "data" / "dir").mkdir(),
                    (bag.path / "data" / "dir" / "a").mkdir(),
                    (bag.path / "data" / "dir" / "a" / ".keep").touch(),
                ],
                True,
            ),
        ]

        for profile, callback, ok in cases:
            with self.subTest(profile=profile, ok=ok):
                with tempfile.TemporaryDirectory() as td:
                    src, dst = get_default_directories(Path(td))

                    bag: Bag = create_test_bag(src, dst)
                    callback(bag)
                    report = BagValidator.validate_once(bag, profile=profile)

                    if ok:
                        self.assertTrue(report.valid)
                    else:
                        self.assertFalse(report.valid)
                        for issue in report.issues:
                            print(f"{issue.level}: {issue.message}")

    def test_allowed(self):
        """Test allowed payload-files."""
        cases = [
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
                True,
            ),
        ]

        for profile, callback, ok in cases:
            with self.subTest(profile=profile, ok=ok):
                with tempfile.TemporaryDirectory() as td:
                    src, dst = get_default_directories(Path(td))

                    bag: Bag = create_test_bag(src, dst)
                    callback(bag)
                    report = BagValidator.validate_once(bag, profile=profile)

                    if ok:
                        self.assertTrue(report.valid)
                    else:
                        self.assertFalse(report.valid)
                        for issue in report.issues:
                            print(f"{issue.level}: {issue.message}")


class TestBagValidatorBagInfo(TestCase):
    """Test `BagValidator` Bag-Info-section."""

    def test_validation(self):
        """Test validation."""
        cases = [
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
                lambda bag: bag.set_baginfo(
                    bag.baginfo | {"a": ["value"]}, False
                ),
                True,
            ),
            (
                {"Bag-Info": {"a": {"required": True}}},
                lambda bag: bag.set_baginfo(
                    bag.baginfo | {"a": ["value"]}, False
                ),
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
                {
                    "Bag-Info": {
                        "a": {"repeatable": False, "regex": r"value[0-9]"}
                    }
                },
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
        ]

        for profile, callback, ok in cases:
            with self.subTest(profile=profile, ok=ok):
                with tempfile.TemporaryDirectory() as td:
                    src, dst = get_default_directories(Path(td))

                    bag: Bag = create_test_bag(src, dst)
                    callback(bag)
                    report = BagValidator.validate_once(bag, profile=profile)

                    if ok:
                        self.assertTrue(report.valid)
                    else:
                        self.assertFalse(report.valid)
                        for issue in report.issues:
                            print(f"{issue.level}: {issue.message}")


class TestValidatorExtension(TestCase):
    """Test `BagValidator` extension."""

    def test_documented_extension(self):
        """Test documented extension."""
        with tempfile.TemporaryDirectory() as td:
            src, dst = get_default_directories(Path(td))

            class MyBagItProfileValidator(BagItProfileValidator):
                """Test profile validator"""

                _ACCEPTED_PROPERTIES = (
                    BagItProfileValidator._ACCEPTED_PROPERTIES + ["My-Tag"]
                )

                @classmethod
                def custom_validation_hook(cls, profile):
                    if "My-Tag" not in profile:
                        raise ValueError(
                            cls._ERROR_PREFIX
                            + "Missing required tag 'My-Tag'."
                        )
                    cls._handle_type_validation(
                        bool, "My-Tag", profile["My-Tag"]
                    )

            with self.assertRaises(ValueError):
                MyBagItProfileValidator.load_profile({})
            with self.assertRaises(ValueError):
                MyBagItProfileValidator.load_profile({"My-Tag": None})

            from bagit_utils.common import Issue, ValidationReport

            class MyBagValidator(BagValidator):
                """Test bag validator"""

                _PROFILE_VALIDATOR = MyBagItProfileValidator

                @classmethod
                def custom_validation_hook(cls, bag, profile):
                    result = ValidationReport(True)
                    if (
                        profile["My-Tag"]
                        and not (bag.path / "my-tag.txt").is_file()
                    ):
                        result.valid = False
                        result.issues.append(
                            Issue(
                                "error",
                                "Bag must contain tag-file 'my-tag.txt'.",
                                "My-Tag",
                            )
                        )
                    return result

            validator = MyBagValidator({"My-Tag": True})

            bag: Bag = create_test_bag(src, dst)
            report = validator.validate(bag)
            self.assertFalse(validator.validate(bag).valid)
            for issue in report.issues:
                print(f"{issue.level}: {issue.message}")

            (bag.path / "my-tag.txt").touch()
            report = validator.validate(bag)
            self.assertTrue(report.valid)
