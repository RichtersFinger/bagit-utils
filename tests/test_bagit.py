"""Test module for `bagit.py`."""

import tempfile
from json import loads
from pathlib import Path
from unittest import TestCase

from bagit_utils import Bag, BagItError
from bagit_utils.common import ValidationReport, Issue


def create_test_bag(
    src, dst, baginfo=None, algorithms=None, create_symlinks=False
) -> Bag:
    """Creates and returns minimal `Bag`."""
    return Bag.build_from(
        src,
        dst,
        baginfo or {},
        algorithms,
        create_symlinks=create_symlinks,
        validate=False,
    )


class BaseBagitTest(TestCase):
    """Base class providing `src` and `dst` directory fixtures."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.src = Path(self._td.name) / "src"
        self.dst = Path(self._td.name) / "dst"
        self.src.mkdir()
        self.dst.mkdir()
        (self.src / "data").mkdir()
        (self.src / "data" / "payload.txt").write_bytes(b"payload content")

    def tearDown(self):
        self._td.cleanup()


class TestBagBuildFrom(BaseBagitTest):
    """Test `Bag.build_from` context."""

    def test_simple(self):
        """Test simple use."""
        src, dst = self.src, self.dst
        bag: Bag = create_test_bag(src, dst, {"BagInfoKey": ["BagInfoValue"]})
        self.assertTrue(bag.validate_format().valid)
        self.assertTrue(bag.validate_manifests().valid)
        self.assertTrue(bag.validate().valid)

        # bagit
        self.assertTrue((bag.path / "bagit.txt").is_file())
        self.assertIn(
            b"BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8",
            (bag.path / "bagit.txt").read_bytes(),
        )

        # bag-info
        self.assertIn("BagInfoKey", bag.baginfo)
        self.assertEqual(bag.baginfo["BagInfoKey"], ["BagInfoValue"])
        self.assertTrue((bag.path / "bag-info.txt").is_file())
        self.assertIn(
            b"BagInfoKey: BagInfoValue",
            (bag.path / "bag-info.txt").read_bytes(),
        )

        # manifests - memory
        self.assertEqual(len(bag.manifests), 1)
        self.assertIn("sha512", bag.manifests)
        self.assertEqual(len(bag.manifests["sha512"]), 1)
        self.assertIn("data/payload.txt", bag.manifests["sha512"])

        # tag-manifests - memory
        self.assertEqual(len(bag.tag_manifests), 1)
        self.assertIn("sha512", bag.tag_manifests)
        self.assertEqual(len(bag.tag_manifests["sha512"]), 3)
        for f in ["bag-info.txt", "bagit.txt", "manifest-sha512.txt"]:
            with self.subTest(file=f):
                self.assertIn(f, bag.tag_manifests["sha512"])

        # manifests - disk
        self.assertTrue((bag.path / "manifest-sha512.txt").is_file())
        manifest_file_contents = (
            (bag.path / "manifest-sha512.txt")
            .read_text(encoding="utf-8")
            .strip()
        )
        self.assertEqual(len(manifest_file_contents.splitlines()), 1)
        self.assertIn("data/payload.txt", manifest_file_contents)
        self.assertIn(
            bag.manifests["sha512"]["data/payload.txt"], manifest_file_contents
        )

        # tag-manifests - disk
        self.assertTrue((bag.path / "tagmanifest-sha512.txt").is_file())
        tagmanifest_file_contents = (
            (bag.path / "tagmanifest-sha512.txt")
            .read_text(encoding="utf-8")
            .strip()
        )
        self.assertEqual(len(tagmanifest_file_contents.splitlines()), 3)
        for f in ["bag-info.txt", "bagit.txt", "manifest-sha512.txt"]:
            with self.subTest(file=f):
                self.assertIn(f, tagmanifest_file_contents)
                self.assertIn(
                    bag.tag_manifests["sha512"][f], tagmanifest_file_contents
                )

        # payload
        self.assertTrue((bag.path / "data" / "payload.txt").is_file())
        self.assertEqual(
            (bag.path / "data" / "payload.txt").read_bytes(),
            (src / "data" / "payload.txt").read_bytes(),
        )

        # meta
        self.assertFalse((bag.path / "meta").is_dir())

    def test_without_payload(self):
        """Test no payload."""
        src, dst = self.src, self.dst
        # delete payload generated from fixture
        for p in (src / "data").glob("*"):
            if p.is_file():
                p.unlink()

        # build
        bag = Bag.build_from(src, dst, {}, algorithms=["md5"], validate=False)

        # check manifest
        manifest = (bag.path / "manifest-md5.txt").read_bytes()
        self.assertEqual(manifest, b"")


class TestBagInit(BaseBagitTest):
    """Test `Bag` initialization."""

    def test_without_load(self):
        """
        Test dynamically loading `Bag`-information if not loaded in
        constructor.
        """
        src, dst = self.src, self.dst
        bag = Bag(create_test_bag(src, dst).path, load=False)

        self.assertIsNotNone(bag.baginfo)
        self.assertIsNotNone(bag.manifests)
        self.assertIsNotNone(bag.tag_manifests)


class TestBagMissing(BaseBagitTest):
    """Test `Bag` with missing resources context."""

    def test_missing_payload(self):
        """Test missing payload."""
        src, dst = self.src, self.dst
        (src / "data" / "payload.txt").unlink()
        bag: Bag = create_test_bag(src, dst)
        self.assertTrue(bag.validate().valid)
        self.assertTrue((bag.path / "data").is_dir())
        self.assertTrue((bag.path / "manifest-sha512.txt").is_file())


class TestBagUpdate(BaseBagitTest):
    """Test `Bag` update methods context."""

    def test_baginfo_manifests(self):
        """Test updating baginfo and manifests."""
        src, dst = self.src, self.dst
        bag: Bag = create_test_bag(src, dst)
        self.assertTrue((bag.path / "bag-info.txt").is_file())
        self.assertEqual((bag.path / "bag-info.txt").read_bytes().strip(), b"")
        self.assertTrue(bag.validate_manifests().valid)

        # change baginfo
        bag.set_baginfo({"BagInfoKey": ["BagInfoValue"]})
        self.assertIn(b"BagInfoKey", (bag.path / "bag-info.txt").read_bytes())
        report = bag.validate_manifests()
        self.assertFalse(report.valid)
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")

        # update manifests
        bag.set_manifests()
        bag.set_tag_manifests()
        self.assertTrue(bag.validate_manifests().valid)


class TestBagBaginfo(BaseBagitTest):
    """Test `Bag` bag-info edge cases."""

    def test_long_lines(self):
        """Test long lines."""
        src, dst = self.src, self.dst
        bag: Bag = create_test_bag(
            src,
            dst,
            {
                "A": ["short line", "long line " * 10, "short line"],
                "B": ["another short line"],
            },
        )

        # check for multi-line formatting
        baginfo_contents = (bag.path / "bag-info.txt").read_bytes()
        self.assertGreater(len(baginfo_contents.splitlines()), 4)

        # manipulate bag-info.txt and reload
        (bag.path / "bag-info.txt").write_bytes(
            baginfo_contents.replace(
                b"B: another short line",
                b"""B: another short line
 a
\tb""",
            )
        )
        self.assertEqual(bag.load_baginfo()["B"][0], "another short line a b")

    def test_empty_tag(self):
        """Test writing with an empty tag."""
        src, dst = self.src, self.dst
        bag: Bag = create_test_bag(
            src,
            dst,
            {
                "A": ["not empty"],
                "B": [],
                "C": ["also not empty"],
            },
        )

        self.assertNotIn(b"\n\n", (bag.path / "bag-info.txt").read_bytes())


class TestBagSetManifests(BaseBagitTest):
    """Test `Bag` manifests algorithms."""

    def test_build_from_algorithms(self):
        """Test specific algorithms with build_from."""
        src, dst = self.src, self.dst
        bag: Bag = create_test_bag(src, dst, algorithms=["md5", "sha1"])

        self.assertEqual(len(bag.manifests), 2)
        self.assertIn("md5", bag.manifests)
        self.assertIn("sha1", bag.manifests)
        self.assertFalse((bag.path / "manifest-sha512.txt").is_file())
        self.assertTrue((bag.path / "manifest-md5.txt").is_file())
        self.assertTrue((bag.path / "manifest-sha1.txt").is_file())
        self.assertEqual(len(bag.tag_manifests), 2)
        self.assertIn("md5", bag.tag_manifests)
        self.assertIn("sha1", bag.tag_manifests)
        self.assertFalse((bag.path / "tagmanifest-sha512.txt").is_file())
        self.assertTrue((bag.path / "tagmanifest-md5.txt").is_file())
        self.assertTrue((bag.path / "tagmanifest-sha1.txt").is_file())

    def test_set_manifests(self):
        """Test setting specific algorithms."""
        src, dst = self.src, self.dst
        bag: Bag = create_test_bag(src, dst)

        self.assertEqual(len(bag.manifests), 1)
        self.assertTrue((bag.path / "manifest-sha512.txt").is_file())
        self.assertIn("sha512", bag.manifests)
        self.assertEqual(len(bag.tag_manifests), 1)
        self.assertTrue((bag.path / "tagmanifest-sha512.txt").is_file())
        self.assertIn("sha512", bag.tag_manifests)

        bag.set_manifests(["md5", "sha1"], False)
        bag.set_tag_manifests(["md5", "sha1"], False)
        self.assertTrue((bag.path / "manifest-sha512.txt").is_file())
        self.assertTrue((bag.path / "tagmanifest-sha512.txt").is_file())
        self.assertFalse((bag.path / "manifest-md5.txt").is_file())
        self.assertFalse((bag.path / "tagmanifest-md5.txt").is_file())
        self.assertFalse((bag.path / "manifest-sha1.txt").is_file())
        self.assertFalse((bag.path / "tagmanifest-sha1.txt").is_file())
        self.assertEqual(len(bag.manifests), 2)
        self.assertEqual(len(bag.tag_manifests), 2)
        self.assertIn("md5", bag.manifests)
        self.assertIn("sha1", bag.manifests)
        self.assertIn("md5", bag.tag_manifests)
        self.assertIn("sha1", bag.tag_manifests)

        bag.set_manifests(["md5", "sha1"])
        bag.set_tag_manifests(["md5", "sha1"])
        self.assertFalse((bag.path / "manifest-sha512.txt").is_file())
        self.assertTrue((bag.path / "manifest-md5.txt").is_file())
        self.assertTrue((bag.path / "manifest-sha1.txt").is_file())
        self.assertFalse((bag.path / "tagmanifest-sha512.txt").is_file())
        self.assertTrue((bag.path / "tagmanifest-md5.txt").is_file())
        self.assertTrue((bag.path / "tagmanifest-sha1.txt").is_file())

    def test_unknown_algorithm(self):
        """Test unknown algorithm."""
        src, dst = self.src, self.dst
        with self.assertRaises(BagItError):
            create_test_bag(src, dst, algorithms=["unknown"])


class TestBagAdditionalFiles(BaseBagitTest):
    """Test `Bag` with additional files and symlinks."""

    def test_additional_tag_files(self):
        """Test additional tag-files."""
        src, dst = self.src, self.dst
        (src / "meta").mkdir()
        (src / "meta" / "source_metadata.xml").write_bytes(b"data")
        bag: Bag = create_test_bag(src, dst)
        self.assertIn("meta/source_metadata.xml", bag.tag_manifests["sha512"])

        self.assertTrue((bag.path / "meta" / "source_metadata.xml").is_file())
        self.assertEqual(
            (bag.path / "meta" / "source_metadata.xml").read_bytes(), b"data"
        )

    def test_create_symlinks(self):
        """Test symlinks."""
        src, dst = self.src, self.dst
        bag_w: Bag = create_test_bag(src, dst / "w", create_symlinks=True)
        bag_wo: Bag = create_test_bag(src, dst / "wo", create_symlinks=False)

        for file in filter(
            lambda p: p.is_file(), (bag_w.path / "data").glob("**/*")
        ):
            with self.subTest(file=file, symlinked=True):
                self.assertTrue(file.is_symlink())
        for file in filter(
            lambda p: p.is_file(), (bag_wo.path / "data").glob("**/*")
        ):
            with self.subTest(file=file, symlinked=False):
                self.assertFalse(file.is_symlink())

        # does not affect other files
        for file in filter(
            lambda p: (bag_wo.path / "data") not in p.parents,
            bag_wo.path.glob("**/*"),
        ):
            with self.subTest(file=file, symlinked=False, context="wo"):
                self.assertFalse(file.is_symlink())
        for file in filter(
            lambda p: (bag_w.path / "data") not in p.parents,
            bag_w.path.glob("**/*"),
        ):
            with self.subTest(file=file, symlinked=False, context="w"):
                self.assertFalse(file.is_symlink())

        # does not affect checksum-generation
        self.assertEqual(bag_w.manifests, bag_wo.manifests)


class TestBagValidate(BaseBagitTest):
    """Test `Bag` invalid states and hooks."""

    def test_missing_bagit(self):
        """Test missing `bagit.txt`."""
        src, dst = self.src, self.dst
        bag: Bag = create_test_bag(src, dst)
        self.assertTrue(bag.validate().valid)
        (bag.path / "bagit.txt").unlink()
        report = bag.validate()
        self.assertFalse(report.valid)
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")

    def test_missing_file(self):
        """Test missing file."""
        src, dst = self.src, self.dst
        bag: Bag = create_test_bag(src, dst)
        self.assertTrue(bag.validate().valid)
        (bag.path / "data" / "payload.txt").unlink()
        report = bag.validate()
        self.assertFalse(report.valid)
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")

    def test_unknown_file(self):
        """Test unknown file."""
        src, dst = self.src, self.dst
        bag: Bag = create_test_bag(src, dst)
        self.assertTrue(bag.validate().valid)
        (bag.path / "data" / "payload2.txt").touch()
        report = bag.validate()
        self.assertFalse(report.valid)
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")

    def test_bad_checksum(self):
        """Test bad checksum."""
        src, dst = self.src, self.dst
        bag: Bag = create_test_bag(src, dst)
        self.assertTrue(bag.validate().valid)
        (bag.path / "data" / "payload.txt").write_bytes(b"different payload")
        report = bag.validate()
        self.assertFalse(report.valid)
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")

    def test_custom_hooks(self):
        """Test hooks for validating and loading."""
        src, dst = self.src, self.dst
        bag: Bag = create_test_bag(src, dst)

        class CustomBag(Bag):
            def custom_load_hook(self):
                self.bag_json = loads((self.path / "bag.json").read_bytes())

            def custom_validate_format_hook(self):
                report = ValidationReport(True, bag=self)

                if not (self.path / "bag.json").is_file():
                    report.valid = False
                    report.issues.append(
                        Issue(
                            "error",
                            f"Missing file 'bag.json' in Bag at '{self.path}'.",
                            "bag.json",
                        )
                    )

                return report

        custom_bag = CustomBag(bag.path)

        report = custom_bag.validate_format()
        self.assertFalse(report.valid)
        for issue in report.issues:
            print(f"{issue.level}: {issue.message}")

        (bag.path / "bag.json").write_bytes(b'{"a":"b"}')

        self.assertTrue(custom_bag.validate_format().valid)
        custom_bag.load()

        self.assertTrue(hasattr(custom_bag, "bag_json"))
        self.assertEqual(custom_bag.bag_json, {"a": "b"})
