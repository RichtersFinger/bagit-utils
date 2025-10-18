"""Test module for `bagit.py`."""

from json import loads

import pytest

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


def test_build_from_simple(src, dst):
    """Test simple use of `Bag.build_from`."""
    bag: Bag = create_test_bag(src, dst, {"BagInfoKey": ["BagInfoValue"]})
    assert bag.validate_format().valid
    assert bag.validate_manifests().valid
    assert bag.validate().valid

    # bagit
    assert (bag.path / "bagit.txt").is_file()
    assert (
        b"BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8"
        in (bag.path / "bagit.txt").read_bytes()
    )

    # bag-info
    assert "BagInfoKey" in bag.baginfo
    assert bag.baginfo["BagInfoKey"] == ["BagInfoValue"]
    assert (bag.path / "bag-info.txt").is_file()
    assert (
        b"BagInfoKey: BagInfoValue" in (bag.path / "bag-info.txt").read_bytes()
    )

    # manifests - memory
    assert len(bag.manifests) == 1
    assert "sha512" in bag.manifests
    assert len(bag.manifests["sha512"]) == 1
    assert "data/payload.txt" in bag.manifests["sha512"]

    # tag-manifests - memory
    assert len(bag.tag_manifests) == 1
    assert "sha512" in bag.tag_manifests
    assert len(bag.tag_manifests["sha512"]) == 3
    assert all(
        f in bag.tag_manifests["sha512"]
        for f in ["bag-info.txt", "bagit.txt", "manifest-sha512.txt"]
    )

    # manifests - disk
    assert (bag.path / "manifest-sha512.txt").is_file()
    manifest_file_contents = (
        (bag.path / "manifest-sha512.txt").read_text(encoding="utf-8").strip()
    )
    assert len(manifest_file_contents.splitlines()) == 1
    assert "data/payload.txt" in manifest_file_contents
    assert (
        bag.manifests["sha512"]["data/payload.txt"] in manifest_file_contents
    )

    # tag-manifests - disk
    assert (bag.path / "tagmanifest-sha512.txt").is_file()
    tagmanifest_file_contents = (
        (bag.path / "tagmanifest-sha512.txt")
        .read_text(encoding="utf-8")
        .strip()
    )
    assert len(tagmanifest_file_contents.splitlines()) == 3
    assert all(
        f in tagmanifest_file_contents
        and bag.tag_manifests["sha512"][f] in tagmanifest_file_contents
        for f in ["bag-info.txt", "bagit.txt", "manifest-sha512.txt"]
    )

    # payload
    assert (bag.path / "data" / "payload.txt").is_file()
    assert (bag.path / "data" / "payload.txt").read_bytes() == (
        src / "data" / "payload.txt"
    ).read_bytes()

    # meta
    assert not (bag.path / "meta").is_dir()


def test_build_from_without_payload(src, dst):
    """
    Test manifest-creation via method `Bag.build_from` for no payload.
    """
    # delete payload generated from fixture
    for p in (src / "data").glob("*"):
        if p.is_file():
            p.unlink()

    # build
    bag = Bag.build_from(src, dst, {}, algorithms=["md5"], validate=False)

    # check manifest
    manifest = (bag.path / "manifest-md5.txt").read_bytes()
    assert manifest == b""


def test_bag_init_without_load(src, dst):
    """
    Test dynamically loading `Bag`-information if not loaded in
    constructor.
    """
    bag = Bag(create_test_bag(src, dst).path, load=False)

    assert bag.baginfo is not None
    assert bag.manifests is not None
    assert bag.tag_manifests is not None


def test_build_from_missing_payload(src, dst):
    """Test building `Bag` for missing payload."""
    (src / "data" / "payload.txt").unlink()
    bag: Bag = create_test_bag(src, dst)
    assert bag.validate().valid
    assert (bag.path / "data").is_dir()
    assert (bag.path / "manifest-sha512.txt").is_file()


def test_update_baginfo_manifests(src, dst):
    """Test updating baginfo and manifests."""
    bag: Bag = create_test_bag(src, dst)
    assert (bag.path / "bag-info.txt").is_file()
    assert (bag.path / "bag-info.txt").read_bytes().strip() == b""
    assert bag.validate_manifests().valid

    # change baginfo
    bag.set_baginfo({"BagInfoKey": ["BagInfoValue"]})
    assert b"BagInfoKey" in (bag.path / "bag-info.txt").read_bytes()
    report = bag.validate_manifests()
    assert not report.valid
    for issue in report.issues:
        print(f"{issue.level}: {issue.message}")

    # update manifests
    bag.set_manifests()
    bag.set_tag_manifests()
    assert bag.validate_manifests().valid


def test_baginfo_long_lines(src, dst):
    """Test baginfo generation/loading with long lines."""
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
    assert len(baginfo_contents.splitlines()) > 4

    # manipulate bag-info.txt and reload
    (bag.path / "bag-info.txt").write_bytes(
        baginfo_contents.replace(
            b"B: another short line",
            b"""B: another short line
 a
\tb""",
        )
    )
    assert bag.load_baginfo()["B"][0] == "another short line a b"


def test_build_from_algorithms(src, dst):
    """Test `Bag.build_from` with specific algorithms."""
    bag: Bag = create_test_bag(src, dst, algorithms=["md5", "sha1"])

    assert len(bag.manifests) == 2
    assert "md5" in bag.manifests and "sha1" in bag.manifests
    assert not (bag.path / "manifest-sha512.txt").is_file()
    assert (bag.path / "manifest-md5.txt").is_file()
    assert (bag.path / "manifest-sha1.txt").is_file()
    assert len(bag.tag_manifests) == 2
    assert "md5" in bag.tag_manifests and "sha1" in bag.tag_manifests
    assert not (bag.path / "tagmanifest-sha512.txt").is_file()
    assert (bag.path / "tagmanifest-md5.txt").is_file()
    assert (bag.path / "tagmanifest-sha1.txt").is_file()


def test_set_manifests(src, dst):
    """Test `Bag.set_manifests` with specific algorithms."""
    bag: Bag = create_test_bag(src, dst)

    assert len(bag.manifests) == 1
    assert (bag.path / "manifest-sha512.txt").is_file()
    assert "sha512" in bag.manifests
    assert len(bag.tag_manifests) == 1
    assert (bag.path / "tagmanifest-sha512.txt").is_file()
    assert "sha512" in bag.tag_manifests

    bag.set_manifests(["md5", "sha1"], False)
    bag.set_tag_manifests(["md5", "sha1"], False)
    assert (bag.path / "manifest-sha512.txt").is_file()
    assert (bag.path / "tagmanifest-sha512.txt").is_file()
    assert not (bag.path / "manifest-md5.txt").is_file()
    assert not (bag.path / "tagmanifest-md5.txt").is_file()
    assert not (bag.path / "manifest-sha1.txt").is_file()
    assert not (bag.path / "tagmanifest-sha1.txt").is_file()
    assert len(bag.manifests) == 2
    assert len(bag.tag_manifests) == 2
    assert "md5" in bag.manifests and "sha1" in bag.manifests
    assert "md5" in bag.tag_manifests and "sha1" in bag.tag_manifests

    bag.set_manifests(["md5", "sha1"])
    bag.set_tag_manifests(["md5", "sha1"])
    assert not (bag.path / "manifest-sha512.txt").is_file()
    assert (bag.path / "manifest-md5.txt").is_file()
    assert (bag.path / "manifest-sha1.txt").is_file()
    assert not (bag.path / "tagmanifest-sha512.txt").is_file()
    assert (bag.path / "tagmanifest-md5.txt").is_file()
    assert (bag.path / "tagmanifest-sha1.txt").is_file()


def test_set_manifests_unknown_algorithm(src, dst):
    """Test `Bag.set_manifests` with unknown algorithm."""
    with pytest.raises(BagItError):
        create_test_bag(src, dst, algorithms=["unknown"])


def test_build_from_additional_tag_files(src, dst):
    """Test `Bag.build_from` with additional tag-files."""
    (src / "meta").mkdir()
    (src / "meta" / "source_metadata.xml").write_bytes(b"data")
    bag: Bag = create_test_bag(src, dst)
    assert "meta/source_metadata.xml" in bag.tag_manifests["sha512"]

    assert (bag.path / "meta" / "source_metadata.xml").is_file()
    assert (bag.path / "meta" / "source_metadata.xml").read_bytes() == b"data"


def test_build_from_create_symlinks(src, dst):
    """Test `Bag.build_from` with symlinks."""
    bag_w: Bag = create_test_bag(src, dst / "w", create_symlinks=True)
    bag_wo: Bag = create_test_bag(src, dst / "wo", create_symlinks=False)

    for file in filter(
        lambda p: p.is_file(), (bag_w.path / "data").glob("**/*")
    ):
        assert file.is_symlink()
    for file in filter(
        lambda p: p.is_file(), (bag_wo.path / "data").glob("**/*")
    ):
        assert not file.is_symlink()

    # does not affect other files
    for file in filter(
        lambda p: (bag_wo.path / "data") not in p.parents,
        bag_wo.path.glob("**/*"),
    ):
        assert not file.is_symlink()
    for file in filter(
        lambda p: (bag_w.path / "data") not in p.parents,
        bag_w.path.glob("**/*"),
    ):
        assert not file.is_symlink()

    # does not affect checksum-generation
    assert bag_w.manifests == bag_wo.manifests


def test_invalid_missing_bagit(src, dst):
    """Test validation for missing `bagit.txt`."""
    bag: Bag = create_test_bag(src, dst)
    assert bag.validate().valid
    (bag.path / "bagit.txt").unlink()
    report = bag.validate()
    assert not report.valid
    for issue in report.issues:
        print(f"{issue.level}: {issue.message}")


def test_invalid_missing_file(src, dst):
    """Test validation for missing file."""
    bag: Bag = create_test_bag(src, dst)
    assert bag.validate().valid
    (bag.path / "data" / "payload.txt").unlink()
    report = bag.validate()
    assert not report.valid
    for issue in report.issues:
        print(f"{issue.level}: {issue.message}")


def test_invalid_unknown_file(src, dst):
    """Test validation for unknown file."""
    bag: Bag = create_test_bag(src, dst)
    assert bag.validate().valid
    (bag.path / "data" / "payload2.txt").touch()
    report = bag.validate()
    assert not report.valid
    for issue in report.issues:
        print(f"{issue.level}: {issue.message}")


def test_invalid_bad_checksum(src, dst):
    """Test validation for bad checksum."""
    bag: Bag = create_test_bag(src, dst)
    assert bag.validate().valid
    (bag.path / "data" / "payload.txt").write_bytes(b"different payload")
    report = bag.validate()
    assert not report.valid
    for issue in report.issues:
        print(f"{issue.level}: {issue.message}")


def test_custom_validate_and_load_hooks(src, dst):
    """Test hooks for validating and loading (README example)."""
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
    assert not report.valid
    for issue in report.issues:
        print(f"{issue.level}: {issue.message}")

    (bag.path / "bag.json").write_bytes(b'{"a":"b"}')

    assert custom_bag.validate_format().valid
    custom_bag.load()

    assert hasattr(custom_bag, "bag_json")
    assert custom_bag.bag_json == {"a": "b"}
