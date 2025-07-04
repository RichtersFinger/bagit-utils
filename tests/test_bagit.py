"""Test module for `bagit.py`."""

import pytest

from bagit_utils import Bag, BagItError


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
    assert bag.validate_format()[0]
    assert bag.validate_manifests()[0]
    assert bag.validate()[0]

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


def test_build_from_missing_payload(src, dst):
    """Test building `Bag` for missing payload."""
    (src / "data" / "payload.txt").unlink()
    bag: Bag = create_test_bag(src, dst)
    assert bag.validate()[0]
    assert (bag.path / "data").is_dir()
    assert (bag.path / "manifest-sha512.txt").is_file()


def test_update_baginfo_manifests(src, dst):
    """Test updating baginfo and manifests."""
    bag: Bag = create_test_bag(src, dst)
    assert (bag.path / "bag-info.txt").is_file()
    assert (bag.path / "bag-info.txt").read_bytes().strip() == b""
    assert bag.validate_manifests()[0]

    # change baginfo
    bag.generate_baginfo({"BagInfoKey": ["BagInfoValue"]})
    assert b"BagInfoKey" in (bag.path / "bag-info.txt").read_bytes()
    assert not bag.validate_manifests()[0]

    # update manifests
    bag.generate_manifests()
    bag.generate_tag_manifests()
    assert bag.validate_manifests()[0]


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


def test_generate_manifests(src, dst):
    """Test `Bag.generate_manifests` with specific algorithms."""
    bag: Bag = create_test_bag(src, dst)

    assert len(bag.manifests) == 1
    assert (bag.path / "manifest-sha512.txt").is_file()
    assert "sha512" in bag.manifests
    assert len(bag.tag_manifests) == 1
    assert (bag.path / "tagmanifest-sha512.txt").is_file()
    assert "sha512" in bag.tag_manifests

    bag.generate_manifests(["md5", "sha1"])
    bag.generate_tag_manifests(["md5", "sha1"])
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


def test_generate_manifests_unknown_algorithm(src, dst):
    """Test `Bag.generate_manifests` with unknown algorithm."""
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

    assert (bag_w.path / "data").is_symlink()
    assert (
        bag_w.manifests == bag_wo.manifests
    )  # does not affect checksum-generation


def test_invalid_missing_bagit(src, dst):
    """Test validation for missing `bagit.txt`."""
    bag: Bag = create_test_bag(src, dst)
    assert bag.validate()[0]
    (bag.path / "bagit.txt").unlink()
    assert not bag.validate()[0]


def test_invalid_missing_file(src, dst):
    """Test validation for missing file."""
    bag: Bag = create_test_bag(src, dst)
    assert bag.validate()[0]
    (bag.path / "data" / "payload.txt").unlink()
    assert not bag.validate()[0]


def test_invalid_unknown_file(src, dst):
    """Test validation for unknown file."""
    bag: Bag = create_test_bag(src, dst)
    assert bag.validate()[0]
    (bag.path / "data" / "payload2.txt").touch()
    assert not bag.validate()[0]


def test_invalid_bad_checksum(src, dst):
    """Test validation for unknown file."""
    bag: Bag = create_test_bag(src, dst)
    assert bag.validate()[0]
    (bag.path / "data" / "payload.txt").write_bytes(b"different payload")
    assert not bag.validate()[0]
