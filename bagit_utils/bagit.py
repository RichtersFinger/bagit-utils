"""BagIt-module."""

from typing import Optional, Mapping, Iterable, Callable
from datetime import datetime
from pathlib import Path
from functools import reduce, partial
from itertools import chain
from hashlib import (
    md5 as _md5,
    sha1 as _sha1,
    sha256 as _sha256,
    sha512 as _sha512,
)
from shutil import copy

from .common import quote_list, Issue, ValidationReport


def get_hash(file: Path, method: Callable, block: int) -> str:
    """
    Calculate and return hash of `file` using the given `method`
    and a block-size of `block`.

    See https://stackoverflow.com/a/1131255
    """
    hash_ = method()
    with open(file, "rb") as f:
        while True:
            buffer = f.read(block)
            if not buffer:
                break
            hash_.update(buffer)
    return hash_.hexdigest()


md5 = partial(get_hash, method=_md5, block=2**16)
sha1 = partial(get_hash, method=_sha1, block=2**16)
sha256 = partial(get_hash, method=_sha256, block=2**16)
sha512 = partial(get_hash, method=_sha512, block=2**16)


class BagItError(ValueError):
    """Generic BagIt error."""


class Bag:
    """
    Simple class that allows to manage data in the BagIt-format. Note
    that not all features of the specification [1] are implemented (see
    project README for details).

    Either instantiate existing Bag as `Bag(..)` or create a new Bag by
    calling `Bag.build_from(..)`.

    Keyword arguments:
    path -- path to parent directory of `bagit.txt`
    load -- whether to validate format and load metadata ((tag-)
            manifests, contents of bag-info)
            (default False)

    References:
    [1] https://www.digitalpreservation.gov/documents/bagitspec.pdf
    """

    # should always reflect algorithm security in increasing order
    CHECKSUM_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]
    _CHECKSUM_METHODS = {
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "sha512": sha512,
    }
    _BAGIT_TXT = b"BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n"

    def __init__(self, path: Path, load: bool = False) -> None:
        self.path = path
        self._baginfo = None
        self._manifests = None
        self._tag_manifests = None
        if load:
            report = self.validate_format()
            if not report.valid:
                raise BagItError(
                    "Directory is not a valid bag:\n"
                    + "\n".join(
                        map(
                            lambda i: f"* {i.level}: {i.message}",
                            report.issues,
                        )
                    )
                )
            self.load()

    @property
    def baginfo(self) -> dict[str, list[str]]:
        """Returns bag-info. Loads data if not loaded previously."""
        if self._baginfo is None:
            self.load_baginfo()
        return self._baginfo

    @property
    def manifests(self) -> dict[str, dict[str, str]]:
        """Returns manifests. Loads data if not loaded previously."""
        if self._manifests is None:
            self.load_manifests()
        return self._manifests

    @property
    def tag_manifests(self) -> dict[str, dict[str, str]]:
        """Returns tag-manifests. Loads data if not loaded previously."""
        if self._tag_manifests is None:
            self.load_manifests()
        return self._tag_manifests

    def load_baginfo(self) -> dict[str, list[str]]:
        """Load bag-info from disk."""
        if not (self.path / "bag-info.txt").is_file():
            self._baginfo = {}
        else:
            self._baginfo = reduce(
                # reduce into dictionary
                lambda info, item: info
                | {item[0]: info.get(item[0].strip(), []) + [item[1].strip()]},
                map(
                    # split lines by separator ':'
                    lambda line: line.split(":", 1),
                    reduce(
                        lambda lines, line: (
                            # recombine lines with break (starting with linear
                            # whitespace)
                            lines[:-1] + [lines[-1] + " " + line.lstrip()]
                            if line[0] in [" ", "\t"]
                            else lines + [line]
                        ),
                        filter(
                            # ignore empty lines
                            lambda line: line.strip() != "",
                            (self.path / "bag-info.txt")
                            .read_text(encoding="utf-8")
                            .strip()
                            .splitlines(),
                        ),
                        [],
                    ),
                ),
                {},
            )

        return self._baginfo

    def _load_manifest(self, file: Path) -> dict[str, str]:
        return reduce(
            lambda manifest, item: manifest
            | {item[1].strip(): item[0].strip()},
            map(
                lambda line: line.split(maxsplit=1),
                file.read_text(encoding="utf-8").strip().splitlines(),
            ),
            {},
        )

    def load_manifests(
        self, algorithms: Optional[list[str]] = None
    ) -> dict[str, dict[str, str]]:
        """
        Load manifest-data from disk. If `algorithms` is provided, load
        the manifests for those algorithms. Otherwise load all available
        manifests.
        """
        if algorithms is not None:
            for a in algorithms:
                if a not in self.CHECKSUM_ALGORITHMS:
                    raise BagItError("Unknown checksum algorithm '{}'.")
                # raise error if explicitly requested manifest is missing
                if not (self.path / f"manifest-{a}.txt").is_file():
                    raise BagItError(
                        f"Missing manifest file for algorithm '{a}'."
                    )

        if self._manifests is None:
            self._manifests = {}
        for a in algorithms or self.CHECKSUM_ALGORITHMS:
            # simply skip missing manifest files
            if not (self.path / f"manifest-{a.lower()}.txt").is_file():
                continue
            self._manifests[a] = self._load_manifest(
                self.path / f"manifest-{a.lower()}.txt"
            )
        return {
            a: m
            for a, m in self._manifests.items()
            if a in (algorithms or self.CHECKSUM_ALGORITHMS)
        }

    def load_tag_manifests(
        self, algorithms: Optional[list[str]] = None
    ) -> dict[str, dict[str, str]]:
        """
        Load tag-manifest-data from disk. If `algorithms` is provided,
        load the manifests for those algorithms. Otherwise load all
        available manifests.
        """
        if algorithms is not None:
            for a in algorithms:
                if a not in self.CHECKSUM_ALGORITHMS:
                    raise BagItError("Unknown checksum algorithm '{}'.")
                # raise error if explicitly requested manifest is missing
                if not (self.path / f"tagmanifest-{a}.txt").is_file():
                    raise BagItError(
                        f"Missing manifest file for algorithm '{a}'."
                    )

        if self._tag_manifests is None:
            self._tag_manifests = {}
        for a in algorithms or self.CHECKSUM_ALGORITHMS:
            # simply skip missing manifest files
            if not (self.path / f"tagmanifest-{a.lower()}.txt").is_file():
                continue
            self._tag_manifests[a] = self._load_manifest(
                self.path / f"tagmanifest-{a.lower()}.txt"
            )
        return {
            a: m
            for a, m in self._tag_manifests.items()
            if a in (algorithms or self.CHECKSUM_ALGORITHMS)
        }

    def load(self) -> None:
        """Load bag-info and all manifest-data from disk."""
        self.load_baginfo()
        self.load_manifests()
        self.load_tag_manifests()

    def validate_format(self) -> ValidationReport:
        """
        Validates the `Bag`'s format (existence of required files). This
        includes
        * bagit.txt (and its contents)
        * bag-info.txt (for content-validation, use the profile-based
          Bag-validator)
        * payload directory
        * at least one payload manifest

        and does not include unknown files.
        """
        result = ValidationReport(True, bag=self)

        # base
        if not self.path.is_dir():
            result.valid = False
            result.issues.append(
                Issue(
                    "error", f"'{self.path}' is not a directory.", "Bag-Format"
                )
            )
            return result
        if not (self.path / "bagit.txt").is_file():
            result.valid = False
            result.issues.append(
                Issue(
                    "error",
                    f"Missing Bag declaration 'bagit.txt' in '{self.path}'.",
                    "Bag-Format",
                )
            )
            return result

        # bag-info
        if (
            self.path / "bagit.txt"
        ).read_bytes().strip() != self._BAGIT_TXT.strip():
            result.valid = False
            result.issues.append(
                Issue(
                    "error",
                    f"Bad Bag declaration in '{self.path}/bagit.txt'.",
                    "Bag-Format",
                )
            )
            return result

        # payload
        if not (self.path / "data").is_dir():
            result.valid = False
            result.issues.append(
                Issue(
                    "error",
                    f"Missing 'data' directory in '{self.path}'.",
                    "Bag-Format",
                )
            )
            return result

        # manifests
        if (
            len([m for m in self.path.glob("manifest-*.txt") if m.is_file()])
            == 0
        ):
            result.valid = False
            result.issues.append(
                Issue(
                    "error",
                    f"Found no manifest file in '{self.path}'.",
                    "Bag-Format",
                )
            )
            return result

        # special files
        for f in self.path.glob("*"):
            if f.is_file() and f.name == "fetch.txt":
                result.issues.append(
                    Issue(
                        "warning",
                        "This library currently does not support 'fetch.txt' "
                        + f"(encountered in '{self.path}').",
                        "Bag-Format",
                    )
                )

        return result

    def validate_manifests(
        self, algorithm: Optional[str] = None, skip_checksums: bool = False
    ) -> ValidationReport:
        """
        Validates payload and metadata integrity using manifest
        information. If `algorithm` is not given, validate checksums via
        the best algorithm for which a manifest exists. Manifests are
        automatically loaded if not at least one has already been
        loaded. Checksum validation is skipped if `skip_checksums`.
        """
        result = ValidationReport(True, bag=self)

        # load manifests
        if self._manifests is None:
            self.load_manifests()
        if self._tag_manifests is None:
            self.load_tag_manifests()

        # validate manifest inconsistencies (files that are listed in one but
        # not others or listed in others but not one) by checking pair-wise
        for m1, m2 in zip(
            self._manifests.items(), list(self._manifests.items())[1:]
        ):
            files_m1 = set(m1[1].keys())
            files_m2 = set(m2[1].keys())
            if files_m1 != files_m2:
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        "Found inconsistent records in manifests for "
                        + f"algorithms '{m1[0]}' and '{m1[0]}' regarding the "
                        + "file(s) "
                        + quote_list(files_m1.symmetric_difference(files_m2))
                        + f" in Bag at '{self.path}'.",
                        "Bag-Manifests",
                    )
                )
        for m1, m2 in zip(
            self._tag_manifests.items(),
            list(self._tag_manifests.items())[1:],
        ):
            files_m1 = set(m1[1].keys())
            files_m2 = set(m2[1].keys())
            if files_m1 != files_m2:
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        "Found inconsistent records in tag-manifests for "
                        + f"algorithms '{m1[0]}' and '{m1[0]}' regarding the "
                        + "file(s) "
                        + quote_list(files_m1.symmetric_difference(files_m2))
                        + f" in Bag at '{self.path}'.",
                        "Bag-Manifests",
                    )
                )

        payload_files = list(
            map(
                lambda f: self.path / f,
                next((m for m in self._manifests.values()), {}).keys(),
            )
        )
        tag_files = list(
            map(
                lambda f: self.path / f,
                next((m for m in self._tag_manifests.values()), {}).keys(),
            )
        ) + list(
            map(
                lambda a: self.path / f"tagmanifest-{a}.txt",
                self._tag_manifests.keys(),
            )
        )

        # validate all files exist
        for f in payload_files + tag_files:
            if not f.is_file():
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        f"Missing file '{f.relative_to(self.path)}' in Bag at "
                        + f"'{self.path}'.",
                        "Bag-Manifests",
                    )
                )

        # validate no unknown files exist
        for f in self.path.glob("**/*"):
            if f.is_file() and f not in payload_files + tag_files:
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        f"File '{f.relative_to(self.path)}' in Bag at "
                        + f"'{self.path}' is not covered by manifests.",
                        "Bag-Manifests",
                    )
                )

        if skip_checksums:
            return result

        # validate checksums
        for d in [self._manifests, self._tag_manifests]:
            _algorithm = algorithm or next(
                (a for a in reversed(self.CHECKSUM_ALGORITHMS) if a in d),
                None,
            )

            # exit if no manifest exists
            if _algorithm is None:
                continue

            if _algorithm not in self.CHECKSUM_ALGORITHMS:
                raise BagItError(f"Unknown checksum algorithm '{_algorithm}'.")
            for f, c in d[_algorithm].items():
                if not (self.path / f).is_file():
                    result.issues.append(
                        Issue(
                            "info",
                            f"Skipping checksum validation for file '{f}' in "
                            + f"Bag at '{self.path}' (file is missing).",
                            "Bag-Checksums",
                        )
                    )
                    continue

                _c = self._CHECKSUM_METHODS[_algorithm](self.path / f)
                if c != _c:
                    result.valid = False
                    result.issues.append(
                        Issue(
                            "error",
                            f"Bad '{_algorithm}'-checksum for file '{f}' in "
                            + f"Bag at '{self.path}' (expected '{c}' but got "
                            + f"'{_c}').",
                            "Bag-Checksums",
                        )
                    )

        return result

    def validate(self) -> ValidationReport:
        """Returns validation results."""
        result = ValidationReport(True, bag=self)

        format_report = self.validate_format()
        result.issues += format_report.issues
        if not format_report.valid:
            result.valid = False

        manifest_report = self.validate_manifests()
        result.issues += manifest_report.issues
        if not manifest_report.valid:
            result.valid = False

        return result

    def generate_bagit_declaration(self) -> None:
        """Writes `bagit.txt`."""
        (self.path / "bagit.txt").write_bytes(self._BAGIT_TXT)

    @staticmethod
    def _format_baginfo_multiline(key: str, value: str) -> str:
        """
        Returns re-formatted string to satisfy max line-length of 79
        (if possible).
        """
        lines = []
        thisline = f"{key}: "
        added_any_word = False
        for word in value.split():
            if not added_any_word or len(thisline) + len(word) < 79:
                thisline += word + " "
                added_any_word = True
            else:
                lines.append(thisline.rstrip())
                thisline = "\t" + word + " "
                added_any_word = False

        lines.append(thisline.rstrip())

        return "\n".join(lines)

    def set_baginfo(
        self,
        baginfo: Mapping[str, list[str]],
        write_to_disk: bool = True,
    ) -> None:
        """Sets new bag-info contents and writes to disk."""
        self._baginfo = baginfo

        if not write_to_disk:
            return

        (self.path / "bag-info.txt").write_text(
            "\n".join(
                [
                    "\n".join(
                        [self._format_baginfo_multiline(k, v_) for v_ in v]
                    )
                    for k, v in baginfo.items()
                ]
                + [""]
            ),
            encoding="utf-8",
        )

    def set_manifests(
        self,
        algorithms: Optional[Iterable[str]] = None,
        write_to_disk: bool = True,
    ) -> dict[str, dict[str, str]]:
        """
        Calculate checksums, clear existing manifests, and write
        manifest file(s) based on current payload. If `algorithms` is
        `None`, either all currently existing manifests are updated or
        the strongest available algorithm is used.
        """
        # prepare
        if algorithms is None:
            # find algorithms of existing manifests
            algorithms = [
                a
                for a in self.CHECKSUM_ALGORITHMS
                if (self.path / f"manifest-{a}.txt").is_file()
            ]
            # if none exist yet, use strongest algorithm instead
            if len(algorithms) == 0:
                algorithms = [self.CHECKSUM_ALGORITHMS[-1]]
        else:
            # use provided algorithms
            if not set(algorithms).issubset(self.CHECKSUM_ALGORITHMS):
                raise BagItError(
                    "Unknown checksum algorithm(s) "
                    + f"{set(algorithms) - set(self.CHECKSUM_ALGORITHMS)}."
                )

        # clear existing data
        self._manifests = {}

        # generate anew
        for a in algorithms:
            self._manifests[a] = {
                str(f.relative_to(self.path)): self._CHECKSUM_METHODS[a](f)
                for f in self.path.glob("data/**/*")
                if f.is_file()
            }

        if not write_to_disk:
            return

        for f in self.path.glob("manifest-*.txt"):
            if f.is_file():
                f.unlink()
        for a, m in self._manifests.items():
            (self.path / f"manifest-{a}.txt").write_text(
                "\n".join(f"{c} {f}" for f, c in m.items()) + "\n",
                encoding="utf-8",
            )

    def set_tag_manifests(
        self,
        algorithms: Optional[Iterable[str]] = None,
        write_to_disk: bool = True,
    ) -> dict[str, dict[str, str]]:
        """
        Calculate checksums, clear existing tag-manifests, and write
        tag-manifest file(s) based on current metadata files. If
        `algorithms` is `None`, either all currently existing manifests
        are updated or the strongest available algorithm is used.
        """
        # prepare
        if algorithms is None:
            # find algorithms of existing manifests
            algorithms = [
                a
                for a in self.CHECKSUM_ALGORITHMS
                if (self.path / f"manifest-{a}.txt").is_file()
            ]
            # if none exist yet, use strongest algorithm instead
            if len(algorithms) == 0:
                algorithms = [self.CHECKSUM_ALGORITHMS[-1]]
        else:
            # use provided algorithms
            if not set(algorithms).issubset(self.CHECKSUM_ALGORITHMS):
                raise BagItError(
                    "Unknown checksum algorithm(s) "
                    + f"{set(algorithms) - set(self.CHECKSUM_ALGORITHMS)}."
                )

        # clear existing data
        self._tag_manifests = {}

        # generate anew
        for a in algorithms:
            self._tag_manifests[a] = {
                str(f.relative_to(self.path)): self._CHECKSUM_METHODS[a](f)
                for f in chain(
                    self.path.glob("meta/**/*"),
                    self.path.glob("manifest-*.txt"),
                    [self.path / "bag-info.txt", self.path / "bagit.txt"],
                )
                if f.is_file()
            }

        if not write_to_disk:
            return

        for f in self.path.glob("tagmanifest-*.txt"):
            if f.is_file():
                f.unlink()
        for a, m in self._tag_manifests.items():
            (self.path / f"tagmanifest-{a}.txt").write_text(
                "\n".join(f"{c} {f}" for f, c in m.items()) + "\n",
                encoding="utf-8",
            )

    @staticmethod
    def get_payload_oxum(path: Path) -> str:
        """
        Returns the octetstream-sum generated from the payload in `path`
        as string to be used as Payload-Oxum in bag-info.
        """
        files = [p for p in path.glob("**/*") if p.is_file()]
        return f"{sum(p.stat().st_size for p in files)}.{len(files)}"

    @staticmethod
    def get_bagging_date(at: Optional[datetime] = None) -> str:
        """
        Returns a date that is properly formatted as string for use
        as Bagging-Date in bag-info (e.g., 2024-01-01).
        """
        return (at or datetime.now().astimezone()).strftime("%Y-%m-%d")

    @staticmethod
    def get_bagging_datetime(at: Optional[datetime] = None) -> str:
        """
        Returns a datetime that is properly formatted as string for use
        as Bagging-DateTime in bag-info (e.g.,
        2024-01-01T00:00:00+00:00).
        """
        return (
            (at or datetime.now().astimezone())
            .replace(microsecond=0)
            .isoformat()
        )

    @classmethod
    def build_from(
        cls,
        src: Path,
        dst: Path,
        baginfo: Mapping[str, list[str]],
        algorithms: Optional[Iterable[str]] = None,
        create_symlinks: bool = False,
        validate: bool = True,
    ) -> "Bag":
        """
        Returns a `Bag` that is built from the contents given in `src`
        at `dst`. If `create_symlinks`, instead of copying the (payload)
        contents in `<src>/data`, symbolic links pointing to the
        original files are placed in the `Bag`'s data/payload-directory.
        """
        # check prerequisites
        if dst.exists() and not dst.is_dir():
            raise BagItError(f"Destination '{dst}' is not a directory.")
        dst.mkdir(parents=True, exist_ok=True)
        if next((p for p in dst.glob("**/*")), None) is not None:
            raise BagItError(f"Destination '{dst}' is not empty.")

        # duplicate/link data by iterating
        (dst / "data").mkdir(parents=True)
        for file in filter(lambda p: p.is_file(), src.glob("**/*")):
            target_path = dst / file.relative_to(src)
            if not target_path.parent.is_dir():
                target_path.parent.mkdir(parents=True)
            if create_symlinks and (src / "data") in file.parents:
                target_path.symlink_to(file.resolve(), True)
            else:
                copy(file, target_path)

        # generate bag
        bag = cls(dst, False)
        bag.generate_bagit_declaration()
        bag.set_baginfo(baginfo)
        bag.set_manifests(algorithms)
        bag.set_tag_manifests(algorithms)

        if validate:
            report = bag.validate()
            if not report.valid:
                raise BagItError(
                    "Bag is invalid:\n"
                    + "\n".join(
                        map(
                            lambda i: f"* {i.level}: {i.message}",
                            report.issues,
                        )
                    )
                )

        return bag
