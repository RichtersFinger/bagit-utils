"""`bagit-utils`-CLI definition."""

from typing import Optional
import sys
from importlib.metadata import version
from pathlib import Path

try:
    from befehl import Parser, Option, Cli, Command, common
except ImportError:
    print(
        "Missing cli-dependencies, please install by entering "
        + "`pip install bagit-utils[cli]`."
    )
    sys.exit(1)

from .bagit import Bag, BagItError


def parse_dir_exists_but_empty(
    data: str,
) -> tuple[bool, Optional[str], Optional[Path]]:
    """
    Parses input as Path, returns ok if path does not exist or is empty.
    """
    path = Path(data)
    if not path.exists():
        return True, None, path
    if len(list(path.glob("**/*"))) == 0:
        return True, None, path
    return False, f"Directory '{data}' is not empty", None


def parse_baginfo(
    data: str,
) -> tuple[bool, Optional[str], Optional[tuple[str, str]]]:
    """
    Parses input as tuple of tag-name and value for use in
    'baginfo-txt'.
    """
    try:
        tag, value = data.split(":", maxsplit=1)
    except ValueError:
        return False, f"bad format in baginfo-tag '{data}'", None
    return True, None, (tag, value)


class BuildBag(Command):
    """Subcommand for building bags."""

    input_ = Option(
        ("-i", "--input"),
        helptext="source directory that should be converted into a bag",
        nargs=1,
        parser=Parser.parse_as_dir,
    )
    output = Option(
        ("-o", "--output"),
        helptext=(
            "output path for the bag; "
            + "directory should either not exist or be empty"
        ),
        nargs=1,
        parser=parse_dir_exists_but_empty,
    )
    baginfo = Option(
        ("-b", "--baginfo"),
        helptext=(
            "add baginfo-metadata, e.g., "
            + "\"-b 'My-Tag:value one' -b 'My-Tag:value two'\""
        ),
        nargs=-1,
        parser=parse_baginfo,
    )
    checksums = Option(
        ("-c", "--checksums"),
        helptext=(
            "request specific algorithms for calculating checksums; "
            + f"one or more of {common.quote_list(Bag.CHECKSUM_ALGORITHMS)}"
        ),
        nargs=-1,
        parser=Parser.parse_with_values(Bag.CHECKSUM_ALGORITHMS),
    )
    symlinks = Option(
        "--use-symlinks", helptext="replace payload files by symlinks"
    )
    verbose = Option(("-v", "--verbose"), helptext="verbose output")

    def run(self, args):
        verbose = self.verbose in args

        baginfo = {}
        for tag, value in args.get(self.baginfo, []):
            if verbose:
                print(f"Adding tag '{tag}: {value}' to 'bag-info.txt'.")
            if tag in baginfo:
                baginfo[tag].append(value)
            else:
                baginfo[tag] = [value]

        bag = Bag.build_from(
            src=args[self.input_][0],
            dst=args[self.output][0],
            baginfo=baginfo,
            algorithms=args.get(self.checksums),
            create_symlinks=self.symlinks in args,
            validate=False,
        )

        if verbose:
            print(
                "Generated manifests with algorithm(s): "
                + common.quote_list(bag.manifests.keys())
            )

        report = bag.validate()
        if not report.valid:
            if verbose:
                print(report)
            sys.exit(1)
        elif verbose:
            print(f"Bag successfully built at '{bag.path}'.")


def parse_as_bag(
    data: str,
) -> tuple[bool, Optional[str], Optional[Bag]]:
    """Parses `data` as `Bag`."""
    ok, msg, path = Parser.parse_as_dir(data)
    if not ok:
        return ok, msg, path

    try:
        bag = Bag(path, True)
    except BagItError as exc_info:
        return False, str(exc_info), None

    return True, None, bag


class ModifyBag(Command):
    """Subcommand for modifying bags."""

    input_ = Option(
        ("-i", "--input"),
        helptext="target bag that should be modified",
        nargs=1,
        parser=parse_as_bag,
    )
    add_tag = Option(
        ("-a", "--add-tag"),
        helptext=(
            "add baginfo-metadata, e.g., \"-a 'My-Tag:value one' "
            + "-a 'My-Tag:value two'\""
        ),
        nargs=-1,
        parser=parse_baginfo,
    )
    delete_tag = Option(
        ("-d", "--delete-tag"),
        helptext=(
            "delete all values of given tag(s), e.g., \"-d My-Tag\""
        ),
        nargs=-1,
    )
    checksums = Option(
        ("-c", "--checksums"),
        helptext=(
            "rebuild bag manifests with the given algorithms; "
            + f"one or more of {common.quote_list(Bag.CHECKSUM_ALGORITHMS)}; "
            + "if no values provided, renew current checksums"
        ),
        nargs=-1,
        parser=Parser.parse_with_values(Bag.CHECKSUM_ALGORITHMS),
    )
    verbose = Option(("-v", "--verbose"), helptext="verbose output")

    def run(self, args):
        bag: Bag = args[self.input_][0]
        renew_checksums = self.checksums in args
        verbose = self.verbose in args

        # baginfo
        if self.delete_tag in args or self.add_tag in args:
            renew_checksums = True

            if verbose and self.delete_tag in args:
                print(
                    "Removing tags from 'bag-info.txt': "
                    + common.quote_list(args[self.delete_tag])
                )

            # filter deleted
            new_baginfo = {
                k: v
                for k, v in bag.baginfo.items()
                if k not in args.get(self.delete_tag, [])
            }

            # add new
            for tag, value in args.get(self.add_tag, []):
                if verbose:
                    print(f"Adding tag '{tag}: {value}' to 'bag-info.txt'.")
                if tag in new_baginfo:
                    new_baginfo[tag].append(value)
                else:
                    new_baginfo[tag] = [value]
            bag.set_baginfo(new_baginfo)

        # checksums
        if renew_checksums:
            manifests = args.get(self.checksums, bag.manifests.keys())
            tag_manifests = args.get(self.checksums, bag.tag_manifests.keys())

            if verbose:
                print(
                    "Refreshing manifest(s): " + common.quote_list(manifests)
                )
            bag.set_manifests(
                args.get(self.checksums, bag.manifests.keys())
            )

            if verbose:
                print(
                    "Refreshing tag-manifest(s): "
                    + common.quote_list(tag_manifests)
                )
            bag.set_tag_manifests(
                args.get(self.checksums, bag.tag_manifests.keys())
            )

        bag.validate()


class ValidateBag(Command):
    """Subcommand for validating bags."""

    input_ = Option(
        ("-i", "--input"),
        helptext="target bag that should be validated",
        nargs=1,
        parser=Parser.parse_as_dir,
    )

    def run(self, args):
        # TODO
        return


class BagItUtilsCli(Cli):
    """CLI for `bagit-utils`."""

    build_ = BuildBag("build", helptext="build bags from directory")
    modify = ModifyBag("modify", helptext="alter existing bags")
    validate_ = ValidateBag("validate", helptext="validate existing bags")

    version = Option(("-v", "--version"), helptext="prints library version")

    def run(self, args):
        if self.version in args:
            print(version("bagit-utils"))
            return
        self._print_help()


# validate + build entry-point
cli = BagItUtilsCli(
    "bagit",
    helptext=(
        f"bagit-utils-cli, v{version('bagit-utils')}"
        + " - Build, modify, and validate BagIt bags"
    ),
).build()
