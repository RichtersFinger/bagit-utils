"""`bagit-utils`-CLI definition."""

from typing import Optional, Any
import sys
from importlib.metadata import version
from pathlib import Path

try:
    from befehl import Parser, Option, Cli, Command
except ImportError:
    print(
        "Missing cli-dependencies, please install by entering "
        + "`pip install bagit-utils[cli]`."
    )
    sys.exit(1)


def parse_dir_exists_but_empty(data: str) -> tuple[bool, Optional[str], Any]:
    """
    Parses input as Path, returns ok if path does not exist or is empty.
    """
    path = Path(data)
    if not path.exists():
        return True, None, path
    if len(list(path.glob("**/*"))) == 0:
        return True, None, path
    return False, f"Directory '{data}' is not empty", None


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

    def run(self, args):
        # TODO
        return


class ModifyBag(Command):
    """Subcommand for modifying bags."""
    input_ = Option(
        ("-i", "--input"),
        helptext="target bag that should be modified",
        nargs=1,
        parser=Parser.parse_as_dir,
    )

    def run(self, args):
        # TODO
        return


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
    )
).build()
