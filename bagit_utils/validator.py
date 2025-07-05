"""BagIt-profile validator definition."""

from typing import Mapping, Optional
from urllib.request import urlopen
from pathlib import Path
from json import load, loads
import re

from .common import quote_list, Issue, ValidationReport
from .bagit import Bag


def load_json_url(url: str, *args, **kwargs) -> dict:
    """
    Returns JSON from source `url`. `args` and `kwargs` are passed into
    `urllib.request.urlopen`.
    """
    with urlopen(url, *args, **kwargs) as content:
        return load(content)


def load_json_path(path: Path) -> dict:
    """Returns JSON from source `path`."""
    return loads(path.read_text(encoding="utf-8"))


class BagItProfileValidator:
    """
    Validator class for BagIt-Profiles as used by the `BagValidator`.
    It is mostly based on the BagIt Profiles-project[1] (@1.4.0). See
    this project's README.md [2] for details.

    [1] https://bagit-profiles.github.io/bagit-profiles-specification
    [2] https://github.com/RichtersFinger/bagit-utils
    """

    _ACCEPTED_PROPERTIES = [
        "BagIt-Profile-Info",
        "Bag-Info",
        "Manifests-Required",
        "Manifests-Allowed",
        "Allow-Fetch.txt",
        "Fetch.txt-Required",
        "Data-Empty",
        "Serialization",
        "Accept-Serialization",
        "Accept-BagIt-Version",
        "Tag-Manifests-Required",
        "Tag-Manifests-Allowed",
        "Tag-Files-Required",
        "Tag-Files-Allowed",
        "Payload-Files-Required",
        "Payload-Files-Allowed",
    ]
    _ACCEPTED_BAGINFO_PROPERTIES = [
        "required",
        "values",
        "repeatable",
        "description",
        "regex",
    ]
    _ACCEPTED_SERIALIZATION_VALUES = ["forbidden", "required", "optional"]
    _ERROR_PREFIX = "BagIt-profile incompatible: "
    _ERROR_BAD_TYPE = (
        "Bad type for '{key}' (expected '{exp}' but got '{got}')."
    )
    _ERROR_UNKOWN_KEY = "Unknown key(s) {keys} in '{key}'"

    @classmethod
    def load_profile(
        cls,
        profile: Optional[Mapping] = None,
        profile_src: Optional[str | Path] = None,
    ) -> dict:
        """
        Loads, validates, and returns BagIt-profile. If the profile is
        not valid, this method raises a `ValueError`.

        Keyword arguments:
        profile -- JSON profile
                   (default None)
        profile_src -- JSON profile url or path
                       (default None)
        """
        if profile is None and profile_src is None:
            raise ValueError(
                "Missing BagIt-profile. Either 'profile' or 'profile_src' "
                + "is required."
            )
        if profile is not None and profile_src is not None:
            raise ValueError(
                "Ambiguous BagIt-profile. Got both 'profile' and 'profile_src'"
                + " in request."
            )
        if profile is None:
            if Path(profile_src).is_file():
                profile = load_json_path(Path(profile_src))
            else:
                profile = load_json_url(profile_src)

        # profile validation
        # * root
        if not isinstance(profile, Mapping):
            raise ValueError(cls._ERROR_PREFIX + "Not an object.")
        # * keys
        unknown_key = next(
            (key for key in profile if key not in cls._ACCEPTED_PROPERTIES),
            None,
        )
        if unknown_key is not None:
            raise ValueError(
                cls._ERROR_PREFIX + f"Unknown key '{unknown_key}'."
            )
        # * children
        for v in [
            cls.validate_baginfo,
            cls.validate_manifests_required,
            cls.validate_manifests_allowed,
            cls.validate_allow_fetchtxt,
            cls.validate_fetchtxt_required,
            cls.validate_data_empty,
            cls.validate_serialization,
            cls.validate_accept_serialization,
            cls.validate_accept_bagit_version,
            cls.validate_tag_manifests_required,
            cls.validate_tag_manifests_allowed,
            cls.validate_tag_files_required,
            cls.validate_tag_files_allowed,
            cls.validate_payload_files_required,
            cls.validate_payload_files_allowed,
            cls.custom_validation_hook,
        ]:
            v(profile)
        return profile

    @classmethod
    def _handle_type_validation(cls, type_, key, value) -> None:
        """
        Raises `ValueError` if `type_` does not match type of `value`.
        """
        if not isinstance(value, type_):
            raise ValueError(
                cls._ERROR_PREFIX
                + cls._ERROR_BAD_TYPE.format(
                    key=key, exp=type_.__name__, got=type(value).__name__
                )
            )

    @classmethod
    def _handle_list_of_str_validation(cls, key, data: list[str]) -> None:
        """
        Raises `ValueError` if `data` contains non-string value.
        """
        if any(not isinstance(value, str) for value in data):
            raise ValueError(
                cls._ERROR_PREFIX
                + f"Bad type in '{key}' (encountered non-string value)."
            )

    @classmethod
    def _validate_baginfo_item_required(cls, key: str, item: Mapping) -> None:
        try:
            value = item["required"]
        except KeyError:
            return
        if not isinstance(value, bool):
            raise ValueError(
                cls._ERROR_PREFIX
                + cls._ERROR_BAD_TYPE.format(
                    key=f"Bag-Info.{key}.required",
                    exp=bool.__name__,
                    got=type(value).__name__,
                )
            )

    @classmethod
    def _validate_baginfo_item_repeatable(
        cls, key: str, item: Mapping
    ) -> None:
        try:
            value = item["repeatable"]
        except KeyError:
            return
        if not isinstance(value, bool):
            raise ValueError(
                cls._ERROR_PREFIX
                + cls._ERROR_BAD_TYPE.format(
                    key=f"Bag-Info.{key}.repeatable",
                    exp=bool.__name__,
                    got=type(value).__name__,
                )
            )

    @classmethod
    def _validate_baginfo_item_description(
        cls, key: str, item: Mapping
    ) -> None:
        try:
            value = item["description"]
        except KeyError:
            return
        if not isinstance(value, str):
            raise ValueError(
                cls._ERROR_PREFIX
                + cls._ERROR_BAD_TYPE.format(
                    key=f"Bag-Info.{key}.description",
                    exp=str.__name__,
                    got=type(value).__name__,
                )
            )

    @classmethod
    def _validate_baginfo_item_values(cls, key: str, item: Mapping) -> None:
        try:
            value = item["values"]
        except KeyError:
            return
        if not isinstance(value, list):
            raise ValueError(
                cls._ERROR_PREFIX
                + cls._ERROR_BAD_TYPE.format(
                    key=f"Bag-Info.{key}.required",
                    exp=bool.__name__,
                    got=type(value).__name__,
                )
            )
        cls._handle_list_of_str_validation(f"Bag-Info.{key}.values", value)

    @classmethod
    def _validate_baginfo_item_regex(cls, key: str, item: Mapping) -> None:
        try:
            value = item["regex"]
        except KeyError:
            return
        if not isinstance(value, str):
            raise ValueError(
                cls._ERROR_PREFIX
                + cls._ERROR_BAD_TYPE.format(
                    key=f"Bag-Info.{key}.regex",
                    exp=str.__name__,
                    got=type(value).__name__,
                )
            )
        try:
            re.compile(item["regex"])
        except re.error as exc_info:
            raise ValueError(
                cls._ERROR_PREFIX
                + f"Bad regex in 'Bag-Info.{key}.regex' ({exc_info})."
            ) from exc_info

    @classmethod
    def _validate_baginfo_custom_item_hook(
        cls, key: str, item: Mapping
    ) -> None:
        """Hook for validation of custom Bag-Info-item fields."""

    @classmethod
    def _validate_baginfo_item(cls, key: str, item: Mapping) -> None:
        """Validate single item of 'Bag-Info'-section of `profile`."""
        cls._handle_type_validation(dict, f"Bag-Info.{key}", item)
        unknown_keys = [
            k for k in item if k not in cls._ACCEPTED_BAGINFO_PROPERTIES
        ]
        if unknown_keys:
            raise ValueError(
                cls._ERROR_PREFIX
                + cls._ERROR_UNKOWN_KEY.format(
                    key=f"Bag-Info.{key}", keys=quote_list(unknown_keys)
                )
            )
        cls._validate_baginfo_item_required(key, item)
        cls._validate_baginfo_item_repeatable(key, item)
        cls._validate_baginfo_item_description(key, item)
        cls._validate_baginfo_item_values(key, item)
        cls._validate_baginfo_item_regex(key, item)
        if "regex" in item and "values" in item:
            raise ValueError(
                cls._ERROR_PREFIX
                + f"Bad object in 'Bag-Info.{key}' ('values' and 'regex' "
                + "are mutually exclusive)."
            )
        cls._validate_baginfo_custom_item_hook(key, item)

    @classmethod
    def validate_baginfo(cls, profile: Mapping) -> None:
        """Validate 'Bag-Info'-section of `profile`."""
        if "Bag-Info" not in profile:
            return
        baginfo = profile["Bag-Info"]
        cls._handle_type_validation(dict, "Bag-Info", baginfo)
        for key, item in baginfo.items():
            cls._validate_baginfo_item(key, item)

    @classmethod
    def _handle_manifest_algorithm_validation(
        cls, key: str, data: list[str]
    ) -> None:
        """Handles validation for a list of manifest algorithms."""
        cls._handle_type_validation(list, key, data)
        cls._handle_list_of_str_validation(key, data)

    @classmethod
    def validate_manifests_required(cls, profile: Mapping) -> None:
        """Validate 'Manifests-Required'-section of `profile`."""
        if "Manifests-Required" not in profile:
            return
        cls._handle_manifest_algorithm_validation(
            "Manifests-Required", profile["Manifests-Required"]
        )

    @classmethod
    def validate_manifests_allowed(cls, profile: Mapping) -> None:
        """Validate 'Manifests-Allowed'-section of `profile`."""
        if "Manifests-Allowed" not in profile:
            return
        cls._handle_manifest_algorithm_validation(
            "Manifests-Allowed", profile["Manifests-Allowed"]
        )
        if "Manifests-Required" not in profile:
            return
        bad_algorithms = set(profile["Manifests-Required"]).difference(
            profile["Manifests-Allowed"]
        )
        if bad_algorithms:
            raise ValueError(
                cls._ERROR_PREFIX
                + "Conflicting manifest configuration. All required "
                + "algorithms ('Manifests-Required') must also be allowed "
                + "('Manifests-Allowed'). Required but not allowed "
                + f"algorithm(s): {quote_list(bad_algorithms)}."
            )

    @classmethod
    def validate_allow_fetchtxt(cls, profile: Mapping) -> None:
        """Validate 'Allow-Fetch.txt'-section of `profile`."""
        if "Allow-Fetch.txt" not in profile:
            return
        cls._handle_type_validation(
            bool, "Allow-Fetch.txt", profile["Allow-Fetch.txt"]
        )

    @classmethod
    def validate_fetchtxt_required(cls, profile: Mapping) -> None:
        """Validate 'Fetch.txt-Required'-section of `profile`."""
        if "Fetch.txt-Required" not in profile:
            return
        cls._handle_type_validation(
            bool, "Fetch.txt-Required", profile["Fetch.txt-Required"]
        )
        if profile["Fetch.txt-Required"] and not profile.get(
            "Allow-Fetch.txt", True
        ):
            raise ValueError(
                cls._ERROR_PREFIX
                + "Inconsistent values for 'Fetch.txt-Required' and 'Allow-"
                + "Fetch.txt' (fetch.txt required but not allowed)."
            )

    @classmethod
    def validate_data_empty(cls, profile: Mapping) -> None:
        """Validate 'Data-Empty'-section of `profile`."""
        if "Data-Empty" not in profile:
            return
        cls._handle_type_validation(bool, "Data-Empty", profile["Data-Empty"])

    @classmethod
    def validate_serialization(cls, profile: Mapping) -> None:
        """Validate 'Serialization'-section of `profile`."""
        if "Serialization" not in profile:
            return
        cls._handle_type_validation(
            str, "Serialization", profile["Serialization"]
        )
        if profile["Serialization"] not in cls._ACCEPTED_SERIALIZATION_VALUES:
            raise ValueError(
                cls._ERROR_PREFIX
                + f"Bad value '{profile['Serialization']}' for 'Serialization'"
                + " (accepted values are "
                + f"{quote_list(cls._ACCEPTED_SERIALIZATION_VALUES)})."
            )

    @classmethod
    def validate_accept_serialization(cls, profile: Mapping) -> None:
        """Validate 'Accept-Serialization'-section of `profile`."""
        if "Accept-Serialization" not in profile:
            return
        cls._handle_type_validation(
            list, "Accept-Serialization", profile["Accept-Serialization"]
        )
        cls._handle_list_of_str_validation(
            "Accept-Serialization", profile["Accept-Serialization"]
        )

    @classmethod
    def validate_accept_bagit_version(cls, profile: Mapping) -> None:
        """Validate 'Accept-BagIt-Version'-section of `profile`."""
        if "Accept-BagIt-Version" not in profile:
            return
        cls._handle_type_validation(
            list, "Accept-BagIt-Version", profile["Accept-BagIt-Version"]
        )
        cls._handle_list_of_str_validation(
            "Accept-BagIt-Version", profile["Accept-BagIt-Version"]
        )
        if len(profile["Accept-BagIt-Version"]) == 0:
            raise ValueError(
                cls._ERROR_PREFIX
                + "Missing data, 'Accept-BagIt-Version' is empty."
            )

    @classmethod
    def validate_tag_manifests_required(cls, profile: Mapping) -> None:
        """Validate 'Tag-Manifests-Required'-section of `profile`."""
        if "Tag-Manifests-Required" not in profile:
            return
        cls._handle_manifest_algorithm_validation(
            "Tag-Manifests-Required", profile["Tag-Manifests-Required"]
        )

    @classmethod
    def validate_tag_manifests_allowed(cls, profile: Mapping) -> None:
        """Validate 'Tag-Manifests-Allowed'-section of `profile`."""
        if "Tag-Manifests-Allowed" not in profile:
            return
        cls._handle_manifest_algorithm_validation(
            "Tag-Manifests-Allowed", profile["Tag-Manifests-Allowed"]
        )
        if "Tag-Manifests-Required" not in profile:
            return
        bad_algorithms = set(profile["Tag-Manifests-Required"]).difference(
            profile["Tag-Manifests-Allowed"]
        )
        if bad_algorithms:
            raise ValueError(
                cls._ERROR_PREFIX
                + "Conflicting manifest configuration. All required "
                + "algorithms ('Tag-Manifests-Required') must also be allowed "
                + "('Tag-Manifests-Allowed'). Required but not allowed "
                + f"algorithm(s): {quote_list(bad_algorithms)}."
            )

    @classmethod
    def validate_tag_files_required(cls, profile: Mapping) -> None:
        """Validate 'Tag-Files-Required'-section of `profile`."""
        if "Tag-Files-Required" not in profile:
            return
        cls._handle_type_validation(
            list, "Tag-Files-Required", profile["Tag-Files-Required"]
        )
        cls._handle_list_of_str_validation(
            "Tag-Files-Required", profile["Tag-Files-Required"]
        )

    @classmethod
    def validate_tag_files_allowed(cls, profile: Mapping) -> None:
        """Validate 'Tag-Files-Allowed'-section of `profile`."""
        if "Tag-Files-Allowed" not in profile:
            return
        cls._handle_type_validation(
            list, "Tag-Files-Allowed", profile["Tag-Files-Allowed"]
        )
        cls._handle_list_of_str_validation(
            "Tag-Files-Allowed", profile["Tag-Files-Allowed"]
        )
        if "Tag-Files-Required" not in profile:
            return
        bad_files = [
            f
            for f in profile["Tag-Files-Required"]
            if not any(Path(f).match(p) for p in profile["Tag-Files-Allowed"])
        ]
        if bad_files:
            raise ValueError(
                cls._ERROR_PREFIX
                + "Conflicting tag-files configuration. All required "
                + "files ('Tag-Files-Required') must also be allowed "
                + "('Tag-Files-Allowed'). Required but not allowed "
                + f"file(s): {quote_list(bad_files)}."
            )

    @classmethod
    def validate_payload_files_required(cls, profile: Mapping) -> None:
        """Validate 'Payload-Files-Required'-section of `profile`."""
        if "Payload-Files-Required" not in profile:
            return
        cls._handle_type_validation(
            list, "Payload-Files-Required", profile["Payload-Files-Required"]
        )
        cls._handle_list_of_str_validation(
            "Payload-Files-Required", profile["Payload-Files-Required"]
        )

    @classmethod
    def validate_payload_files_allowed(cls, profile: Mapping) -> None:
        """Validate 'Payload-Files-Allowed'-section of `profile`."""
        if "Payload-Files-Allowed" not in profile:
            return
        cls._handle_type_validation(
            list, "Payload-Files-Allowed", profile["Payload-Files-Allowed"]
        )
        cls._handle_list_of_str_validation(
            "Payload-Files-Allowed", profile["Payload-Files-Allowed"]
        )
        if "Payload-Files-Required" not in profile:
            return
        bad_files = [
            f
            for f in profile["Payload-Files-Required"]
            if not any(
                Path(f).match(p) for p in profile["Payload-Files-Allowed"]
            )
        ]
        if bad_files:
            raise ValueError(
                cls._ERROR_PREFIX
                + "Conflicting payload-files configuration. All required "
                + "files ('Payload-Files-Required') must also be allowed "
                + "('Payload-Files-Allowed'). Required but not allowed "
                + f"file(s): {quote_list(bad_files)}."
            )

    @classmethod
    def custom_validation_hook(
        # pylint: disable=unused-argument
        cls,
        profile: Mapping,
    ) -> None:
        """Hook for custom validation steps."""


class BagValidator:
    """
    BagIt-validator class mostly based on the BagIt Profiles-project[1]
    (@1.4.0). See this project's README.md [2] for details.

    This validator supports two modes of operation:
    1. instantiate with a profile/profile_src `BagValidator(..)` and run
       repeated validations using that profile via `validate(..)`, or
    2. run one-shot validations via `BagValidator.validate_once(..)`.

    Keyword arguments:
    profile -- JSON profile
                (default None)
    profile_src -- JSON profile url or path
                    (default None)
    profile_validator -- BagIt-profile validator class override
                         (default None)

    At least one of the arguments `profile` or `profile_src` need to
    be given.

    [1] https://bagit-profiles.github.io/bagit-profiles-specification
    [2] https://github.com/RichtersFinger/bagit-utils
    """

    _PROFILE_VALIDATOR = BagItProfileValidator
    ISSUE_INFO_MESSAGES = True
    ISSUE_WARNINGS = True

    def __init__(
        self,
        profile: Optional[Mapping] = None,
        profile_src: Optional[str | Path] = None,
        profile_validator: Optional[type[BagItProfileValidator]] = None,
    ) -> None:
        self.profile = (
            profile_validator or self._PROFILE_VALIDATOR
        ).load_profile(profile, profile_src)

    def validate(
        self,
        bag: Bag,
    ) -> ValidationReport:
        """
        Run validation on a `bag` with this validator's profile.

        The given `bag` is expected to be passing `bag.validate`.

        Keyword arguments:
        bag -- Bag-instance to be validated
        """
        return self.validate_once(bag, self.profile)

    @classmethod
    def validate_once(
        cls,
        bag: Bag,
        profile: Optional[Mapping] = None,
        profile_src: Optional[str | Path] = None,
    ) -> ValidationReport:
        """
        Run one-shot validation on a `bag` with the given profile.

        The given `bag` is expected to be passing `bag.validate`.

        At least one of the arguments `profile` or `profile_src` need to
        be given.

        Keyword arguments:
        bag -- Bag-instance to be validated
        profile -- JSON profile
                   (default None)
        profile_src -- JSON profile url or path
                       (default None)
        """
        profile = cls._PROFILE_VALIDATOR.load_profile(profile, profile_src)
        result = ValidationReport(bag=bag)
        for v in [
            cls.validate_baginfo,
            cls.validate_manifests_required,
            cls.validate_manifests_allowed,
            cls.validate_allow_fetchtxt,
            cls.validate_fetchtxt_required,
            cls.validate_data_empty,
            cls.validate_serialization,
            cls.validate_accept_serialization,
            cls.validate_accept_bagit_version,
            cls.validate_tag_manifests_required,
            cls.validate_tag_manifests_allowed,
            cls.validate_tag_files_required,
            cls.validate_tag_files_allowed,
            cls.validate_payload_files_required,
            cls.validate_payload_files_allowed,
            cls.custom_validation_hook,
        ]:
            cls._handle_validation_step(result, v(bag, profile))
        return result

    @classmethod
    def _handle_validation_step(
        cls, total: ValidationReport, partial: ValidationReport
    ) -> None:
        """
        Helper to process individual `partial` reports into `total`
        report in place.
        """
        if partial.valid is not None:
            if total.valid is None:
                total.valid = partial.valid
            else:
                total.valid = total.valid and partial.valid
        total.issues += partial.issues

    @classmethod
    def validate_baginfo_tag_required(
        cls, tag: str, bag: Bag, tag_profile: Mapping
    ) -> ValidationReport:
        """
        Validate 'required'-property of `bag.baginfo`-tag with name
        `tag` using tag's subsection of profile `tag_profile`.
        """
        result = ValidationReport(True)
        if tag_profile.get("required", False) and tag not in bag.baginfo:
            result.valid = False
            result.issues.append(
                Issue(
                    "error",
                    f"Missing required 'bag-info.txt'-metadata tag '{tag}' in "
                    + f"bag at '{bag.path}'.",
                    f"Bag-Info.{tag}",
                )
            )
        return result

    @classmethod
    def validate_baginfo_tag_repeatable(
        cls, tag: str, bag: Bag, tag_profile: Mapping
    ) -> ValidationReport:
        """
        Validate 'repeatable'-property of `bag.baginfo`-tag with name
        `tag` using tag's subsection of profile `tag_profile`.
        """
        result = ValidationReport(True)
        if (
            not tag_profile.get("repeatable", True)
            and len(bag.baginfo.get(tag, [])) > 1
        ):
            result.valid = False
            result.issues.append(
                Issue(
                    "error",
                    f"Too many 'bag-info.txt'-metadata tags '{tag}' in "
                    + f"bag at '{bag.path}' (tag must not be repeated).",
                    f"Bag-Info.{tag}",
                )
            )
        return result

    @classmethod
    def validate_baginfo_tag_values(
        cls, tag: str, bag: Bag, tag_profile: Mapping
    ) -> ValidationReport:
        """
        Validate 'values'-property of `bag.baginfo`-tag with name
        `tag` using tag's subsection of profile `tag_profile`.
        """
        result = ValidationReport(True)
        values = tag_profile.get("values")
        if values is None or tag not in bag.baginfo:
            return result
        for value in bag.baginfo[tag]:
            if value not in values:
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        f"Bad value '{value}' for 'bag-info.txt'-metadata "
                        + f"tag '{tag}' in bag at '{bag.path}' (accepted "
                        + f"values are: {quote_list(values) or '-'}).",
                        f"Bag-Info.{tag}",
                    )
                )
        return result

    @classmethod
    def validate_baginfo_tag_regex(
        cls, tag: str, bag: Bag, tag_profile: Mapping
    ) -> ValidationReport:
        """
        Validate 'regex'-property of `bag.baginfo`-tag with name
        `tag` using tag's subsection of profile `tag_profile`.
        """
        result = ValidationReport(True)
        if "regex" not in tag_profile:
            return result
        regex = re.compile(tag_profile["regex"])
        for value in bag.baginfo.get(tag, []):
            if not regex.fullmatch(value):
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        f"Value '{value}' of 'bag-info.txt'-metadata tag "
                        + f"'{tag}' in bag at '{bag.path}' does not satisfy "
                        + f"regex '{tag_profile['regex']}'.",
                        f"Bag-Info.{tag}",
                    )
                )
        return result

    @classmethod
    def validate_baginfo(cls, bag: Bag, profile: Mapping) -> ValidationReport:
        """Validate 'Bag-Info'-section of `profile` in `bag`."""
        result = ValidationReport(True)
        for tag, tag_profile in profile.get("Bag-Info", {}).items():
            for v in [
                cls.validate_baginfo_tag_required,
                cls.validate_baginfo_tag_repeatable,
                cls.validate_baginfo_tag_values,
                cls.validate_baginfo_tag_regex,
            ]:
                cls._handle_validation_step(
                    result,
                    v(tag, bag, tag_profile),
                )
        unknown_tags = set(bag.baginfo.keys()) - set(
            profile.get("Bag-Info", {}).keys()
        )
        if unknown_tags:
            result.issues.append(
                Issue(
                    "warning",
                    f"The 'bag-info.txt'-metadata in bag at '{bag.path}' "
                    + "contains tags that are not described by the given "
                    + f"profile: {quote_list(unknown_tags)}.",
                    "Bag-Info",
                )
            )
        return result

    @classmethod
    def validate_manifests_required(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Manifests-Required'-section of `profile` in `bag`."""
        result = ValidationReport(True)
        for method in profile.get("Manifests-Required", []):
            if not (bag.path / f"manifest-{method}.txt").is_file():
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        f"Missing manifest for algorithm '{method}' in bag at "
                        + f"'{bag.path}'.",
                        "Manifests-Required",
                    )
                )
        return result

    @classmethod
    def validate_manifests_allowed(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Manifests-Allowed'-section of `profile` in `bag`."""
        result = ValidationReport(True)
        if profile.get("Manifests-Allowed") is None:
            return result

        for file in bag.path.glob("manifest-*.txt"):
            if file.name not in map(
                lambda m: f"manifest-{m}.txt", profile["Manifests-Allowed"]
            ):
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        f"Manifest file '{file.relative_to(bag.path)}' not "
                        + f"allowed in bag at '{bag.path}'.",
                        "Manifests-Allowed",
                    )
                )
        return result

    @classmethod
    def validate_allow_fetchtxt(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Allow-Fetch.txt'-section of `profile` in `bag`."""
        result = ValidationReport(True)
        if (
            "Allow-Fetch.txt" in profile
            and profile["Allow-Fetch.txt"]
            and cls.ISSUE_INFO_MESSAGES
        ):
            result.issues.append(
                Issue(
                    "info",
                    "A 'fetch.txt'-file is currently not supported.",
                    "Allow-Fetch.txt",
                )
            )
        if (
            not profile.get("Allow-Fetch.txt", True)
            and (bag.path / "fetch.txt").is_file()
        ):
            result.valid = False
            result.issues.append(
                Issue(
                    "error",
                    f"File 'fetch.txt' in bag at '{bag.path}' is not allowed.",
                    "Allow-Fetch.txt",
                )
            )
        return result

    @classmethod
    def validate_fetchtxt_required(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Fetch.txt-Required'-section of `profile` in `bag`."""
        result = ValidationReport(True)
        if (
            "Fetch.txt-Required" in profile
            and profile["Fetch.txt-Required"]
            and cls.ISSUE_INFO_MESSAGES
        ):
            result.issues.append(
                Issue(
                    "info",
                    "A 'fetch.txt'-file is currently not supported.",
                    "Fetch.txt-Required",
                )
            )
        if (
            profile.get("Fetch.txt-Required", False)
            and not (bag.path / "fetch.txt").is_file()
        ):
            result.valid = False
            result.issues.append(
                Issue(
                    "error",
                    f"Missing file 'fetch.txt' in bag at '{bag.path}'.",
                    "Fetch.txt-Required",
                )
            )
        return result

    @classmethod
    def validate_data_empty(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Data-Empty'-section of `profile` in `bag`."""
        result = ValidationReport(True)
        if profile.get("Data-Empty", False):
            files = list((bag.path / "data").glob("**/*"))
            if len(files) > 1:
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        f"Payload of bag at '{bag.path}' must not contain more"
                        + f" than one file (found {len(files)} files).",
                        "Data-Empty",
                    )
                )
            elif len(files) == 1 and files[0].lstat().st_size > 0:
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        f"Payload file '{files[0].relative_to(bag.path)}' in "
                        + f"bag at '{bag.path}' must be zero bytes "
                        + f"(found {files[0].lstat().st_size}B).",
                        "Data-Empty",
                    )
                )
        return result

    @classmethod
    def validate_serialization(
        # pylint: disable=unused-argument
        cls,
        bag: Bag,
        profile: Mapping,
    ) -> ValidationReport:
        """Validate 'Serialization'-section of `profile` in `bag`."""
        result = ValidationReport(True)
        if "Serialization" in profile and cls.ISSUE_WARNINGS:
            result.issues.append(
                Issue(
                    "warning",
                    "Validation of bag-'Serialization' is currently not"
                    + " supported.",
                    "Serialization",
                )
            )
        return result

    @classmethod
    def validate_accept_serialization(
        # pylint: disable=unused-argument
        cls,
        bag: Bag,
        profile: Mapping,
    ) -> ValidationReport:
        """Validate 'Accept-Serialization'-section of `profile` in `bag`."""
        result = ValidationReport(True)
        if "Accept-Serialization" in profile and cls.ISSUE_WARNINGS:
            result.issues.append(
                Issue(
                    "warning",
                    "Validation of bag-'Accept-Serialization' is currently not"
                    + " supported.",
                    "Accept-Serialization",
                )
            )
        return result

    @classmethod
    def validate_accept_bagit_version(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Accept-BagIt-Version'-section of `profile` in `bag`."""
        result = ValidationReport(True)
        if "Accept-BagIt-Version" in profile:
            if (
                profile["Accept-BagIt-Version"] != ["1.0"]
                and cls.ISSUE_INFO_MESSAGES
            ):
                result.issues.append(
                    Issue(
                        "info",
                        "This library currently only supports BagIt at version"
                        + " '1.0'.",
                        "Accept-BagIt-Version",
                    )
                )
            bag_version = (
                (bag.path / "bagit.txt")
                .read_text(encoding="utf-8")
                .splitlines()[0]
            )
            if not any(
                bag_version in f"BagIt-Version: {version}"
                for version in profile["Accept-BagIt-Version"]
            ):
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        f"Bad BagIt-version for bag at '{bag.path}' (got "
                        + f"'{bag_version}' but expected one of "
                        + f"{quote_list(profile['Accept-BagIt-Version'])}).",
                        "Accept-BagIt-Version",
                    )
                )
        return result

    @classmethod
    def validate_tag_manifests_required(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Tag-Manifests-Required'-section of `profile` in `bag`."""
        result = ValidationReport(True)
        for method in profile.get("Tag-Manifests-Required", []):
            if not (bag.path / f"tagmanifest-{method}.txt").is_file():
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        f"Missing tagmanifest for algorithm '{method}' in bag"
                        + f" at '{bag.path}'.",
                        "Tag-Manifests-Required",
                    )
                )
        return result

    @classmethod
    def validate_tag_manifests_allowed(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Tag-Manifests-Allowed'-section of `profile` in `bag`."""
        result = ValidationReport(True)
        if profile.get("Tag-Manifests-Allowed") is None:
            return result

        for file in bag.path.glob("tagmanifest-*.txt"):
            if file.name not in map(
                lambda m: f"tagmanifest-{m}.txt",
                profile["Tag-Manifests-Allowed"],
            ):
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        f"Tag-manifest file '{file.relative_to(bag.path)}' not"
                        + f" allowed in bag at '{bag.path}'.",
                        "Tag-Manifests-Allowed",
                    )
                )
        return result

    @classmethod
    def validate_tag_files_required(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Tag-Files-Required'-section of `profile` in `bag`."""
        result = ValidationReport(True)
        if profile.get("Tag-Files-Required") is None:
            return result

        for file in map(lambda f: bag.path / f, profile["Tag-Files-Required"]):
            if not file.is_file():
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        "Missing required tag-file "
                        + f"'{Path(file).relative_to(bag.path)}' in bag at "
                        + f"'{bag.path}'.",
                        "Tag-Files-Required",
                    )
                )
        return result

    @classmethod
    def validate_tag_files_allowed(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Tag-Files-Allowed'-section of `profile` in `bag`."""
        result = ValidationReport(True)
        if profile.get("Tag-Files-Allowed") is None:
            return result

        excluded_files = (
            list(bag.path.glob("data/**/*"))
            + list(bag.path.glob("manifest-*.txt"))
            + list(bag.path.glob("tagmanifest-*.txt"))
            + [
                bag.path / "bagit.txt",
                bag.path / "bag-info.txt",
                bag.path / "fetch.txt",
            ]
        )

        for file in [
            f
            for f in bag.path.glob("**/*")
            if f.is_file() and f not in excluded_files
        ]:
            if not any(
                file.relative_to(bag.path).match(p)
                for p in profile["Tag-Files-Allowed"]
            ):
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        f"Tag file '{Path(file).relative_to(bag.path)}' in bag"
                        + f" at '{bag.path}' is not allowed.",
                        "Tag-Files-Allowed",
                    )
                )
        return result

    @classmethod
    def validate_payload_files_required(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Payload-Files-Required'-section of `profile` in `bag`."""
        result = ValidationReport(True)
        if profile.get("Payload-Files-Required") is None:
            return result

        for file in map(
            lambda f: bag.path / f, profile["Payload-Files-Required"]
        ):
            if not file.is_file():
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        "Missing required payload-file "
                        + f"'{Path(file).relative_to(bag.path)}' in bag at "
                        + f"'{bag.path}'.",
                        "Payload-Files-Required",
                    )
                )
        return result

    @classmethod
    def validate_payload_files_allowed(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Payload-Files-Allowed'-section of `profile` in `bag`."""
        result = ValidationReport(True)
        if profile.get("Payload-Files-Allowed") is None:
            return result

        for file in [f for f in bag.path.glob("data/**/*") if f.is_file()]:
            if not any(
                file.relative_to(bag.path).match(p)
                for p in profile["Payload-Files-Allowed"]
            ):
                result.valid = False
                result.issues.append(
                    Issue(
                        "error",
                        f"Payload file '{Path(file).relative_to(bag.path)}' in"
                        + f" bag at '{bag.path}' is not allowed.",
                        "Payload-Files-Allowed",
                    )
                )
        return result

    @classmethod
    def custom_validation_hook(
        # pylint: disable=unused-argument
        cls,
        bag: Bag,
        profile: Mapping,
    ) -> ValidationReport:
        """Hook for custom validation steps."""
        return ValidationReport(True)
