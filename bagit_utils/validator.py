"""BagIt-profile validator definition."""

from typing import Mapping, Optional
from dataclasses import dataclass, field
from urllib.request import urlopen
from json import load

from .bagit import Bag


def load_json(url: str, *args, **kwargs) -> dict:
    """
    Returns JSON from source `url`. `args` and `kwargs` are passed into
    `urllib.request.urlopen`.
    """
    with urlopen(url, *args, **kwargs) as content:
        return load(content)


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

    @classmethod
    def load_profile(
        cls,
        profile: Optional[Mapping] = None,
        profile_url: Optional[str] = None,
    ):
        """
        Loads, validates, and returns BagIt-profile. If the profile is
        not valid, this method raises a `ValueError`.

        Keyword arguments:
        profile -- JSON profile
                   (default None)
        profile_url -- JSON profile url
                       (default None)
        """
        if profile is None and profile_url is None:
            raise ValueError(
                "Missing BagIt-profile. Either 'profile' or 'profile_url' "
                + "is required."
            )
        if profile is not None and profile_url is not None:
            raise ValueError(
                "Ambiguous BagIt-profile. Got both 'profile' and 'profile_url'"
                + " in request."
            )
        if profile is None:
            profile = load_json(profile_url)

        # profile validation
        # * root
        if not isinstance(profile, Mapping):
            raise ValueError("BagIt-profile incompatible: Not an object.")
        # * keys
        unknown_key = next(
            (key for key in profile if key not in cls._ACCEPTED_PROPERTIES),
            None,
        )
        if unknown_key is not None:
            raise ValueError(
                f"BagIt-profile incompatible: Unknown key '{unknown_key}'."
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
                f"BagIt-profile incompatible: Bad type for '{key}' (expected "
                + f"'{type_.__name__}' but got '{type(value).__name__}')."
            )

    @classmethod
    def validate_baginfo(cls, profile: Mapping) -> None:
        """Validate 'Bag-Info'-section of `profile`."""
        if "Bag-Info" in profile:
            cls._handle_type_validation(dict, "Bag-Info", profile["Bag-Info"])
        # TODO

    @classmethod
    def validate_manifests_required(cls, profile: Mapping) -> None:
        """Validate 'Manifests-Required'-section of `profile`."""
        # TODO

    @classmethod
    def validate_manifests_allowed(cls, profile: Mapping) -> None:
        """Validate 'Manifests-Allowed'-section of `profile`."""
        # TODO

    @classmethod
    def validate_allow_fetchtxt(cls, profile: Mapping) -> None:
        """Validate 'Allow-Fetch.txt'-section of `profile`."""
        # TODO

    @classmethod
    def validate_fetchtxt_required(cls, profile: Mapping) -> None:
        """Validate 'Fetch.txt-Required'-section of `profile`."""
        # TODO

    @classmethod
    def validate_data_empty(cls, profile: Mapping) -> None:
        """Validate 'Data-Empty'-section of `profile`."""
        # TODO

    @classmethod
    def validate_serialization(cls, profile: Mapping) -> None:
        """Validate 'Serialization'-section of `profile`."""
        # TODO

    @classmethod
    def validate_accept_serialization(cls, profile: Mapping) -> None:
        """Validate 'Accept-Serialization'-section of `profile`."""
        # TODO

    @classmethod
    def validate_accept_bagit_version(cls, profile: Mapping) -> None:
        """Validate 'Accept-BagIt-Version'-section of `profile`."""
        # TODO

    @classmethod
    def validate_tag_manifests_required(cls, profile: Mapping) -> None:
        """Validate 'Tag-Manifests-Required'-section of `profile`."""
        # TODO

    @classmethod
    def validate_tag_manifests_allowed(cls, profile: Mapping) -> None:
        """Validate 'Tag-Manifests-Allowed'-section of `profile`."""
        # TODO

    @classmethod
    def validate_tag_files_required(cls, profile: Mapping) -> None:
        """Validate 'Tag-Files-Required'-section of `profile`."""
        # TODO

    @classmethod
    def validate_tag_files_allowed(cls, profile: Mapping) -> None:
        """Validate 'Tag-Files-Allowed'-section of `profile`."""
        # TODO

    @classmethod
    def validate_payload_files_required(cls, profile: Mapping) -> None:
        """Validate 'Payload-Files-Required'-section of `profile`."""
        # TODO

    @classmethod
    def validate_payload_files_allowed(cls, profile: Mapping) -> None:
        """Validate 'Payload-Files-Allowed'-section of `profile`."""
        # TODO

    @classmethod
    def custom_validation_hook(
        # pylint: disable=unused-argument
        cls,
        profile: Mapping,
    ) -> None:
        """Hook for custom validation steps."""


@dataclass
class Issue:
    """
    Record class for validation issues.

    Keyword arguments:
    level -- issue severity (one of 'info', 'warning', and 'error')
    message -- issue description
    """

    level: str
    message: str


@dataclass
class ValidationReport:
    """Record class for validation reports."""

    valid: Optional[bool] = None
    issues: list[Issue] = field(default_factory=list)


class BagValidator:
    """
    BagIt-validator class mostly based on the BagIt Profiles-project[1]
    (@1.4.0). See this project's README.md [2] for details.

    start TODO: ----------------------
    add to README
    * validation of BagIt-Profile-Info mostly skipped
    * ...
    end TODO    ----------------------

    This validator supports two modes of operation:
    1. instantiate with a profile/profile_url `BagValidator(..)` and run
       repeated validations using that profile via `validate(..)`, or
    2. run one-shot validations via `BagValidator.validate_once(..)`.

    Keyword arguments:
    profile -- JSON profile
                (default None)
    profile_url -- JSON profile url
                    (default None)
    profile_validator -- BagIt-profile validator class override
                         (default None)

    At least one of the arguments `profile` or `profile_url` need to
    be given.

    [1] https://bagit-profiles.github.io/bagit-profiles-specification
    [2] https://github.com/RichtersFinger/bagit-utils
    """

    _PROFILE_VALIDATOR = BagItProfileValidator

    def __init__(
        self,
        profile: Optional[Mapping] = None,
        profile_url: Optional[str] = None,
        profile_validator: Optional[type[BagItProfileValidator]] = None,
    ) -> None:
        self.profile = (
            profile_validator or self._PROFILE_VALIDATOR
        ).load_profile(profile, profile_url)

    def validate(
        self,
        bag: Bag,
    ) -> ValidationReport:
        """
        Run validation on a `bag` with this validator's profile.

        Keyword arguments:
        bag -- Bag-instance to be validated
        """
        return self.validate_once(bag, self.profile)

    @classmethod
    def validate_once(
        cls,
        bag: Bag,
        profile: Optional[Mapping] = None,
        profile_url: Optional[str] = None,
    ) -> ValidationReport:
        """
        Run one-shot validation on a `bag` with the given profile.

        At least one of the arguments `profile` or `profile_url` need to
        be given.

        Keyword arguments:
        bag -- Bag-instance to be validated
        profile -- JSON profile
                   (default None)
        profile_url -- JSON profile url
                       (default None)
        """
        profile = cls._PROFILE_VALIDATOR.load_profile(profile, profile_url)
        result = ValidationReport()
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
    def validate_baginfo(cls, bag: Bag, profile: Mapping) -> ValidationReport:
        """Validate 'Bag-Info'-section of `profile` in `bag`."""
        # TODO
        return ValidationReport()

    @classmethod
    def validate_manifests_required(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Manifests-Required'-section of `profile` in `bag`."""
        # TODO
        return ValidationReport()

    @classmethod
    def validate_manifests_allowed(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Manifests-Allowed'-section of `profile` in `bag`."""
        # TODO
        return ValidationReport()

    @classmethod
    def validate_allow_fetchtxt(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Allow-Fetch.txt'-section of `profile` in `bag`."""
        # TODO
        return ValidationReport()

    @classmethod
    def validate_fetchtxt_required(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Fetch.txt-Required'-section of `profile` in `bag`."""
        # TODO
        return ValidationReport()

    @classmethod
    def validate_data_empty(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Data-Empty'-section of `profile` in `bag`."""
        # TODO
        return ValidationReport()

    @classmethod
    def validate_serialization(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Serialization'-section of `profile` in `bag`."""
        # TODO
        return ValidationReport()

    @classmethod
    def validate_accept_serialization(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Accept-Serialization'-section of `profile` in `bag`."""
        # TODO
        return ValidationReport()

    @classmethod
    def validate_accept_bagit_version(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Accept-BagIt-Version'-section of `profile` in `bag`."""
        # TODO
        return ValidationReport()

    @classmethod
    def validate_tag_manifests_required(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Tag-Manifests-Required'-section of `profile` in `bag`."""
        # TODO
        return ValidationReport()

    @classmethod
    def validate_tag_manifests_allowed(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Tag-Manifests-Allowed'-section of `profile` in `bag`."""
        # TODO
        return ValidationReport()

    @classmethod
    def validate_tag_files_required(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Tag-Files-Required'-section of `profile` in `bag`."""
        # TODO
        return ValidationReport()

    @classmethod
    def validate_tag_files_allowed(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Tag-Files-Allowed'-section of `profile` in `bag`."""
        # TODO
        return ValidationReport()

    @classmethod
    def validate_payload_files_required(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Payload-Files-Required'-section of `profile` in `bag`."""
        # TODO
        return ValidationReport()

    @classmethod
    def validate_payload_files_allowed(
        cls, bag: Bag, profile: Mapping
    ) -> ValidationReport:
        """Validate 'Payload-Files-Allowed'-section of `profile` in `bag`."""
        # TODO
        return ValidationReport()

    @classmethod
    def custom_validation_hook(
        # pylint: disable=unused-argument
        cls,
        bag: Bag,
        profile: Mapping,
    ) -> ValidationReport:
        """Hook for custom validation steps."""
        return ValidationReport(True)
