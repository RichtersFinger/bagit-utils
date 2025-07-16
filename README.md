 ![Tests](https://github.com/RichtersFinger/bagit-utils/actions/workflows/tests.yml/badge.svg?branch=main) ![PyPI - License](https://img.shields.io/pypi/l/bagit-utils) ![GitHub top language](https://img.shields.io/github/languages/top/RichtersFinger/bagit-utils) ![PyPI - Python Version](https://img.shields.io/pypi/pyversions/bagit-utils) ![PyPI version](https://badge.fury.io/py/bagit-utils.svg) ![PyPI - Wheel](https://img.shields.io/pypi/wheel/bagit-utils)

# BagItUtils

This repository contains a simple python interface for creating, interacting with, and validating files in the [BagIt-format (v1.0)](https://www.digitalpreservation.gov/documents/bagitspec.pdf).
It implements most but not all of the specification (see [planned additions](#planned-additions)).
The package consists of two major modules:
* `bagit`: basic support for the BagIt-spec including parsing (meta-)data and validating structure as well as checksums
* `validator`: an implementation of the [BagIt Profiles-project](https://bagit-profiles.github.io/bagit-profiles-specification)'s (1.4) specification for extended Bag validation; takes a modular approach for easy customization (see [details](#validator-customization))

Please refer to the [examples-section](#basic-usage-examples) for a brief overwiew of the features.

## Basic usage examples

### BagIt

Initialize an existing `Bag` with
```python
from pathlib import Path
from bagit_utils import Bag

bag = Bag(Path("path/to/bag"))
```

Access bag-metadata via properties
```python
print(bag.baginfo)
print(bag.manifests)
print(bag.tag_manifests)
```

Reload data after initialization
```python
bag = Bag(Path("path/to/bag"))

# .. some operation that changes bag-info.txt

bag.load_baginfo()
```

Update manifests (on disk) after changes to the bag-payload/tag-files occurred
```python
bag = Bag(Path("path/to/bag"))

# .. some operation that, e.g., adds/removes/changes files in data/ or meta/

bag.set_manifests()
bag.set_tag_manifests()
```

Update bag-info after initialization
```python
bag = Bag(Path("path/to/bag"))

bag.set_baginfo(
    bag.baginfo | {"AdditionalField": ["value0", "value1"]}
)
```

Create bag from source
```python
bag = Bag.build_from(
    Path("path/to/source"),  # should contain payload in data/-directory
    Path("path/to/bag"),  # should be empty
    baginfo={
        "Source-Organization": ["My Organization"].
        ...,
        "Payload-Oxum": [Bag.get_payload_oxum(Path("path/to/source"))],
        "Bagging-Date": [Bag.get_bagging_date()],
    },
    algorithms=["md5", "sha1"],
)
```

If a `Bag` is created with the `load`-flag or created via `Bag.build_from` with the `validate`-flag, the contents of the directory/created Bag are validated regarding the BagIt-specification (1.0) (Bag format or Bag format and file checksums, respectively).
This validation can also be triggered manually by entering
```python
report = bag.validate()
```
The report that is returned contains an overall flag for validity and a list of detected issues.
For more advanced validation, see also the following section on [Profile-Validation](#bagit-profile-validation).

### BagIt-profile validation
The `bagit_utils.validator`-module consists of two classes that can be used for advanced `Bag`-validation and is based on the [BagIt Profiles-project](https://bagit-profiles.github.io/bagit-profiles-specification) (1.4).
Their implementation takes a modular approach to simplify customization.

#### `BagItProfileValidator`: A customizable validator for BagIt-profiles themselves

In order to load and validate a JSON-profile, run for example
```python
from bagit_utils import BagItProfileValidator

profile = BagItProfileValidator.load_profile(profile_src="https://raw.githubusercontent.com/bagit-profiles/bagit-profiles/master/bagProfileFoo.json")
```
A `ValueError` will be raised if a problem is detected during validation of that profile.

#### `BagValidator`: A customizable validator for Bags based on BagIt-profiles

Using a BagIt-JSON-profile, the class `BagValidator` can be used to validate a `Bag`'s contents (structure and metadata) in great detail.
To run validation on a `Bag`-instance using the previously loaded profile, simply enter
```python
from bagit_utils import BagValidator

report = BagValidator.validate_once(bag, profile=profile)
```
Just like the basic validation of the `Bag`, the response is a `ValidationReport` detailing validity and issues.

The validator can also be initialized only once and then be reused by instead writing
```python
validator = BagValidator(profile=profile)
report1 = validator.validate(bag1)
report2 = validator.validate(bag2)
# ...
```

#### Validator customization
This section shows a simple example on how to extend the `BagItProfileValidator` and `BagValidator` classes.

Consider an extended BagIt-profile specification should be supported.
For simplicity, the following will use the simple example of a boolean profile-tag `My-Tag`, which is required in the profile and, if set to `true`, requires the Bag to include a tag-file `my-tag.txt`.

The updated `BagItProfileValidator` could then be defined as follows:
```python
class MyBagItProfileValidator(BagItProfileValidator):
    _ACCEPTED_PROPERTIES = BagItProfileValidator._ACCEPTED_PROPERTIES + ["My-Tag"]
    @classmethod
    def custom_validation_hook(cls, profile):
        if "My-Tag" not in profile:
            raise ValueError(cls._ERROR_PREFIX + "Missing required tag 'My-Tag'.")
        cls._handle_type_validation(bool, "My-Tag", profile["My-Tag"])
```
Similarly, the `BagValidator` also has a hook that can be used to implement the Bag-validation itself:
```python
from bagit_utils.common import Issue, ValidationReport
class MyBagValidator(BagValidator):
    _PROFILE_VALIDATOR = MyBagItProfileValidator
    @classmethod
    def custom_validation_hook(cls, bag, profile):
        result = ValidationReport(True)
        if profile["My-Tag"] and not (bag.path / "my-tag.txt").is_file():
            result.valid = False
            result.issues.append(
                Issue("error", "Bag must contain tag-file 'my-tag.txt'.", "My-Tag")
            )
        return result
```
With these definitions, a validation using the changed specification can be run via
```python
report = MyBagValidator.validate_once(bag, profile={"My-Tag": True})
```

The hooks available for these kinds of extensions are
* `BagItProfileValidator._validate_baginfo_custom_item_hook`
* `BagItProfileValidator.custom_validation_hook`
* `BagValidator._validate_baginfo_custom_tags_hook`
* `BagValidator.custom_validation_hook`
Please refer to the source code for even more details on/documentation of arguments and expected behavior/return values.

#### Extensions of/Deviations from specification

In some minor aspects, these validators deviate from the BagIt-profiles specification:
* items in the `"Bag-Info"`-section of the profile support the additional field `"regex"` which enables optional regex-matching (using the fullmatch-strategy)
* the `"BagIt-Profile-Info"`-section is not validated
* the tag `"BagIt-Profile-Identifier"`-tag in `bag-info.txt` is not validated
* the `"Accept-BagIt-Version"`-section can be omitted which is then interpreted as it having the value `["1.0"]`

## Planned additions
* support for `fetch.txt` (currently validation only)
* support for Bag-serialization

## Tests
The project has a high test-coverage.
To run the tests locally, first install the dependencies
```
pip install .
pip install -r dev-requirements.txt
```
and afterwards run `pytest` with
```
pytest -v -s tests
```
