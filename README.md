# BagItUtils

This repository contains a simple python interface for creating and interacting with files in the `BagIt`-format (v1.0).
It does not provide a complete implementation of the specification.
Please refer to the [examples-section](#basic-usage-examples) for a description of supported features.

## Basic usage examples

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

bag.generate_manifests()
bag.generate_tag_manifests()
```

Update bag-info after initialization
```python
bag = Bag(Path("path/to/bag"))

bag.generate_baginfo(
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
