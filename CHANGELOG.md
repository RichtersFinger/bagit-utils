# Changelog

## [1.0.0] - 2025-07-??

### Changed

- **Breaking:** refactored and extended some methods of `Bag`-class
  - `set_baginfo` (formerly `generate_baginfo`): now accepts the flag `write_to_disk`
  - `set_manifests` (formerly `generate_manifests`): now accepts the flag `write_to_disk`
  - `set_tag_manifests` (formerly `generate_tag_manifests`): now accepts the flag `write_to_disk`
- **Breaking:** refactored Bag-validation response-format to match profile-validation

### Added

- added BagIt profile- and Bag-validation functionality

## [0.1.0] - 2025-06-09

### Changed

- initial release
