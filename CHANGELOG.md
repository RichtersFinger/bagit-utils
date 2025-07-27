# Changelog

## [1.1.1] - 2025-07-27

### Fixed

- fixed `Bag.tag_manifests`-property loading wrong data on initial call

## [1.1.0] - 2025-07-17

### Changed

- relaxed Bag-declaration validation error to warning
- when building Bags with symlinks, link files instead of payload-directory

### Added

- added initial cli based on `befehl`

### Fixed

- fixed Bag-creation not considering all tag-files while building manifests

## [1.0.0] - 2025-07-05

### Changed

- **Breaking:** refactored and extended some methods of `Bag`-class
  - `set_baginfo` (formerly `generate_baginfo`): now accepts the flag `write_to_disk`
  - `set_manifests` (formerly `generate_manifests`): now accepts the flag `write_to_disk`
  - `set_tag_manifests` (formerly `generate_tag_manifests`): now accepts the flag `write_to_disk`
- **Breaking:** refactored Bag-validation response-format to match profile-validation

### Added

- added automated tests
- added BagIt profile- and Bag-validation functionality

## [0.1.0] - 2025-06-09

### Changed

- initial release
