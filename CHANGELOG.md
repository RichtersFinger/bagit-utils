# Changelog

## [1.2.3] - 2025-11-10

### Fixed

- fixed bad formatting when writing `bag-info.txt` with emty tag

  skip tag instead of writing an empty line

## [1.2.2] - 2025-11-01

### Fixed

- improved pattern matching during profile validation in `BagItProfileValidator` of 'Tag-Files-Allowed'/'Tag-Files-Required' and 'Payload-Files-Allowed'/'Payload-Files-Required'
- fixed `BagValidator` not respecting directories in 'Payload-Files-Required'

## [1.2.0] - 2025-10-18

### Added

- added hooks for custom `Bag`-loading and -validation

### Fixed

- fixed additional newline in manifest files if payload-directory is empty
- fixed references to BagIt-spec referring to a draft of the spec

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
