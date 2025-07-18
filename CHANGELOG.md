# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
and is generated by [Changie](https://github.com/miniscruff/changie).


## v0.3.2 - 2025-07-07
### Added
* Included Cell type for subharvester location id

## v0.3.1 - 2025-06-28
### Fixed
* Issue when parsing Core Location subharvester events
* Issue when piping output to stdout

## v0.3.0 - 2025-06-21
### Added
* Support for parsing DNS info objects
* Support for parsing Network Interface (NWI) objects
### Changed
* Better logging when encountering log messages that do not follow printf formatting. Ex: printf(%u, "message") instead of printf(%u, 10)
### Fixed
* Better handling when dealing with logs that are private but have precision values
* Added additional DNS record type (NULL)

## v0.2.0 - 2025-03-30
### Added
* Support for parsing StateDump Protobuf data
### Changed
* Updated dependencies and migrated to Rust 2024 edition
* Made log_type and event_type enums
* Improved handling of log number data marked as private
* Moved to HashMap instead of Vec for UUIDText and dsc parsing
* Only keep a small cache of UUID strings instead of all strings. Should reduce memory usage quite a bit
