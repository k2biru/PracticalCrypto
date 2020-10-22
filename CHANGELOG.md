# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0.1] - 2020-10-22
### Added
* Encryption char array
* Decryption char array
* Add `arrayToHexCharArray` and `hexCharArrayToArray`
* Add `calculateBuffer` to calculate size of buffer to be use for any given size

### Changed
* Change flow of `encrypt` and `decrypt` from full String to char array
* Using `arrayToHexCharArray` to `encrypt` instead `arrayToHexString`
* Using `hexCharArrayToArray` to `decrypt` instead `hexStringToArray`


### Removed
* none