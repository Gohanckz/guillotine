
# Change Log
All notable changes to this project will be documented in this file.

## [2.2.2] - 2023-11-30
 
### Added
- Custom headers are now enabled in requests.
    > `python guillotine.py -t https://www.domain.com --headers "<header>:<value>|<header2>:<value2>|..."`
- Changelog File.

### Changed

- Included status code on the base information of the assessment.

### Fixed

## [2.2.1] - 2023-11-30
 
### Added
- Warning on some security headers.
    > `python guillotine.py -t https://www.domain.com --warnings`

### Changed

- Verbose mode now enables all of the optional information.

### Fixed

## [2.2] - 2023-11-22
 
### Added
- Basic Authentication support
    > `python guillotine.py -t https://www.domain.com --basic <username>:<password>`
- NTLM Authentication support
    > `python guillotine.py -t https://www.domain.com --ntlm [<domain>\\]<username>:<password>`

### Changed

- Header version comparison is now an option.
    > `python guillotine.py -t https://www.domain.com --compare-versions`

### Fixed

- The versions of the headers now are trunked to a 38 characters.
 
## [2.1] - 2023-11-22
 
### Added
 
- Header Version comparison with response.

### Changed
  
### Fixed
 
## [2.0] - 2023-03-19
 
### First Release