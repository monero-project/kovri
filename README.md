[<img width="300" src="https://static.getmonero.org/images/kovri/logo.png" alt="ˈKoʊvriː" />](https://github.com/monero-project/kovri)

1. [To cover, veil, wrap](https://en.wikipedia.org/wiki/Esperanto)
2. A free, decentralized, anonymity technology based on [I2P](https://getmonero.org/resources/moneropedia/i2p.html)'s open specifications

## Disclaimer
- Currently **Alpha** software; under heavy development (and not yet integrated with monero)

## Quickstart

- Want pre-built binaries? [Download below](#downloads)
- Want to build and install yourself? [Build instructions below](#building)

## Multilingual README
This page is also available in the following languages

- [Italiano](https://github.com/monero-project/kovri-docs/blob/master/i18n/it/README.md)
- Español
- Pусский
- [Français](https://github.com/monero-project/kovri-docs/blob/master/i18n/fr/README.md)
- [Deutsch](https://github.com/monero-project/kovri-docs/blob/master/i18n/de/README.md)
- Dansk

## Downloads

### Releases

### [Nightly Releases (bleeding edge)](https://build.getmonero.org/waterfall)

| Installer | Checksum | Status |
| --------- | -------- | ------ |
| [Linux (x86-64)](https://build.getmonero.org/downloads/kovri-latest-linux-amd64.tar.bz2) | [Linux (x86-64)](https://build.getmonero.org/downloads/kovri-latest-linux-amd64.tar.bz2.sha256sum.txt) | [![Linux (x86-64)](https://build.getmonero.org/png?builder=kovri-static-ubuntu-amd64)](https://build.getmonero.org/builders/kovri-static-ubuntu-amd64) |
| [Linux (i686)](https://build.getmonero.org/downloads/kovri-latest-linux-i686.tar.bz2) | [Linux (i686)](https://build.getmonero.org/downloads/kovri-latest-linux-i686.tar.bz2.sha256sum.txt) | [![Linux (i686)](https://build.getmonero.org/png?builder=kovri-static-ubuntu-i686)](https://build.getmonero.org/builders/kovri-static-ubuntu-i686) |
| [Linux (ARMv8)](https://build.getmonero.org/downloads/kovri-latest-linux-armv8.tar.bz2) | [Linux (ARMv8)](https://build.getmonero.org/downloads/kovri-latest-linux-armv8.tar.bz2.sha256sum.txt) | [![Linux (ARMv8)](https://build.getmonero.org/png?builder=kovri-static-debian-arm8)](https://build.getmonero.org/builders/kovri-static-debian-arm8) |
| [Linux (ARMv7)](https://build.getmonero.org/downloads/kovri-latest-linux-armv7.tar.bz2) | [Linux (ARMv8)](https://build.getmonero.org/downloads/kovri-latest-linux-armv7.tar.bz2.sha256sum.txt) | [![Linux (ARMv8)](https://build.getmonero.org/png?builder=kovri-static-ubuntu-arm7)](https://build.getmonero.org/builders/kovri-static-ubuntu-) |
| [macOS (x86-64)](https://build.getmonero.org/downloads/kovri-latest-osx-10.13.tar.bz2) | [macOS (x86-64)](https://build.getmonero.org/downloads/kovri-latest-osx-10.13.tar.bz2.sha256sum.txt) | [![macOS (x86-64)](https://build.getmonero.org/png?builder=kovri-static-osx)](https://build.getmonero.org/builders/kovri-static-osx) |
| [FreeBSD (x86-64)](https://build.getmonero.org/downloads/kovri-latest-freebsd-amd64.tar.bz2) | [FreeBSD (x86-64)](https://build.getmonero.org/downloads/kovri-latest-freebsd-amd64.tar.bz2.sha256sum.txt) | [![FreeBSD (x86-64)](https://build.getmonero.org/png?builder=kovri-static-freebsd64)](https://build.getmonero.org/builders/kovri-static-freebsd64) |
| [OpenBSD (x86-64)](https://build.getmonero.org/downloads/kovri-latest-openbsd-amd64.tar.bz2) | [OpenBSD (x86-64)](https://build.getmonero.org/downloads/kovri-latest-openbsd-amd64.tar.bz2.sha256sum.txt) | [![OpenBSD (x86-64)](https://build.getmonero.org/png?builder=kovri-static-openbsd-amd64)](https://build.getmonero.org/builders/kovri-static-openbsd-amd64) |
| [DragonFly BSD (x86-64)](https://build.getmonero.org/downloads/kovri-latest-dragonflybsd-4.6.tar.bz2) | [DragonFly BSD (x86-64)](https://build.getmonero.org/downloads/kovri-latest-dragonflybsd-4.6.tar.bz2.sha256sum.txt) | [![DragonFly BSD (x86-64)](https://build.getmonero.org/png?builder=kovri-static-dragonflybsd-amd64)](https://build.getmonero.org/builders/kovri-static-dragonflybsd-amd64) |
| [Windows (x86-64)](https://build.getmonero.org/downloads/kovri-latest-win64.exe) | [Windows (x86-64)](https://build.getmonero.org/downloads/kovri-latest-win64.exe.sha256sum.txt) | [![Windows (x86-64)](https://build.getmonero.org/png?builder=kovri-static-win64)](https://build.getmonero.org/builders/kovri-static-win64) |
| [Windows (i686)](https://build.getmonero.org/downloads/kovri-latest-win32.exe) | [Windows (i686)](https://build.getmonero.org/downloads/kovri-latest-win32.exe.sha256sum.txt) | [![Windows (i686)](https://build.getmonero.org/png?builder=kovri-static-win32)](https://build.getmonero.org/builders/kovri-static-win32) |

## Coverage

| Type      | Status |
|-----------|--------|
| Coverity  | [![Coverity Status](https://scan.coverity.com/projects/7621/badge.svg)](https://scan.coverity.com/projects/7621/)
| Coveralls | [![Coveralls Status](https://coveralls.io/repos/github/monero-project/kovri/badge.svg?branch=master)](https://coveralls.io/github/monero-project/kovri?branch=master)
| License   | [![License](https://img.shields.io/badge/license-BSD3-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

## Building

### Dependencies and environment

| Dependency          | Minimum version              | Optional | Arch Linux  | Ubuntu/Debian    | macOS (Homebrew) | FreeBSD       | OpenBSD     | Fedora	  |
| ------------------- | ---------------------------- |:--------:| ----------- | ---------------- | ---------------- | ------------- | ----------- | -----------   |
| git                 | 1.9.1                        |          | git         | git              | git              | git           | git         | git		  |
| gcc                 | 4.9.2                        |          | gcc         | gcc              |                  |               |             | gcc		  |
| clang               | 3.5 (3.6 on FreeBSD)         |          | clang       | clang            | clang (Apple)    | clang36       | llvm        | clang	  |
| CMake               | 3.5.1                        |          | cmake       | cmake            | cmake            | cmake         | cmake       | cmake	  |
| gmake (BSD)         | 4.2.1                        |          |             |                  |                  | gmake         | gmake       | 		  |
| Boost               | 1.58                         |          | boost       | libboost-all-dev | boost            | boost-libs    | boost       | boost-devel   |
| OpenSSL             | Always latest stable version |          | openssl     | libssl-dev       | openssl          | openssl       | openssl     | openssl-devel |
| Doxygen             | 1.8.6                        |    X     | doxygen     | doxygen          | doxygen          | doxygen       | doxygen     | doxygem	  |
| Graphviz            | 2.36                         |    X     | graphviz    | graphviz         | graphviz         | graphviz      | graphviz    | graphviz	  |
| Docker              | Always latest stable version |    X     | See website | See website      | See website      | See website   | See website | See website	  |

#### Windows (MSYS2/MinGW-64)
* Download the [MSYS2 installer](http://msys2.github.io/), 64-bit or 32-bit as needed
* Use the shortcut associated with your architecture to launch the MSYS2 environment. On 64-bit systems that would be the `MinGW-w64 Win64 Shell` shortcut. Note: if you are running 64-bit Windows, you'll have both 64-bit and 32-bit environments
* Update the packages in your MSYS2 install:

```shell
$ pacman -Sy
$ pacman -Su --ignoregroup base
$ pacman -Syu
```

#### Install packages

Note: For i686 builds, replace `mingw-w64-x86_64` with `mingw-w64-i686`

`$ pacman -S make mingw-w64-x86_64-cmake mingw-w64-x86_64-gcc mingw-w64-x86_64-boost mingw-w64-x86_64-openssl`

Optional:

`$ pacman -S mingw-w64-x86_64-doxygen mingw-w64-x86_64-graphviz`

### Make and install

**Do *not* use the zip file from github: do a recursive clone only**

```bash
$ git clone --recursive https://github.com/monero-project/kovri
$ cd kovri && make release  # see the Makefile for all build options
$ make install
```

- End-users MUST run `make install` for new installations
- Developers SHOULD run `make install` after a fresh build

### Docker

Or build locally with Docker

```bash
$ docker build -t kovri:latest .
```

## Documentation and Development
- A [User Guide](https://github.com/monero-project/kovri-docs/blob/master/i18n/en/user_guide.md) is available for all users
- A [Developer Guide](https://github.com/monero-project/kovri-docs/blob/master/i18n/en/developer_guide.md) is available for developers (please read before opening a pull request)
- More documentation can be found in your language of choice within the [kovri-docs](https://github.com/monero-project/kovri-docs/) repository
- [Moneropedia](https://getmonero.org/resources/moneropedia/kovri.html) is recommended for all users and developers
- [Forum Funding System](https://forum.getmonero.org/8/funding-required) to get funded for your work, [submit a proposal](https://forum.getmonero.org/7/open-tasks/2379/forum-funding-system-ffs-sticky)
- [build.getmonero.org](https://build.getmonero.org/) or monero-build.i2p for detailed build information
- [repo.getmonero.org](https://repo.getmonero.org/monero-project/kovri) or monero-repo.i2p are alternatives to GitHub for non-push repository access
- See also [kovri-site](https://github.com/monero-project/kovri-site) and [monero/kovri meta](https://github.com/monero-project/meta)

## Vulnerability Response
- Our [Vulnerability Response Process](https://github.com/monero-project/meta/blob/master/VULNERABILITY_RESPONSE_PROCESS.md) encourages responsible disclosure
- We are also available via [HackerOne](https://hackerone.com/monero)

## Contact and Support
- IRC: [Freenode](https://webchat.freenode.net/) | Irc2P with Kovri
  - `#kovri` | Community & Support Channel
  - `#kovri-dev` | Development Channel
- [Monero Mattermost](https://mattermost.getmonero.org/)
- [Monero Slack](https://monero.slack.com/) (ask for an invite on IRC)
- [Monero StackExchange](https://monero.stackexchange.com/)
- [Reddit /r/Kovri](https://www.reddit.com/r/Kovri/)
- Twitter: [@getkovri](https://twitter.com/getkovri)
- Email:
  - General Purpose / Media Contact
    - dev [at] getmonero.org
  - All other contact
    - anonimal [at] getmonero.org
    - PGP Key fingerprint: 1218 6272 CD48 E253 9E2D  D29B 66A7 6ECF 9144 09F1

## Donations
- Visit our [Donations Page](https://getmonero.org/getting-started/donate/) to help Kovri with your donations
