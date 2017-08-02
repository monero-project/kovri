[<img width="300" src="https://static.getmonero.org/images/kovri/logo.png" alt="ˈKoʊvriː" />](https://github.com/monero-project/kovri)

1. [To cover, veil, wrap](https://en.wikipedia.org/wiki/Esperanto)
2. A secure, private, untraceable C++ implementation of the [I2P anonymous network](https://getmonero.org/knowledge-base/moneropedia/i2p)

## Disclaimer
- Currently **pre-alpha** software; under heavy development (and not yet integrated with monero)

## Downloads

### Releases

Alpha release coming soon

### [Nightly Releases (bleeding edge)](https://build.getmonero.org/waterfall)

| Operating System      | Processor | Status | Download | Checksum |
| --------------------- | --------- |--------| -------- | -------- |
| Ubuntu 16.04          |   i686    | [![Ubuntu i686](https://build.getmonero.org/png?builder=kovri-static-ubuntu-i686)](https://build.getmonero.org/builders/kovri-static-ubuntu-i686) | [kovri-latest-linux-i686.tar.bz2](https://build.getmonero.org/downloads/kovri-latest-linux-i686.tar.bz2) | [kovri-latest-linux-i686.tar.bz2.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-linux-i686.tar.bz2.sha256sum.txt)
| Ubuntu 16.04          |   amd64   | [![Ubuntu amd64](https://build.getmonero.org/png?builder=kovri-static-ubuntu-amd64)](https://build.getmonero.org/builders/kovri-static-ubuntu-amd64) | [kovri-latest-linux-amd64.tar.bz2](https://build.getmonero.org/downloads/kovri-latest-linux-amd64.tar.bz2) | [kovri-latest-linux-amd64.tar.bz2.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-linux-amd64.tar.bz2.sha256sum.txt)
| Ubuntu 16.04          |   armv7   | [![Ubuntu armv7](https://build.getmonero.org/png?builder=kovri-static-ubuntu-arm7)](https://build.getmonero.org/builders/kovri-static-ubuntu-arm7) | [kovri-latest-linux-armv7.tar.bz2](https://build.getmonero.org/downloads/kovri-latest-linux-armv7.tar.bz2) | [kovri-latest-linux-armv7.tar.bz2.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-linux-armv7.tar.bz2.sha256sum.txt)
| Debian Stable         |   armv8   | [![Debian armv8](https://build.getmonero.org/png?builder=kovri-static-debian-arm8)](https://build.getmonero.org/builders/kovri-static-debian-arm8) | [kovri-latest-linux-armv8.tar.bz2](https://build.getmonero.org/downloads/kovri-latest-linux-armv8.tar.bz2) | [kovri-latest-linux-armv8.tar.bz2.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-linux-armv8.tar.bz2.sha256sum.txt)
| OSX 10.10/11/12       |   amd64   | [![OSX amd64](https://build.getmonero.org/png?builder=kovri-static-osx)](https://build.getmonero.org/builders/kovri-static-osx) | [kovri-latest-osx-10.10.tar.bz2](https://build.getmonero.org/downloads/kovri-latest-osx-10.10.tar.bz2) | [kovri-latest-osx-10.10.tar.bz2.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-osx-10.10.tar.bz2.sha256sum.txt)
| FreeBSD 11            |   amd64   | [![FreeBSD amd64](https://build.getmonero.org/png?builder=kovri-static-freebsd64)](https://build.getmonero.org/builders/kovri-static-freebsd64) | [kovri-latest-freebsd-amd64.tar.bz2](https://build.getmonero.org/downloads/kovri-latest-freebsd-amd64.tar.bz2) | [kovri-latest-freebsd-amd64.tar.bz2.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-freebsd-amd64.tar.bz2.sha256sum.txt)
| OpenBSD 6            |   amd64   | [![OpenBSD amd64](https://build.getmonero.org/png?builder=kovri-static-openbsd-amd64)](https://build.getmonero.org/builders/kovri-static-openbsd-amd64) | [kovri-latest-openbsd-amd64.tar.bz2](https://build.getmonero.org/downloads/kovri-latest-openbsd-amd64.tar.bz2) | [kovri-latest-openbsd-amd64.tar.bz2.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-openbsd-amd64.tar.bz2.sha256sum.txt)
| DragonFly BSD 4.6     |   amd64   | [![DragonFly BSD amd64](https://build.getmonero.org/png?builder=kovri-static-dragonflybsd-amd64)](https://build.getmonero.org/builders/kovri-static-dragonflybsd-amd64) | [kovri-latest-dragonfly-4.6.tar.bz2](https://build.getmonero.org/downloads/kovri-latest-dragonfly-4.6.tar.bz2) | [kovri-latest-dragonfly-4.6.tar.bz2.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-dragonfly-4.6.tar.bz2.sha256sum.txt)
| Windows |   i686    | [![Windows i686](https://build.getmonero.org/png?builder=kovri-static-win32)](https://build.getmonero.org/builders/kovri-static-win32) | [kovri-latest-win32.exe](https://build.getmonero.org/downloads/kovri-latest-win32.exe) | [kovri-latest-win32.exe.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-win32.exe.sha256sum.txt)
| Windows |   amd64   | [![Windows amd64](https://build.getmonero.org/png?builder=kovri-static-win64)](https://build.getmonero.org/builders/kovri-static-win64) | [kovri-latest-win64.exe](https://build.getmonero.org/downloads/kovri-latest-win64.exe) | [kovri-latest-win64.exe.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-win64.exe.sha256sum.txt)

## Coverage

| Type      | Status |
|-----------|--------|
| Coverity  | [![Coverity Status](https://scan.coverity.com/projects/7621/badge.svg)](https://scan.coverity.com/projects/7621/)
| Coveralls | [![Coveralls Status](https://coveralls.io/repos/github/monero-project/kovri/badge.svg?branch=master)](https://coveralls.io/github/monero-project/kovri?branch=master)
| License   | [![License](https://img.shields.io/badge/license-BSD3-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

## Documentation
- Build instructions, User Guide, and more can be found in your language within the [kovri-docs](https://github.com/monero-project/kovri-docs/) repository
- [Moneropedia](https://getmonero.org/knowledge-base/moneropedia/kovri) is recommended for all users and developers

## Developers
- The Contributing Guide, Style guide, Vulnerability Response Process, and more can be found in your language within the [kovri-docs](https://github.com/monero-project/kovri-docs/) repository (please review before submitting a pull request)
- [Forum Funding System](https://forum.getmonero.org/8/funding-required) to get funded for your work, [submit a proposal](https://forum.getmonero.org/7/open-tasks/2379/forum-funding-system-ffs-sticky)
- [build.getmonero.org](https://build.getmonero.org/) or monero-build.i2p for detailed build information
- [repo.getmonero.org](https://repo.getmonero.org/monero-project/kovri) or monero-repo.i2p are alternatives to GitHub for non-push repository access

## Contact
- IRC: [Freenode](https://webchat.freenode.net/) | [OFTC](https://webchat.oftc.net/) | Irc2P with Kovri
  - ```#kovri``` | Community & Support Channel
  - ```#kovri-dev``` | Development Channel
- [Monero Slack](https://monero.slack.com/)
- [Monero StackExchange](https://monero.stackexchange.com/)
- [Monero Forum](https://forum.getmonero.org/)
- [Monero Meta Repository](https://github.com/monero-project/meta)
- [@monerocurrency](https://twitter.com/monerocurrency)
- Email:
  - General Purpose / Media Contact
    - dev [at] getmonero.org
  - All other contact
    - anonimal [at] i2pmail.org
    - PGP Key fingerprint: 1218 6272 CD48 E253 9E2D  D29B 66A7 6ECF 9144 09F1

## Vulnerability Response
- **We will pay hackers in XMR to exploit Kovri responsibly!** Please see our [Vulnerability Response Process](https://github.com/monero-project/kovri-docs/blob/master/developer/VULNERABILITY_RESPONSE_PROCESS.md) for responsible disclosure

## Donations
- Visit our [Donations Page](https://getmonero.org/getting-started/donate/) to help Kovri with your donations
