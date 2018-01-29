[<img width="300" src="https://static.getmonero.org/images/kovri/logo.png" alt="ˈKoʊvriː" />](https://github.com/monero-project/kovri)

1. [To cover, veil, wrap](https://en.wikipedia.org/wiki/Esperanto)
2. A free, decentralized, anonymity technology based on [I2P](https://getmonero.org/resources/moneropedia/i2p.html)'s open specifications

## Disclaimer
- Currently **pre-alpha** software; under heavy development (and not yet integrated with monero)

## Quickstart

- Non-technical users should download the binaries/installer from the Downloads section below
- Do *not* use the zip file from github: do a recursive clone only

1. Install dependencies as described in the [documentation](https://github.com/monero-project/kovri-docs/tree/master/i18n)
2. `$ git clone --recursive https://github.com/monero-project/kovri && cd kovri/ && make && make install`
3. [Read the user-guide](https://github.com/monero-project/kovri-docs/tree/master/i18n) in your language of choice

## Downloads

### Releases

Alpha release coming soon

### [Nightly Releases (bleeding edge)](https://build.getmonero.org/waterfall)

| Operating System      | Processor | Status | Download | Checksum |
| --------------------- | --------- |--------| -------- | -------- |
| Linux |   amd64   | [![Linux amd64](https://build.getmonero.org/png?builder=kovri-static-ubuntu-amd64)](https://build.getmonero.org/builders/kovri-static-ubuntu-amd64) | [kovri-latest-linux-amd64.tar.bz2](https://build.getmonero.org/downloads/kovri-latest-linux-amd64.tar.bz2) | [kovri-latest-linux-amd64.tar.bz2.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-linux-amd64.tar.bz2.sha256sum.txt)
| Linux |   i686    | [![Linux i686](https://build.getmonero.org/png?builder=kovri-static-ubuntu-i686)](https://build.getmonero.org/builders/kovri-static-ubuntu-i686) | [kovri-latest-linux-i686.tar.bz2](https://build.getmonero.org/downloads/kovri-latest-linux-i686.tar.bz2) | [kovri-latest-linux-i686.tar.bz2.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-linux-i686.tar.bz2.sha256sum.txt)
| Linux |   armv8   | [![Linux armv8](https://build.getmonero.org/png?builder=kovri-static-debian-arm8)](https://build.getmonero.org/builders/kovri-static-debian-arm8) | [kovri-latest-linux-armv8.tar.bz2](https://build.getmonero.org/downloads/kovri-latest-linux-armv8.tar.bz2) | [kovri-latest-linux-armv8.tar.bz2.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-linux-armv8.tar.bz2.sha256sum.txt)
| Linux |   armv7   | [![Linux armv7](https://build.getmonero.org/png?builder=kovri-static-ubuntu-arm7)](https://build.getmonero.org/builders/kovri-static-ubuntu-arm7) | [kovri-latest-linux-armv7.tar.bz2](https://build.getmonero.org/downloads/kovri-latest-linux-armv7.tar.bz2) | [kovri-latest-linux-armv7.tar.bz2.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-linux-armv7.tar.bz2.sha256sum.txt)
| OS X  |   amd64   | [![OS X amd64](https://build.getmonero.org/png?builder=kovri-static-osx)](https://build.getmonero.org/builders/kovri-static-osx) | [kovri-latest-osx-10.10.tar.bz2](https://build.getmonero.org/downloads/kovri-latest-osx-10.10.tar.bz2) | [kovri-latest-osx-10.10.tar.bz2.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-osx-10.10.tar.bz2.sha256sum.txt)
| FreeBSD |   amd64   | [![FreeBSD amd64](https://build.getmonero.org/png?builder=kovri-static-freebsd64)](https://build.getmonero.org/builders/kovri-static-freebsd64) | [kovri-latest-freebsd-amd64.tar.bz2](https://build.getmonero.org/downloads/kovri-latest-freebsd-amd64.tar.bz2) | [kovri-latest-freebsd-amd64.tar.bz2.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-freebsd-amd64.tar.bz2.sha256sum.txt)
| OpenBSD |   amd64   | [![OpenBSD amd64](https://build.getmonero.org/png?builder=kovri-static-openbsd-amd64)](https://build.getmonero.org/builders/kovri-static-openbsd-amd64) | [kovri-latest-openbsd-amd64.tar.bz2](https://build.getmonero.org/downloads/kovri-latest-openbsd-amd64.tar.bz2) | [kovri-latest-openbsd-amd64.tar.bz2.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-openbsd-amd64.tar.bz2.sha256sum.txt)
| DragonFly BSD |   amd64   | [![DragonFly BSD amd64](https://build.getmonero.org/png?builder=kovri-static-dragonflybsd-amd64)](https://build.getmonero.org/builders/kovri-static-dragonflybsd-amd64) | [kovri-latest-dragonfly-4.6.tar.bz2](https://build.getmonero.org/downloads/kovri-latest-dragonfly-4.6.tar.bz2) | [kovri-latest-dragonfly-4.6.tar.bz2.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-dragonfly-4.6.tar.bz2.sha256sum.txt)
| Windows |   amd64   | [![Windows amd64](https://build.getmonero.org/png?builder=kovri-static-win64)](https://build.getmonero.org/builders/kovri-static-win64) | [kovri-latest-win64.exe](https://build.getmonero.org/downloads/kovri-latest-win64.exe) | [kovri-latest-win64.exe.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-win64.exe.sha256sum.txt)
| Windows |   i686    | [![Windows i686](https://build.getmonero.org/png?builder=kovri-static-win32)](https://build.getmonero.org/builders/kovri-static-win32) | [kovri-latest-win32.exe](https://build.getmonero.org/downloads/kovri-latest-win32.exe) | [kovri-latest-win32.exe.sha256sum.txt](https://build.getmonero.org/downloads/kovri-latest-win32.exe.sha256sum.txt)

## Coverage

| Type      | Status |
|-----------|--------|
| Coverity  | [![Coverity Status](https://scan.coverity.com/projects/7621/badge.svg)](https://scan.coverity.com/projects/7621/)
| Coveralls | [![Coveralls Status](https://coveralls.io/repos/github/monero-project/kovri/badge.svg?branch=master)](https://coveralls.io/github/monero-project/kovri?branch=master)
| License   | [![License](https://img.shields.io/badge/license-BSD3-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

## Documentation and Contributing
- Various guides like how to build, how to contribe, style, etc., can be found in your language within the [kovri-docs](https://github.com/monero-project/kovri-docs/) repository (please review before submitting a pull request)
- [Moneropedia](https://getmonero.org/knowledge-base/moneropedia/kovri) is recommended for all users and developers
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
- [Monero Slack](https://monero.slack.com/) (ask for an invite on IRC or email anonimal)
- [Monero StackExchange](https://monero.stackexchange.com/)
- [Reddit /r/Kovri](https://www.reddit.com/r/Kovri/)
- Twitter: [@getkovri](https://twitter.com/getkovri)
- Email:
  - General Purpose / Media Contact
    - dev [at] getmonero.org
  - All other contact
    - anonimal [at] i2pmail.org
    - PGP Key fingerprint: 1218 6272 CD48 E253 9E2D  D29B 66A7 6ECF 9144 09F1

## Donations
- Visit our [Donations Page](https://getmonero.org/getting-started/donate/) to help Kovri with your donations
