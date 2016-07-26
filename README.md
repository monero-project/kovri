# **ˈKɔːvrɪ**

1. To cover, veil, wrap *[(Esperanto)](https://en.wikipedia.org/wiki/Esperanto)*.
2. A secure, private, untraceable C++ implementation of the [I2P](https://geti2p.net) anonymous network.

[![Build Status](https://travis-ci.org/monero-project/kovri.svg?branch=master)](https://travis-ci.org/monero-project/kovri)
[![Coverity Status](https://scan.coverity.com/projects/7621/badge.svg)](https://scan.coverity.com/projects/7621/)
[![Documentation](https://codedocs.xyz/monero-project/kovri.svg)](https://codedocs.xyz/monero-project/kovri/)
[![License](https://img.shields.io/badge/license-BSD3-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

## Disclaimer
- Currently **pre-alpha** software; under heavy development

## Quickstart
1. Read [Build Instructions](https://github.com/monero-project/kovri/blob/master/doc/BUILDING.md) for instructions and minimum version requirements
2. Choose a port between ```9111``` and ```30777```
3. Open your NAT/Firewall to allow incoming TCP/UDP connections to your chosen port
   - UPnP optional; see [Build Instructions](https://github.com/monero-project/kovri/blob/master/doc/BUILDING.md)
4. Download, build, and run:
```bash
$ git clone --recursive https://github.com/monero-project/kovri
$ make dependencies && make && make install-resources # to decrease build-time, run make -j [available CPU cores]
$ ./build/kovri -p [your chosen port number] # port number without brackets
```
- For quick help options: ```$ ./kovri --help```
- For a detailed listing of options: ```$ ./kovri --help-with all```

## Documentation
- Our [FAQ](https://github.com/monero-project/kovri/blob/master/doc/FAQ.md) and other documentation are in our [doc](https://github.com/monero-project/kovri/tree/master/doc) directory

## Developers
- Read our [Contributing Guide](https://github.com/monero-project/kovri/blob/master/doc/CONTRIBUTING.md) before sending a pull-request
- Visit our [Forum Funding System](https://forum.getmonero.org/8/funding-required) to get funded for your work

## Contact
- Visit us on [Slack](https://monero.slack.com)
- IRC: [Freenode](https://webchat.freenode.net/) | [OFTC](https://webchat.oftc.net/) | Irc2P
  - ```#kovri``` | Community & Support Channel
  - ```#kovri-dev``` | Development Channel
- https://forum.getmonero.org/

## Vulnerability Response
- Submit a report via [HackerOne](https://hackerone.com/kovri)
- If you're having trouble using HackerOne, email us *(please, use PGP)*:
```
anonimal [anonimal @ mail.i2p] or [anonimal @ i2pmail.org]
Key fingerprint = 1218 6272 CD48 E253 9E2D  D29B 66A7 6ECF 9144 09F1
```
Note: our future VRP will be inline with [I2P's VRP](https://trac.i2p2.de/ticket/1119)

## Donations
- Visit our [Donations Page](https://getmonero.org/getting-started/donate/) to help Kovri with your donations
