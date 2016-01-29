# **ˈKɔːvrɪ**

1. To cover, veil, wrap *[(Esperanto)](https://en.wikipedia.org/wiki/Esperanto)*
2. The secure, private, untraceable C++ [I2P router](https://geti2p.net), forked from [i2pd](https://github.com/PurpleI2P/i2pd/tree/master).

[![Build Status](https://travis-ci.org/monero-project/kovri.svg?branch=master)](https://travis-ci.org/monero-project/kovri)
[![Documentation](https://codedocs.xyz/monero-project/kovri.svg)](https://codedocs.xyz/monero-project/kovri/)

## Disclaimer
- Currently pre-alpha software; under heavy overhaul and development! Stick to branch ```master``` for stability.
- See branch ```development``` for the meat of Kovri evolution.

## Quickstart
1. Download/install the **latest** [CMake](https://cmake.org/), [Boost](http://www.boost.org/), [Crypto++](https://cryptopp.com/#download), and [OpenSSL](https://www.openssl.org/source/). If you use a package manager, check against [BUILDING.md](https://github.com/monero-project/kovri/blob/master/BUILDING.md) for minimum version requirements.
1. Choose a port between ```9111``` and ```30777```. For this example,  we'll use port ```12345```. **Please, do not use this number outside of this example as it will effect your anonymity**.
2. Open port ```12345``` in your NAT/Firewall to allow incoming TCP/UDP connections.
3. Clone, build, and run Kovri with one line:
```bash
$ git clone https://github.com/monero-project/kovri && cd kovri/build && cmake ../ && make && ./kovri --port 12345
```

## Build. Contribute. Ask questions!
- See [BUILDING.md](https://github.com/monero-project/kovri/blob/master/BUILDING.md) for more options and instructions for your favourite OS.
- See [CONTRIBUTING.md](https://github.com/monero-project/kovri/blob/master/CONTRIBUTING.md) and send us a PR. All developers welcome!
- See [FAQ.md](https://github.com/monero-project/kovri/blob/master/FAQ.md) or join us in ```#kovri``` or ```#kovri-dev``` on Irc2P or Freenode.

## Vulnerability Response
- Please, submit a report via [HackerOne](https://hackerone.com/kovri)
- If you're having trouble using HackerOne, email us *(please, use PGP)*:
```
anonimal@mail.i2p (or @i2pmail.org if you're not on the I2P network)
PGP fingerprint: 1218 6272 CD48 E253 9E2D D29B 66A7 6ECF 9144 09F1
```
Note: our future VRP will be inline with [I2P's VRP](https://trac.i2p2.de/ticket/1119).

## Acknowledgments
- **orion** and **EinMByte** for providing the [first](http://git.repo.i2p.xyz/w/i2pcpp.git) C++ implementation of I2P.
- **orignal** and **EinMByte** for providing a [mostly-working](https://github.com/PurpleI2P/i2pd/issues) C++ implementation of I2P.
- The ed25519/ folder is based on the [ref10 implementation from SUPERCOP](http://bench.cr.yp.to/supercop.html).
