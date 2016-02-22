# **ˈKɔːvrɪ**

1. To cover, veil, wrap *[(Esperanto)](https://en.wikipedia.org/wiki/Esperanto)*
2. The secure, private, untraceable C++ implementation of the [I2P](https://geti2p.net) anonymous network,

[![Build Status](https://travis-ci.org/monero-project/kovri.svg?branch=master)](https://travis-ci.org/monero-project/kovri)
[![Documentation](https://codedocs.xyz/monero-project/kovri.svg)](https://codedocs.xyz/monero-project/kovri/)

## Disclaimer
- Currently pre-alpha software; under heavy development!
- Use branch ```master``` for more stability.
- See branch ```development``` for most recent activity.

## Quickstart
1. Read [BUILDING.md](https://github.com/monero-project/kovri/blob/master/doc/BUILDING.md) and build instructions and minimum version requirements
1. Choose a port between ```9111``` and ```30777```.
2. Open your chosen port in your NAT/Firewall to allow incoming TCP/UDP connections (or optional UPnP, see [BUILDING.md](https://github.com/monero-project/kovri/blob/master/doc/BUILDING.md))
3. Clone, build, and run Kovri:
```bash
$ git clone https://github.com/monero-project/kovri
$ cd kovri/build && cmake ../ && make
$ ./kovri -p [your chosen port number]
```

## Developers
- See [CONTRIBUTING.md](https://github.com/monero-project/kovri/blob/master/doc/CONTRIBUTING.md) before sending PR.

## Documentation
- See [FAQ.md](https://github.com/monero-project/kovri/blob/master/doc/FAQ.md) or join us in ```#kovri``` or ```#kovri-dev``` on Irc2P or Freenode.
- All other documentation is on our ./doc directory

## Vulnerability Response
- Please, submit a report via [HackerOne](https://hackerone.com/kovri)
- If you're having trouble using HackerOne, email us *(please, use PGP)*:
```
anonimal@mail.i2p (or @i2pmail.org if you're not on the I2P network)
PGP fingerprint: 1218 6272 CD48 E253 9E2D D29B 66A7 6ECF 9144 09F1
```
Note: our future VRP will be inline with [I2P's VRP](https://trac.i2p2.de/ticket/1119).

## Acknowledgments
- **orion** and **EinMByte** for providing ```i2pcpp```: the [original](http://git.repo.i2p.xyz/w/i2pcpp.git) C++ implementation of I2P.
- **orignal** for providing ```i2pd```: an insecure and issue-ridden (but mostly-working) C++ implementation of I2P for [us to fork from](https://github.com/purplei2p/i2pd/commit/45d27f8ddc43e220a9eea42de41cb67d5627a7d3).
- **EinMByte** for improving *both* implementations.
- The ed25519/ folder is based on the [ref10 implementation from SUPERCOP](http://bench.cr.yp.to/supercop.html).
