# FAQ

## What is Kovri?
Kovri is a secure, private, untraceable C++ router implementation of the [I2P](https://geti2p.net) anonymous network. It was originally forked from i2pd but has undergone many distinct changes & improvements and will continue to do so throughout development.

## When is your first release?
Once essential QA has been resolved and I2CP is implemented, we will bring-forth a beta release.

## Kovri contact information?
- ```#kovri``` or ```#kovri-dev``` on Freenode or Irc2P
- Media inquieries, helpline, and website questions, email:

```
Riccardo Spagni [ric @ spagni.net]
Key fingerprint = BDA6 BD70 42B7 21C4 67A9  759D 7455 C5E3 C0CD CEB9
```
- Project development, security and vulnerability response:
```
anonimal [anonimal @ mail.i2p] or [anonimal @ i2pmail.org]
Key fingerprint = 1218 6272 CD48 E253 9E2D  D29B 66A7 6ECF 9144 09F1
```
- https://forum.getmonero.org/

## What are the biggest differences between Kovri and i2pd?
As we are currently in pre-alpha, we are working on following:

- We provide both end-users and developers a [quality assurance](https://github.com/monero-project/kovri/issues/58) and [development model](https://github.com/monero-project/kovri/blob/master/doc/CONTRIBUTING.md) in order to provide better software for everyone.
- We focus on implementing an [I2CP](https://geti2p.net/en/docs/spec/i2cp) server for any application to connect to and use the I2P network; this includes Monero.
- We focus on creating a ["secure by default"](http://www.openbsd.org/security.html), easily maintainable, more-likely-to-be-reviewed I2P router. This will come with the cost of dropping lesser-used features found in the other routers, but core functionality and I2CP will be fully intact. By creating a smaller, efficient, "bare-bones" router, we will provide developers and researchers more time for security auditing and more time to question the I2P design and specifications.
- We will provide a Forum Funding System for features/development and vulnerability disclosures.
- We will implement alternative reseeding options so users can use [Pluggable Transports](https://www.torproject.org/docs/pluggable-transports.html.en) instead of HTTPS for reseed.
- We will implement extended functionality *(hidden mode + disabled inbound)* to provide anonymity for those who live in countries with extreme conditions or those firewalled by carrier-grade NAT or DS-Lite.
- We will always create a welcome environment for collaboration.
- We will always listen to your feedback and do our best to improve Kovri!

## Why should I use Kovri instead of i2pd?
Ask yourself one question: do you trust your anonymity with i2pd's [attitude](https://github.com/PurpleI2P/i2pd/issues/279) and response to vulnerability disclosure?
```
2015-12-08 16:12:46     +anonimal       orignal: Can you please contact me via PM or verify that i2porignal@yandex.ru is a working address? This is urgent.
2015-12-08 16:17:15     +anonimal       Also, there is no PGP key for that address, AFAICT.
2015-12-09 11:40:48     +anonimal       orignal | [22:39:28] anonimal, I doubt we have any topics to discuss
2015-12-09 11:41:12     +anonimal       orignal: I've 0day'd i2pd. Quit being an idiot and respect my responsible disclosure. Don't put your users at risk.
```
Our answer? **...No, we don't!**

## Why did you fork from i2pd and why are there two i2pd repositories; one on Bitbucket and one on GitHub?
So begins the drama of i2pd.

One of the developers with push privileges on GitHub pushed a commit(s) that orignal did not like. Instead of working together to resolve the issue, orignal took i2pd to Bitbucket, deleted all existing git history, and made himself sole 'contributor' of the software. He then vowed to never return to Irc2P.

These actions pissed off a lot of people, and nearly killed the software.

Along came anonimal who, not wanting to see everyone's work to go to waste, revived the project through contributions and by reigning-in development. An open invitation for all remaining active developers to meet and discuss i2pd's future was given. This action apparently rustled orignal's feathers to the point where he [retaliated](https://github.com/PurpleI2P/i2pd/issues/279) and began to work on GitHub again - but this time within an ```openssl``` branch (which turned out to be the Bitbucket repository) instead of the ```master``` branch.

Seeing that this sort of behavior would only hurt the I2P network, the remaining developers had [several important meetings](https://github.com/monero-project/kovri/issues/47) and Kovri was born.

## I found a vulnerability and/or bug. What do I do?
See our [README.md](https://github.com/monero-project/kovri/blob/master/doc/README.md) for reporting vulnerabilities.
See our [CONTRIBUTING.md](https://github.com/monero-project/kovri/blob/master/doc/CONTRIBUTING.md) guide for bugs.
