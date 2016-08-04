# Frequently Asked Questions (and answers)

## What is Kovri?
Kovri is a secure, private, untraceable C++ router implementation of the [I2P](https://geti2p.net) anonymous network. What was once a fork of i2pd, Kovri has become a unique, actively-developed, community-driven C++ I2P implementation with many improvements, security enhancements, and new features over its predecessor.

## What is the current state of Kovri?
Kovri is in pre-alpha but in active development. Several core features and functionality have yet to be implemented. Currently, you can use the router to connect to (and partake in) the I2P network: browse eepsites, connect to IRC, and run client and server tunnels.

## When is your first release?
Once essential quality-assurance has been resolved and an API has been implemented, we will bring-forth a beta release.

## What is the development team currently focusing on?
Currently, we are focusing on everything listed in our [issues tracker](https://github.com/monero-project/kovri/issues/). They cover a bulk of what we need to finish before an official release (alpha, beta, or greater).

## Is Kovri usable, partially usable, or recommended to not be used for actual privacy at the moment?
Kovri is usable to the extent of what ```./kovri --help-with all``` has to offer. Kovri currently has no interaction with Monero. With regard to privacy, we have fixed many security issues since inception but we are still in pre-alpha.

There is still much code to cover so don't expect a strong guarantee of anonymity like with Tor or even java I2P. Those projects have 10+ years of research and implementation experience - and we are just getting started.

Feel free to play the role of developer and experiment/play with Kovri but only if **not** being anonymous doesn't put you in danger - as there is always the risk of possible de-anonymization due to being in pre-alpha (this is not unique to Kovri).

## Kovri contact information?
See our [README](https://github.com/monero-project/kovri/blob/master/README.md).

## Why should I use Kovri instead of i2pd?

- Security: our focus is on securing our software; not [rushing to get things done](https://github.com/monero-project/kovri/issues/65) for the sake of having a release
- Quality: you're supporting efforts to ensure a quality codebase that will stand the test of time. This includes all aspects of code maintainability
- Monero: you will be supporting a crypto-currency that prides itself on privacy-preservation and anonymity while increasing both your privacy and anonymity

## What are the biggest differences between Kovri and i2pd?

- We provide a [Forum Funding System](https://forum.getmonero.org/8/funding-required) for features/development.
- We focus on creating a ["secure by default"](http://www.openbsd.org/security.html), easily maintainable, more-likely-to-be-reviewed I2P router. This will come with the cost of dropping lesser-used features found in the other routers, but core functionality and an API will be fully intact. By creating a smaller, efficient, "bare-bones" router, we will provide developers and researchers more time for security auditing and more time to question the I2P design and specifications.
- We focus on implementing an intuitive, developer-friendly API for any application to connect to and use the I2P network; this includes Monero.
- We provide both end-users and developers a [quality assurance](https://github.com/monero-project/kovri/issues/58) and [development model](https://github.com/monero-project/kovri/blob/master/doc/CONTRIBUTING.md) in order to provide better software for everyone.
- We will implement alternative reseeding options so users can use [Pluggable Transports](https://www.torproject.org/docs/pluggable-transports.html.en) instead of HTTPS for reseed.
- We will implement extended functionality *(hidden mode + disabled inbound)* to provide anonymity for those who live in countries with extreme conditions or those firewalled by carrier-grade NAT or DS-Lite.
- We will always create a welcome environment for collaboration.
- We will always listen to your feedback and do our best to improve Kovri!

## Why did you fork from i2pd?

We forked for at least several reasons:

- We wanted a robust, secure, and viable C++ implementation of the I2P network; and i2pd was not delivering
- We wanted a positive community that encouraged collaboration for the betterment of the software; not negative, narcissist glory
- We wanted a lead developer who could lead; not someone who could ignore requests for responsible disclosure or tuck-tail-and-run when faced with collaborator conflict

## What were the turning points that lead to forking from i2pd (and why are there two i2pd repositories: one on Bitbucket and one on GitHub)?

*So began the drama of i2pd*.

In early/mid 2015, one of the developers with push privileges on GitHub pushed a commit(s) that i2pd's first author did not like. Instead of working together to resolve the issue, said author took i2pd to Bitbucket, deleted **all** existing git history, and made himself sole 'contributor' of the software. He then vowed to never return to Irc2P.

These actions offended many in the I2P community, including the developers, and nearly ended the C++ project.

In the fall of 2015, along came anonimal who, not wanting to see everyone's work to go to waste, revived the project through contributions of their own and by reigning-in development. An open invitation for all remaining active developers to meet and discuss i2pd's future was then given. i2pd's first author never showed but the act of meeting apparently rustled i2pd's feathers to the point where he [retaliated](https://github.com/PurpleI2P/i2pd/issues/279) and began to work on GitHub again - but this time within an ```openssl``` branch (which turned out to be the Bitbucket repository) instead of the community-driven ```master``` branch.

Seeing that this sort of erratic behavior would only hurt the I2P network and the project as a whole, the remaining developers continued to have [several important meetings](https://github.com/monero-project/kovri/issues/47) and set the foundation for what is now Kovri.

## I found a vulnerability! I found a bug! What do I do?
- Vulnerabilities: see our [README](https://github.com/monero-project/kovri/blob/master/README.md)
- Bugs: see our [Contributing Guide](https://github.com/monero-project/kovri/blob/master/doc/CONTRIBUTING.md)
