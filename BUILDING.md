# 1. Satisfy requirements

## Linux/FreeBSD/OSX
- GCC 4.6 or newer (Clang is optional)
- Boost 1.46 or newer
- Crypto++
- OpenSSL

## Windows
- VS2013 (known to work with 12.0.21005.1 or newer)
- Boost 1.46 or newer
- Crypto++ 5.62
- OpenSSL

## Open your NAT/Firewall
1. Choose a port between 9111 and 30777.
2. Poke a hole in your NAT/Firewall to allow incoming TCP/UDP connections on that port.
3. Don't share this number with anyone as it will effect your anonymity.

If you do not choose a port via cli or kovri.conf, Kovri will randomly generate a new one on each startup. If you do not have access to your NAT, you can instead install and build with [MiniUPnP](http://miniupnp.free.fr/files/) support

# 2. Install dependencies

## Debian/Ubuntu
```
$ sudo apt-get install g++ cmake libboost-all-dev libcrypto++-dev libssl-dev libssl1.0.0
```

## Arch
```
$ sudo pacman -Syu cmake boost crypto++ openssl
```

## FreeBSD
Branch 9.X has gcc v4.2, that knows nothing about required c++11 standard.

Required ports:

- devel/cmake
- devel/boost-libs
- lang/gcc47 # or later version
- security/cryptopp
- security/openssl

To use newer compiler you should set these variables:

  export CC=/usr/local/bin/gcc47
  export CXX=/usr/local/bin/g++47

Replace "47" with your actual gcc version

# 3. Building

## To view CMake options:
```bash
$ cd kovri/build
$ cmake -L ../
```

## For a regular build:
```
$ cd kovri/build
$ cmake ../
$ make
```

## For UPnP support *(see requirements above)*:
```
$ cd kovri/build
$ cmake -DWITH_UPNP=ON ../
$ make
```

## To build tests:
```
$ cd kovri/build
$ cmake -DWITH_TESTS=ON -DWITH_BENCHMARKS=ON ../
$ make
```

## Run Kovri!

```$ ./kovri --port (your chosen port)```

or set your port in kovri.conf


For a full list of options:

```$ ./kovri --help```


# 4. Configuration files *(optional)*

Configuration files has INI-like syntax: <key> = <value>.
All command-line parameters are allowed as keys, for example:

kovri.conf:

    log = 1
    v6 = 0
    ircdest = irc.dg.i2p

tunnels.cfg:

    ; outgoing tunnel sample, to remote service
    ; mandatory parameters:
    ; * type -- always "client"
    ; * port -- local port to listen to
    ; * destination -- i2p hostname
    ; optional parameters (may be omitted)
    ; * keys -- our identity, if unset, will be generated on every startup,
    ;     if set and file missing, keys will be generated and placed to this file
    ; * address -- address to listen on, 127.0.0.1 by default
    [IRC]
    type = client
    port = 6669
    destination = irc.dg.i2p
    keys = irc-keys.dat

    ; incoming tunnel sample, for local service
    ; mandatory parameters:
    ; * type -- always "server"
    ; * host -- ip address of our service
    ; * port -- port of our service
    ; * keys -- file with LeaseSet of address in i2p
    ; optional parameters (may be omitted)
    ; * inport -- optional, i2p service port, if unset - the same as 'port'
    ; * accesslist -- comma-separated list of i2p addresses, allowed to connect
    ;    every address is b32 without '.b32.i2p' part
    [LOCALSITE]
    type = server
    host = 127.0.0.1
    port = 80
    keys = site-keys.dat
    inport = 81
    accesslist = <b32>[,<b32>]
