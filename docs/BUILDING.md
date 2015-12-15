# Step 1. Satisfy requirements

## Linux/FreeBSD/OSX

* GCC 4.6 or newer (Clang can be used instead of GCC)
* Boost 1.46 or newer
* crypto++
* openssl

## Windows

* VS2013 (known to work with 12.0.21005.1 or newer)
* Boost 1.46 or newer
* crypto++ 5.62
* openssl

## Open you NAT/Firewall

Pick a port and allow inbound TCP/UDP.
Do not tell anyone your port number as it can effect your anonymity!

# Step 2. Install dependencies

## Debian/Ubuntu

```
$ sudo apt-get install cmake libboost-all-dev libcrypto++-dev libssl-dev libssl1.0.0
```

## Arch

```
$ sudo pacman -Syu cmake boost crypto++ openssl
```

## FreeBSD

Branch 9.X has gcc v4.2, that knows nothing about required c++11 standard.

Required ports:

* devel/cmake
* devel/boost-libs
* lang/gcc47 # or later version
* security/cryptopp
* security/openssl

To use newer compiler you should set these variables:

  export CC=/usr/local/bin/gcc47
  export CXX=/usr/local/bin/g++47

Replace "47" with your actual gcc version

# Step 3: Building

## To view CMake options:

```
$ cd kovri/build
$ cmake -L ../
```

## For a regular build:

```
$ cd kovri/build
$ cmake ../
$ make
```

## Run Kovri!

```
$ ./kovri --port <your chosen port>
```
or set your port in kovri.conf


For a full list of options:

```
$ ./kovri --help
```

# Step 4: Send feedback, contribute, or donate

* Visit https://github.com/monero-project/kovri
