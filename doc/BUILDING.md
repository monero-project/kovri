## Step 1. Minimum requirements

### Linux / MacOSX (Mavericks 10.9.4) / FreeBSD 10 / Windows (Cygwin)
- [Boost](http://www.boost.org/) 1.54
- [CMake](https://cmake.org/) 2.8.12
- [Crypto++](https://cryptopp.com/) 5.6.2
- [GCC](https://gcc.gnu.org/) 5.3.0
- [OpenSSL](https://openssl.org/) (always the latest stable version)

Optional: [Doxygen](http://www.doxygen.org/) (for Doxygen documentation)

### MacOSX (Mavericks 10.9.4)
- [Homebrew](http://brew.sh/)

Note: We've dropped clang support on all platforms in an effort to streamline development. Regular clang users are welcome to bring back support!

Note: the MacOSX and FreeBSD build need love! See [#175](https://github.com/monero-project/kovri/issues/175) and [#176](https://github.com/monero-project/kovri/issues/176)

## Step 2. Install dependencies

### Debian / Ubuntu
```bash
$ sudo apt-get install g++-5 cmake libboost-all-dev libcrypto++-dev libssl-dev libssl1.0.0
$ sudo apt-get install libminiupnpc-dev doxygen  # optional
```

### Arch Linux
```bash
$ sudo pacman -Syu cmake boost crypto++  # gcc/g++ and openssl installed by default
$ sudo pacman -S miniupnpc doxygen  # optional
```

### FreeBSD 10
```bash
$ sudo pkg install gcc5 cmake boost-libs cryptopp openssl
$ sudo pkg install miniupnpc doxygen  # optional
```

### MacOSX (Mavericks)
```bash
$ brew install gcc5 cmake boost cryptopp openssl
$ brew install miniupnpc doxygen  # optional
```

## Step 3. Build

### To view CMake options:
```bash
$ cd kovri/build
$ cmake -L ../
```

### For a regular build:
```bash
$ cd kovri/build
$ cmake ../
$ make
```

Note: all builds require building out of the ```build``` directory as described above

### For UPnP support:
- Install [MiniUPnP](http://miniupnp.free.fr/files/) or use your package manager (see above)
```bash
$ cmake -DWITH_UPNP=ON ../ && make
```

### To build tests:
```bash
$ cmake -DWITH_TESTS=ON -DWITH_BENCHMARKS=ON ../ && make
```

### To produce Doxygen
```bash
$ cmake -DWITH_DOXYGEN=ON ../ && make doc  # output will be in kovri/doc/Doxygen/
```

## Step 4. Open your NAT/Firewall
1. Choose a port between ```9111``` and ```30777```
2. Poke a hole in your NAT/Firewall to allow incoming TCP/UDP connections to that port
3. Don't share this number with anyone as it will effect your anonymity!

If you do not choose a port via cli or ```kovri.conf```, Kovri will randomly generate a new one on each startup. If you do not have access to your NAT, you can instead install and build with [MiniUPnP](http://miniupnp.free.fr/files/) support

## Step 5. Run Kovri
```bash
$ ./kovri -p [your chosen port]
```
or set your port in kovri.conf


For a full list of options:

```bash
$ ./kovri -h
```

## Step 6. Configuration files *(optional)*

Configuration files has INI-like syntax: <key> = <value>.
All command-line parameters are allowed as keys, for example:

kovri.conf:

    log = 1
    v6 = 0
    ircdest = irc.dg.i2p

tunnels.conf:

    [IRC]
    type = client
    port = 6669
    destination = irc.dg.i2p
    keys = irc-keys.dat
