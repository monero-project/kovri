## 1. Satisfy minimum requirements

- [CMake](https://cmake.org/) 2.8.12
- [Boost](http://www.boost.org/) 1.54
- [Crypto++](https://cryptopp.com/) 5.6.2
- [OpenSSL](https://openssl.org/) (always the latest stable version)

Optional

- [Doxygen](http://www.doxygen.org/) (for Doxygen documentation)

### Linux
- [GCC](https://gcc.gnu.org/) 4.8.2

### FreeBSD 10
- [Clang](http://clang.llvm.org/) 3.4.1

### MacOSX 10.9.4 (Mavericks)
- [Apple LLVM](https://developer.apple.com/library/mac/documentation/CompilerTools/Conceptual/LLVMCompilerOverview/) 5.1
- [Homebrew](http://brew.sh/)

### Windows
- [VS2013](https://www.visualstudio.com/en-us/downloads/download-visual-studio-vs.aspx) (last known to work with 12.0.21005.1)

### Open your NAT/Firewall
1. Choose a port between ```9111``` and ```30777```.
2. Poke a hole in your NAT/Firewall to allow incoming TCP/UDP connections to that port.
3. Don't share this number with anyone as it will effect your anonymity!

If you do not choose a port via cli or ```kovri.conf```, Kovri will randomly generate a new one on each startup. If you do not have access to your NAT, you can instead install and build with [MiniUPnP](http://miniupnp.free.fr/files/) support

## 2. Install dependencies

### Debian (Jessie) / Ubuntu (Trusty, Vivid, Wily)
```bash
$ sudo apt-get install g++ cmake libboost-all-dev libcrypto++-dev libssl-dev libssl1.0.0
$ sudo apt-get install libminiupnpc-dev doxygen  ## (optional)
```

### Arch Linux
```bash
$ sudo pacman -Syu cmake boost crypto++  ## gcc and openssl installed by default
$ sudo pacman -S miniupnpc doxygen  ## (optional)
```

### FreeBSD 10
```bash
$ sudo pkg install cmake boost-libs cryptopp openssl
$ sudo pkg install miniupnpc doxygen  ## (optional)
```

### MacOSX (Mavericks)
```bash
$ brew install cmake boost cryptopp openssl
$ brew install miniupnpc doxygen  ## (optional)
```

## 3. Building

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

### For UPnP support:
- Install [MiniUPnP](http://miniupnp.free.fr/files/) or use your package manager (see above)
```bash
$ cd kovri/build
$ cmake -DWITH_UPNP=ON ../
$ make
```

### To build tests:
```bash
$ cd kovri/build
$ cmake -DWITH_TESTS=ON -DWITH_BENCHMARKS=ON ../
$ make
```

### To produce Doxygen
```bash
$ cd kovri/build
$ cmake -DWITH_DOXYGEN=ON ../
$ make doc && firefox ./doc/html/index.html  ## or use browser of choice
```

### Run Kovri!
```bash
$ ./kovri -p [your chosen port]
```

or set your port in kovri.conf


For a full list of options:

```bash
$ ./kovri -h
```

## 4. Configuration files *(optional)*

Configuration files has INI-like syntax: <key> = <value>.
All command-line parameters are allowed as keys, for example:

kovri.conf:

    log = 1
    v6 = 0
    ircdest = irc.dg.i2p

tunnels.cfg:

    [IRC]
    type = client
    port = 6669
    destination = irc.dg.i2p
    keys = irc-keys.dat
