# Step 1. Satisfy requirements

## Requirements for Linux/FreeBSD/OSX

* GCC 4.6 or newer (Clang can be used instead of GCC)
* Boost 1.46 or newer
* crypto++

## Requirements for Windows

* VS2013 (known to work with 12.0.21005.1 or newer)
* Boost 1.46 or newer
* crypto++ 5.62

# Step 2. Install dependencies

## Debian/Ubuntu

``` console
$ sudo apt-get install cmake libboost-date-time-dev libboost-filesystem-dev libboost-log-dev libboost-program-options-dev libboost-regex-dev libboost-system-dev libcrypto++-dev
```

Optional packages (for tests):
``` console
$ sudo apt-get install libboost-test-dev
```

## Arch

``` console
$ sudo pacman -Syu cmake boost crypto++
```

## FreeBSD

Branch 9.X has gcc v4.2, that knows nothing about required c++11 standard.

Required ports:

* devel/cmake
* devel/boost-libs
* lang/gcc47 # or later version
* security/cryptopp

To use newer compiler you should set these variables:

  export CC=/usr/local/bin/gcc47
  export CXX=/usr/local/bin/g++47

Replace "47" with your actual gcc version

# Step 3: Building

## (Optional) CMake options

* CMAKE_BUILD_TYPE -- build profile (Debug/Release)
* WITH_AESNI -- AES-NI support (ON/OFF)
* WITH_HARDENING -- enable hardening features (ON/OFF) (gcc only)
* WITH_TESTS -- build tests (ON/OFF)
* WITH_BENCHMARK -- build bechmarking code (ON/OFF)
* WITH_OPTIMIZE -- enable optimization flags (ON/OFF) (not for MSVC)
* KOVRI_DATA_DIR -- directory where kovri will store data

## Now, build!

``` console
$ cd kovri/build
$ cmake ../
$ make
```

## Then, run!

``` console
$ ./kovri
```

For a full list of options:

``` console
$ ./kovri --help
```

Note: by default, the web console is located at `http://localhost:7070/`.

# Step 4: Send feedback, contribute, or donate

* Visit https://github.com/monero-project/kovri
