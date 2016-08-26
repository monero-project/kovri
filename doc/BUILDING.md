## Step 1. Minimum requirements

### Linux / MacOSX (10.9.5) / FreeBSD 10
- [Git](https://git-scm.com/download) 1.9.1
- [GCC](https://gcc.gnu.org/) 4.9.3
- [CMake](https://cmake.org/) 2.8.12
- [Boost](http://www.boost.org/) 1.58
- [OpenSSL](https://openssl.org/) (always the latest stable version)

### Windows
- [MSYS2](https://msys2.github.io/)
- [MinGW-w64](http://mingw-w64.org/doku.php)

Optional:

- [Clang](http://clang.llvm.org/) 3.5 ([3.6 on FreeBSD](https://llvm.org/bugs/show_bug.cgi?id=28887))
- [MiniUPnP](http://miniupnp.free.fr/files/) 1.6
- [Doxygen](http://www.doxygen.org/) 1.8.6
- [Graphviz](http://graphviz.org/) 2.36

### MacOSX
- [Homebrew](http://brew.sh/)

## Step 2. Install dependencies

### Ubuntu Xenial (16.04)
Required dependencies:
```bash
$ sudo apt-get install git cmake libboost-all-dev libssl-dev  # gcc/g++ and libssl installed by default
```
Optional dependencies:
```bash
$ sudo apt-get install clang
$ sudo apt-get install doxygen graphviz
$ sudo apt-get install libminiupnpc-dev
```

### Ubuntu Trusty (14.04)
You can either build Boost from source or use PPA
Below are instructions for PPA:

Required dependencies:
```bash
$ sudo add-apt-repository ppa:ubuntu-toolchain-r/test
$ sudo add-apt-repository ppa:kojoley/boost
$ sudo apt-get update
$ sudo apt-get install libboost-{chrono,log,program-options,date-time,thread,system,filesystem,regex,test}1.58-dev
$ sudo apt-get install git g++-4.9 cmake libboost-all-dev libssl-dev libssl1.0.0
```
Optional dependencies:
```bash
$ sudo apt-get install clang-3.5
$ sudo apt-get install doxygen graphviz
$ sudo apt-get install libminiupnpc-dev
```

### Debian (stable)
We'll need to pull from ```testing``` for ```Boost 1.58+``` and because of a [broken CMake](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=826656). For documentation's sake, we will pull all dependencies from ```testing```. If you're unfamiliar with apt-pinning, proceed with the following before installing dependencies:

- Create and edit ```/etc/apt/preferences.d/custom.pref```
- Enter and save the following:

```
Package: *
Pin: release a=stable
Pin-Priority: 700

Package: *
Pin: release a=testing
Pin-Priority: 650
```
- Create and edit ```/etc/apt/sources.list.d/custom.list```
```
# Stable
deb [Enter your mirror here] stable main non-free contrib
# Testing
deb [Enter your mirror here] testing main non-free contrib
```
- Replace ```[Enter your mirror here]``` with your mirror (see ```/etc/apt/sources.list```)
- Run ```$ sudo apt-get update```
- Install dependencies with the ```-t testing``` switch:

Required dependencies:
```bash
$ sudo apt-get -t testing install git g++ cmake libboost-all-dev libssl-dev libssl1.0.0
```
Optional dependencies:
```bash
$ sudo apt-get -t testing install clang
$ sudo apt-get -t testing install doxygen graphviz
$ sudo apt-get -t testing install libminiupnpc-dev
```

### Arch Linux
Required dependencies:
```bash
$ sudo pacman -Syu cmake boost  # gcc/g++ and openssl installed by default
```
Optional dependencies:
```bash
$ sudo pacman -S clang
$ sudo pacman -S doxygen graphviz
$ sudo pacman -S miniupnpc
```

### Mac OSX
Required dependencies:
```bash
$ brew install cmake boost openssl # clang installed by default
```
Optional dependencies:
```bash
$ brew install doxygen graphviz
$ brew install miniupnpc
```

### FreeBSD 10
Required dependencies:
```bash
$ sudo pkg install git cmake gmake clang36 openssl
# Build latest boost (1.58 minimum)
$ wget https://sourceforge.net/projects/boost/files/boost/1.61.0/boost_1_61_0.tar.bz2/download -O boost_1_61_0.tar.bz2
$ tar xvjf boost_1_61_0.tar.bz2 && cd boost_1_61_0
$ ./bootstrap.sh --with-toolset=clang  # OK to build with clang < 3.6
$ sudo ./b2 --toolset=clang install
```
Optional dependencies:
```bash
$ sudo pkg install doxygen graphviz
$ sudo pkg install miniupnpc
```
**Note: see FreeBSD build instructions below**

### Windows (MSYS2/MinGW-64)
* Download the [MSYS2 installer](http://msys2.github.io/), 64-bit or 32-bit as needed, and run it.
* Use the shortcut associated with your architecture to launch the MSYS2 environment. On 64-bit systems that would be the MinGW-w64 Win64 Shell shortcut. Note that if you are running 64-bit Windows, you will have both 64-bit and 32-bit environments.
* Update the packages in your MSYS2 install:
```
pacman -Sy
pacman -Su --ignoregroup base
pacman -Su
```
* For those of you already familiar with pacman, you can run the normal ```pacman -Syu``` to update, but you may get errors and need to restart MSYS2 if pacman's dependencies are updated.
* Install dependencies: ```pacman -S make mingw-w64-x86_64-cmake mingw-w64-x86_64-gcc mingw-w64-x86_64-boost mingw-w64-x86_64-openssl```
* Optional: ```mingw-w64-x86_64-doxygen mingw-w64-x86_64-miniupnpc```
* Note: if using doxygen, you'll need [Graphviz](http://graphviz.org/doc/winbuild.html)

## Step 3. Build

### 1. Clone the repository
```bash
$ git clone --recursive https://github.com/monero-project/kovri
```
### 2. Build kovri and submodule dependencies with one command
```bash
$ make # to decrease build-time, run make -j [available CPU cores]
```
### 3. Install resources (configuration files + package resources)
```bash
$ make install-resources
```

- End-users MUST run ```make install-resources``` for new installations
- Developers SHOULD run ```make install-resources``` after a fresh fetch

### Other options you can use in place of step 2:

- ```make upnp``` produces vanilla binary with UPnP support (requires [MiniUPnP](http://miniupnp.free.fr/files/))
- ```make optimized-hardening``` produces optimized, hardened binary
- ```make all-options``` produces optimized, hardened, UPnP enabled binary
- ```make tests``` produces all unit-tests and benchmarks
- ```make tests-optimized-hardening``` produces all unit-tests and benchmarks with optimized hardening
- ```make static``` produces static binary

### Other available options
- ```make doxygen``` produces Doxygen documentation
- ```make clean``` cleans build directories and Doxygen output
- ```make help``` shows available CMake build options

#### Notes
- Doxygen output will be in ```doc``` directory
- All other build output will be in the ``build``` directory

### Clang
To build with clang, you **must** export the following:

```bash
$ export CC=clang CXX=clang++  # replace ```clang``` with a clang version/path of your choosing
```

### FreeBSD
```bash
$ export CC=clang36 CXX=clang++36
$ gmake dependencies && gmake && gmake install-resources
```
- Replace ```make``` with ```gmake``` for all other build options

### Custom data path
You can customize Kovri's data path to your liking. Simply export ```KOVRI_DATA_PATH```; example:

```bash
$ export KOVRI_DATA_PATH=$HOME/.another-kovri-data-path && make && make install-resources
```

## Step 4. Open your NAT/Firewall
1. Choose a port between ```9111``` and ```30777```
2. Poke a hole in your NAT/Firewall to allow incoming TCP/UDP connections to that port
3. Don't share this number with anyone as it will effect your anonymity!

If you do not choose a port via cli or ```kovri.conf```, Kovri will randomly generate a new one on each startup. If you do not have access to your NAT, you can instead install and build with [MiniUPnP](http://miniupnp.free.fr/files/) support

## Step 5. Configure Kovri
Read the configuration files for available options

## Step 6. Run Kovri
For a full list of options:

```bash
$ ./kovri --help
```

Basic command:
```bash
$ ./kovri -p [your chosen port]  # or set your port in kovri.conf
```

Wait 10-15 minutes or so to get bootstrapped into the network and then point your IRC client to port 6669 and join ```#kovri``` and ```#kovri-dev```
