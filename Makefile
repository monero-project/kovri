# Copyright (c) 2015-2017, The Kovri I2P Router Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Get custom Kovri data path + set appropriate CMake generator.
# If no path is given, set default path
system := $(shell uname)
ifeq ($(KOVRI_DATA_PATH),)
  ifeq ($(system), Linux)
    data-path = $(HOME)/.kovri
  endif
  ifeq ($(system), Darwin)
    data-path = $(HOME)/Library/Application\ Support/Kovri
  endif
  ifneq (, $(findstring BSD, $(system))) # We should support other BSD's
    data-path = $(HOME)/.kovri
  endif
  ifeq ($(system), DragonFly)
    data-path = $(HOME)/.kovri
  endif
  ifneq (, $(findstring MINGW, $(system)))
    data-path = "$(APPDATA)"\\Kovri
    cmake-gen = -G 'MSYS Makefiles'
  endif
else
  data-path = $(KOVRI_DATA_PATH)
endif

# Our base cmake command
cmake = cmake $(cmake-gen)

# Release types
cmake-debug = $(cmake) -D CMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake-release = $(cmake) -D CMAKE_BUILD_TYPE=Release

# TODO(unassigned): cmake-release when we're out of alpha
cmake-kovri = $(cmake-debug)
cmake-kovri-util = -D WITH_KOVRI_UTIL=ON

# Current off-by-default Kovri build options
cmake-upnp       = -D WITH_UPNP=ON
cmake-optimize   = -D WITH_OPTIMIZE=ON
cmake-hardening  = -D WITH_HARDENING=ON
cmake-tests      = -D WITH_TESTS=ON
cmake-fuzz-tests = -D WITH_FUZZ_TESTS=ON
cmake-static     = -D WITH_STATIC=ON
cmake-static-deps= -D WITH_STATIC_DEPS=ON
cmake-doxygen    = -D WITH_DOXYGEN=ON
cmake-coverage   = -D WITH_COVERAGE=ON
cmake-python     = -D WITH_PYTHON=ON

# cpp-netlib shared
cmake-cpp-netlib-shared = -D CPP-NETLIB_BUILD_SHARED_LIBS=ON

# Android-specific
cmake-android = -D ANDROID=1 -D KOVRI_DATA_PATH="/data/local/tmp/.kovri"

# Native
cmake-native = -DCMAKE_CXX_FLAGS="-march=native"
cryptopp-native = CXXFLAGS="-march=native -DCRYPTOPP_NO_CPU_FEATURE_PROBES=1"  # Refs #699

# Filesystem
build = build/
build-cpp-netlib = deps/cpp-netlib/$(build)
build-cryptopp = deps/cryptopp/  # No longer using CMake
build-doxygen = doc/Doxygen
build-fuzzer = contrib/Fuzzer/$(build)

# CMake builder macros
define CMAKE
  mkdir -p $1
  cd $1 && $2 ../
endef

define MAKE_CRYPTOPP
  @echo "=== Building cryptopp ==="
  cd $(build-cryptopp) && $1
endef

define CMAKE_FUZZER
  @echo "=== Building fuzzer ==="
  $(eval cmake-fuzzer = $(cmake-release) -DLLVM_USE_SANITIZER=Address -DLLVM_USE_SANITIZE_COVERAGE=YES \
      -DCMAKE_CXX_FLAGS="-g -O2 -fno-omit-frame-pointer -std=c++11" $1)
  $(call CMAKE,$(build-fuzzer),$(cmake-fuzzer))
endef

# Targets
all: dynamic

#--------------------------------#
# Dependency build types/options #
#--------------------------------#

deps:
	$(call MAKE_CRYPTOPP, $(MAKE) $(cryptopp-native) static)

shared-deps:
	$(eval cmake-kovri += $(cmake-cpp-netlib-shared))
	$(call MAKE_CRYPTOPP, $(MAKE) shared)

release-deps:
	$(call MAKE_CRYPTOPP, $(MAKE) static)

release-static-deps:
	$(eval cmake-kovri += $(cmake-static-deps))
	$(call MAKE_CRYPTOPP, $(MAKE) static)

#-----------------------------------#
# For local, end-user cloned builds #
#-----------------------------------#

dynamic: shared-deps
	$(eval cmake-kovri += $(cmake-native))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

static: deps
	$(eval cmake-kovri += $(cmake-native) $(cmake-static))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

#-----------------------------------#
# For  dynamic distribution release #
#-----------------------------------#

release: release-deps
	# TODO(unassigned): cmake release flags + optimizations/hardening when we're out of alpha
	$(eval cmake-kovri += $(cmake-kovri-util))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

#--------------------------------------------------------------#
# For static distribution release (website and nightly builds) #
#--------------------------------------------------------------#

release-static: release-static-deps
        # TODO(unassigned): cmake release flags + optimizations/hardening when we're out of alpha
	$(eval cmake-kovri += $(cmake-static) $(cmake-kovri-util))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

release-static-android: release-static-deps
	$(eval cmake-kovri += $(cmake-static) $(cmake-android) $(cmake-kovri-util))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

# TODO(unassigned): static UPnP once our UPnP implementation is release-ready

#-----------------#
# Optional builds #
#-----------------#

# Utility binary
util: deps
	$(eval cmake-kovri += $(cmake-kovri-util))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

# For API/testnet development
python: shared-deps
	$(eval cmake-kovri += $(cmake-python))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

# Produce vanilla binary with UPnP support
upnp: deps
	$(eval cmake-kovri += $(cmake-upnp))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

# Produce optimized, hardened binary *with* UPnP
all-options: deps
	$(eval cmake-kovri += $(cmake-optimize) $(cmake-hardening) $(cmake-upnp) $(cmake-kovri-util))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

# Produce optimized, hardened binary *without* UPnP. Note: we need (or very much should have) optimizations with hardening
optimized-hardened: deps
	$(eval cmake-kovri += $(cmake-optimize) $(cmake-hardening))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

# Produce all unit-tests with optimized hardening
optimized-hardened-tests: deps
	$(eval cmake-kovri += $(cmake-optimize) $(cmake-hardening) $(cmake-tests))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

# Produce build with coverage. Note: leaving out hardening because of need for optimizations
coverage: deps
	$(eval cmake-kovri += $(cmake-coverage) $(cmake-upnp) $(cmake-kovri-util))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

# Produce unit-tests with coverage
coverage-tests: deps
	$(eval cmake-kovri += $(cmake-coverage) $(cmake-tests))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

# Produce vanilla unit-tests
tests: deps
	$(eval cmake-kovri += $(cmake-tests))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

# Produce vanilla fuzzer-tests
fuzz-tests: deps
	$(call CMAKE_FUZZER) && $(MAKE)
	$(eval cmake-kovri += $(cmake-fuzz-tests))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

# Produce Doxygen documentation
doxygen:
	$(eval cmake-kovri += $(cmake-doxygen))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE) doc

# Produce available CMake build options
help:
	$(call CMAKE,$(build),$(cmake-kovri) -LH)

# Clean all build directories and Doxygen output
clean:
	$(eval remove-build = rm -fR $(build) $(build-cpp-netlib) $(build-doxygen) $(build-fuzzer) && cd $(build-cryptopp) && $(MAKE) clean)
	@if [ "$$FORCE_CLEAN" = "yes" ]; then $(remove-build); \
	else echo "CAUTION: This will remove the build directories for Kovri and all submodule dependencies, and remove all Doxygen output"; \
	read -r -p "Is this what you wish to do? (y/N)?: " CONFIRM; \
	  if [ $$CONFIRM = "y" ] || [ $$CONFIRM = "Y" ]; then $(remove-build); \
          else echo "Exiting."; exit 1; \
          fi; \
        fi

# Install binaries and package
install:
	@_install="./pkg/installers/kovri-install.sh"; \
	if [ -e $$_install ]; then $$_install; else echo "Unable to find $$_install"; exit 1; fi

# Un-install binaries and package
uninstall:
	@_install="./pkg/installers/kovri-install.sh"; \
	if [ -e $$_install ]; then $$_install -u; else echo "Unable to find $$_install"; exit 1; fi

.PHONY: all deps release-deps release-static-deps dynamic static release release-static release-static-android all-options optimized-hardened optimized-hardened-tests coverage coverage-tests tests doxygen help clean install uninstall
