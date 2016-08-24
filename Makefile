# Copyright (c) 2015-2016, The Kovri I2P Router Project
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

#TODO(unassigned): improve this Makefile

# TODO(unassigned): hack for weidai11/cryptopp#232
# Only needed for clang but doesn't hurt with gcc
ifeq ($(CXXFLAGS),)
  CXXFLAGS += -maes -march=native
  export CXXFLAGS
endif

# Get custom data path
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
  ifneq (, $(findstring MINGW, $(system)))
    data-path = "$(APPDATA)"\\Kovri
    cmake-gen = -G 'MSYS Makefiles'
  endif
else
  data-path = $(KOVRI_DATA_PATH)
endif

# Set custom data path
cmake-data-path = -D KOVRI_DATA_PATH=$(data-path)

# Release types
# TODO(unassigned): put these to good use; will require rewrite of root recipe.
cmake-debug = -D CMAKE_BUILD_TYPE=Debug
# TODO(unassigned): use release flag for dependencies when we release
#cmake-release = -D CMAKE_BUILD_TYPE=Release

# Our base cmake command
cmake = cmake $(cmake-gen) $(cmake-debug)

# Dependencies options
cmake-cpp-netlib = -D CPP-NETLIB_BUILD_TESTS=OFF -D CPP-NETLIB_BUILD_EXAMPLES=OFF
cmake-cryptopp = -D BUILD_TESTING=OFF

# Current off-by-default Kovri build options
cmake-upnp       = -D WITH_UPNP=ON
cmake-optimize   = -D WITH_OPTIMIZE=ON
cmake-hardening  = -D WITH_HARDENING=ON
cmake-tests      = -D WITH_TESTS=ON
cmake-benchmarks = -D WITH_BENCHMARKS=ON
cmake-static     = -D WITH_STATIC=ON
cmake-doxygen    = -D WITH_DOXYGEN=ON

# Disable build options that will fail CMake if not built
# (used for help and doxygen build options)
disable-options = -D WITH_CPPNETLIB=OFF

# Filesystem
build = build/
cpp-netlib-build = deps/cpp-netlib/$(build)
cryptopp-build = deps/cryptopp/$(build)
doxygen-output = doc/Doxygen
remove-build = rm -fR $(build) $(cpp-netlib-build) $(cryptopp-build) $(doxygen-output)
copy-resources = mkdir -p $(data-path) && cp -fR pkg/* $(data-path)
run-tests = ./kovri-tests && ./kovri-benchmarks

# TODO(unassigned): implement cmake-release build options
all: dynamic

dependencies:
	mkdir -p $(cpp-netlib-build)
	cd $(cpp-netlib-build) && $(cmake) $(cmake-cpp-netlib) ../ && $(MAKE)
	mkdir -p $(cryptopp-build)
	cd $(cryptopp-build) && $(cmake) $(cmake-cryptopp) ../ && $(MAKE)

dynamic: dependencies
	mkdir -p $(build)
	cd $(build) && $(cmake) ../ && $(MAKE)

static: dependencies
	mkdir -p $(build)
	cd $(build) && $(cmake) $(cmake-static) ../ && $(MAKE)

# We need (or very much should have) optimizations with hardening
optimized-hardening: dependencies
	mkdir -p $(build)
	cd $(build) && $(cmake) $(cmake-optimize) $(cmake-hardening) ../ && $(MAKE)

upnp: dependencies
	mkdir -p $(build)
	cd $(build) && $(cmake) $(cmake-upnp) ../ && $(MAKE)

all-options: dependencies
	mkdir -p $(build)
	cd $(build) && $(cmake) $(cmake-optimize) $(cmake-hardening) $(cmake-upnp) ../ && $(MAKE)

tests: dependencies
	mkdir -p $(build)
	cd $(build) && $(cmake) $(cmake-tests) $(cmake-benchmarks) ../ && $(MAKE) #&& $(run-tests)  # Reinstate once #317 is resolved

tests-optimized-hardening: dependencies
	mkdir -p $(build)
	cd $(build) && $(cmake) $(cmake-optimize) $(cmake-hardening) $(cmake-tests) $(cmake-benchmarks) ../ && $(MAKE) #&& $(run-tests)  # Reinstate once #317 is resolved

doxygen:
	mkdir -p $(build)
	cd $(build) && $(cmake) $(disable-options) $(cmake-doxygen) ../ && $(MAKE) doc

help:
	mkdir -p $(build)
	cd $(build) && $(cmake) $(disable-options) -LH ../

clean:
	@if [ "$$FORCE_CLEAN" = "yes" ]; then $(remove-build); \
	else echo "CAUTION: This will remove the build directories for Kovri and all submodule dependencies, and remove all Doxygen output"; \
	read -r -p "Is this what you wish to do? (y/N)?: " CONFIRM; \
	  if [ $$CONFIRM = "y" ] || [ $$CONFIRM = "Y" ]; then $(remove-build); \
          else echo "Exiting."; exit 1; \
          fi; \
        fi

# TODO(unassigned): we need to consider using a proper CMake generated make install.
# For now, we'll simply (optionally) copy resources. Binaries will remain in build directory.
install-resources:
	@if [ "$$FORCE_INSTALL" = "yes" ]; then $(copy-resources); \
	else echo "WARNING: This will overwrite all resources and configuration files"; \
	read -r -p "Is this what you wish to do? (y/N)?: " CONFIRM; \
	  if [ $$CONFIRM = "y" ] || [ $$CONFIRM = "Y" ]; then $(copy-resources); \
          else echo "Exiting."; exit 1; \
	  fi; \
	fi

.PHONY: all dependencies dynamic static optimized-hardening upnp all-options tests tests-optimized-hardening doxygen help clean install-resources
