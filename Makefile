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

# Current off-by-default Kovri build options
cmake-upnp       = -D WITH_UPNP=ON
cmake-optimize   = -D WITH_OPTIMIZE=ON
cmake-hardening  = -D WITH_HARDENING=ON
cmake-tests      = -D WITH_TESTS=ON
cmake-static     = -D WITH_STATIC=ON
cmake-doxygen    = -D WITH_DOXYGEN=ON
cmake-coverage   = -D WITH_COVERAGE=ON

# Disable build options that will fail CMake if not built
# (used for help and doxygen build options)
cmake-disable-options = -D WITH_CPPNETLIB=OFF

# Currently, our dependencies are static but cpp-netlib's dependencies are not (by default)
cmake-cpp-netlib-static = -D CPP-NETLIB_STATIC_OPENSSL=ON -D CPP-NETLIB_STATIC_BOOST=ON

# Refrain from native CPU optimizations for crypto
cmake-cryptopp-no-opt = -D DISABLE_CXXFLAGS_OPTIMIZATIONS=ON

# Android-specific
cmake-android = -D ANDROID=1 -D KOVRI_DATA_PATH="/data/local/tmp/.kovri"

# Filesystem
build = build/
build-cpp-netlib = deps/cpp-netlib/$(build)
build-cryptopp = deps/cryptopp/$(build)
build-doxygen = doc/Doxygen

# CMake builder macros
define CMAKE
  mkdir -p $1
  cd $1 && $2 ../
endef

define CMAKE_CPP-NETLIB
  @echo "=== Building cpp-netlib ==="
  $(eval cmake-cpp-netlib = $(cmake-release) -D CPP-NETLIB_BUILD_TESTS=OFF -D CPP-NETLIB_BUILD_EXAMPLES=OFF $1)
  $(call CMAKE,$(build-cpp-netlib),$(cmake-cpp-netlib))
endef

define CMAKE_CRYPTOPP
  @echo "=== Building cryptopp ==="
  $(eval cmake-cryptopp = $(cmake-release) -D BUILD_TESTING=OFF -D BUILD_SHARED=OFF $1)
  $(call CMAKE,$(build-cryptopp),$(cmake-cryptopp))
endef

# Targets
all: dynamic

#--------------------------------#
# Dependency build types/options #
#--------------------------------#

deps:
	$(call CMAKE_CPP-NETLIB) && $(MAKE)
	$(call CMAKE_CRYPTOPP) && $(MAKE)

release-deps:
	$(call CMAKE_CPP-NETLIB) && $(MAKE)
	$(call CMAKE_CRYPTOPP,$(cmake-cryptopp-no-opt)) && $(MAKE)

release-static-deps:
	$(call CMAKE_CPP-NETLIB,$(cmake-cpp-netlib-static)) && $(MAKE)
	$(call CMAKE_CRYPTOPP,$(cmake-cryptopp-no-opt)) && $(MAKE)

#-----------------------------------#
# For local, end-user cloned builds #
#-----------------------------------#

dynamic: deps
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

static: release-deps  # Keep crypto CPU optimizations (don't use "release" static deps)
	$(eval cmake-kovri += $(cmake-static))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

#-----------------------------------#
# For  dynamic distribution release #
#-----------------------------------#

release: release-deps
	# TODO(unassigned): cmake release flags + optimizations/hardening when we're out of alpha
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

#--------------------------------------------------------------#
# For static distribution release (website and nightly builds) #
#--------------------------------------------------------------#

release-static: release-static-deps
        # TODO(unassigned): cmake release flags + optimizations/hardening when we're out of alpha
	$(eval cmake-kovri += $(cmake-static))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

release-static-android: release-static-deps
	$(eval cmake-kovri += $(cmake-static) $(cmake-android))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

#-----------------#
# Optional builds #
#-----------------#

# Optimized + hardening + UPnP
all-options: deps
	$(eval cmake-kovri += $(cmake-optimize) $(cmake-hardening) $(cmake-upnp))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

# We need (or very much should have) optimizations with hardening
optimized-hardened: deps
	$(eval cmake-kovri += $(cmake-optimize) $(cmake-hardening))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

optimized-hardened-tests: deps
	$(eval cmake-kovri += $(cmake-optimize) $(cmake-hardening) $(cmake-tests) $(cmake-benchmarks))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

# Note: leaving out hardening because of need for optimizations
coverage: deps
	$(eval cmake-kovri += $(cmake-coverage) $(cmake-upnp))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

coverage-tests: deps
	$(eval cmake-kovri += $(cmake-coverage) $(cmake-tests) $(cmake-benchmarks))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

tests: deps
	$(eval cmake-kovri += $(cmake-tests) $(cmake-benchmarks))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

doxygen:
	$(eval cmake-kovri += $(cmake-disable-options) $(cmake-doxygen))
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

help:
	$(eval cmake-kovri += $(cmake-disable-options) -LH)
	$(call CMAKE,$(build),$(cmake-kovri)) && $(MAKE)

clean:
	$(eval remove-build = rm -fR $(build) $(build-cpp-netlib) $(build-cryptopp) $(build-doxygen))
	@if [ "$$FORCE_CLEAN" = "yes" ]; then $(remove-build); \
	else echo "CAUTION: This will remove the build directories for Kovri and all submodule dependencies, and remove all Doxygen output"; \
	read -r -p "Is this what you wish to do? (y/N)?: " CONFIRM; \
	  if [ $$CONFIRM = "y" ] || [ $$CONFIRM = "Y" ]; then $(remove-build); \
          else echo "Exiting."; exit 1; \
          fi; \
        fi

install:
	@_install="./pkg/kovri-install.sh"; \
	if [ -e $$_install ]; then $$_install; else echo "Unable to find $$_install"; exit 1; fi

uninstall:
	@_install="./pkg/kovri-install.sh"; \
	if [ -e $$_install ]; then $$_install -u; else echo "Unable to find $$_install"; exit 1; fi

.PHONY: all deps release-deps release-static-deps dynamic static release release-static release-static-android all-options optimized-hardened optimized-hardened-tests coverage coverage-tests tests doxygen help clean install uninstall
