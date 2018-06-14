# Copyright (c) 2015-2018, The Kovri I2P Router Project
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
#
# Parts of this file are originally copyright (c) 2014-2018 The Monero Project

message(STATUS "Using in-tree miniupnpc")

add_subdirectory(miniupnp/miniupnpc)

# It is better to setup these options inside miniupnp/miniupnpc/CMakeLists.txt
# But the following line allow us to do it here
set_property(TARGET libminiupnpc-static PROPERTY FOLDER "deps")

# Suppress noise warnings
if(MSVC)
  set_property(TARGET libminiupnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -wd4244 -wd4267")
elseif(NOT MSVC)
  set_property(TARGET libminiupnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-undef -Wno-unused-result -Wno-unused-value")
endif()

# https://github.com/monero-project/kovri/pull/865#discussion_r184370624
set_property(TARGET libminiupnpc-static APPEND PROPERTY INTERFACE_COMPILE_DEFINITIONS MINIUPNP_STATICLIB)

# Use #include <miniupnp/miniupnpc/miniupnpc.h>
set_property(TARGET libminiupnpc-static APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR})
# Suppress warnings from miniupnpc headers
set_property(TARGET libminiupnpc-static APPEND PROPERTY INTERFACE_SYSTEM_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR})
