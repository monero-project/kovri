// Copyright (c) 2015-2017, The Kovri I2P Router Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef CONTRIB_PYTHON_INSTANCE_H_
#define CONTRIB_PYTHON_INSTANCE_H_

#include <boost/python.hpp>

#include <string>

#include "src/client/instance.h"

#include "contrib/python/util.h"

/// @brief Wrapper for libcore instance
class Core final : public Util
{
 public:
  explicit Core(const std::string& args = std::string())
      : m_core(parse_string(args))
  {
  }
  explicit Core(const boost::python::list& args) : m_core(parse_list(args)) {}
  ~Core() {}

  void init()
  {
    m_core.Initialize();
  }

  void start()
  {
    m_core.Start();
  }

  void stop()
  {
    m_core.Stop();
  }

  // TODO(anonimal): upon further API development, we'll most likely want non-const reference
  const kovri::core::Instance& get() const noexcept
  {
    return m_core;
  }

 private:
  kovri::core::Instance m_core;
};

/// @brief Wrapper for libclient instance
class Client final
{
 public:
  // TODO(anonimal): upon further API development, we'll most likely want non-const reference
  explicit Client(const Core& core) : m_client(core.get()) {}

  void init()
  {
    m_client.Initialize();
  }

  void start()
  {
    m_client.Start();
  }

  void stop()
  {
    m_client.Stop();
  }

 private:
  kovri::client::Instance m_client;
};

#endif  // CONTRIB_PYTHON_INSTANCE_H_
