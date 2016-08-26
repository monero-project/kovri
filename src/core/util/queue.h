/**                                                                                           //
 * Copyright (c) 2013-2016, The Kovri I2P Router Project                                      //
 *                                                                                            //
 * All rights reserved.                                                                       //
 *                                                                                            //
 * Redistribution and use in source and binary forms, with or without modification, are       //
 * permitted provided that the following conditions are met:                                  //
 *                                                                                            //
 * 1. Redistributions of source code must retain the above copyright notice, this list of     //
 *    conditions and the following disclaimer.                                                //
 *                                                                                            //
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list     //
 *    of conditions and the following disclaimer in the documentation and/or other            //
 *    materials provided with the distribution.                                               //
 *                                                                                            //
 * 3. Neither the name of the copyright holder nor the names of its contributors may be       //
 *    used to endorse or promote products derived from this software without specific         //
 *    prior written permission.                                                               //
 *                                                                                            //
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY        //
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF    //
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL     //
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,       //
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,               //
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS    //
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,          //
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF    //
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.               //
 *                                                                                            //
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project          //
 */

#ifndef SRC_CORE_UTIL_QUEUE_H_
#define SRC_CORE_UTIL_QUEUE_H_

#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace i2p {
namespace util {

template<typename Element>
class Queue {
 public:
  void Put(
      Element e) {
    std::unique_lock<std::mutex> l(m_QueueMutex);
    m_Queue.push(e);
    m_NonEmpty.notify_one();
  }
  void Put(
      const std::vector<Element>& vec) {
    if (!vec.empty()) {
      std::unique_lock<std::mutex> l(m_QueueMutex);
      for (auto it : vec)
        m_Queue.push(it);
      m_NonEmpty.notify_one();
    }
  }

  Element GetNext() {
    std::unique_lock<std::mutex> l(m_QueueMutex);
    auto el = GetNonThreadSafe();
    if (!el) {
      m_NonEmpty.wait(l);
      el = GetNonThreadSafe();
    }
    return el;
  }

  Element GetNextWithTimeout(
      int usec) {
    std::unique_lock<std::mutex> l(m_QueueMutex);
    auto el = GetNonThreadSafe();
    if (!el) {
      m_NonEmpty.wait_for(l, std::chrono::milliseconds(usec));
      el = GetNonThreadSafe();
    }
    return el;
  }

  void Wait() {
    std::unique_lock<std::mutex> l(m_QueueMutex);
    m_NonEmpty.wait(l);
  }
  bool Wait(
      int sec,
      int usec) {
    std::unique_lock<std::mutex> l(m_QueueMutex);
    return m_NonEmpty.wait_for(
        l,
        std::chrono::seconds(sec) +
        std::chrono::milliseconds(usec))
      != std::cv_status::timeout;
  }

  bool IsEmpty() {
    std::unique_lock<std::mutex> l(m_QueueMutex);
    return m_Queue.empty();
  }

  int GetSize() {
    std::unique_lock<std::mutex> l(m_QueueMutex);
    return m_Queue.size();
  }

  void WakeUp() {
    m_NonEmpty.notify_all();
  }

  Element Get() {
    std::unique_lock<std::mutex> l(m_QueueMutex);
    return GetNonThreadSafe();
  }

  Element Peek() {
    std::unique_lock<std::mutex> l(m_QueueMutex);
    return GetNonThreadSafe(true);
  }

 private:
  Element GetNonThreadSafe(
      bool peek = false) {
    if (!m_Queue.empty()) {
      auto el = m_Queue.front();
      if (!peek)
        m_Queue.pop();
      return el;
    }
    return nullptr;
  }

 private:
  std::queue<Element> m_Queue;
  std::mutex m_QueueMutex;
  std::condition_variable m_NonEmpty;
};

template<class Msg>
class MsgQueue : public Queue<Msg *> {
 public:
  typedef std::function<void()> OnEmpty;

  MsgQueue()
      : m_IsRunning(true),
        m_Thread(
            std::bind(
              &MsgQueue<Msg>::Run,
              this)) {}
  ~MsgQueue() {
    Stop();
  }

  void Stop() {
    if (m_IsRunning) {
      m_IsRunning = false;
      Queue<Msg *>::WakeUp();
      m_Thread.join();
    }
  }

  void SetOnEmpty(
      OnEmpty const& e) {
    m_OnEmpty = e;
  }

 private:
  void Run() {
    while (m_IsRunning) {
      while (auto msg = Queue<Msg *>::Get()) {
        msg->Process();
        delete msg;
      }
      if (m_OnEmpty != nullptr)
        m_OnEmpty();
      if (m_IsRunning)
        Queue<Msg *>::Wait();
    }
  }

 private:
  volatile bool m_IsRunning;
  OnEmpty m_OnEmpty;
  std::thread m_Thread;
};

}  // namespace util
}  // namespace i2p

#endif  // SRC_CORE_UTIL_QUEUE_H_
