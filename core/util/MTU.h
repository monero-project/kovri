#ifndef MTU_H
#define MTU_H

#include <boost/asio.hpp>
#include "Log.h"

namespace i2p {
namespace util {
namespace mtu {

    /**
     * @return the maximum transmission unit, or 576 on failure
     */
     int GetMTU(const boost::asio::ip::address& localAddress);
}
}
}

#endif
