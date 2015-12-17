#include "MTU.h"
#if defined(__linux__) || defined(__FreeBSD_kernel__) || defined(__APPLE__) || defined(__OpenBSD__)
#include <sys/types.h>
#include <ifaddrs.h>
#elif defined(_WIN32)
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <shlobj.h>

#pragma comment(lib, "IPHLPAPI.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

int inet_pton(int af, const char *src, void *dst)
{ /* This function was written by Petar Korponai?. See
http://stackoverflow.com/questions/15660203/inet-pton-identifier-not-found */
    struct sockaddr_storage ss;
    int size = sizeof (ss);
    char src_copy[INET6_ADDRSTRLEN + 1];

    ZeroMemory (&ss, sizeof (ss));
    strncpy_s (src_copy, src, INET6_ADDRSTRLEN + 1);
    src_copy[INET6_ADDRSTRLEN] = 0;

    if (WSAStringToAddress (src_copy, af, NULL, (struct sockaddr *)&ss, &size) == 0)
    {
        switch (af)
        {
            case AF_INET:
                *(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
                return 1;
            case AF_INET6:
                *(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr;
                return 1;
        }
    }
    return 0;
}
#endif

namespace i2p {
namespace util {
namespace mtu {

#if defined(__linux__) || defined(__FreeBSD_kernel__) || defined(__APPLE__) || defined(__OpenBSD__)
    int GetMTUUnix(const boost::asio::ip::address& localAddress, int fallback)
    {
        ifaddrs* ifaddr, *ifa = nullptr;
        if(getifaddrs(&ifaddr) == -1) {
            LogPrint(eLogError, "Can't execute getifaddrs()");
            return fallback;
        }

        int family = 0;
        // look for interface matching local address
        for(ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if(!ifa->ifa_addr)
                continue;

            family = ifa->ifa_addr->sa_family;
            if(family == AF_INET && localAddress.is_v4()) {
                sockaddr_in* sa = (sockaddr_in*) ifa->ifa_addr;
                if(!memcmp(&sa->sin_addr, localAddress.to_v4().to_bytes().data(), 4))
                    break; // address matches
            } else if(family == AF_INET6 && localAddress.is_v6()) {
                sockaddr_in6* sa = (sockaddr_in6*) ifa->ifa_addr;
                if(!memcmp(&sa->sin6_addr, localAddress.to_v6().to_bytes().data(), 16))
                    break; // address matches
            }
        }
        int mtu = fallback;
        if(ifa && family) { // interface found?
            int fd = socket(family, SOCK_DGRAM, 0);
            if(fd > 0) {
                ifreq ifr;
                strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ); // set interface for query
                if(ioctl(fd, SIOCGIFMTU, &ifr) >= 0)
                    mtu = ifr.ifr_mtu; // MTU
                else
                    LogPrint (eLogError, "Failed to run ioctl");
                close(fd);
            } else
                LogPrint(eLogError, "Failed to create datagram socket");
        } else {
            LogPrint(
                eLogWarning, "Interface for local address",
                localAddress.to_string(), " not found"
            );
        }

        freeifaddrs(ifaddr);

        return mtu;
    }

#elif defined(_WIN32)
    int GetMTUWindowsIpv4(sockaddr_in inputAddress, int fallback)
    {
        ULONG outBufLen = 0;
        PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
        PIP_ADAPTER_ADDRESSES pCurrAddresses = nullptr;
        PIP_ADAPTER_UNICAST_ADDRESS pUnicast = nullptr;


        if(GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen)
          == ERROR_BUFFER_OVERFLOW) {
            FREE(pAddresses);
            pAddresses = (IP_ADAPTER_ADDRESSES*) MALLOC(outBufLen);
        }

        DWORD dwRetVal = GetAdaptersAddresses(
            AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen
        );

        if(dwRetVal != NO_ERROR) {
            LogPrint(
                eLogError, "GetMTU() has failed: enclosed GetAdaptersAddresses() call has failed"
            );
            FREE(pAddresses);
            return fallback;
        }

        pCurrAddresses = pAddresses;
        while(pCurrAddresses) {
            PIP_ADAPTER_UNICAST_ADDRESS firstUnicastAddress = pCurrAddresses->FirstUnicastAddress;

            pUnicast = pCurrAddresses->FirstUnicastAddress;
            if(pUnicast == nullptr) {
                LogPrint(
                    eLogError, "GetMTU() has failed: not a unicast ipv4 address, this is not supported"
                );
            }
            for(int i = 0; pUnicast != nullptr; ++i) {
                LPSOCKADDR lpAddr = pUnicast->Address.lpSockaddr;
                sockaddr_in* localInterfaceAddress = (sockaddr_in*) lpAddr;
                if(localInterfaceAddress->sin_addr.S_un.S_addr == inputAddress.sin_addr.S_un.S_addr) {
                    auto result = pAddresses->Mtu;
                    FREE(pAddresses);
                    return result;
                }
                pUnicast = pUnicast->Next;
            }
            pCurrAddresses = pCurrAddresses->Next;
        }

        LogPrint(eLogError, "GetMTU() error: no usable unicast ipv4 addresses found");
        FREE(pAddresses);
        return fallback;
    }

    int GetMTUWindowsIpv6(sockaddr_in6 inputAddress, int fallback)
    {
        ULONG outBufLen = 0;
        PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
        PIP_ADAPTER_ADDRESSES pCurrAddresses = nullptr;
        PIP_ADAPTER_UNICAST_ADDRESS pUnicast = nullptr;

        if(GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen)
          == ERROR_BUFFER_OVERFLOW) {
            FREE(pAddresses);
            pAddresses = (IP_ADAPTER_ADDRESSES*) MALLOC(outBufLen);
        }

        DWORD dwRetVal = GetAdaptersAddresses(
            AF_INET6, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen
        );

        if(dwRetVal != NO_ERROR) {
            LogPrint(
                eLogError,
                "GetMTU() has failed: enclosed GetAdaptersAddresses() call has failed"
            );
            FREE(pAddresses);
            return fallback;
        }

        bool found_address = false;
        pCurrAddresses = pAddresses;
        while(pCurrAddresses) {
            PIP_ADAPTER_UNICAST_ADDRESS firstUnicastAddress = pCurrAddresses->FirstUnicastAddress;
            pUnicast = pCurrAddresses->FirstUnicastAddress;
            if(pUnicast == nullptr) {
                LogPrint(
                    eLogError,
                    "GetMTU() has failed: not a unicast ipv6 address, this is not supported"
                );
            }
            for(int i = 0; pUnicast != nullptr; ++i) {
                LPSOCKADDR lpAddr = pUnicast->Address.lpSockaddr;
                sockaddr_in6 *localInterfaceAddress = (sockaddr_in6*) lpAddr;

                for (int j = 0; j != 8; ++j) {
                    if (localInterfaceAddress->sin6_addr.u.Word[j] != inputAddress.sin6_addr.u.Word[j]) {
                        break;
                    } else {
                        found_address = true;
                    }
                } if (found_address) {
                    auto result = pAddresses->Mtu;
                    FREE(pAddresses);
                    pAddresses = nullptr;
                    return result;
                }
                pUnicast = pUnicast->Next;
            }

            pCurrAddresses = pCurrAddresses->Next;
        }

        LogPrint(eLogError, "GetMTU() error: no usable unicast ipv6 addresses found");
        FREE(pAddresses);
        return fallback;
    }

    int GetMTUWindows(const boost::asio::ip::address& localAddress, int fallback)
    {
#ifdef UNICODE
        string localAddress_temporary = localAddress.to_string();
        wstring localAddressUniversal(localAddress_temporary.begin(), localAddress_temporary.end());
#else
        std::string localAddressUniversal = localAddress.to_string();
#endif

        if(localAddress.is_v4()) {
            sockaddr_in inputAddress;
            inet_pton(AF_INET, localAddressUniversal.c_str(), &(inputAddress.sin_addr));
            return GetMTUWindowsIpv4(inputAddress, fallback);
        } else if(localAddress.is_v6()) {
            sockaddr_in6 inputAddress;
            inet_pton(AF_INET6, localAddressUniversal.c_str(), &(inputAddress.sin6_addr));
            return GetMTUWindowsIpv6(inputAddress, fallback);
        } else {
            LogPrint(eLogError, "GetMTU() has failed: address family is not supported");
            return fallback;
        }

    }
#endif // WIN32

    int GetMTU(const boost::asio::ip::address& localAddress)
    {
        const int fallback = 576; // fallback MTU

#if defined(__linux__) || defined(__FreeBSD_kernel__) || defined(__APPLE__) || defined(__OpenBSD__)
        return GetMTUUnix(localAddress, fallback);
#elif defined(WIN32)
        return GetMTUWindows(localAddress, fallback);
#endif
        return fallback;
    }

} // mtu
} // util
} // i2p
