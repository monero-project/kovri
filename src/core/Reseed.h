#ifndef RESEED_H
#define RESEED_H

#include <iostream>
#include <string>
#include <vector>
#include <map>

#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#include "crypto/AES.h"
#include "Identity.h"

namespace i2p {
namespace data {

    class Reseeder {
        typedef Tag<512> PublicKey; 
        std::map<std::string, PublicKey> m_SigningKeys;
        
        int ReseedFromSU3(const std::string& host);
        int ProcessSU3Stream(std::istream& s);
        bool FindZipDataDescriptor(std::istream& s);

        bool ProcessSU3Cert(const std::string& filename);
        std::string ProcessSU3Cert (CryptoPP::ByteQueue& queue); // returns issuer's name

        public:
            Reseeder();
            ~Reseeder();
            int ReseedNowSU3();
            bool LoadSU3Certs();
    };
    const char SU3_MAGIC_NUMBER[]="I2Psu3";
    const uint32_t ZIP_HEADER_SIGNATURE = 0x04034B50;
    const uint32_t ZIP_CENTRAL_DIRECTORY_HEADER_SIGNATURE = 0x02014B50;
    const uint16_t ZIP_BIT_FLAG_DATA_DESCRIPTOR = 0x0008;
    const uint8_t ZIP_DATA_DESCRIPTOR_SIGNATURE[] = { 0x50, 0x4B, 0x07, 0x08 };
    const char CERTIFICATE_HEADER[] = "-----BEGIN CERTIFICATE-----";
    const char CERTIFICATE_FOOTER[] = "-----END CERTIFICATE-----";
}
}

#endif
