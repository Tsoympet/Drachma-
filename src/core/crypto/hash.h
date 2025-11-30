#ifndef DRACHMA_CRYPTO_HASH_H
#define DRACHMA_CRYPTO_HASH_H

#include <vector>
#include <string>
#include "sha256.h"
#include "ripemd160.h"

class Hash
{
public:
    //
    // HASH256 = SHA256(SHA256(data))
    //
    static std::vector<uint8_t> SHA256D(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> SHA256D(const uint8_t* data, size_t len);

    //
    // HASH160 = RIPEMD160(SHA256(data))
    //
    static std::vector<uint8_t> Hash160(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> Hash160(const uint8_t* data, size_t len);

    //
    // HMAC-SHA256
    //
    static std::vector<uint8_t> HMAC_SHA256(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data
    );

    //
    // Utility helpers
    //
    static std::vector<uint8_t> SHA256(const std::vector<uint8_t>& data);
};

#endif
