#ifndef DRACHMA_CRYPTO_RIPEMD160_H
#define DRACHMA_CRYPTO_RIPEMD160_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

class RIPEMD160
{
public:
    RIPEMD160();
    void Reset();

    void Update(const uint8_t* data, size_t len);
    void Update(const std::vector<uint8_t>& data);
    void Update(const std::string& s);

    void Final(uint8_t out[20]);
    std::vector<uint8_t> Final();

    static std::vector<uint8_t> Hash(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> Hash(const uint8_t* data, size_t len);

private:
    void Transform(const uint8_t block[64]);

    uint32_t state[5];
    uint64_t bitlen;
    uint8_t buffer[64];
    size_t bufferLen;
};

#endif
