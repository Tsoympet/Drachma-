#ifndef DRACHMA_BASE58_H
#define DRACHMA_BASE58_H

#include <string>
#include <vector>
#include <cstdint>

namespace Base58
{
    std::string Encode(const std::vector<uint8_t>& data);
    bool Decode(const std::string& str, std::vector<uint8_t>& out);

    // Bitcoin-style Base58Check (version + checksum)
    std::string EncodeCheck(const std::vector<uint8_t>& data);
    bool DecodeCheck(const std::string& str, std::vector<uint8_t>& out);

    // Helpers
    uint32_t Checksum(const std::vector<uint8_t>& data);
}

#endif
