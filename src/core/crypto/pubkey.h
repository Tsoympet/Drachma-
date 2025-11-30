#ifndef DRACHMA_PUBKEY_H
#define DRACHMA_PUBKEY_H

#include <array>
#include <vector>
#include <string>
#include <cstdint>

#include "ecdsa.h"
#include "hash.h"

//
// =====================================================================
//  PubKeyID (20-byte hash, same concept as Bitcoin's CKeyID)
// =====================================================================
class PubKeyID
{
public:
    static constexpr size_t SIZE = 20;

    PubKeyID() { data.fill(0); }

    explicit PubKeyID(const std::array<uint8_t,SIZE>& d)
    {
        data = d;
    }

    const std::array<uint8_t,SIZE>& GetData() const { return data; }

    std::string ToHex() const { return Utils::HexStr(data); }

private:
    std::array<uint8_t, SIZE> data;
};

//
// =====================================================================
//  PublicKey – Bitcoin-style public key wrapper
// =====================================================================
//
// Handles:
//   - Parsing compressed/uncompressed keys
//   - Validity checks
//   - Export to bytes
//   - Hash160()
//   - PubKeyID
//   - secp256k1 verification routing
//
class PublicKey
{
public:
    PublicKey();
    explicit PublicKey(const std::array<uint8_t,33>& compressed);
    explicit PublicKey(const std::array<uint8_t,65>& uncompressed);

    // Basic checks
    bool IsValid() const { return valid; }
    bool IsCompressed() const { return compressed; }

    // Export raw bytes
    std::vector<uint8_t> GetBytes() const { return keydata; }

    // Hash160(pubkey)
    std::array<uint8_t,20> GetHash160() const;

    // Return 20-byte identifier
    PubKeyID GetID() const;

    // Verify signature
    bool Verify(const std::array<uint8_t,32>& msgHash,
                const Signature& sig) const;

    // Detect format from raw bytes (33/65)
    static PublicKey FromBytes(const std::vector<uint8_t>& bytes);

private:
    bool valid;
    bool compressed;
    std::vector<uint8_t> keydata; // 33 or 65 bytes
};

#endif // DRACHMA_PUBKEY_H
