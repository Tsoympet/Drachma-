#ifndef DRACHMA_KEY_H
#define DRACHMA_KEY_H

#include <array>
#include <vector>
#include <string>
#include <cstdint>

#include "ecdsa.h"

//
// Key – High level wrapper for wallet usage
// ---------------------------------------------------------------
// Provides:
//   - Private key storage
//   - Public key derivation
//   - Signing/verification entry points
//   - WIF import/export
//   - Serialization
//
// Matches Bitcoin Core behavior 1:1 where possible.
//
class Key
{
public:
    Key();
    explicit Key(const PrivateKey& pk);

    // ---- Identity ----
    bool IsValid() const { return valid; }
    bool IsCompressed() const { return compressed; }

    // ---- Private key operations ----
    static Key Generate(bool compressed = true);
    bool SetPrivateKey(const std::array<uint8_t,32>& pk, bool compressed = true);

    std::array<uint8_t,32> GetPrivateKey() const;
    std::string ToWIF() const;
    static Key FromWIF(const std::string& wif);

    // ---- Public key operations ----
    PublicKey GetPublicKey() const;
    std::vector<uint8_t> GetPublicKeyBytes() const;

    // ---- Signing ----
    Signature Sign(const std::array<uint8_t,32>& msgHash) const;

    // ---- Verification ----
    bool Verify(const std::array<uint8_t,32>& msgHash,
                const Signature& sig) const;

    // ---- Serialization ----
    std::vector<uint8_t> Serialize() const;
    bool Deserialize(const std::vector<uint8_t>& in);

private:
    bool valid;
    bool compressed;

    std::array<uint8_t,32> privKey;
};

#endif // DRACHMA_KEY_H
