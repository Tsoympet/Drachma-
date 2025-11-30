#ifndef DRACHMA_ECDSA_H
#define DRACHMA_ECDSA_H

#include <array>
#include <vector>
#include <string>
#include <cstdint>

//
// ===============================================================
//  SECP256K1 - ECDSA KEY SYSTEM
// ===============================================================
//
//  Classes:
//    - Signature:  (r, s) pair
//    - PrivateKey: 32-byte scalar + sign()
//    - PublicKey:  point on curve + verify()
//    - ECDSA: core math for sign/verify operations
//
//  Notes:
//    • Deterministic signatures (RFC 6979)
//    • Compressed public keys default (33 bytes)
//    • Compatible with Bitcoin, Electrum, etc.
//    • Requires: sha256 + hash.cpp + base58
//
// ===============================================================
//

//
// ===============================================================
//  STRUCT: ECDSA Signature (r, s)
// ===============================================================
//
struct Signature
{
    std::array<uint8_t, 32> r;
    std::array<uint8_t, 32> s;

    // DER encode
    std::vector<uint8_t> ToDER() const;

    // From DER
    static bool FromDER(const std::vector<uint8_t>& der, Signature& out);
};


//
// ===============================================================
//  CLASS: PublicKey
// ===============================================================
//
class PublicKey
{
public:
    PublicKey();
    PublicKey(const std::array<uint8_t, 33>& compressed);
    PublicKey(const std::array<uint8_t, 65>& uncompressed);

    bool IsValid() const { return valid; }
    bool IsCompressed() const { return compressed; }

    const std::vector<uint8_t>& GetBytes() const { return keydata; }

    // Verify signature of message hash
    bool Verify(const std::array<uint8_t, 32>& msgHash, const Signature& sig) const;

private:
    bool valid;
    bool compressed;
    std::vector<uint8_t> keydata;    // 33 or 65 bytes
};


//
// ===============================================================
//  CLASS: PrivateKey
// ===============================================================
//
class PrivateKey
{
public:
    PrivateKey();
    explicit PrivateKey(const std::array<uint8_t, 32>& priv);

    bool IsValid() const { return valid; }
    bool IsCompressed() const { return compressed; }

    const std::array<uint8_t,32>& GetBytes() const { return key; }

    // Generate new random private key
    static PrivateKey Generate(bool compressed=true);

    // Derive public key
    PublicKey GetPublicKey() const;

    // Deterministic (RFC6979) signature
    Signature Sign(const std::array<uint8_t,32>& msgHash) const;

    // Export WIF format
    std::string ToWIF() const;

    // Import WIF
    static PrivateKey FromWIF(const std::string& wif);

private:
    bool valid;
    bool compressed;
    std::array<uint8_t, 32> key;  // 256-bit scalar
};


//
// ===============================================================
//  CLASS: ECDSA - Core SECP256K1 Math
// ===============================================================
//
//  - Implements:
//      * Scalar operations
//      * Point multiplication
//      * Deterministic k (RFC 6979)
//      * Signature create/verify
//      * Curve constants
//
// ===============================================================
//
class ECDSA
{
public:
    // secp256k1 curve order (n)
    static const std::array<uint8_t, 32> curve_n;

    // Generator point G (uncompressed)
    static const std::array<uint8_t, 65> G;

    // Add two scalars mod n
    static void ScalarAdd(const uint8_t* a, const uint8_t* b, uint8_t* out);

    // Multiply scalar by generator: out = k*G
    static bool PointMultiply(const uint8_t* scalar, std::vector<uint8_t>& outPub);

    // Deterministic nonce (RFC 6979)
    static std::array<uint8_t,32> RFC6979(const std::array<uint8_t,32>& prv,
                                          const std::array<uint8_t,32>& msg);

    // ECDSA sign
    static Signature Sign(const std::array<uint8_t,32>& prv,
                          const std::array<uint8_t,32>& msg);

    // ECDSA verify
    static bool Verify(const std::vector<uint8_t>& pubkey,
                       const std::array<uint8_t,32>& msg,
                       const Signature& sig);
};

#endif // DRACHMA_ECDSA_H
