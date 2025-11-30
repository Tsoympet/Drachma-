#include "key.h"
#include "base58.h"
#include "hash.h"
#include <cstring>
#include <cassert>

//
// ===================================================================
//  Constructor
// ===================================================================
Key::Key()
{
    valid = false;
    compressed = true;
    privKey.fill(0);
}

Key::Key(const PrivateKey& pk)
{
    if (!pk.IsValid())
    {
        valid = false;
        compressed = true;
        privKey.fill(0);
        return;
    }

    valid = true;
    compressed = pk.IsCompressed();
    privKey = pk.GetKeyRaw();
}

//
// ===================================================================
//  Generate new private key
// ===================================================================
Key Key::Generate(bool compressed)
{
    PrivateKey pk = PrivateKey::Generate(compressed);
    return Key(pk);
}

//
// ===================================================================
//  SetPrivateKey
// ===================================================================
bool Key::SetPrivateKey(const std::array<uint8_t,32>& pk, bool comp)
{
    PrivateKey test(pk);

    if (!test.IsValid())
    {
        valid = false;
        return false;
    }

    valid = true;
    compressed = comp;
    privKey = pk;
    return true;
}

//
// ===================================================================
//  Get private key
// ===================================================================
std::array<uint8_t,32> Key::GetPrivateKey() const
{
    return privKey;
}

//
// ===================================================================
//  WIF Export
// ===================================================================
std::string Key::ToWIF() const
{
    if (!valid) return "";

    std::vector<uint8_t> data;

    // Version byte (same as BTC mainnet WIF = 0x80)
    data.push_back(0x80);

    // Private key bytes
    data.insert(data.end(), privKey.begin(), privKey.end());

    if (compressed)
        data.push_back(0x01);

    return Base58::EncodeCheck(data);
}

//
// ===================================================================
//  WIF Import
// ===================================================================
Key Key::FromWIF(const std::string& wif)
{
    std::vector<uint8_t> buf;
    if (!Base58::DecodeCheck(wif, buf))
        return Key();

    if (buf.size() != 33 && buf.size() != 34)
        return Key();

    bool comp = false;

    if (buf.size() == 34)
    {
        if (buf.back() != 0x01)
            return Key();
        comp = true;
        buf.pop_back();
    }

    // Drop version byte (0x80)
    buf.erase(buf.begin());

    if (buf.size() != 32)
        return Key();

    std::array<uint8_t,32> priv;
    std::memcpy(priv.data(), buf.data(), 32);

    Key out;
    out.SetPrivateKey(priv, comp);
    return out;
}

//
// ===================================================================
//  Public key generation
// ===================================================================
PublicKey Key::GetPublicKey() const
{
    if (!valid)
        return PublicKey();

    PrivateKey pk(privKey);
    pk.SetCompressed(compressed);
    return pk.GetPublicKey();
}

std::vector<uint8_t> Key::GetPublicKeyBytes() const
{
    PublicKey pk = GetPublicKey();
    return pk.GetBytes();
}

//
// ===================================================================
//  Signing
// ===================================================================
Signature Key::Sign(const std::array<uint8_t,32>& msgHash) const
{
    assert(valid);

    PrivateKey pk(privKey);
    pk.SetCompressed(compressed);

    return pk.Sign(msgHash);
}

//
// ===================================================================
//  Verify
// ===================================================================
bool Key::Verify(const std::array<uint8_t,32>& msgHash,
                 const Signature& sig) const
{
    PublicKey pk = GetPublicKey();
    return pk.Verify(msgHash, sig);
}

//
// ===================================================================
//  Serialize
// ===================================================================
std::vector<uint8_t> Key::Serialize() const
{
    std::vector<uint8_t> data;
    data.reserve(35);

    data.push_back(valid ? 1 : 0);
    data.push_back(compressed ? 1 : 0);
    data.insert(data.end(), privKey.begin(), privKey.end());

    return data;
}

//
// ===================================================================
//  Deserialize
// ===================================================================
bool Key::Deserialize(const std::vector<uint8_t>& in)
{
    if (in.size() != 34)
        return false;

    valid = (in[0] != 0);
    compressed = (in[1] != 0);

    std::memcpy(privKey.data(), &in[2], 32);

    // Validate the key
    PrivateKey pk(privKey);
    if (!pk.IsValid())
    {
        valid = false;
        return false;
    }

    return true;
}
