#include "hash.h"
#include <cstring>

std::vector<uint8_t> Hash::SHA256D(const std::vector<uint8_t>& data)
{
    auto h1 = SHA256(data);
    return SHA256(h1);
}

std::vector<uint8_t> Hash::SHA256D(const uint8_t* data, size_t len)
{
    std::vector<uint8_t> v(data, data + len);
    return SHA256D(v);
}

std::vector<uint8_t> Hash::Hash160(const std::vector<uint8_t>& data)
{
    auto sha = SHA256(data);
    return RIPEMD160::Hash(sha);
}

std::vector<uint8_t> Hash::Hash160(const uint8_t* data, size_t len)
{
    std::vector<uint8_t> v(data, data + len);
    return Hash160(v);
}

std::vector<uint8_t> Hash::SHA256(const std::vector<uint8_t>& data)
{
    SHA256 ctx;
    ctx.Update(data);
    return ctx.Final();
}

//
// HMAC-SHA256 implementation
//
std::vector<uint8_t> Hash::HMAC_SHA256(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data)
{
    const size_t BLOCK_SIZE = 64;

    std::vector<uint8_t> k = key;

    // Key longer than block → hash it
    if (k.size() > BLOCK_SIZE)
        k = SHA256(k);

    // Pad key to 64 bytes
    k.resize(BLOCK_SIZE, 0x00);

    std::vector<uint8_t> o_key_pad(BLOCK_SIZE);
    std::vector<uint8_t> i_key_pad(BLOCK_SIZE);

    for (size_t i = 0; i < BLOCK_SIZE; ++i)
    {
        o_key_pad[i] = k[i] ^ 0x5c;
        i_key_pad[i] = k[i] ^ 0x36;
    }

    // inner hash = SHA256(i_key_pad || data)
    std::vector<uint8_t> inner(i_key_pad);
    inner.insert(inner.end(), data.begin(), data.end());

    auto innerHash = SHA256(inner);

    // outer hash = SHA256(o_key_pad || inner_hash)
    std::vector<uint8_t> outer(o_key_pad);
    outer.insert(outer.end(), innerHash.begin(), innerHash.end());

    return SHA256(outer);
}
