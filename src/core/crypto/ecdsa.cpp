#include "ecdsa.h"
#include "base58.h"
#include "hash.h"

#include "secp256k1/secp256k1.h"

#include <cstring>
#include <random>
#include <cassert>

static secp256k1_context* secpCtx = nullptr;

static void InitSecp()
{
    if (!secpCtx)
    {
        secpCtx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
}

//
// ================================================================
//  Signature DER encode
// ================================================================
std::vector<uint8_t> Signature::ToDER() const
{
    // Simple DER builder
    std::vector<uint8_t> out;
    out.reserve(72);

    out.push_back(0x30);  // sequence

    std::vector<uint8_t> ri(r.begin(), r.end());
    std::vector<uint8_t> si(s.begin(), s.end());

    // Trim leading zeros
    while (ri.size() > 1 && ri[0] == 0) ri.erase(ri.begin());
    while (si.size() > 1 && si[0] == 0) si.erase(si.begin());

    size_t len = 2 + ri.size() + 2 + si.size();
    out.push_back(len);

    // r
    out.push_back(0x02);
    out.push_back(ri.size());
    out.insert(out.end(), ri.begin(), ri.end());

    // s
    out.push_back(0x02);
    out.push_back(si.size());
    out.insert(out.end(), si.begin(), si.end());

    return out;
}

bool Signature::FromDER(const std::vector<uint8_t>& der, Signature& out)
{
    if (der.size() < 8) return false;
    if (der[0] != 0x30) return false;

    size_t p = 2; // skip sequence header

    if (der[p++] != 0x02) return false;
    int rlen = der[p++];
    if (rlen <= 0 || p + rlen > der.size()) return false;

    std::vector<uint8_t> rv(32, 0);
    std::memcpy(rv.data() + (32 - rlen), &der[p], rlen);
    p += rlen;

    if (der[p++] != 0x02) return false;
    int slen = der[p++];
    if (slen <= 0 || p + slen > der.size()) return false;

    std::vector<uint8_t> sv(32, 0);
    std::memcpy(sv.data() + (32 - slen), &der[p], slen);

    std::memcpy(out.r.data(), rv.data(), 32);
    std::memcpy(out.s.data(), sv.data(), 32);

    return true;
}

//
// ================================================================
//  PrivateKey
// ================================================================
PrivateKey::PrivateKey()
{
    valid = false;
    compressed = true;
    key.fill(0);
}

PrivateKey::PrivateKey(const std::array<uint8_t,32>& priv)
{
    InitSecp();

    if (secp256k1_ec_seckey_verify(secpCtx, priv.data()))
    {
        key = priv;
        valid = true;
        compressed = true;
    }
    else
    {
        valid = false;
        key.fill(0);
    }
}

PrivateKey PrivateKey::Generate(bool compressed)
{
    InitSecp();
    std::array<uint8_t,32> k;

    std::random_device rd;
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);

    do {
        for (int i = 0; i < 8; ++i)
        {
            uint32_t r = dist(rd);
            std::memcpy(k.data() + i*4, &r, 4);
        }
    } while (!secp256k1_ec_seckey_verify(secpCtx, k.data()));

    PrivateKey out(k);
    out.compressed = compressed;
    return out;
}

PublicKey PrivateKey::GetPublicKey() const
{
    assert(valid);
    InitSecp();

    secp256k1_pubkey pub;
    secp256k1_ec_pubkey_create(secpCtx, &pub, key.data());

    size_t outlen = compressed ? 33 : 65;
    std::vector<uint8_t> buf(outlen);

    unsigned int flags = compressed ?
        SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    secp256k1_ec_pubkey_serialize(secpCtx, buf.data(), &outlen, &pub, flags);

    if (compressed)
    {
        std::array<uint8_t,33> c;
        std::memcpy(c.data(), buf.data(), 33);
        return PublicKey(c);
    }
    else
    {
        std::array<uint8_t,65> u;
        std::memcpy(u.data(), buf.data(), 65);
        return PublicKey(u);
    }
}

Signature PrivateKey::Sign(const std::array<uint8_t,32>& msgHash) const
{
    assert(valid);
    InitSecp();

    secp256k1_ecdsa_signature sig;
    secp256k1_ecdsa_sign(secpCtx, &sig, msgHash.data(), key.data(), NULL, NULL);

    // Normalize (important)
    secp256k1_ecdsa_signature_normalize(secpCtx, &sig, &sig);

    Signature out;
    secp256k1_ecdsa_signature_serialize_compact(secpCtx,
        out.r.data(), &sig);

    // The compact format gives us 64 bytes: r||s
    std::array<uint8_t,64> tmp;
    secp256k1_ecdsa_signature_serialize_compact(secpCtx, tmp.data(), &sig);

    std::memcpy(out.r.data(), tmp.data(), 32);
    std::memcpy(out.s.data(), tmp.data() + 32, 32);

    return out;
}

std::string PrivateKey::ToWIF() const
{
    std::vector<uint8_t> buf;

    // Version byte (Bitcoin mainnet = 0x80)
    buf.push_back(0x80);
    buf.insert(buf.end(), key.begin(), key.end());

    if (compressed)
        buf.push_back(0x01);

    return Base58::EncodeCheck(buf);
}

PrivateKey PrivateKey::FromWIF(const std::string& wif)
{
    std::vector<uint8_t> buf;

    if (!Base58::DecodeCheck(wif, buf))
        return PrivateKey();

    if (buf.size() != 33 && buf.size() != 34)
        return PrivateKey();

    bool comp = false;
    if (buf.size() == 34)
    {
        if (buf.back() != 0x01)
            return PrivateKey();
        comp = true;
        buf.pop_back();
    }

    // Remove version byte
    buf.erase(buf.begin());

    std::array<uint8_t,32> priv;
    std::memcpy(priv.data(), buf.data(), 32);

    PrivateKey pk(priv);
    pk.compressed = comp;
    return pk;
}

//
// ================================================================
//  PublicKey
// ================================================================
PublicKey::PublicKey()
{
    valid = false;
    compressed = true;
}

PublicKey::PublicKey(const std::array<uint8_t,33>& c)
{
    InitSecp();
    compressed = true;

    secp256k1_pubkey pub;
    if (secp256k1_ec_pubkey_parse(secpCtx, &pub, c.data(), 33))
    {
        valid = true;
        keydata.assign(c.begin(), c.end());
    }
    else
    {
        valid = false;
    }
}

PublicKey::PublicKey(const std::array<uint8_t,65>& u)
{
    InitSecp();
    compressed = false;

    secp256k1_pubkey pub;
    if (secp256k1_ec_pubkey_parse(secpCtx, &pub, u.data(), 65))
    {
        valid = true;
        keydata.assign(u.begin(), u.end());
    }
    else
    {
        valid = false;
    }
}

bool PublicKey::Verify(const std::array<uint8_t,32>& msgHash, const Signature& sig) const
{
    if (!valid) return false;
    InitSecp();

    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_parse(secpCtx, &pub, keydata.data(), keydata.size()))
        return false;

    secp256k1_ecdsa_signature secpSig;
    std::array<uint8_t,64> tmp;

    std::memcpy(tmp.data(), sig.r.data(), 32);
    std::memcpy(tmp.data()+32, sig.s.data(), 32);

    secp256k1_ecdsa_signature_parse_compact(secpCtx, &secpSig, tmp.data());

    return secp256k1_ecdsa_verify(secpCtx, &secpSig, msgHash.data(), &pub);
}

//
// ================================================================
//  ECDSA class (wrappers)
// ================================================================
const std::array<uint8_t,32> ECDSA::curve_n = {
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,
  0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,
  0xD0,0x36,0x41,0x41,0x02,0xDF,0xA9,0x89
};

const std::array<uint8_t,65> ECDSA::G = {
    0x04,
    0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,
    0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
    0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,
    0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98,
    0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,
    0x5D,0xA4,0xFB,0xFC,0x0E,0x11,0x08,0xA8,
    0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,
    0x9C,0x47,0xD0,0x8F,0xFB,0x10,0xD4,0xB8
};

void ECDSA::ScalarAdd(const uint8_t* a, const uint8_t* b, uint8_t* out)
{
    // This is rarely needed; left as a placeholder
}

bool ECDSA::PointMultiply(const uint8_t* scalar, std::vector<uint8_t>& outPub)
{
    InitSecp();
    secp256k1_pubkey pub;

    if (!secp256k1_ec_pubkey_create(secpCtx, &pub, scalar))
        return false;

    size_t len = 33;
    outPub.resize(33);
    secp256k1_ec_pubkey_serialize(secpCtx, outPub.data(), &len, &pub, SECP256K1_EC_COMPRESSED);

    return true;
}

std::array<uint8_t,32> ECDSA::RFC6979(const std::array<uint8_t,32>& prv,
                                     const std::array<uint8_t,32>& msg)
{
    // RFC6979 handled internally by libsecp256k1
    return msg;
}

Signature ECDSA::Sign(const std::array<uint8_t,32>& prv,
                      const std::array<uint8_t,32>& msg)
{
    PrivateKey p(prv);
    return p.Sign(msg);
}

bool ECDSA::Verify(const std::vector<uint8_t>& pubkey,
                   const std::array<uint8_t,32>& msg,
                   const Signature& sig)
{
    PublicKey p = (pubkey.size() == 33 ?
        PublicKey(*(const std::array<uint8_t,33>*)pubkey.data()) :
        PublicKey(*(const std::array<uint8_t,65>*)pubkey.data()));

    return p.Verify(msg, sig);
}
