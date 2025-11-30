#include "sha256.h"
#include <cstring>

static const uint32_t K[64] =
{
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline uint32_t ROTR(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32 - n));
}

inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t Sigma0(uint32_t x)
{
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

inline uint32_t Sigma1(uint32_t x)
{
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

inline uint32_t sigma0(uint32_t x)
{
    return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
}

inline uint32_t sigma1(uint32_t x)
{
    return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
}

SHA256::SHA256()
{
    Reset();
}

void SHA256::Reset()
{
    state[0]=0x6a09e667;
    state[1]=0xbb67ae85;
    state[2]=0x3c6ef372;
    state[3]=0xa54ff53a;
    state[4]=0x510e527f;
    state[5]=0x9b05688c;
    state[6]=0x1f83d9ab;
    state[7]=0x5be0cd19;

    bitlen = 0;
    bufferLen = 0;
}

void SHA256::Update(const uint8_t* data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        buffer[bufferLen++] = data[i];
        if (bufferLen == 64)
        {
            Transform(buffer);
            bitlen += 512;
            bufferLen = 0;
        }
    }
}

void SHA256::Update(const std::vector<uint8_t>& data)
{
    Update(data.data(), data.size());
}

void SHA256::Update(const std::string& s)
{
    Update((const uint8_t*)s.data(), s.size());
}

void SHA256::Transform(const uint8_t block[64])
{
    uint32_t m[64];
    for (int i = 0; i < 16; i++)
    {
        m[i] =
            (block[i * 4] << 24) |
            (block[i * 4 + 1] << 16) |
            (block[i * 4 + 2] << 8) |
            block[i * 4 + 3];
    }

    for (int i = 16; i < 64; i++)
        m[i] = sigma1(m[i - 2]) + m[i - 7] + sigma0(m[i - 15]) + m[i - 16];

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (int i = 0; i < 64; i++)
    {
        uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + m[i];
        uint32_t t2 = Sigma0(a) + Maj(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void SHA256::Final(uint8_t out[32])
{
    bitlen += bufferLen * 8;

    buffer[bufferLen++] = 0x80;

    if (bufferLen > 56)
    {
        while (bufferLen < 64)
            buffer[bufferLen++] = 0;

        Transform(buffer);
        bufferLen = 0;
    }

    while (bufferLen < 56)
        buffer[bufferLen++] = 0;

    for (int i = 7; i >= 0; i--)
        buffer[bufferLen++] = (bitlen >> (i * 8)) & 0xFF;

    Transform(buffer);

    for (int i = 0; i < 8; i++)
    {
        out[i * 4]     = (state[i] >> 24) & 0xFF;
        out[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        out[i * 4 + 2] = (state[i] >> 8)  & 0xFF;
        out[i * 4 + 3] = state[i] & 0xFF;
    }
}

std::vector<uint8_t> SHA256::Final()
{
    uint8_t out[32];
    Final(out);
    return std::vector<uint8_t>(out, out + 32);
}

std::vector<uint8_t> SHA256::Hash(const std::vector<uint8_t>& data)
{
    SHA256 ctx;
    ctx.Update(data);
    return ctx.Final();
}

std::vector<uint8_t> SHA256::Hash(const uint8_t* data, size_t len)
{
    SHA256 ctx;
    ctx.Update(data, len);
    return ctx.Final();
}
