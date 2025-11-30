#include "ripemd160.h"
#include <cstring>

static const uint32_t K1[5]  = {0x00000000,0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xA953FD4E};
static const uint32_t K2[5]  = {0x50A28BE6,0x5C4DD124,0x6D703EF3,0x7A6D76E9,0x00000000};

inline uint32_t ROTL(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

inline uint32_t f(int j, uint32_t x, uint32_t y, uint32_t z)
{
    if (j <= 15) return x ^ y ^ z;
    if (j <= 31) return (x & y) | (~x & z);
    if (j <= 47) return (x | ~y) ^ z;
    if (j <= 63) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
}

static const int r1[80] =
{
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
     7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
     3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
     1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
     4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13
};

static const int r2[80] =
{
     5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
     6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
    15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
     8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
    12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11
};

static const int s1[80] =
{
    11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
     7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
    11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
    11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8,13, 6, 5,
    12, 9,12, 5,15, 8, 8, 5,12, 9,12, 5,14, 6, 8,13
};

static const int s2[80] =
{
     8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
     9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
     9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
    15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
     8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15, 8,11,14
};

RIPEMD160::RIPEMD160()
{
    Reset();
}

void RIPEMD160::Reset()
{
    state[0]=0x67452301;
    state[1]=0xefcdab89;
    state[2]=0x98badcfe;
    state[3]=0x10325476;
    state[4]=0xc3d2e1f0;

    bitlen = 0;
    bufferLen = 0;
}

void RIPEMD160::Update(const uint8_t* data, size_t len)
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

void RIPEMD160::Update(const std::vector<uint8_t>& data)
{
    Update(data.data(), data.size());
}

void RIPEMD160::Update(const std::string& s)
{
    Update((const uint8_t*)s.data(), s.size());
}

void RIPEMD160::Transform(const uint8_t block[64])
{
    uint32_t X[16];
    for (int i = 0; i < 16; i++)
    {
        X[i] =
            block[i*4] |
            (block[i*4+1] << 8) |
            (block[i*4+2] << 16) |
            (block[i*4+3] << 24);
    }

    uint32_t A1 = state[0], B1 = state[1], C1 = state[2], D1 = state[3], E1 = state[4];
    uint32_t A2 = A1, B2 = B1, C2 = C1, D2 = D1, E2 = E1;

    for (int j = 0; j < 80; j++)
    {
        uint32_t T = ROTL(A1 + f(j, B1, C1, D1) + X[r1[j]] + K1[j/16], s1[j]) + E1;
        A1 = E1; E1 = D1; D1 = ROTL(C1, 10); C1 = B1; B1 = T;

        T = ROTL(A2 + f(79-j, B2, C2, D2) + X[r2[j]] + K2[j/16], s2[j]) + E2;
        A2 = E2; E2 = D2; D2 = ROTL(C2, 10); C2 = B2; B2 = T;
    }

    uint32_t T = state[1] + C1 + D2;
    state[1] = state[2] + D1 + E2;
    state[2] = state[3] + E1 + A2;
    state[3] = state[4] + A1 + B2;
    state[4] = state[0] + B1 + C2;
    state[0] = T;
}

void RIPEMD160::Final(uint8_t out[20])
{
    bitlen += bufferLen * 8;

    buffer[bufferLen++] = 0x80;

    if (bufferLen > 56)
    {
        while (bufferLen < 64) buffer[bufferLen++] = 0;
        Transform(buffer);
        bufferLen = 0;
    }

    while (bufferLen < 56)
        buffer[bufferLen++] = 0;

    for (int i = 0; i < 8; i++)
        buffer[bufferLen++] = (bitlen >> (8*i)) & 0xFF;

    Transform(buffer);

    for (int i = 0; i < 5; i++)
    {
        out[i*4]   =  state[i]        & 0xFF;
        out[i*4+1] = (state[i] >> 8)  & 0xFF;
        out[i*4+2] = (state[i] >> 16) & 0xFF;
        out[i*4+3] = (state[i] >> 24) & 0xFF;
    }
}

std::vector<uint8_t> RIPEMD160::Final()
{
    uint8_t out[20];
    Final(out);
    return std::vector<uint8_t>(out, out + 20);
}

std::vector<uint8_t> RIPEMD160::Hash(const std::vector<uint8_t>& data)
{
    RIPEMD160 ctx;
    ctx.Update(data);
    return ctx.Final();
}

std::vector<uint8_t> RIPEMD160::Hash(const uint8_t* data, size_t len)
{
    RIPEMD160 ctx;
    ctx.Update(data, len);
    return ctx.Final();
}
