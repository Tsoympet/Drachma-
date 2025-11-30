#include "base58.h"
#include "hash.h"
#include <algorithm>

static const char* ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static int8_t MAP[256];

static void InitMap()
{
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    std::fill(std::begin(MAP), std::end(MAP), -1);

    for (int i = 0; i < 58; ++i)
        MAP[(uint8_t)ALPHABET[i]] = i;
}

std::string Base58::Encode(const std::vector<uint8_t>& data)
{
    InitMap();

    // Count leading zeros
    int zeros = 0;
    while (zeros < (int)data.size() && data[zeros] == 0)
        zeros++;

    std::vector<uint8_t> input(data.begin(), data.end());
    std::vector<uint8_t> temp;

    int start = zeros;
    while (start < (int)input.size())
    {
        int carry = 0;
        temp.clear();

        for (int i = start; i < (int)input.size(); i++)
        {
            int v = (int)input[i] + carry * 256;
            input[i] = v / 58;
            carry = v % 58;
        }

        while (start < (int)input.size() && input[start] == 0)
            start++;

        temp.push_back(carry);
    }

    std::string result;
    result.reserve(zeros + temp.size());

    // Leading zeros
    for (int i = 0; i < zeros; ++i)
        result.push_back('1');

    // Digits
    for (auto it = temp.rbegin(); it != temp.rend(); ++it)
        result.push_back(ALPHABET[*it]);

    return result;
}

bool Base58::Decode(const std::string& str, std::vector<uint8_t>& out)
{
    InitMap();
    out.clear();

    int zeros = 0;
    while (zeros < (int)str.size() && str[zeros] == '1')
        zeros++;

    std::vector<uint8_t> b256((str.size() - zeros) * 733 / 1000 + 1);

    int length = 0;

    for (int i = zeros; i < (int)str.size(); i++)
    {
        int carry = MAP[(uint8_t)str[i]];
        if (carry < 0) return false;

        int j = 0;
        for (auto it = b256.rbegin(); it != b256.rend() && (carry != 0 || j < length); it++, j++)
        {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        length = j;
    }

    // Skip leading zeros in b256
    auto it = b256.begin();
    while (it != b256.end() && *it == 0)
        ++it;

    out.reserve(zeros + (b256.end() - it));
    out.assign(zeros, 0);
    out.insert(out.end(), it, b256.end());
    return true;
}

uint32_t Base58::Checksum(const std::vector<uint8_t>& data)
{
    auto h = Hash::SHA256D(data);
    return (h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3];
}

std::string Base58::EncodeCheck(const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> buf = data;

    uint32_t cs = Checksum(data);
    buf.push_back((cs >> 24) & 0xFF);
    buf.push_back((cs >> 16) & 0xFF);
    buf.push_back((cs >> 8)  & 0xFF);
    buf.push_back((cs      ) & 0xFF);

    return Encode(buf);
}

bool Base58::DecodeCheck(const std::string& str, std::vector<uint8_t>& out)
{
    std::vector<uint8_t> buf;

    if (!Decode(str, buf) || buf.size() < 4)
        return false;

    uint32_t cs1 =
        (buf[buf.size()-4] << 24) |
        (buf[buf.size()-3] << 16) |
        (buf[buf.size()-2] << 8)  |
        (buf[buf.size()-1]);

    buf.resize(buf.size()-4);

    uint32_t cs2 = Checksum(buf);
    if (cs1 != cs2)
        return false;

    out = buf;
    return true;
}
