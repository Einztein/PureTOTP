// TOTP.cpp
//
#include "TOTP/TOTP.h"
#include <vector>
#include <stack>
#include <queue>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <array>
#include <stdexcept>
#include <algorithm>
using namespace std;

struct JEVP_MD
{
    enum Kind {
        SHA1,
        SHA256,
        SHA512
    };

    Kind kind;
    int  md_size;
    int  block_size;
};

static inline uint32_t rotl32(uint32_t x, uint32_t n) { return (x << n) | (x >> (32 - n)); }
static inline uint32_t rotr32(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
static inline uint64_t rotr64(uint64_t x, uint64_t n) { return (x >> n) | (x << (64 - n)); }

static uint32_t load_be32(const unsigned char* p)
{
    return (uint32_t(p[0]) << 24) |
           (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) |
           uint32_t(p[3]);
}

static uint64_t load_be64(const unsigned char* p)
{
    return (uint64_t(p[0]) << 56) |
           (uint64_t(p[1]) << 48) |
           (uint64_t(p[2]) << 40) |
           (uint64_t(p[3]) << 32) |
           (uint64_t(p[4]) << 24) |
           (uint64_t(p[5]) << 16) |
           (uint64_t(p[6]) << 8) |
           uint64_t(p[7]);
}

static void store_be32(uint32_t v, unsigned char* p)
{
    p[0] = static_cast<unsigned char>((v >> 24) & 0xFF);
    p[1] = static_cast<unsigned char>((v >> 16) & 0xFF);
    p[2] = static_cast<unsigned char>((v >> 8) & 0xFF);
    p[3] = static_cast<unsigned char>(v & 0xFF);
}

static void store_be64(uint64_t v, unsigned char* p)
{
    p[0] = static_cast<unsigned char>((v >> 56) & 0xFF);
    p[1] = static_cast<unsigned char>((v >> 48) & 0xFF);
    p[2] = static_cast<unsigned char>((v >> 40) & 0xFF);
    p[3] = static_cast<unsigned char>((v >> 32) & 0xFF);
    p[4] = static_cast<unsigned char>((v >> 24) & 0xFF);
    p[5] = static_cast<unsigned char>((v >> 16) & 0xFF);
    p[6] = static_cast<unsigned char>((v >> 8) & 0xFF);
    p[7] = static_cast<unsigned char>(v & 0xFF);
}

static vector<unsigned char> sha1_hash(const unsigned char* data, size_t len)
{
    vector<unsigned char> msg(data, data + len);
    uint64_t              bit_len = static_cast<uint64_t>(len) * 8;

    msg.push_back(0x80);
    while ((msg.size() % 64) != 56) msg.push_back(0x00);

    unsigned char lenbuf[8];
    store_be64(bit_len, lenbuf);
    msg.insert(msg.end(), lenbuf, lenbuf + 8);

    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    for (size_t chunk = 0; chunk < msg.size(); chunk += 64)
    {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = load_be32(&msg[chunk + i * 4]);
        for (int i = 16; i < 80; ++i)
            w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;

        for (int i = 0; i < 80; ++i)
        {
            uint32_t f, k;
            if (i < 20)
            {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (i < 40)
            {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (i < 60)
            {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else
            {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = rotl32(a, 5) + f + e + k + w[i];

            e = d;
            d = c;
            c = rotl32(b, 30);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    vector<unsigned char> out(20);
    store_be32(h0, &out[0]);
    store_be32(h1, &out[4]);
    store_be32(h2, &out[8]);
    store_be32(h3, &out[12]);
    store_be32(h4, &out[16]);
    return out;
}

static vector<unsigned char> sha256_hash(const unsigned char* data, size_t len)
{
    static const uint32_t K[64] =
        {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    vector<unsigned char> msg(data, data + len);
    uint64_t              bit_len = static_cast<uint64_t>(len) * 8;

    msg.push_back(0x80);
    while ((msg.size() % 64) != 56) msg.push_back(0x00);

    unsigned char lenbuf[8];
    store_be64(bit_len, lenbuf);
    msg.insert(msg.end(), lenbuf, lenbuf + 8);

    uint32_t h[8] =
        {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    for (size_t chunk = 0; chunk < msg.size(); chunk += 64)
    {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = load_be32(&msg[chunk + i * 4]);

        for (int i = 16; i < 64; ++i)
        {
            uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i]        = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i = 0; i < 64; ++i)
        {
            uint32_t S1    = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            uint32_t ch    = (e & f) ^ ((~e) & g);
            uint32_t temp1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0    = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            uint32_t maj   = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            hh = g;
            g  = f;
            f  = e;
            e  = d + temp1;
            d  = c;
            c  = b;
            b  = a;
            a  = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    vector<unsigned char> out(32);
    for (int i = 0; i < 8; ++i)
        store_be32(h[i], &out[i * 4]);
    return out;
}

static vector<unsigned char> sha512_hash(const unsigned char* data, size_t len)
{
    static const uint64_t K[80] =
        {
            0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
            0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
            0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
            0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
            0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
            0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
            0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
            0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
            0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
            0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
            0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
            0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
            0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
            0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
            0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
            0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
            0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
            0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
            0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
            0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

    vector<unsigned char> msg(data, data + len);
    uint64_t              bit_len_low = static_cast<uint64_t>(len) * 8;

    msg.push_back(0x80);
    while ((msg.size() % 128) != 112) msg.push_back(0x00);

    unsigned char high[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char low[8];
    store_be64(bit_len_low, low);
    msg.insert(msg.end(), high, high + 8);
    msg.insert(msg.end(), low, low + 8);

    uint64_t h[8] =
        {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

    for (size_t chunk = 0; chunk < msg.size(); chunk += 128)
    {
        uint64_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = load_be64(&msg[chunk + i * 8]);

        for (int i = 16; i < 80; ++i)
        {
            uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
            uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i]        = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint64_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint64_t e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i = 0; i < 80; ++i)
        {
            uint64_t S1    = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
            uint64_t ch    = (e & f) ^ ((~e) & g);
            uint64_t temp1 = hh + S1 + ch + K[i] + w[i];
            uint64_t S0    = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
            uint64_t maj   = (a & b) ^ (a & c) ^ (b & c);
            uint64_t temp2 = S0 + maj;

            hh = g;
            g  = f;
            f  = e;
            e  = d + temp1;
            d  = c;
            c  = b;
            b  = a;
            a  = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    vector<unsigned char> out(64);
    for (int i = 0; i < 8; ++i)
        store_be64(h[i], &out[i * 8]);
    return out;
}

static vector<unsigned char> digest_once(const JEVP_MD* JEVP_MD, const unsigned char* data, size_t len)
{
    if (!JEVP_MD) throw std::invalid_argument("JEVP_MD is null");

    switch (JEVP_MD->kind)
    {
    case JEVP_MD::SHA1: return sha1_hash(data, len);
    case JEVP_MD::SHA256: return sha256_hash(data, len);
    case JEVP_MD::SHA512: return sha512_hash(data, len);
    default: throw std::invalid_argument("unsupported digest");
    }
}

static const JEVP_MD g_sha1   = {JEVP_MD::SHA1, 20, 64};
static const JEVP_MD g_sha256 = {JEVP_MD::SHA256, 32, 64};
static const JEVP_MD g_sha512 = {JEVP_MD::SHA512, 64, 128};

const JEVP_MD* JEVP_sha1() { return &g_sha1; }
const JEVP_MD* JEVP_sha256() { return &g_sha256; }
const JEVP_MD* JEVP_sha512() { return &g_sha512; }

unsigned char* JHMAC(const JEVP_MD* JEVP_MD, const void* key, int key_len, const unsigned char* data, size_t data_len, unsigned char* md, unsigned int* md_len)
{
    if (!JEVP_MD || !key || key_len < 0 || !data)
        return nullptr;

    static thread_local unsigned char static_md[64];

    if (!md)
        md = static_md;

    vector<unsigned char> key_block(JEVP_MD->block_size, 0);
    const unsigned char*  key_bytes = static_cast<const unsigned char*>(key);

    vector<unsigned char> real_key;
    if (key_len > JEVP_MD->block_size)
    {
        real_key = digest_once(JEVP_MD, key_bytes, static_cast<size_t>(key_len));
        std::copy(real_key.begin(), real_key.end(), key_block.begin());
    }
    else
    {
        std::copy(key_bytes, key_bytes + key_len, key_block.begin());
    }

    vector<unsigned char> ipad(JEVP_MD->block_size);
    vector<unsigned char> opad(JEVP_MD->block_size);
    for (int i = 0; i < JEVP_MD->block_size; ++i)
    {
        ipad[i] = static_cast<unsigned char>(key_block[i] ^ 0x36);
        opad[i] = static_cast<unsigned char>(key_block[i] ^ 0x5C);
    }

    vector<unsigned char> inner;
    inner.reserve(JEVP_MD->block_size + data_len);
    inner.insert(inner.end(), ipad.begin(), ipad.end());
    inner.insert(inner.end(), data, data + data_len);

    vector<unsigned char> inner_hash = digest_once(JEVP_MD, inner.data(), inner.size());

    vector<unsigned char> outer;
    outer.reserve(JEVP_MD->block_size + inner_hash.size());
    outer.insert(outer.end(), opad.begin(), opad.end());
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());

    vector<unsigned char> final_hash = digest_once(JEVP_MD, outer.data(), outer.size());

    std::memcpy(md, final_hash.data(), final_hash.size());
    if (md_len) *md_len = static_cast<unsigned int>(final_hash.size());

    return md;
}

// Base32 decoding table
/* clang-format off */
const int base32_reverse_map[128] =
{
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 15
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 31
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 47
 //      (49)   2    3    4    5    6    7  (56)
    255, 255,  26,  27,  28,  29,  30,  31, 255, 255, 255, 255, 255, 255, 255, 255, // 63
 // (64)   A    B    C    D    E    F    G    H    I    J    K    L    M    N    O
    255,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14, // 79
 //   P    Q    R    S    T    U    V    W    X    Y    Z  (91)
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255, // 95
 // (96)   A    B    C    D    E    F    G    H    I    J    K    L    M    N    O  // lower case instead
    255,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14, // 111
 //   P    Q    R    S    T    U    V    W    X    Y    Z (123)                     // lower case instead
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255  // 127
};
/* clang-format on */

// Base32 decoding function
vector<unsigned char> base32_decode(const string& base32)
{
    queue<int> q_rev;
    for (const char& c : base32)
    {
        if (c <= 49 || (c >= 56 && c <= 64) || (c >= 91 && c <= 96) || c >= 123)
        { // illegal lower case will be treat as upper case thanks to base32_reverse_map
            if (c == '=') break;
            else throw std::runtime_error("illegal base32"); // meet illegal base32 char, return empty
        }
        else
        {
            q_rev.push(base32_reverse_map[(int)c]); // get integers of base32
        }
    }
    queue<bool> q_bin;
    while (!q_rev.empty()) // transform the integers into bits and queue them up
    {
        int now = q_rev.front(); // get a integer from queue
        q_rev.pop();
        stack<bool> sb;
        for (int i = 0; i < 5; i++) // push the bits of this integer into stack
        {                           // 5 bits into 1 group
            sb.push(now & 1);       // push the last bit of this integer into stack
            now >>= 1;              // flush the last bit
        }
        while (!sb.empty()) // flush the bits of this integer into binary queue
        {
            q_bin.push(sb.top()); // pop bits from stack into binary queue
            sb.pop();
        }
    }
    vector<unsigned char> uc;
    while (!q_bin.empty()) // transform the bits into bytes
    {
        int thehex = 0;
        for (int i = 0; i < 8; i++) // read a byte from the bits queue
        {
            if (q_bin.empty())
            {                     // if the bits queue is empty now
                thehex <<= 8 - i; // set 0 on the last bits of a byte
                break;
            }
            thehex <<= 1;                 // make the space for the new bit
            thehex |= (int)q_bin.front(); // push this bit into byte
            q_bin.pop();
        }
        uc.push_back((unsigned char)thehex);
    }

    if (uc.back() == 0) uc.pop_back();     // totp may abandon last zero
    if (uc.size() % 2 != 0) uc.pop_back(); // totp may abandon odd res
    return uc;
}

// Get Unix Time
time_t getUnixTime()
{
    return time(0);
}

// Culculate the TOTP time signature
time_t getTimeSign(int refreshPeriod, time_t specUnixTime)
{
    time_t outTime = specUnixTime / refreshPeriod;
    return outTime;
}

// transform time_t aka <long long> to bytes
vector<unsigned char> llong2bytes(time_t tt)
{
    uint64_t value = static_cast<uint64_t>(tt);

    vector<unsigned char> bytes(8);

    for (int i = 7; i >= 0; --i)
    {
        bytes[i] = static_cast<unsigned char>(value & 0xFF);
        value >>= 8;
    }

    return bytes;
}

// Fast Exponentiation algorithm
unsigned fastpow(unsigned base, unsigned index)
{
    if (index == 0) return 1;
    unsigned t = 1;
    while (index != 0)
    {
        if (index & 1) t *= base;
        index >>= 1;
        base *= base;
    }
    return t;
}

// calculate TOTP according to RFC standard
std::string hash_to_TOTP(const unsigned char* hmac, unsigned int length, int digit)
{
    int offset = hmac[length - 1] & 0x0F;

    uint32_t bin_code = ((hmac[offset] & 0x7F) << 24) |
                        ((hmac[offset + 1] & 0xFF) << 16) |
                        ((hmac[offset + 2] & 0xFF) << 8) |
                        (hmac[offset + 3] & 0xFF);

    uint32_t mod = 1;
    for (int i = 0; i < digit; ++i) mod *= 10;

    uint32_t otp = bin_code % mod;

    std::ostringstream oss;
    oss << std::setw(digit) << std::setfill('0') << otp;
    return oss.str();
}

std::string TOTP::GenerateTOTP(const std::string& secret)
{
    return GenerateTOTP(6, 30, HMAC_SHA1, secret, getUnixTime());
}

std::string TOTP::GenerateTOTP(int digit, int refreshSeconds, int algorithm, const std::string& secret, time_t specTime)
{
    if (refreshSeconds <= 0) throw std::invalid_argument("refreshSeconds must be > 0");
    vector<unsigned char> h_msg = llong2bytes(getTimeSign(refreshSeconds, specTime)); // get current time signature and transform time_t aka <long long> to bytes
    vector<unsigned char> h_key = base32_decode(secret);                              // transform base32 encoded secret key to decoded bytes

    unsigned char* out_hmac = new unsigned char[algorithm]; // perform openssl function to calculate HMAC-SHA1 hash
    unsigned int   out_hmac_length;
    const JEVP_MD* emd;
    switch (algorithm)
    {
    case HMAC_SHA1:
        emd = JEVP_sha1();
        break;
    case HMAC_SHA256:
        emd = JEVP_sha256();
        break;
    case HMAC_SHA512:
        emd = JEVP_sha512();
        break;
    default:
        throw std::invalid_argument("unsupported algorithm");
    }
    JHMAC(emd, h_key.data(), (int)h_key.size(), h_msg.data(), (int)h_msg.size(), out_hmac, &out_hmac_length);

    string fine = hash_to_TOTP(out_hmac, out_hmac_length, digit);
    delete[] out_hmac;

    return fine; // calculate TOTP according to RFC standard
}

std::string TOTP::currentTOTP()
{
    return GenerateTOTP(digit, refreshSeconds, algorithm, secret, getUnixTime());
}
