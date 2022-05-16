// TOTP.cpp
//
#include "TOTP/TOTP.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <vector>
#include <stack>
#include <queue>
#include <sstream>
#include <iomanip>
using namespace std;

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

    if (uc.back() == 0) uc.pop_back();
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
    vector<unsigned char> bytes;
    unsigned char*        emp = (unsigned char*)&tt;
    for (int i = sizeof(tt) - 1; i >= 0; i--) bytes.push_back(emp[i]);
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
string hash_to_TOTP(unsigned char* hmac, unsigned int length, int digit)
{
    stringstream ss;
    for (size_t i = 0; i < length; i++) // get hash string from hmac
    {
        ss << setfill('0') << setw(2) << hex << (int)hmac[i];
    }

    string raw_key;
    ss >> raw_key;

    ss.str("");
    ss.clear();

    unsigned overflow_key;
    ss << hex << raw_key.substr((int)hmac[19] % 16 * 2, 8);
    ss >> overflow_key;
    ss.str("");
    ss.clear();

    int safe_key = overflow_key &= 0x7fffffff; // abandon bits over signed int
    int out_key  = safe_key % fastpow(10, digit);

    string result;
    ss << setw(digit) << setfill('0') << to_string(out_key);
    ss >> result;
    ss.str("");
    ss.clear();

    return result;
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
    const EVP_MD*  emd;
    switch (algorithm)
    {
    case HMAC_SHA1:
        emd = EVP_sha1();
        break;
    case HMAC_SHA256:
        emd = EVP_sha256();
        break;
    case HMAC_SHA512:
        emd = EVP_sha512();
        break;
    default:
        abort();
    }
    HMAC(emd, h_key.data(), (int)h_key.size(), h_msg.data(), (int)h_msg.size(), out_hmac, &out_hmac_length);

    string fine = hash_to_TOTP(out_hmac, out_hmac_length, digit);
    delete[] out_hmac;

    return fine; // calculate TOTP according to RFC standard
}

std::string TOTP::currentTOTP()
{
    return GenerateTOTP(digit, refreshSeconds, algorithm, secret, getUnixTime());
}
