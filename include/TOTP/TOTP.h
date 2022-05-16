// TOTP.h
//
#pragma once
#include <string>
class TOTP
{
public:
    const static int HMAC_SHA1   = 20;
    const static int HMAC_SHA256 = 32;
    const static int HMAC_SHA512 = 64;

    static std::string GenerateTOTP(const std::string& secret);
    static std::string GenerateTOTP(int digit, int refreshSeconds, int algorithm, const std::string& secret, time_t specTime);

    TOTP(int digit, int refreshSeconds, int algorithm, const std::string& secret): digit(digit), refreshSeconds(refreshSeconds), algorithm(algorithm), secret(secret) {}
    TOTP(const std::string& secret): digit(6), refreshSeconds(30), algorithm(HMAC_SHA1), secret(secret) {}

    std::string currentTOTP();

private:
    int digit, refreshSeconds, algorithm;

    std::string secret;
};