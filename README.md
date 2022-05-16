# PureTOTP

> A minimal and dependency-free TOTP library written in C++.

PureTOTP is a small C++ library for generating TOTP codes without external dependencies.

## Features

- Minimal and easy to integrate
- No third-party dependencies
- Simple CMake build

## Project Structure

PureTOTP/
©À©¤ include/
©¦  ©¸©¤ TOTP/
©¦     ©¸©¤ TOTP.h
©À©¤ src/
©¦  ©¸©¤ TOTP.cpp
©¸©¤ CMakeLists.txt

## Requirements

- CMake 3.10+
- A C++11-compatible compiler

## Build

```bash
git clone https://github.com/Einztein/PureTOTP.git
cd PureTOTP

mkdir out
cd out

cmake ..
cmake --build .
```

## API

```cpp
class TOTP
{
public:
    const static int HMAC_SHA1   = 20;
    const static int HMAC_SHA256 = 32;
    const static int HMAC_SHA512 = 64;

    static std::string GenerateTOTP(const std::string& secret);
    static std::string GenerateTOTP(int digit, int refreshSeconds, int algorithm, const std::string& secret, time_t specTime);

    TOTP(int digit, int refreshSeconds, int algorithm, const std::string& secret);
    TOTP(const std::string& secret);

    std::string currentTOTP();
};
```

## Examples

### 1. Generate a TOTP with default settings

Defaults:

- Digits: `6`
- Refresh interval: `30` seconds
- Algorithm: `TOTP::HMAC_SHA1`

```cpp
#include <iostream>
#include <TOTP/TOTP.h>

int main() {
    std::string secret = "YOUR_SECRET";

    std::string code = TOTP::GenerateTOTP(secret);
    std::cout << "Current TOTP: " << code << std::endl;

    return 0;
}
```

### 2. Generate a TOTP for a specific time

```cpp
#include <iostream>
#include <ctime>
#include <TOTP/TOTP.h>

int main() {
    std::string secret = "YOUR_SECRET";
    time_t t = std::time(nullptr);

    std::string code = TOTP::GenerateTOTP(
        6,
        30,
        TOTP::HMAC_SHA1,
        secret,
        t
    );

    std::cout << "TOTP: " << code << std::endl;
    return 0;
}
```

### 3. Use the instance-based API

```cpp
#include <iostream>
#include <TOTP/TOTP.h>

int main() {
    TOTP totp("YOUR_SECRET");

    std::cout << "Current TOTP: " << totp.currentTOTP() << std::endl;
    return 0;
}
```

### 4. Use custom parameters

```cpp
#include <iostream>
#include <TOTP/TOTP.h>

int main() {
    TOTP totp(
        8,
        30,
        TOTP::HMAC_SHA256,
        "YOUR_SECRET"
    );

    std::cout << "Current TOTP: " << totp.currentTOTP() << std::endl;
    return 0;
}
```

## Minimal Example Project

```cpp
#include <iostream>
#include <TOTP/TOTP.h>

int main() {
    std::string secret = "YOUR_SECRET";

    std::cout << "Static API:   " << TOTP::GenerateTOTP(secret) << std::endl;

    TOTP totp(secret);
    std::cout << "Object API:   " << totp.currentTOTP() << std::endl;

    return 0;
}
```

## Notes

- `HMAC_SHA1`, `HMAC_SHA256`, and `HMAC_SHA512` are provided as algorithm selectors.
