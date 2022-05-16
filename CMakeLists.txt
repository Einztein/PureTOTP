cmake_minimum_required(VERSION 3.10)

project(TOTP LANGUAGES CXX)

add_library(TOTP STATIC
    src/TOTP.cpp
)

target_include_directories(TOTP PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(TOTP PUBLIC cxx_std_11)
