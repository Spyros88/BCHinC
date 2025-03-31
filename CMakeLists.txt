cmake_minimum_required(VERSION 3.10.0)
project(BTC VERSION 0.1.0 LANGUAGES C)
# Manually specify OpenSSL paths
set(OPENSSL_ROOT_DIR "/usr/lib/x86_64-linux-gnu")
set(OPENSSL_INCLUDE_DIR "/usr/include")

# Manually set secp256k1 include and library paths
set(SECP256K1_INCLUDE_DIR "/usr/include")
set(SECP256K1_LIB "/usr/lib/x86_64-linux-gnu/libsecp256k1.so")

# Manually set libbech32 include and lirary paths
set(LIBBECH32_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/libbech32/include/)
set(LIBBECH32_LIB_DIR ${CMAKE_SOURCE_DIR}/libbech32/build/libbech32)
set(LIBBECH32_LIB ${LIBBECH32_LIB_DIR})

include_directories(${SECP256K1_INCLUDE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/libbech32/include/)
include_directories(${LIBBECH32_INCLUDE_DIR}/libbech32)

find_package(OpenSSL REQUIRED)

add_executable(BTC main.c base58.c sha2.c base32_bch.c)

link_directories(${LIBBECH32_LIB_DIR})

include(CTest)
enable_testing()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

# Link against secp256k1
target_link_libraries(BTC PRIVATE ${SECP256K1_LIB})
# Link against openssl
target_include_directories(BTC PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(BTC PRIVATE OpenSSL::Crypto OpenSSL::SSL)

target_link_libraries(BTC PRIVATE ${LIBBECH32_LIB_DIR}/libbech32.a
stdc++ ) # Add this line to link the C++ standard library
