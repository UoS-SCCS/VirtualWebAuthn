cmake_minimum_required(VERSION 3.13)

target_sources(watpm
    PRIVATE
        Byte_array.cpp
        Byte_buffer.cpp
        Clock_utils.cpp
        CMakeLists.txt
        Hex_string.cpp
        Hmac.cpp
        Io_utils.cpp
        Logging.cpp
        Number_conversions.cpp
        Openssl_bnp256.cpp
        Openssl_bn_utils.cpp
        Openssl_ec_utils.cpp
        Openssl_utils.cpp
        Sha256.cpp
)
