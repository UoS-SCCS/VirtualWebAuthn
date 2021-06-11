set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

# dl and pthread needed by RPi, not for Ubuntu (?) RPi had later version of OSSL
set(ossl_libs OpenSSL::Crypto OpenSSL::SSL dl pthread)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
