cmake_minimum_required(VERSION 3.13)

project(Test_wa_tpm C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(Sources
    Test_wa_tpm.cpp
)

add_executable(test_wa_tpm ${Sources})

target_include_directories(test_wa_tpm SYSTEM PRIVATE ${include_dirs} ${tss2_includes})

target_link_libraries(test_wa_tpm PRIVATE project_options project_warnings ${tss2_libs} ${ossl_libs} stdc++ webauthntpm)
