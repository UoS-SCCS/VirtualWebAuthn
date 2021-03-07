cmake_minimum_required(VERSION 3.13)

project(Test_wa_tpm_2 C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(Sources
    Test_wa_tpm_2.cpp
)

add_executable(test_wa_tpm_2 ${Sources})

target_compile_definitions(test_wa_tpm_2 PRIVATE TPM_POSIX)

target_compile_options(test_wa_tpm_2 PRIVATE -pg -O3)

target_link_options(test_wa_tpm_2 PRIVATE -pg)

target_include_directories(test_wa_tpm_2 PRIVATE
        ${CMAKE_SOURCE_DIR}/Utilities/Include 
        ${CMAKE_SOURCE_DIR}/Tss_utilities/Include 
        ${CMAKE_SOURCE_DIR}/Ibmtss/Include 
        ${tss_includes}
)

target_link_libraries(test_wa_tpm_2 PRIVATE project_options project_warnings ${tss_lib} ${ossl_libs} stdc++ watpm)
