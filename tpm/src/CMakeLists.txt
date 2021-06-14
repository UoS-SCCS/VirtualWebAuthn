# Based on:
#
# https://github.com/lefticus/cpp_starter_project/blob/master/CMakeLists.txt
#

cmake_minimum_required(VERSION 3.13)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Set the project name to your project name
project(WebAuthnLib CXX)
include(Cmake/StandardProjectSettings.cmake)

# Link this 'library' to set the c++ standard / compile-time options requested
add_library(project_options INTERFACE)
target_compile_features(project_options INTERFACE cxx_std_17)

# Link this 'library' to use the warnings specified in CompilerWarnings.cmake
add_library(project_warnings INTERFACE)

# standard compiler warnings
include(Cmake/CompilerWarnings.cmake)
set_project_warnings(project_warnings)

# sanitizer options if supported by compiler
include(Cmake/Sanitizers.cmake)
enable_sanitizers(project_options)

# enable doxygen
include(Cmake/Doxygen.cmake)
enable_doxygen()

# allow for static analysis options
include(Cmake/StaticAnalysers.cmake)

# Debugging option to print varaibles
#    e.g. cmake_print_variables(<variable>)
include(CMakePrintHelpers)

set(LIBRARY_OUTPUT_PATH  ${CMAKE_SOURCE_DIR}/../lib)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin) 

add_library(watpm SHARED "")

add_compile_definitions(IBM_TSS)
set(tss_includes
  "/opt/ibmtss/utils"
)

find_library(tss_lib
    tss
    PATHS /opt/ibmtss/utils
)

target_include_directories(watpm
    PUBLIC
#        ${CMAKE_SOURCE_DIR}/Utilities/Include 
#        ${CMAKE_SOURCE_DIR}/Tss_utilities/Include 
#        ${CMAKE_SOURCE_DIR}/Ibmtss/Include 
        ${tss_includes}
)

target_compile_definitions(watpm PRIVATE TPM_POSIX)

target_compile_options(watpm PRIVATE -pg -O3)

target_link_options(watpm PRIVATE -pg)

target_link_libraries(watpm PUBLIC project_options project_warnings stdc++ ${ossl_libs} ${tss_lib})
#target_link_libraries(watpm PRIVATE project_options project_warnings)

add_subdirectory(Utilities)
add_subdirectory(Tss_utilities)
add_subdirectory(Ibmtss)

