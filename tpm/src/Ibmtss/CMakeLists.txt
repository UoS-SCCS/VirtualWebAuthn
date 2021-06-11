cmake_minimum_required(VERSION 3.13)

#list(APPEND include_dirs "${CMAKE_CURRENT_SOURCE_DIR}/Include")

#cmake_print_variables(include_dirs)

target_include_directories(watpm PUBLIC ${CMAKE_CURRENT_LIST_DIR}/Include)

set(ibmtss_lib tss)

add_subdirectory(Common)
add_subdirectory(Test)
