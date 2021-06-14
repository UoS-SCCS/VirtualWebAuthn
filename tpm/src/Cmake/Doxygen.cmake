# Derived from here:
#
# https://github.com/lefticus/cpp_starter_project/blob/master/
# cmake/Doxygen.cmake
#

function(enable_doxygen)
  option(ENABLE_DOXYGEN "Enable doxygen doc builds of source" OFF)
  if(ENABLE_DOXYGEN)
    set(DOXYGEN_OUTPUT_DIRECTORY "../../docs")
    set(DOXYGEN_CALLER_GRAPH NO)
    set(DOXYGEN_CALL_GRAPH YES)
    set(DOXYGEN_EXTRACT_ALL YES)
    set(DOXYGEN_EXCLUDE_PATTERNS "*/Utilities/*")
    find_package(Doxygen REQUIRED dot)
    doxygen_add_docs(doxygen-docs ${PROJECT_SOURCE_DIR})

  endif()
endfunction()

