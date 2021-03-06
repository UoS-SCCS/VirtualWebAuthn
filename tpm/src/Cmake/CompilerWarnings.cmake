# from here:
#
# https://github.com/lefticus/cpp_starter_project/blob/master/cmake/
# CompilerWarnings.cmake
#

function(set_project_warnings project_name)
  option(WARNINGS_AS_ERRORS "Treat compiler warnings as errors" TRUE)

  set(C_WARNINGS
      -Wall
      -Wextra # reasonable and standard
      -Wshadow # warn the user if a variable declaration shadows one from a
               # parent context
      -Wcast-align # warn for potential performance problem casts
      -Wunused # warn on anything being unused
      -Wpedantic # warn if non-standard C++ is used
      -Wconversion # warn on type conversions that may lose data
      -Wsign-conversion # warn on sign conversions
      -Wnull-dereference # warn if a null dereference is detected
      -Wdouble-promotion # warn if float is implicit promoted to double
      -Wformat=2 # warn on security issues around functions that format output
                 # (ie printf)
  )

  set(CLANG_WARNINGS
      ${C_WARNINGS}
      -Wnon-virtual-dtor # warn the user if a class with virtual functions has a
                         # non-virtual destructor. This helps catch hard to
                         # track down memory errors
      -Wno-old-style-cast # don't warn for c-style casts
                          # causes problems with IBMTSS
      -Woverloaded-virtual # warn if you overload (not override) a virtual
                           # function
  )

  if (WARNINGS_AS_ERRORS)
    set(CLANG_WARNINGS ${CLANG_WARNINGS} -Werror)
  endif()

  set(GCC_WARNINGS
      ${CLANG_WARNINGS}
      -Wmisleading-indentation # warn if identation implies blocks where blocks
                               # do not exist
      -Wduplicated-cond # warn if if / else chain has duplicated conditions
      -Wduplicated-branches # warn if if / else branches have duplicated code
      -Wlogical-op # warn about logical operations being used where bitwise were
                   # probably wanted
      -Wuseless-cast # warn if you perform a cast to the same type
  )

  if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(PROJECT_WARNINGS ${CLANG_WARNINGS}
            -Wno-extern-c-compat
            -Wno-cast-align
            -Wno-return-type-c-linkage
    )
    # cast-align causes issues with IBM TSS code
    # return-type-linkage causes warning aout the code for the Python interface
  else()
    set(PROJECT_WARNINGS ${GCC_WARNINGS})
  endif()

#  target_compile_options(${project_name} INTERFACE ${PROJECT_WARNINGS})

target_compile_options(${project_name} INTERFACE 
    $<$<COMPILE_LANGUAGE:CXX>:${PROJECT_WARNINGS}>
    $<$<COMPILE_LANGUAGE:C>:${C_WARNINGS}>
    )
endfunction()
