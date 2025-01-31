# CMake minimum version and project details
cmake_minimum_required(VERSION 3.16)
project(PQCSphincsPlus VERSION 1.0 LANGUAGES C CXX ASM)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Option to enable/disable tests
option(ENABLE_TESTS "Enable Unit Tests" ON)

# Set the output directories for binaries and libraries
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

find_package(OpenSSL REQUIRED)

# Available build options
# Note that simple and robust will generate identical output
set(AVAILABLE_LIBRARIES "")
list(APPEND AVAILABLE_LIBRARIES
  sphincs-haraka-128f-simple
  sphincs-haraka-128f-robust
  sphincs-haraka-128s-simple
  sphincs-haraka-128s-robust
  sphincs-haraka-192f-simple
  sphincs-haraka-192f-robust
  sphincs-haraka-192s-simple
  sphincs-haraka-192s-robust
  sphincs-haraka-256f-simple
  sphincs-haraka-256f-robust
  sphincs-haraka-256s-simple
  sphincs-haraka-256s-robust
  sphincs-sha2-128f-simple
  sphincs-sha2-128f-robust
  sphincs-sha2-128s-simple
  sphincs-sha2-128s-robust
  sphincs-sha2-192f-simple
  sphincs-sha2-192f-robust
  sphincs-sha2-192s-simple
  sphincs-sha2-192s-robust
  sphincs-sha2-256f-simple
  sphincs-sha2-256f-robust
  sphincs-sha2-256s-simple
  sphincs-sha2-256s-robust
  sphincs-shake-128f-simple
  sphincs-shake-128f-robust
  sphincs-shake-128s-simple
  sphincs-shake-128s-robust
  sphincs-shake-192f-simple
  sphincs-shake-192f-robust
  sphincs-shake-192s-simple
  sphincs-shake-192s-robust
  sphincs-shake-256f-simple
  sphincs-shake-256f-robust
  sphincs-shake-256s-simple
  sphincs-shake-256s-robust
)
string(REPLACE ";" ", " AVAILABLE_LIBRARIES_STRING "${AVAILABLE_LIBRARIES}")

set(DEFAULT_LIBRARY sphincs-haraka-128f-robust)

set(TARGET ${DEFAULT_LIBRARY} CACHE STRING "Select target library from available options")

list(FIND AVAILABLE_LIBRARIES ${TARGET} LIB_INDEX)
if(LIB_INDEX EQUAL -1)
    message(FATAL_ERROR
        "Invalid TARGET value: ${TARGET}\nAvailable options are: ${AVAILABLE_LIBRARIES_STRING}")
endif()

message(STATUS "Selected TARGET: ${TARGET}")

add_subdirectory(ref)
add_subdirectory(haraka-aesni)
add_subdirectory(sha2-avx2)
add_subdirectory(shake-avx2)