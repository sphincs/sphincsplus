set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -Wmissing-prototypes -O3 -std=c99 -march=native -flto -fomit-frame-pointer ${EXTRA_CFLAGS}")

# sphincs+ security level definition
set(l_securitylevel 128 192 256)
set(l_robustness simple robust)
set(l_variant s f)

# randombytes and rng are built in the ref directory
# # build randombytes
# add_library(randombytes SHARED randombytes.c)
#
# # build nist rng
# add_library(rng SHARED rng.c)
# target_link_libraries(rng OpenSSL::Crypto)

set(SRCS
  address.c
  merkle.c
  wots.c
  utils.c
  utilsx8.c
  fors.c
  sign.c
)

foreach(level IN LISTS l_securitylevel)
foreach(variant IN LISTS l_variant)
  set(PARAMS "sphincs-sha2-${level}${variant}")
  foreach(robustness IN LISTS l_robustness)
    set(LIBNAME "sphincs-${level}${variant}-${robustness}-sha2x8")
    set(hash_file
        hash_sha2.c
        hash_sha2x8.c
        thash_sha2_${robustness}.c
        thash_sha2_${robustness}x8.c
        sha2.c
        sha256x8.c
        sha512x4.c
        sha256avx.c
    )
    add_library(${LIBNAME} SHARED ${SRCS} ${hash_file})
    target_compile_definitions(${LIBNAME} PUBLIC PARAMS=${PARAMS})
  endforeach()
endforeach()
endforeach()

foreach(level IN LISTS l_securitylevel)
foreach(variant IN LISTS l_variant)
foreach(robustness IN LISTS l_robustness)
  set(SUFFIX "sha2x8-${level}${variant}-${robustness}")
  set(LIBNAME "sphincs-${level}${variant}-${robustness}-sha2x8")
  # build PQCgenKAT_sign sha2x8 version
  add_executable(PQCgenKAT_sign_${SUFFIX} PQCgenKAT_sign.c)
  target_link_libraries(PQCgenKAT_sign_${SUFFIX} PRIVATE rng ${LIBNAME})

  # build benchmark sha2x8 version
  add_executable(test_benchmark_${SUFFIX} test/benchmark.c)
  target_link_libraries(test_benchmark_${SUFFIX} PRIVATE randombytes ${LIBNAME})

  # build test_fors sha2x8 version
  add_executable(test_fors_${SUFFIX} test/fors.c)
  target_link_libraries(test_fors_${SUFFIX} PRIVATE randombytes ${LIBNAME})

  # build test_spx sha2x8 version
  add_executable(test_spx_${SUFFIX} test/spx.c)
  target_link_libraries(test_spx_${SUFFIX} PRIVATE randombytes ${LIBNAME})

  # build hash x8 test
  add_executable(test_${SUFFIX} test/spx.c)
  target_link_libraries(test_${SUFFIX} PRIVATE randombytes ${LIBNAME})

endforeach()
endforeach()
endforeach()