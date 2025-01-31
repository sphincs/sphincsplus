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
  utilsx4.c
  fors.c
  sign.c
)

foreach(level IN LISTS l_securitylevel)
foreach(variant IN LISTS l_variant)
  set(PARAMS "sphincs-haraka-${level}${variant}")
  foreach(robustness IN LISTS l_robustness)
    set(LIBNAME "sphincs-${level}${variant}-${robustness}-harakax4")
    set(hash_file
        haraka.c
        hash_haraka.c
        hash_harakax4.c
        thash_haraka_${robustness}.c
        thash_haraka_${robustness}x4.c
    )
    add_library(${LIBNAME} SHARED ${SRCS} ${hash_file})
    target_compile_definitions(${LIBNAME} PUBLIC PARAMS=${PARAMS})
  endforeach()
endforeach()
endforeach()

foreach(level IN LISTS l_securitylevel)
foreach(variant IN LISTS l_variant)
foreach(robustness IN LISTS l_robustness)
  set(SUFFIX "harakax4-${level}${variant}-${robustness}")
  set(LIBNAME "sphincs-${level}${variant}-${robustness}-harakax4")

  # build PQCgenKAT_sign harakax4 version
  add_executable(PQCgenKAT_sign_${SUFFIX} PQCgenKAT_sign.c)
  target_link_libraries(PQCgenKAT_sign_${SUFFIX} PRIVATE rng ${LIBNAME})

  # build benchmark harakax4 version
  add_executable(test_benchmark_${SUFFIX} test/benchmark.c)
  target_link_libraries(test_benchmark_${SUFFIX} PRIVATE randombytes ${LIBNAME})

  # build test_fors harakax4 version
  add_executable(test_fors_${SUFFIX} test/fors.c)
  target_link_libraries(test_fors_${SUFFIX} PRIVATE randombytes ${LIBNAME})

  # build test_spx harakax4 version
  add_executable(test_spx_${SUFFIX} test/spx.c)
  target_link_libraries(test_spx_${SUFFIX} PRIVATE randombytes ${LIBNAME})

endforeach()
endforeach()
endforeach()