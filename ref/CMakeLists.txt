set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -O3 -std=c99 -Wconversion -Wmissing-prototypes ${EXTRA_CFLAGS}")

# sphincs+ security level definition
set(l_securitylevel 128 192 256)
set(l_robustness simple robust)

set(shake fips202.c)
set(haraka haraka.c)
set(sha2 sha2.c)
set(l_hash shake haraka sha2)
set(l_variant s f)

# build randombytes
add_library(randombytes SHARED randombytes.c)

# build nist rng
add_library(rng SHARED rng.c)
target_link_libraries(rng OpenSSL::Crypto)

set(SRCS
  address.c
  merkle.c
  wots.c
  wotsx1.c
  utils.c
  utilsx1.c
  fors.c
  sign.c
)

foreach(level IN LISTS l_securitylevel)
foreach(hash IN LISTS l_hash)
foreach(variant IN LISTS l_variant)
  set(PARAMS "sphincs-${hash}-${level}${variant}")
  foreach(robustness IN LISTS l_robustness)
    set(LIBNAME "sphincs-${hash}-${level}${variant}-${robustness}")
    set(hash_file ${${hash}} hash_${hash}.c thash_${hash}_${robustness}.c)
    add_library(${LIBNAME} SHARED ${SRCS} ${hash_file})
    target_compile_definitions(${LIBNAME} PUBLIC PARAMS=${PARAMS})
  endforeach()
endforeach()
endforeach()
endforeach()

foreach(level IN LISTS l_securitylevel)
foreach(hash IN LISTS l_hash)
foreach(variant IN LISTS l_variant)
foreach(robustness IN LISTS l_robustness)
  set(SUFFIX "${hash}-${level}${variant}-${robustness}")
  set(LIBNAME "sphincs-${hash}-${level}${variant}-${robustness}")

  # build PQCgenKAT_sign
  add_executable(PQCgenKAT_sign-${SUFFIX} PQCgenKAT_sign.c)
  target_link_libraries(PQCgenKAT_sign-${SUFFIX} PRIVATE rng ${LIBNAME})

  # build test/benchmark
  add_executable(benchmark-${SUFFIX} test/benchmark.c test/cycles.c)
  target_link_libraries(benchmark-${SUFFIX} PRIVATE randombytes ${LIBNAME})

  # build test/fors
  add_executable(test_fors-${SUFFIX} test/fors.c)
  target_link_libraries(test_fors-${SUFFIX} PRIVATE randombytes ${LIBNAME})

  # build test/spx
  add_executable(test_spx-${SUFFIX} test/spx.c)
  target_link_libraries(test_spx-${SUFFIX} PRIVATE randombytes ${LIBNAME})

endforeach()
endforeach()
endforeach()
endforeach()