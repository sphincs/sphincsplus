## SPHINCS+ [![Build Status](https://travis-ci.org/sphincs/sphincsplus.svg?branch=master)](https://travis-ci.org/sphincs/sphincsplus)

This repository contains the software that accompanies the [SPHINCS+ submission](https://sphincs.org/) to [NIST's Post-Quantum Cryptography](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography) project.

### Parameters

The [SPHINCS+ specification](https://sphincs.org/data/sphincs+-specification.pdf) proposed a set of 18 named instances, specifying hash functions and concrete parameters for the security level, tree dimensions, WOTS+ and FORS. This reference implementation allows for more flexibility, as parameters can be specified in a `params.h` file. The proposed parameter sets have been predefined in `ref/params/params-*.h`, and the hash function can be varied by linking with the different implementations of `hash.h`, i.e. `hash_haraka.c`, `hash_sha256.c` and `hash_shake256.c`.

### Dependencies

For the instances that use SHA-256, we rely on OpenSSL. If you want to use `hash_sha256.c`, make sure to install the OpenSSL development headers. On Debian-based systems, this is achieved by installing the OpenSSL development package `libssl-dev`.

### License

All included code is available under the CC0 1.0 Universal Public Domain Dedication, with the exception of `rng.c`, `rng.h` and `PQCgenKAT_sign.c`, which were provided by NIST.
