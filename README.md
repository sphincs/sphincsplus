## SPHINCS+ [![Build Status](https://travis-ci.org/sphincs/sphincsplus.svg?branch=master)](https://travis-ci.org/sphincs/sphincsplus)

This repository contains the software that accompanies the [SPHINCS+ submission](https://sphincs.org/) to [NIST's Post-Quantum Cryptography](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography) project.

### Parameters

The [SPHINCS+ specification](https://sphincs.org/data/sphincs+-specification.pdf) proposed a set of 36 named instances, specifying hash functions and concrete parameters for the security level, tree dimensions, WOTS+ and FORS. This reference implementation allows for more flexibility, as parameters can be specified in a `params.h` file. The proposed parameter sets have been predefined in `ref/params/params-*.h`, and the hash function can be varied by linking with the different implementations of `hash.h`, i.e., `hash_haraka.c`, `hash_sha256.c` and `hash_shake256.c`, as well as different implementations of `thash.h`, i.e., `*_robust.c` and `*_simple.c`. This is demonstrated in the `Makefile`. See the table below for a summary of the parameter sets. These parameters target the NIST security categories 1, 3 and 5; for each category, there is a parameter set geared towards either small signatures or fast signature generation.

|               | n  | h  | d  | log(t) | k  | w  | bit security | pk bytes | sk bytes | sig bytes |
| :------------ | -: | -: | -: | -----: | -: | -: | -----------: | -------: | -------: | --------: |
| SPHINCS+-128s | 16 | 64 |  8 |     15 | 10 | 16 |          133 |       32 |       64 |     8,080 |
| SPHINCS+-128f | 16 | 60 | 20 |      9 | 30 | 16 |          128 |       32 |       64 |    16,976 |
| SPHINCS+-192s | 24 | 64 |  8 |     16 | 14 | 16 |          196 |       48 |       96 |    17,064 |
| SPHINCS+-192f | 24 | 66 | 22 |      8 | 33 | 16 |          194 |       48 |       96 |    35,664 |
| SPHINCS+-256s | 32 | 64 |  8 |     14 | 22 | 16 |          255 |       64 |      128 |    29,792 |
| SPHINCS+-256f | 32 | 68 | 17 |     10 | 30 | 16 |          254 |       64 |      128 |    49,216 |

### License

All included code is available under the CC0 1.0 Universal Public Domain Dedication, with the exception of `rng.c`, `rng.h` and `PQCgenKAT_sign.c`, which were provided by NIST.
