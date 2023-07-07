## SPHINCS+

This repository contains the software that accompanies the [SPHINCS+ submission](https://sphincs.org/) to [NIST's Post-Quantum Cryptography](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography) project.

![][test-ref]
![][test-sha256-avx2]
![][test-shake256-avx2]
![][test-haraka-aesni]

### Parameters

The [SPHINCS+ specification](https://sphincs.org/data/sphincs+-specification.pdf) proposed a set of 36 named instances, specifying hash functions and concrete parameters for the security level, tree dimensions, WOTS+ and FORS. This reference implementation allows for more flexibility, as parameters can be specified in a `params.h` file. The proposed parameter sets have been predefined in `ref/params/params-*.h`, and the hash function can be varied by linking with the different implementations of `hash.h`, i.e., `hash_haraka.c`, `hash_sha2.c` and `hash_shake.c`, as well as different implementations of `thash.h`, i.e., `*_robust.c` and `*_simple.c`. This is demonstrated in the `Makefile`. See the table below for a summary of the parameter sets. These parameters target the NIST security categories 1, 3 and 5; for each category, there is a parameter set geared towards either small signatures or fast signature generation.

|               | n  | h  | d  | log(t) | k  |  w  | bit security | pk bytes | sk bytes | sig bytes |
| :------------ | -: | -: | -: | -----: | -: | --: | -----------: | -------: | -------: | --------: |
| SPHINCS+-128s | 16 | 63 |  7 |     12 | 14 |  16 |          133 |       32 |       64 |     7,856 |
| SPHINCS+-128f | 16 | 66 | 22 |      6 | 33 |  16 |          128 |       32 |       64 |    17,088 |
| SPHINCS+-192s | 24 | 63 |  7 |     14 | 17 |  16 |          193 |       48 |       96 |    16,224 |
| SPHINCS+-192f | 24 | 66 | 22 |      8 | 33 |  16 |          194 |       48 |       96 |    35,664 |
| SPHINCS+-256s | 32 | 64 |  8 |     14 | 22 |  16 |          255 |       64 |      128 |    29,792 |
| SPHINCS+-256f | 32 | 68 | 17 |      9 | 35 |  16 |          255 |       64 |      128 |    49,856 |

### License

All included code has been placed into
[Public Domain](LICENSES/LicenseRef-SPHINCS-PLUS-Public-Domain.txt)
and is available under various open source licenses
([Creative Commons Zero v1.0 Universal (CC0-1.0)](LICENSES/CC0-1.0.txt),
[BSD Zero Clause License (0BSD)](LICENSES/0BSD.txt), and
[MIT No Attribution (MIT-0)](LICENSES/MIT-0.txt),
see the [LICENSE file](LICENSE) and the licenses in the [LICENSES folder](LICENSES)), with the exception of `rng.c`, `rng.h` and `PQCgenKAT_sign.c`, which were provided by NIST, and parts of `ref/haraka.c`, which are under
[MIT license (MIT)](LICENSES/MIT.txt).

[test-ref]: https://github.com/sphincs/sphincsplus/actions/workflows/test-ref.yml/badge.svg
[test-sha256-avx2]: https://github.com/sphincs/sphincsplus/actions/workflows/test-sha256-avx2.yml/badge.svg
[test-shake256-avx2]: https://github.com/sphincs/sphincsplus/actions/workflows/test-shake256-avx2.yml/badge.svg
[test-haraka-aesni]: https://github.com/sphincs/sphincsplus/actions/workflows/test-haraka-aesni.yml/badge.svg
