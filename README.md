## SPHINCS+ / SLH-DSA

This repository contains the software that accompanies the [SPHINCS+ submission](https://sphincs.org/) to [NIST's Post-Quantum Cryptography](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography) project. SPHINCS+ was standardised by NIST as **SLH-DSA in [FIPS-205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)** (August 2024); this implementation tracks the standard.

![][test-ref]
![][test-sha256-avx2]
![][test-shake256-avx2]
![][test-acvp]

### API

The public C entry points in [`ref/api.h`](ref/api.h) follow the FIPS-205 §10.2 surface:

- `crypto_sign_keypair`, `crypto_sign_seed_keypair` — key generation.
- `crypto_sign_signature`, `crypto_sign_signature_derand` — pure SLH-DSA (Alg 22). Both take an explicit context string `(ctx, ctxlen)` up to 255 bytes; pass `NULL, 0` for empty. The `_derand` variant accepts caller-supplied `addrnd` instead of drawing it via `randombytes()`.
- `crypto_sign_signature_prehash`, `crypto_sign_signature_prehash_derand` — HashSLH-DSA (Alg 23). Caller supplies the pre-hashed message and the DER-encoded OID of the pre-hash function.
- `crypto_sign_verify`, `crypto_sign_verify_prehash` — corresponding verifiers.
- `crypto_sign_signature_internal`, `crypto_sign_verify_internal` — the FIPS-205 §10.2 internal cores, taking a raw `(pre, prelen)` prefix buffer that the wrappers construct for the pure / pre-hash entry points.

The combined "signed message" form is also available as `crypto_sign` / `crypto_sign_open` and takes the same `(ctx, ctxlen)` arguments.

Conformance against the NIST [ACVP SLH-DSA test vectors](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files) is checked by [`acvp.py`](acvp.py); see the `test-acvp` workflow.

### Parameters

The [SPHINCS+ specification](https://sphincs.org/data/sphincs+-specification.pdf) proposed a set of named instances, specifying hash functions and concrete parameters for the security level, tree dimensions, WOTS+ and FORS. FIPS-205 (SLH-DSA) standardises the SHA2 and SHAKE families using the "simple" tweakable hash. This reference implementation allows for more flexibility, as parameters can be specified in a `params.h` file. The proposed parameter sets have been predefined in `ref/params/params-*.h`, and the hash function can be varied by linking with the different implementations of `hash.h`, i.e., `hash_sha2.c` and `hash_shake.c`, together with the simple `thash.h` instantiations (`thash_sha2_simple.c` / `thash_shake_simple.c`). This is demonstrated in the `Makefile`. See the table below for a summary of the parameter sets. These parameters target the NIST security categories 1, 3 and 5; for each category, there is a parameter set geared towards either small signatures or fast signature generation.

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
see the [LICENSE file](LICENSE) and the licenses in the [LICENSES folder](LICENSES)), with the exception of `rng.c`, `rng.h` and `PQCgenKAT_sign.c`, which were provided by NIST.

[test-ref]: https://github.com/sphincs/sphincsplus/actions/workflows/test-ref.yml/badge.svg
[test-sha256-avx2]: https://github.com/sphincs/sphincsplus/actions/workflows/test-sha2-avx2.yml/badge.svg
[test-shake256-avx2]: https://github.com/sphincs/sphincsplus/actions/workflows/test-shake-avx2.yml/badge.svg
[test-acvp]: https://github.com/sphincs/sphincsplus/actions/workflows/test-acvp.yml/badge.svg
