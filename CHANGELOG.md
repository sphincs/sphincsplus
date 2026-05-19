# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.html).

### Summary
This version introduces modifications to the `ref` implementation for performance analysis and benchmarking purposes. The core cryptographic logic of the original SPHINCS+ algorithm remains unchanged. All modifications are confined to the `ref` directory, supplementary testing scripts, and configuration files.

### Added
- **Performance Benchmarking Framework:**
  - Introduced a `timing_info_t` struct in `ref/api.h` to capture execution time for key generation, signing, and verification steps.
  - Added `print_timing_info()` function prototype in `ref/api.h` to display aggregated timing results.
  - Added `run_test` function prototype in `ref/api.h` to facilitate running tests multiple times for stable performance metrics.
- **Automated Testing Support:**
  - Added `ref/test/input.txt` to provide a consistent sample input for testing and debugging.
- **VS Code Configuration Support:**
  - Added `.vscode/c_cpp_properties.json` to enhance development experience with debugging, code suggestions, and to fix all warnings.
  - Configured include paths for all implementations (`ref`, `haraka-aesni`, `shake-avx2`, `sha2-avx2`) and parameter files.
  - Defined default `PARAMS` macro for easier switching between parameter sets in the editor (note: this macro is only for code suggestions and does not affect the actual `make` process).

### Changed
- **Makefile Adjustments:**
  - Updated `Makefile` in `ref` to support new benchmarking and testing options.

### Removed
- No changes in this version.

This project is a fork of the official [SPHINCS+](https://github.com/sphincs/sphincsplus) repository. The modifications, available at [quannguyen247/sphincsplus-dev](https://github.com/quannguyen247/sphincsplus-dev), are focused on performance analysis, benchmarking, and development tooling. The core cryptographic logic of the original public domain implementation of SPHINCS+ remains unchanged.