#!/usr/bin/env python3
"""
Run the NIST ACVP SLH-DSA (FIPS-205) test vectors against this implementation.

For each (implementation, parameter-set) combination supported by FIPS-205
(SHA2/SHAKE, simple thash), this script:

  1. builds <impl>/libspx.so with PARAMS=<params>
  2. loads it via cffi using a small subset of crypto_sign_* declarations
  3. exercises the keyGen, sigGen, and sigVer ACVP test vectors found in
     ./acvp/

The "internal" ACVP test groups exercise crypto_sign_seed_keypair,
crypto_sign_signature_internal, and crypto_sign_verify_internal directly.
The "external" (pure) groups call crypto_sign_signature_derand and
crypto_sign_verify with the FIPS-205 (0x00 || |ctx| || ctx) prefix.
The "preHash" (HashSLH-DSA) groups pre-hash the message in Python and
call crypto_sign_signature_prehash_derand / crypto_sign_verify_prehash.

Usage:
    ./acvp.py                                  # all (impl, params) combos
    ./acvp.py --impl ref --params sphincs-sha2-128f
    ./acvp.py --phase keygen
    ./acvp.py --limit 1                        # one test per group (smoke)
    ./acvp.py -j 4                             # parallelism
"""

import argparse
import hashlib
import json
import multiprocessing
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    from cffi import FFI
except ImportError:  # pragma: no cover
    sys.exit("error: this script needs the `cffi` package (`pip install cffi`)")

ROOT = Path(__file__).resolve().parent
ACVP_DIR = ROOT / "acvp"

# Map ACVP parameter-set names to the PARAMS value the Makefile expects.
ACVP_TO_PARAMS = {
    "SLH-DSA-SHA2-128s":  "sphincs-sha2-128s",
    "SLH-DSA-SHA2-128f":  "sphincs-sha2-128f",
    "SLH-DSA-SHA2-192s":  "sphincs-sha2-192s",
    "SLH-DSA-SHA2-192f":  "sphincs-sha2-192f",
    "SLH-DSA-SHA2-256s":  "sphincs-sha2-256s",
    "SLH-DSA-SHA2-256f":  "sphincs-sha2-256f",
    "SLH-DSA-SHAKE-128s": "sphincs-shake-128s",
    "SLH-DSA-SHAKE-128f": "sphincs-shake-128f",
    "SLH-DSA-SHAKE-192s": "sphincs-shake-192s",
    "SLH-DSA-SHAKE-192f": "sphincs-shake-192f",
    "SLH-DSA-SHAKE-256s": "sphincs-shake-256s",
    "SLH-DSA-SHAKE-256f": "sphincs-shake-256f",
}

# FIPS-205 covers SHA2 and SHAKE only. Each impl supports a subset.
IMPL_FAMILIES = {
    "ref":         {"sha2", "shake"},
    "sha2-avx2":   {"sha2"},
    "shake-avx2":  {"shake"},
    "shake-a64":   {"shake"},
}

# Minimal cffi cdef covering the symbols we need from api.h. Kept in sync with
# ref/api.h manually so we don't need a full C preprocessor at runtime.
CDEF = """
typedef unsigned long size_t;
typedef unsigned char uint8_t;

unsigned long long crypto_sign_secretkeybytes(void);
unsigned long long crypto_sign_publickeybytes(void);
unsigned long long crypto_sign_bytes(void);
unsigned long long crypto_sign_seedbytes(void);

int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed);

int crypto_sign_signature_internal(uint8_t *sig, size_t *siglen,
                                   const uint8_t *m, size_t mlen,
                                   const uint8_t *pre, size_t prelen,
                                   const uint8_t *sk,
                                   const uint8_t *addrnd);

int crypto_sign_signature_derand(uint8_t *sig, size_t *siglen,
                                 const uint8_t *m, size_t mlen,
                                 const uint8_t *ctx, size_t ctxlen,
                                 const uint8_t *sk,
                                 const uint8_t *addrnd);

int crypto_sign_verify_internal(const uint8_t *sig, size_t siglen,
                                const uint8_t *m, size_t mlen,
                                const uint8_t *pre, size_t prelen,
                                const uint8_t *pk);

int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *ctx, size_t ctxlen,
                       const uint8_t *pk);

int crypto_sign_signature_prehash_derand(uint8_t *sig, size_t *siglen,
                                         const uint8_t *phm, size_t phmlen,
                                         const uint8_t *oid, size_t oidlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *sk,
                                         const uint8_t *addrnd);

int crypto_sign_verify_prehash(const uint8_t *sig, size_t siglen,
                               const uint8_t *phm, size_t phmlen,
                               const uint8_t *oid, size_t oidlen,
                               const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *pk);
"""

# Map ACVP hashAlg strings to (pre-hash function, DER-encoded OID).
# OIDs are 11-byte DER-encoded ASN.1 OBJECT IDENTIFIERs as specified in
# FIPS-205 §10.2.2 / IANA. All begin with 06 09 60 86 48 01 65 03 04 02
# (object identifier, 9-byte body, joint-iso-itu-t.country.us.gov.csor.
# nistalgorithm.hashalgs) and end with a single byte for the specific hash.
# FIPS-205 SHAKE PHM output lengths are fixed (Table 3).
PREHASH = {
    "SHA2-224":     (lambda m: hashlib.sha224(m).digest(),               bytes.fromhex("0609608648016503040204")),
    "SHA2-256":     (lambda m: hashlib.sha256(m).digest(),               bytes.fromhex("0609608648016503040201")),
    "SHA2-384":     (lambda m: hashlib.sha384(m).digest(),               bytes.fromhex("0609608648016503040202")),
    "SHA2-512":     (lambda m: hashlib.sha512(m).digest(),               bytes.fromhex("0609608648016503040203")),
    "SHA2-512/224": (lambda m: hashlib.new("sha512_224", m).digest(),    bytes.fromhex("0609608648016503040205")),
    "SHA2-512/256": (lambda m: hashlib.new("sha512_256", m).digest(),    bytes.fromhex("0609608648016503040206")),
    "SHA3-224":     (lambda m: hashlib.sha3_224(m).digest(),             bytes.fromhex("0609608648016503040207")),
    "SHA3-256":     (lambda m: hashlib.sha3_256(m).digest(),             bytes.fromhex("0609608648016503040208")),
    "SHA3-384":     (lambda m: hashlib.sha3_384(m).digest(),             bytes.fromhex("0609608648016503040209")),
    "SHA3-512":     (lambda m: hashlib.sha3_512(m).digest(),             bytes.fromhex("060960864801650304020A")),
    "SHAKE-128":    (lambda m: hashlib.shake_128(m).digest(32),          bytes.fromhex("060960864801650304020B")),
    "SHAKE-256":    (lambda m: hashlib.shake_256(m).digest(64),          bytes.fromhex("060960864801650304020C")),
}


# ---------------------------------------------------------------------------
# Build + load
# ---------------------------------------------------------------------------


def build_libspx(impl, params, bindir, jobs=1):
    """Build libspx.so for one (impl, params) combo and move it into `bindir`.

    Returns the final unique path. Mirrors the pattern in vectors.py: the
    Makefile builds in-tree, then we move the artifact out so each (impl,
    params) gets its own file. Callers must serialise builds per-impl-dir.
    """
    impl_dir = ROOT / impl
    overrides = [f"PARAMS={params}"]
    # Suppress stdout (compiler info messages) but capture stderr so build
    # failures surface useful diagnostics on CI.
    for argv in (
        ["make", "-C", str(impl_dir), "clean", *overrides],
        ["make", "-C", str(impl_dir), f"-j{jobs}", "libspx.so", *overrides],
    ):
        p = subprocess.run(argv, stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE)
        if p.returncode != 0:
            raise subprocess.CalledProcessError(
                p.returncode, argv,
                output=p.stdout,
                stderr=p.stderr.decode(errors="replace"),
            )
    src = impl_dir / "libspx.so"
    dst = Path(bindir) / f"libspx_{impl}_{params}.so"
    shutil.move(str(src), str(dst))
    return dst


class SlhDsa:
    """cffi wrapper around one libspx.so."""

    def __init__(self, lib_path):
        self.ffi = FFI()
        self.ffi.cdef(CDEF)
        self.lib = self.ffi.dlopen(str(lib_path))
        self.n_bytes    = int(self.lib.crypto_sign_seedbytes()) // 3
        self.pk_bytes   = int(self.lib.crypto_sign_publickeybytes())
        self.sk_bytes   = int(self.lib.crypto_sign_secretkeybytes())
        self.sig_bytes  = int(self.lib.crypto_sign_bytes())
        self.seed_bytes = int(self.lib.crypto_sign_seedbytes())

    # ---- primitives ----

    def keygen(self, sk_seed, sk_prf, pk_seed):
        assert len(sk_seed) == self.n_bytes
        assert len(sk_prf)  == self.n_bytes
        assert len(pk_seed) == self.n_bytes
        seed = sk_seed + sk_prf + pk_seed
        pk = self.ffi.new(f"unsigned char[{self.pk_bytes}]")
        sk = self.ffi.new(f"unsigned char[{self.sk_bytes}]")
        rc = self.lib.crypto_sign_seed_keypair(pk, sk, seed)
        if rc != 0:
            raise RuntimeError(f"crypto_sign_seed_keypair returned {rc}")
        return bytes(self.ffi.buffer(sk)), bytes(self.ffi.buffer(pk))

    def sign_internal(self, msg, sk, addrnd):
        """Call crypto_sign_signature_internal with pre=NULL, prelen=0.
        Matches FIPS-205 §10.2 slh_sign_internal."""
        assert len(sk) == self.sk_bytes
        assert len(addrnd) == self.n_bytes
        sig = self.ffi.new(f"unsigned char[{self.sig_bytes}]")
        siglen = self.ffi.new("size_t *")
        m_buf = self.ffi.new(f"unsigned char[{max(len(msg), 1)}]",
                             msg if msg else b"\x00")
        rc = self.lib.crypto_sign_signature_internal(
            sig, siglen, m_buf, len(msg),
            self.ffi.NULL, 0, sk, addrnd
        )
        if rc != 0:
            raise RuntimeError(f"crypto_sign_signature_internal returned {rc}")
        return bytes(self.ffi.buffer(sig, siglen[0]))

    def sign_derand(self, msg, ctx, sk, addrnd):
        """Call crypto_sign_signature_derand with an explicit context string.
        Matches FIPS-205 §10.2 slh_sign (pure, derandomised)."""
        assert len(sk) == self.sk_bytes
        assert len(addrnd) == self.n_bytes
        sig = self.ffi.new(f"unsigned char[{self.sig_bytes}]")
        siglen = self.ffi.new("size_t *")
        m_buf = self.ffi.new(f"unsigned char[{max(len(msg), 1)}]",
                             msg if msg else b"\x00")
        if ctx:
            ctx_buf = self.ffi.new(f"unsigned char[{len(ctx)}]", ctx)
        else:
            ctx_buf = self.ffi.NULL
        rc = self.lib.crypto_sign_signature_derand(
            sig, siglen, m_buf, len(msg),
            ctx_buf, len(ctx), sk, addrnd
        )
        if rc != 0:
            raise RuntimeError(f"crypto_sign_signature_derand returned {rc}")
        return bytes(self.ffi.buffer(sig, siglen[0]))

    def verify_internal(self, msg, sig, pk):
        assert len(pk) == self.pk_bytes
        sig_buf = self.ffi.new(f"unsigned char[{max(len(sig), 1)}]",
                               sig if sig else b"\x00")
        m_buf = self.ffi.new(f"unsigned char[{max(len(msg), 1)}]",
                             msg if msg else b"\x00")
        rc = self.lib.crypto_sign_verify_internal(
            sig_buf, len(sig), m_buf, len(msg), self.ffi.NULL, 0, pk
        )
        return rc == 0

    def verify(self, msg, sig, ctx, pk):
        assert len(pk) == self.pk_bytes
        sig_buf = self.ffi.new(f"unsigned char[{max(len(sig), 1)}]",
                               sig if sig else b"\x00")
        m_buf = self.ffi.new(f"unsigned char[{max(len(msg), 1)}]",
                             msg if msg else b"\x00")
        if ctx:
            ctx_buf = self.ffi.new(f"unsigned char[{len(ctx)}]", ctx)
        else:
            ctx_buf = self.ffi.NULL
        rc = self.lib.crypto_sign_verify(
            sig_buf, len(sig), m_buf, len(msg), ctx_buf, len(ctx), pk
        )
        return rc == 0

    def sign_prehash_derand(self, phm, oid, ctx, sk, addrnd):
        """Call crypto_sign_signature_prehash_derand. Matches FIPS-205
        §10.2.2 HashSLH-DSA (derandomised)."""
        assert len(sk) == self.sk_bytes
        assert len(addrnd) == self.n_bytes
        sig = self.ffi.new(f"unsigned char[{self.sig_bytes}]")
        siglen = self.ffi.new("size_t *")
        phm_buf = self.ffi.new(f"unsigned char[{max(len(phm), 1)}]",
                               phm if phm else b"\x00")
        oid_buf = self.ffi.new(f"unsigned char[{len(oid)}]", oid)
        if ctx:
            ctx_buf = self.ffi.new(f"unsigned char[{len(ctx)}]", ctx)
        else:
            ctx_buf = self.ffi.NULL
        rc = self.lib.crypto_sign_signature_prehash_derand(
            sig, siglen, phm_buf, len(phm), oid_buf, len(oid),
            ctx_buf, len(ctx), sk, addrnd
        )
        if rc != 0:
            raise RuntimeError(f"crypto_sign_signature_prehash_derand returned {rc}")
        return bytes(self.ffi.buffer(sig, siglen[0]))

    def verify_prehash(self, phm, sig, oid, ctx, pk):
        assert len(pk) == self.pk_bytes
        sig_buf = self.ffi.new(f"unsigned char[{max(len(sig), 1)}]",
                               sig if sig else b"\x00")
        phm_buf = self.ffi.new(f"unsigned char[{max(len(phm), 1)}]",
                               phm if phm else b"\x00")
        oid_buf = self.ffi.new(f"unsigned char[{len(oid)}]", oid)
        if ctx:
            ctx_buf = self.ffi.new(f"unsigned char[{len(ctx)}]", ctx)
        else:
            ctx_buf = self.ffi.NULL
        rc = self.lib.crypto_sign_verify_prehash(
            sig_buf, len(sig), phm_buf, len(phm), oid_buf, len(oid),
            ctx_buf, len(ctx), pk
        )
        return rc == 0


# ---------------------------------------------------------------------------
# ACVP vectors
# ---------------------------------------------------------------------------


@dataclass
class PhaseResult:
    name: str
    passed: int = 0
    failed: int = 0
    failures: list = field(default_factory=list)

    def __iadd__(self, other):
        self.passed   += other.passed
        self.failed   += other.failed
        self.failures += other.failures
        return self

    def summary(self):
        bits = [f"{self.passed} pass"]
        if self.failed:
            bits.append(f"{self.failed} FAIL")
        return ", ".join(bits)


def _hex(s):
    return bytes.fromhex(s)


def _is_internal(group):
    return group.get("signatureInterface", "internal") == "internal"


def _is_prehash(group):
    return group.get("preHash", "none") == "preHash"


def _load_vectors(name):
    p = ACVP_DIR / f"{name}-internalProjection.json"
    if not p.is_file():
        raise FileNotFoundError(p)
    with p.open() as f:
        return json.load(f)


def run_keygen_for(slh, pset, vectors, limit):
    res = PhaseResult("keyGen")
    for group in vectors["testGroups"]:
        if group["parameterSet"] != pset:
            continue
        for t in (group["tests"][:limit] if limit else group["tests"]):
            sk_exp = _hex(t["sk"])
            pk_exp = _hex(t["pk"])
            sk, pk = slh.keygen(_hex(t["skSeed"]), _hex(t["skPrf"]), _hex(t["pkSeed"]))
            if sk == sk_exp and pk == pk_exp:
                res.passed += 1
            else:
                res.failed += 1
                res.failures.append(f"keyGen {pset} tc={t['tcId']}: sk/pk mismatch")
    return res


def run_siggen_for(slh, pset, vectors, limit):
    res = PhaseResult("sigGen")
    for group in vectors["testGroups"]:
        if group["parameterSet"] != pset:
            continue
        deterministic = group["deterministic"]
        internal = _is_internal(group)
        prehash = _is_prehash(group)
        for t in (group["tests"][:limit] if limit else group["tests"]):
            sk = _hex(t["sk"])
            msg = _hex(t.get("message", ""))
            sig_exp = _hex(t["signature"])
            # FIPS-205 deterministic mode uses PK.seed as addrnd. PK.seed sits
            # at sk[2N : 3N].
            if deterministic:
                addrnd = sk[2*slh.n_bytes : 3*slh.n_bytes]
            else:
                addrnd = _hex(t["additionalRandomness"])

            try:
                if internal:
                    sig = slh.sign_internal(msg, sk, addrnd)
                elif prehash:
                    ph, oid = PREHASH[t["hashAlg"]]
                    phm = ph(msg)
                    ctx = _hex(t.get("context", ""))
                    sig = slh.sign_prehash_derand(phm, oid, ctx, sk, addrnd)
                else:
                    ctx = _hex(t.get("context", ""))
                    sig = slh.sign_derand(msg, ctx, sk, addrnd)
                ok = sig == sig_exp
            except Exception as exc:
                res.failed += 1
                res.failures.append(f"sigGen {pset} tc={t['tcId']}: {exc!r}")
                continue

            if ok:
                res.passed += 1
            else:
                res.failed += 1
                diff_idx = next((i for i, (a, b) in enumerate(zip(sig, sig_exp)) if a != b),
                                min(len(sig), len(sig_exp)))
                res.failures.append(
                    f"sigGen {pset} tc={t['tcId']}: sig mismatch at byte {diff_idx} "
                    f"(got {len(sig)}, expected {len(sig_exp)})"
                )
    return res


def run_sigver_for(slh, pset, vectors, limit):
    res = PhaseResult("sigVer")
    for group in vectors["testGroups"]:
        if group["parameterSet"] != pset:
            continue
        internal = _is_internal(group)
        prehash = _is_prehash(group)
        for t in (group["tests"][:limit] if limit else group["tests"]):
            pk = _hex(t["pk"])
            sig = _hex(t["signature"])
            msg = _hex(t.get("message", ""))
            expected = bool(t["testPassed"])
            try:
                if internal:
                    ok = slh.verify_internal(msg, sig, pk)
                elif prehash:
                    ph, oid = PREHASH[t["hashAlg"]]
                    phm = ph(msg)
                    ctx = _hex(t.get("context", ""))
                    ok = slh.verify_prehash(phm, sig, oid, ctx, pk)
                else:
                    ctx = _hex(t.get("context", ""))
                    ok = slh.verify(msg, sig, ctx, pk)
            except Exception as exc:
                res.failed += 1
                res.failures.append(f"sigVer {pset} tc={t['tcId']}: {exc!r}")
                continue
            if ok == expected:
                res.passed += 1
            else:
                res.failed += 1
                reason = t.get("reason", "")
                res.failures.append(
                    f"sigVer {pset} tc={t['tcId']}: expected {expected}, got {ok} ({reason})"
                )
    return res


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------


def _run_worker(args):
    """Load one libspx.so via cffi and exercise the requested ACVP phases.

    Returns (impl, acvp_pset, {phase: PhaseResult}, error_or_None).
    """
    impl, acvp_pset, lib_path, phases, limit = args
    try:
        slh = SlhDsa(Path(lib_path))
        out = {}
        if "keygen" in phases:
            out["keyGen"] = run_keygen_for(slh, acvp_pset, _load_vectors("keyGen"), limit)
        if "siggen" in phases:
            out["sigGen"] = run_siggen_for(slh, acvp_pset, _load_vectors("sigGen"), limit)
        if "sigver" in phases:
            out["sigVer"] = run_sigver_for(slh, acvp_pset, _load_vectors("sigVer"), limit)
        summary = ", ".join(f"{p}: {r.summary()}" for p, r in out.items())
        print(f"[{impl}/{acvp_pset}] {summary}")
        return impl, acvp_pset, out, None
    except Exception as exc:                                    # noqa: BLE001
        return impl, acvp_pset, {}, f"{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--impl", help="comma-separated list of implementations to test",
                    default=",".join(IMPL_FAMILIES))
    ap.add_argument("--params", help="comma-separated ACVP parameter sets",
                    default=",".join(ACVP_TO_PARAMS))
    ap.add_argument("--phase", choices=("keygen", "siggen", "sigver", "all"), default="all")
    ap.add_argument("--limit", type=int, default=None,
                    help="cap tests per group (smoke testing)")
    ap.add_argument("-j", "--jobs", type=int,
                    default=multiprocessing.cpu_count())
    ap.add_argument("--max-failures", type=int, default=10)
    args = ap.parse_args()

    impls = [i.strip() for i in args.impl.split(",") if i.strip()]
    for i in impls:
        if i not in IMPL_FAMILIES:
            sys.exit(f"unknown impl: {i}")
    psets = [p.strip() for p in args.params.split(",") if p.strip()]
    for p in psets:
        if p not in ACVP_TO_PARAMS:
            sys.exit(f"unknown ACVP parameter set: {p}")

    phases = ("keygen", "siggen", "sigver") if args.phase == "all" else (args.phase,)

    # Build the (impl, pset) work list, skipping combinations the impl can't
    # handle (e.g., shake-only impls do not have sha2 params).
    work = []
    for impl in impls:
        fams = IMPL_FAMILIES[impl]
        for pset in psets:
            fam = "sha2" if "SHA2" in pset else "shake"
            if fam not in fams:
                continue
            work.append((impl, pset))

    if not work:
        sys.exit("no (impl, params) combinations to run")

    t0 = time.monotonic()
    totals = {p: PhaseResult(p) for p in ("keyGen", "sigGen", "sigVer")}
    build_errors = []

    # vectors.py-style two-phase orchestration:
    #   1) build libspx.so for each (impl, params) serially (the Makefile rule
    #      writes into <impl>/libspx.so in-tree, so we can't parallelise
    #      builds in the same impl dir). We move each artifact out to a
    #      uniquely-named file in a shared tempdir.
    #   2) run all ACVP tests in parallel; each worker loads its assigned
    #      libspx_<impl>_<params>.so via cffi.
    with tempfile.TemporaryDirectory(prefix="spx-acvp-") as bindir:
        run_items = []
        for impl, acvp_pset in work:
            params = ACVP_TO_PARAMS[acvp_pset]
            try:
                lib_path = build_libspx(impl, params, bindir)
                run_items.append((impl, acvp_pset, str(lib_path), phases, args.limit))
            except subprocess.CalledProcessError as exc:
                msg = f"{impl}/{acvp_pset}: build failed: {exc}"
                if isinstance(exc.stderr, str) and exc.stderr.strip():
                    msg += "\n    " + exc.stderr.strip().replace("\n", "\n    ")
                build_errors.append(msg)

        with multiprocessing.Pool(processes=args.jobs) as pool:
            for impl, acvp_pset, phase_results, err in pool.imap_unordered(
                _run_worker, run_items
            ):
                if err:
                    build_errors.append(f"{impl}/{acvp_pset}: {err}")
                    continue
                for phase, r in phase_results.items():
                    totals[phase] += r

    dt = time.monotonic() - t0

    print()
    print(f"=== ACVP summary  ({dt:.1f}s, jobs={args.jobs}) ===")
    for name, r in totals.items():
        if r.passed or r.failed:
            print(f"  {name:7s}  {r.summary()}")
    if build_errors:
        print()
        print("Build errors:")
        for e in build_errors[: args.max_failures]:
            print(f"  - {e}")
        if len(build_errors) > args.max_failures:
            print(f"  ... and {len(build_errors) - args.max_failures} more")

    all_failures = [f for r in totals.values() for f in r.failures]
    if all_failures:
        print()
        print("Failures:")
        for f in all_failures[: args.max_failures]:
            print(f"  - {f}")
        if len(all_failures) > args.max_failures:
            print(f"  ... and {len(all_failures) - args.max_failures} more")

    overall_failed = sum(r.failed for r in totals.values())
    if overall_failed or build_errors:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
