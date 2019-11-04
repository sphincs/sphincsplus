#! /usr/bin/env python3
import fileinput
import os
from subprocess import run, DEVNULL
import sys
import itertools

implementations = [
                   ('ref', ['shake256', 'sha256', 'haraka']),
                   #('haraka-aesni', ['haraka']),
                   #('shake256-avx2', ['shake256']),
                   #('sha256-avx2', ['sha256']),
                   ]

options = ["f", "s"]
sizes = [128, 192, 256]
thashes = ['robust', 'simple']

PARAMDIR = "../ref/params/"  # relative to an implementation directory

try:
    for impl, fns in implementations:
        params = os.path.join(impl, "params.h")
        run(["mv", params, params+'.keep'], stdout=DEVNULL, stderr=DEVNULL)
        for fn in fns:
            for opt, size, thash in itertools.product(options, sizes, thashes):
                paramset = "sphincs-{}-{}{}".format(fn, size, opt)
                paramfile = "params-{}.h".format(paramset)
                print("Benchmarking", paramset, thash, "using", impl)
                hashf = 'HASH={}'.format(fn)  # overrides Makefile var
                thash = 'THASH={}'.format(thash)  # overrides Makefile var
                run(["ln", "-fs", os.path.join(PARAMDIR, paramfile), params],
                    stdout=DEVNULL, stderr=sys.stderr)
                run(["make", "-C", impl, "clean", thash, hashf],
                    stdout=DEVNULL, stderr=sys.stderr)
                run(["make", "-C", impl, "benchmarks", thash, hashf],
                    stdout=DEVNULL, stderr=sys.stderr)
                run(["make", "-C", impl, "benchmark", thash, hashf],
                    stdout=sys.stdout, stderr=sys.stderr)
                print()

finally:
    print("Cleaning up..")
    for impl, fns in implementations:
        params = os.path.join(impl, "params.h")
        run(["mv", params+'.keep', params], stdout=DEVNULL, stderr=DEVNULL)
