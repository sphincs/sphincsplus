#! /usr/bin/env python3
import fileinput
import itertools
import os
import sys
from subprocess import DEVNULL, run

implementations = [
                   ('ref', ['shake256', 'sha256', 'haraka']),
                   ('haraka-aesni', ['haraka']),
                   ('shake256-avx2', ['shake256']),
                   ('sha256-avx2', ['sha256']),
                   ]

options = ["f", "s"]
sizes = [128, 192, 256]
thashes = ['robust', 'simple']

for impl, fns in implementations:
    params = os.path.join(impl, "params.h")
    for fn in fns:
        for opt, size, thash in itertools.product(options, sizes, thashes):
            paramset = "sphincs-{}-{}{}".format(fn, size, opt)
            paramfile = "params-{}.h".format(paramset)

            print("Benchmarking", paramset, thash, "using", impl, flush=True)

            params = 'PARAMS={}'.format(paramset)  # overrides Makefile var
            thash = 'THASH={}'.format(thash)  # overrides Makefile var

            run(["make", "-C", impl, "clean", thash, params],
                stdout=DEVNULL, stderr=sys.stderr)
            run(["make", "-C", impl, "benchmarks", thash, params],
                stdout=DEVNULL, stderr=sys.stderr)
            run(["make", "-C", impl, "benchmark", thash, params],
                stdout=sys.stdout, stderr=sys.stderr)

            print(flush=True)

