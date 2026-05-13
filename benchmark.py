#! /usr/bin/env python3
import fileinput
import itertools
import os
import sys
from subprocess import DEVNULL, run

implementations = [
                   ('ref', ['shake', 'sha2']),
                   ('shake-avx2', ['shake']),
                   ('sha2-avx2', ['sha2']),
                   ]

options = ["f", "s"]
sizes = [128, 192, 256]

for impl, fns in implementations:
    params = os.path.join(impl, "params.h")
    for fn in fns:
        for opt, size in itertools.product(options, sizes):
            paramset = "sphincs-{}-{}{}".format(fn, size, opt)
            paramfile = "params-{}.h".format(paramset)

            print("Benchmarking", paramset, "using", impl, flush=True)

            params = 'PARAMS={}'.format(paramset)  # overrides Makefile var

            run(["make", "-C", impl, "clean", params],
                stdout=DEVNULL, stderr=sys.stderr)
            run(["make", "-C", impl, "benchmarks", params],
                stdout=DEVNULL, stderr=sys.stderr)
            run(["make", "-C", impl, "benchmark", params],
                stdout=sys.stdout, stderr=sys.stderr)

            print(flush=True)

