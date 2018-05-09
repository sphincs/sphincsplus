#! /usr/bin/env python3
import fileinput
import os
from subprocess import run, DEVNULL
import sys
import itertools

implementations = [
                   ('ref', ['shake256', 'sha256', 'haraka']),
                   ('haraka-aesni', ['haraka']),
                   ('shake256-avx2', ['shake256']),
                   ]

options = ["f", "s"]
sizes = [128, 192, 256]

PARAMDIR = "../ref/params/"  # relative to an implementation directory

try:
    for impl, fns in implementations:
        params = os.path.join(impl, "params.h")
        makefile = os.path.join(impl, "Makefile")
        run(["mv", params, params+'.keep'], stdout=DEVNULL, stderr=DEVNULL)
        run(["cp", makefile, makefile+'.keep'], stdout=DEVNULL, stderr=DEVNULL)
        for fn in fns:
            with fileinput.FileInput(makefile, inplace=True) as f:
                for line in f:
                    if line.startswith("HASH_C = hash_"):
                        print("HASH_C = hash_{}.c".format(fn))
                    else:
                        print(line, end='')
            for opt, size in itertools.product(options, sizes):
                paramset = "sphincs-{}-{}{}".format(fn, size, opt)
                paramfile = "params-{}.h".format(paramset)
                print("## Benchmarking", paramset, "using", impl)
                run(["ln", "-fs", os.path.join(PARAMDIR, paramfile), params],
                    stdout=DEVNULL, stderr=DEVNULL)
                run(["make", "-C", impl, "clean"],
                    stdout=DEVNULL, stderr=DEVNULL)
                run(["make", "-C", impl, "benchmarks"],
                    stdout=DEVNULL, stderr=DEVNULL)
                run(["make", "-C", impl, "benchmark"],
                    stdout=sys.stdout, stderr=DEVNULL)
                print()

finally:
    print("Cleaning up..")
    for impl, fns in implementations:
        params = os.path.join(impl, "params.h")
        makefile = os.path.join(impl, "Makefile")
        run(["mv", params+'.keep', params], stdout=DEVNULL, stderr=DEVNULL)
        run(["mv", makefile+'.keep', makefile], stdout=DEVNULL, stderr=DEVNULL)
