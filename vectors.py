#! /usr/bin/env python3

# Without arguments, generates sha256 sums of NIST KAT response files
# for each of the instances (which should match SHA256SUMS.)
#
# With two arguments, checks whether the sha256 sum of the given
# generated NIST KAT response file is correct, e.g.:
#
#       ./vectors.py sphincs-shake-128s-simple shake-avx2

import multiprocessing
import subprocess
import itertools
import tempfile
import hashlib
import shutil
import os
import sys

fns = ['shake', 'sha2', 'haraka']
options = ["f", "s"]
sizes = [128, 192, 256]
thashes = ['robust', 'simple']

def nameFor(fn, opt, size, thash):
    return f"sphincs-{fn}-{size}{opt}-{thash}"

def make(fn, opt, size, thash, bindir, impl):
    name = nameFor(fn, opt, size, thash)
    overrides = [f'PARAMS=sphincs-{fn}-{size}{opt}', 'THASH='+thash]

    sys.stderr.write(f"Compiling {name} …\n")
    sys.stderr.flush()

    subprocess.run(["make", "-C", impl, "clean"] + overrides,
        stdout=subprocess.DEVNULL, stderr=sys.stderr, check=True)
    subprocess.run(["make", '-j', "-C", impl, "PQCgenKAT_sign"] + overrides,
        stdout=subprocess.DEVNULL, stderr=sys.stderr, check=True)

    shutil.move(
        os.path.join(impl, 'PQCgenKAT_sign'),
        os.path.join(bindir, name),
    )

    return (name, size)

def run(name_size, bindir):
    name, size = name_size
    rsp = f'PQCsignKAT_{size//2}.rsp'
    req = f'PQCsignKAT_{size//2}.req'

    with tempfile.TemporaryDirectory() as rundir:
        sys.stderr.write(f"Running {name} …\n")
        sys.stderr.flush()

        subprocess.run([os.path.join(bindir, name)],
            stdout=subprocess.DEVNULL, stderr=sys.stderr, cwd=rundir, check=True)
        with open(os.path.join(rundir, rsp), 'rb') as f:
            h = hashlib.sha256(f.read()).hexdigest()
            return f"{h} {name}"

def generate_sums():
    with tempfile.TemporaryDirectory() as bindir:
        with multiprocessing.Pool() as pool:
            name_sizes = []
            for fn in fns:
                for opt, size, thash in itertools.product(options, sizes, thashes):
                    name_sizes.append(make(fn, opt, size, thash, bindir, 'ref'))

            res = pool.starmap(run, zip(name_sizes, [bindir]*len(name_sizes)))
            res.sort()
            print('\n'.join(res))

def check_sum(name, impl):
    line = None
    with tempfile.TemporaryDirectory() as bindir:
        for fn in fns:
            for opt, size, thash in itertools.product(
                    options, sizes, thashes):
                if nameFor(fn, opt, size, thash) != name:
                    continue
                name_size = make(fn, opt, size, thash, bindir, impl)
                line = run(name_size, bindir)
                break
    if not line:
        sys.stderr.write("No such instance\n")
        sys.exit(1)
    with open('SHA256SUMS', 'r') as f:
        if f.read().find(line + '\n') == -1:
            sys.stderr.write(f"Test vector mismatch: {line}\n")
            sys.exit(2)
        sys.stderr.write("ok\n")

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        generate_sums()
    elif len(sys.argv) == 3:
        check_sum(sys.argv[1], sys.argv[2])
    else:
        sys.stderr.write("Expect two or no arguments\n")
        sys.exit(3)
