#!/usr/bin/env python3

import fileinput
import os
import shutil
import itertools
import subprocess
import re
import jinja2
import glob

# Output here
TARGET_DIR = './crypto_sign'
# Rename implementations?
IMPLEMENTATION_NAME_MAP = {
    'ref': 'clean',
    'haraka-aesni': 'aesni',
    'shake256-avx2': 'avx2',
    'sha256-avx2': 'avx2',
}
# Enable me if you want the PQClean/SUPERCOP layout (target_dir/variant/impl)
# Also enables astyle and disables NIST_COMPATIBLE – though setting an empty
# namespace will then get the NIST API after all.
#
# This switch will also create the PQClean duplicate_consistency files.
PQCLEAN_LAYOUT = True


# Change me to generate a different namespace.
def generate_namespace(func, size, opt, variant, impl):
    return f"PQCLEAN_SPHINCS{func}{size}{opt}{variant}_{impl}_".upper()


# You shouldn't have to change anything below this line.


TARGET_DIR = os.path.realpath(TARGET_DIR)


def replace_in_file(path, text_to_search, replacement_text):
    with fileinput.FileInput(path, inplace=True) as file:
        for line in file:
            print(re.sub(text_to_search, replacement_text, line), end='')


funcs = ['sha256', 'haraka', 'shake256']
variants = ['simple', 'robust']
sizes = [128, 192, 256]
options = ['s', 'f']

sigsizes = {(128, 's'): 8080,
            (128, 'f'): 16976,
            (192, 's'): 17064,
            (192, 'f'): 35664,
            (256, 's'): 29792,
            (256, 'f'): 49216}

X4_IMPLS = ('shake256-avx2', 'haraka-aesni')
X8_IMPLS = ('sha256-avx2',)

nistkat = {
    "sphincs-haraka-128f-robust": "22afe9a2b538742f99fbf02293024de6424726eebddb3cac456534055689a4c3",      # noqa
    "sphincs-haraka-128f-simple": "d0161f60f8bdd26fa2f03a881eb517adf7d3e9a44f5cc337cb9c0d8acf82c145",      # noqa
    "sphincs-haraka-128s-robust": "de504b1aa6ee3cc6513a0da3511414b5d2472c5bd9efa780239518876c4e9fb2",      # noqa
    "sphincs-haraka-128s-simple": "a83a6512c773b1f305f07a383ececf607ecfbd0e5ad49b4ab444faed019f66c8",      # noqa
    "sphincs-haraka-192f-robust": "1d32cab46df0d4e6678a06a9eae7b187c80eaedf56b1e7d221035d7c6f08ef06",      # noqa
    "sphincs-haraka-192f-simple": "4888059ed11c192b3a07e227e3befc967819d05f85723a7740bbc31eadc37f37",      # noqa
    "sphincs-haraka-192s-robust": "3bb2c0ea5d4b7c39d1c63b424493ab9b739c64adf511abf7e4107ad750a46273",      # noqa
    "sphincs-haraka-192s-simple": "c8e823fe6b03f35a0d9996dea1559e6924b86e2631e945a3ab9bb4e55c22c068",      # noqa
    "sphincs-haraka-256f-robust": "b31c6a00604e5f1eed1534c0f8ab29ceb0c831397075ca93c43c5a2a73e2649c",      # noqa
    "sphincs-haraka-256f-simple": "73d4172d95d0e668f7ac535a67f6ab26a963a604391053c9a2ce62cba88f2220",      # noqa
    "sphincs-haraka-256s-robust": "a419bdba92da2d07f99c3c3ba4f776b955244a7c3b565816c7fd2151f6c3363f",      # noqa
    "sphincs-haraka-256s-simple": "0b8c7d3d8001eec6ddb317e0301fef4adc4f5b03301e5f4b93d09881b1a5ba7a",      # noqa
    "sphincs-sha256-128f-robust": "cf7935fc0277099a7453f6c5dc54e40d5cf34fbe989909940a77a3fbbab6c42e",      # noqa
    "sphincs-sha256-128f-simple": "4375bc4276fa44654979db0da886ba5cf754011db268fc63fa7584d50f5dfb63",      # noqa
    "sphincs-sha256-128s-robust": "4ddcad5141217340f9f28afdcf25cc236d7975bcfb41b39660e84568a9a461fe",      # noqa
    "sphincs-sha256-128s-simple": "8ae7a91b321cd18bd855710eea9d13deea1a53bb7858baee5f77d0237d1897eb",      # noqa
    "sphincs-sha256-192f-robust": "9d0898cb264172c31d0fb4901dd56d46728e83e0bf008abccb8b0912c2ebbc52",      # noqa
    "sphincs-sha256-192f-simple": "306fef951d07b17b27c67ffe9e63185ae5d5fde87619b76872a3ca969299d47c",      # noqa
    "sphincs-sha256-192s-robust": "23374b2ece45c8ec7272473d70eb424894324702616b8456343dbd79f109b675",      # noqa
    "sphincs-sha256-192s-simple": "02b192ff93bc8977a80e9efc8fa6814ae85c2ad939f7185a959b428c1eb77150",      # noqa
    "sphincs-sha256-256f-robust": "e6fafb97dc3575d5dcd79183a4d7faad4f2c986745c63e61ddae3648559664f7",      # noqa
    "sphincs-sha256-256f-simple": "88fa150041ce9c305a971cef8ec444881afc14c4590637fa4b91c1deb15bb215",      # noqa
    "sphincs-sha256-256s-robust": "da28ff350ac552f100b35b01ecb494dc02f9dcf542fa2d88439cd427985e9581",      # noqa
    "sphincs-sha256-256s-simple": "768d61c537b3abacca3ab468623edafb33d28a33dc5a9859f803679a3020b639",      # noqa
    "sphincs-shake256-128f-robust": "e7789df37278d1e147996bd9bf4cda55d5ec5cbe921e64b0766927af4b02decd",    # noqa
    "sphincs-shake256-128f-simple": "c99700873ca6914944fcef3b649270c86c056dcd11ce6e8f22580b193a136e6f",    # noqa
    "sphincs-shake256-128s-robust": "e9c31937277677d1cb387ce76408c76b0128938f3af047f60fb5d073a3c788b3",    # noqa
    "sphincs-shake256-128s-simple": "5d23c9f334e9bd99d5294cf40c6b2c096ee668076e809b44b928ca146d2c5e3a",    # noqa
    "sphincs-shake256-192f-robust": "5cfcf998ad0bedf8e6b961c8891048f456d6422d3b4a26fcb095a913c9efd03e",    # noqa
    "sphincs-shake256-192f-simple": "28528adef75a728d013bb493d85e358a75344c72000792419f1f539c16f24f10",    # noqa
    "sphincs-shake256-192s-robust": "619ce596575f52ed8fd3e5b0501db21985e505c95f0f595faa4d6a6f0a2fd81c",    # noqa
    "sphincs-shake256-192s-simple": "31b341c25230f8524e123db8a5dc29e8dd952cd11a63a821ac488b97d5106597",    # noqa
    "sphincs-shake256-256f-robust": "d5410edbaa120cf24f0bcf8cb834fdb08b4b5652809ee17c026d37212f4a4934",    # noqa
    "sphincs-shake256-256f-simple": "5a8959fc0436a66d6d69cc8adb2f24936b763ae324bc97ed139ae92f9f7e03c3",    # noqa
    "sphincs-shake256-256s-robust": "09004dba03b2a190a327b5404a4d75c663f025703253b78946d0a99ca1492d6f",    # noqa
    "sphincs-shake256-256s-simple": "f704deaf990987c306082bb28258cfb8c6f03b49940c06df582ef3fb86958e8a",    # noqa
}

testvectors = {
    "sphincs-haraka-128f-robust": "a86f82106578f5bb8ea54caa913dbe2b0ca13294432e06c615e0cc2f3fba66ac",      # noqa
    "sphincs-haraka-128f-simple": "db98c3cd0ac0292a2b62e11c52851087d84971277188814bf14cbde7ca60c3e9",      # noqa
    "sphincs-haraka-128s-robust": "b39fd1f6f34923b4c0696b72a1242f5a9e45df48eb28dcb9a53e4ba9955e130c",      # noqa
    "sphincs-haraka-128s-simple": "526b848d03142746354042329e174aedda2acd70269a57017e37edd5b1b8976a",      # noqa
    "sphincs-haraka-192f-robust": "28a3b10cfcd0bd8b2b9789f7ceb86f764b3be5f22aacad9d66b51d76077d8bc0",      # noqa
    "sphincs-haraka-192f-simple": "2d630dda998eda5fa634867af350a211276ad37f95506c48fdb06dc96f78d348",      # noqa
    "sphincs-haraka-192s-robust": "524edf3f752a7f203fb128d9ca3ad530fba09777527f7d7511477dbaaea185ca",      # noqa
    "sphincs-haraka-192s-simple": "0228f1872256e698360c0b156e7fffc12d234e50acbf05a4e899d4d8105d2796",      # noqa
    "sphincs-haraka-256f-robust": "7cc4c9a8720401ed53bc2fa9a0dd9e316dca3a715b3c730d1e0c4822dfdfd0b5",      # noqa
    "sphincs-haraka-256f-simple": "dec0d78c3084540ea5c8a4ced594d07b0110d21d4a5564b80c4ea2638030b44d",      # noqa
    "sphincs-haraka-256s-robust": "10ea3f99d8899cc82d3a21f2198e93f32585b1c08022e57c1984b0811336f09f",      # noqa
    "sphincs-haraka-256s-simple": "cab3bd8c005a4e868052c471ec110359305e986f237f8ce2c7c08ae45c424bbe",      # noqa
    "sphincs-sha256-128f-robust": "3e7c782b25e405940160468c2d777a5ab6eb9b6cfe318efed257f3270cca8c72",      # noqa
    "sphincs-sha256-128f-simple": "5ce16422e028eb7a6198d0a276a1760a6bbcd4ba9457ddbbfd5e08f34985c0ce",      # noqa
    "sphincs-sha256-128s-robust": "29d6d0dd732078d177779a61b7654bbe59fcf2ecb9bcd2ade8391791a6570a63",      # noqa
    "sphincs-sha256-128s-simple": "edf1b76246ac560558d7938f8ac7bbf820f1e697ef4f5b5e1962f04fadb84a76",      # noqa
    "sphincs-sha256-192f-robust": "ca61e66c0377fd367ab0c920d2190855a64348668a336d300ec7f2c72e721be4",      # noqa
    "sphincs-sha256-192f-simple": "b25e0f2560f500d8988809522c72ea3ab0f81be52476a6cdf9d05a890a2d2ce0",      # noqa
    "sphincs-sha256-192s-robust": "1be5c30de6d0b856b1b51f0ff50a2acf9c3a359ee2178004e153bdfc50a68832",      # noqa
    "sphincs-sha256-192s-simple": "ee413e410a29274a9647b9440d6a554670e0f9587efaaddedf82e4923f68f80e",      # noqa
    "sphincs-sha256-256f-robust": "14dd19ba3ff75bad890949050289ab0f178d7baa6dcb8ff6bcd6a873692a5686",      # noqa
    "sphincs-sha256-256f-simple": "b4755edf8351c51225921af38a724d2bd9ff9f3afe4ae2abbc3a59763ecc897d",      # noqa
    "sphincs-sha256-256s-robust": "6a85ec1f64d017fc2ffd88aa7d679de7e0554e00bdea62c7fea5c4c403e3eafa",      # noqa
    "sphincs-sha256-256s-simple": "796b5101fa5170c92f0186b347716dc0662eac35002a8c4d80ac9283cbef5a02",      # noqa
    "sphincs-shake256-128f-robust": "eea7f59958e732c15110d0d06e3c23005d73df2b15a1e7b4ebc0ca2dcf162bb5",    # noqa
    "sphincs-shake256-128f-simple": "a14cb8e4f149493fc5979e465e09ce943e8d669186ff5c7c3d11239fa869def6",    # noqa
    "sphincs-shake256-128s-robust": "f3f56ddff38a75ee07b44c023b9c9133ffe9538bb4b64f8ec8742b21fcaa6a50",    # noqa
    "sphincs-shake256-128s-simple": "ee2af38333f6ba705102ab66689c262b07c1fd9ce1d46180796bcb263bf1a654",    # noqa
    "sphincs-shake256-192f-robust": "de65b2a7b6d5e819f58b6e1a08ec4ef3308a9c36b7c962450105f82263e35e98",    # noqa
    "sphincs-shake256-192f-simple": "14f60a3099cfddf30c46491a98a5f3508739df108425b2eaa5c19383f0ca4b22",    # noqa
    "sphincs-shake256-192s-robust": "4f80c9cf98c017293c7543f96170f18655e6ef65675300aa302de42562b21f5a",    # noqa
    "sphincs-shake256-192s-simple": "ea1c38dafdeec8bd6b5a844955b1edffbb1d16f392a647fdae8e6dd148c6396c",    # noqa
    "sphincs-shake256-256f-robust": "4757a2ce7aec6daac4ab894336586949f7919c63d55200ec6325eb395efcf1ef",    # noqa
    "sphincs-shake256-256f-simple": "1b261fc7394dc847349c07bde922ac028aad94c534f51341f8202670558ed27a",    # noqa
    "sphincs-shake256-256s-robust": "eea62308d71394a888e05128f078c4663dc83e128c34e0300bb16cb839d8698b",    # noqa
    "sphincs-shake256-256s-simple": "fc518be7778d0363f17a30c50efbe28841f5a795e7375e94d206f115967f30df",    # noqa
}

IMPLEMENTATION_FILES = {
    'ref': [
        'address.c',
        'address.h',
        'api.h',
        'fors.c',
        'fors.h',
        'hash.h',
        'hash_state.h',
        'sign.c',
        'thash.h',
        'utils.c',
        'utils.h',
        'wots.c',
        'wots.h',
    ],
    'haraka-aesni': [
        'address.c',
        'address.h',
        'api.h',
        'fors.c',
        'fors.h',
        'haraka.c',
        'haraka.h',
        'hash.h',
        'hash_harakax4.c',
        'hash_state.h',
        'hashx4.h',
        'sign.c',
        'thash.h',
        'thashx4.h',
        'utils.c',
        'utils.h',
        'utilsx4.c',
        'utilsx4.h',
        'wots.c',
        'wots.h',
    ],
    'shake256-avx2': [
        'address.c',
        'address.h',
        'api.h',
        'fips202x4.c',
        'fips202x4.h',
        'fors.c',
        'fors.h',
        'hash.h',
        'hash_shake256x4.c',
        'hash_state.h',
        'hashx4.h',
        'sign.c',
        'thash.h',
        'thashx4.h',
        'utils.c',
        'utils.h',
        'utilsx4.c',
        'utilsx4.h',
        'wots.c',
        'wots.h',
    ],
    'sha256-avx2': [
        'address.c',
        'address.h',
        'api.h',
        'fors.c',
        'fors.h',
        'hash.h',
        'hash_sha256x8.c',
        'hash_state.h',
        'hashx8.h',
        'sha256avx.c',
        'sha256avx.h',
        'sha256x8.c',
        'sha256x8.h',
        'sign.c',
        'thash.h',
        'thashx8.h',
        'utils.c',
        'utils.h',
        'utilsx8.c',
        'utilsx8.h',
        'wots.c',
        'wots.h',
    ],

}


sphincs_variants = (
    itertools.chain(
        itertools.product(funcs, sizes, options, variants, ['ref']),
        itertools.product(['haraka'], sizes, options, variants, ['haraka-aesni']),  # noqa
        itertools.product(['shake256'], sizes, options, variants, ['shake256-avx2']),  # noqa
        itertools.product(['sha256'], sizes, options, variants, ['sha256-avx2']),  # noqa
    )
)


for (func, size, opt, variant, impl) in sphincs_variants:
    varname = f'sphincs-{func}-{size}{opt}-{variant}'
    target_impl = (IMPLEMENTATION_NAME_MAP[impl]
                   if impl in IMPLEMENTATION_NAME_MAP else impl)
    print(f"Generating {varname} {target_impl}")
    if PQCLEAN_LAYOUT:
        instpath = os.path.join(TARGET_DIR, varname, target_impl)
    else:
        instpath = os.path.join(TARGET_DIR, f"{varname}_{target_impl}")
    target_namespace = generate_namespace(
        func, size, opt, variant, target_impl)
    canonical_path = impl
    try:
        shutil.rmtree(instpath)
    except Exception:
        pass
    os.makedirs(instpath)
    for filename in (
            IMPLEMENTATION_FILES[impl]
            + [f'hash_{func}.c', f'thash_{func}_{variant}.c']
            + ([f'thash_{func}_{variant}x4.c']
               if impl in X4_IMPLS else [])
            + ([f'thash_{func}_{variant}x8.c']
               if impl in X8_IMPLS else [])):
        shutil.copy(os.path.join(canonical_path, filename), instpath)
    shutil.copy(os.path.join('pqclean', 'makefiles', impl, 'Makefile'),
                instpath)
    shutil.copy(
        os.path.join('pqclean', 'makefiles', impl, 'Makefile.Microsoft_nmake'),
        instpath)
    shutil.copy('LICENSE', instpath)

    OBJS = f" hash_{func}.o thash_{func}_{variant}.o"
    if impl in X4_IMPLS:
        OBJS += f" hash_{func}x4.o thash_{func}_{variant}x4.o"
    elif impl in X8_IMPLS:
        OBJS += f" hash_{func}x8.o thash_{func}_{variant}x8.o"

    HEADERS = ""
    if func in ['sha256', 'haraka']:
        shutil.copy(os.path.join(canonical_path, f'{func}.c'), instpath)
        shutil.copy(os.path.join(canonical_path, f'{func}.h'), instpath)
        OBJS += f" {func}.o"
        HEADERS += f" {func}.h"

    replace_in_file(
        os.path.join(instpath, 'Makefile'),
        'libsphincs_clean.a', f'lib{varname}_{target_impl}.a')
    replace_in_file(
        os.path.join(instpath, 'Makefile'),
        'HASHOBJECTS', OBJS)
    replace_in_file(
        os.path.join(instpath, 'Makefile'),
        'HASHHEADERS', HEADERS)
    OBJS = OBJS.replace('.o', '.obj')
    replace_in_file(
        os.path.join(instpath, 'Makefile.Microsoft_nmake'),
        'libsphincs_clean.lib', f'lib{varname}_{target_impl}.lib')
    replace_in_file(
        os.path.join(instpath, 'Makefile.Microsoft_nmake'),
        'HASHOBJECTS', OBJS)
    replace_in_file(
        os.path.join(instpath, 'Makefile.Microsoft_nmake'),
        'HASHHEADERS', HEADERS)

    shutil.copy(
        os.path.join('ref', 'params',
                     f'params-sphincs-{func}-{size}{opt}.h'),
        os.path.join(instpath, 'params.h'))
    for file in os.listdir(instpath):
        replace_in_file(os.path.join(instpath, file),
                        "SPX_", target_namespace)
    metafile = os.path.join(instpath, '..', 'META.yml')
    apifile = os.path.join(instpath, 'api.h')

    # copy hash_state.h
    if impl == 'ref':
        shutil.copy(os.path.join(canonical_path, 'hash_states', f'{func}.h'),
                    os.path.join(instpath, 'hash_state.h'))

    with open('pqclean/META.yml.j2') as f:
        tmpl = jinja2.Template(f.read(), trim_blocks=True)
    tmpl.stream(
        nist_level=size // 64 * 2 - 3,
        pk_len=size // 8 * 2,
        sk_len=size // 8 * 4,
        sig_len=sigsizes[(size, opt)],
        nistkat=nistkat[varname],
        testvectors=testvectors[varname],
        func=func,
    ).dump(metafile)

    # Update api.h
    replace_in_file(apifile,
                    '#include "params.h"', '')
    replace_in_file(apifile,
                    "_CRYPTO_SECRETKEYBYTES .*",
                    f"_CRYPTO_SECRETKEYBYTES {(size // 8) * 4}")
    replace_in_file(apifile,
                    "_CRYPTO_PUBLICKEYBYTES .*",
                    f"_CRYPTO_PUBLICKEYBYTES {(size // 8) * 2}")
    replace_in_file(apifile,
                    "_CRYPTO_BYTES .*",
                    f"_CRYPTO_BYTES {sigsizes[(size, opt)]}")
    replace_in_file(apifile,
                    "_CRYPTO_SEEDBYTES .*",
                    f"_CRYPTO_SEEDBYTES {(size // 8) * 3}")

    if PQCLEAN_LAYOUT:
        subprocess.run(
            ['unifdef', '-UNIST_COMPATIBLE', '-o', apifile, apifile])
        cfiles = glob.glob(os.path.join(instpath, '*.c'))
        hfiles = glob.glob(os.path.join(instpath, '*.h'))
        subprocess.run(
            ['astyle', '--options=pqclean/.astylerc', *cfiles, *hfiles],
            capture_output=True)

        with open('pqclean/duplicate-consistency.yml.j2') as f:
            tmpl = jinja2.Template(f.read(), trim_blocks=True)
        duplicatefile = os.path.join(
            instpath, '..', '..', '..', 'test', 'duplicate_consistency',
            f'{varname}-{target_impl}.yml')
        tmpl.stream(
            impl=target_impl,
            size=str(size),
            opt=opt,
            func=func,
            varname=varname,
            variant=variant,
        ).dump(duplicatefile)
