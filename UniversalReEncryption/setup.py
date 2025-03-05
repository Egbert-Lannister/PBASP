from setuptools import setup, Extension

module = Extension(
    'paillier',
    sources=['paillier_module.c'],
    include_dirs=['C:/src/vcpkg/installed/x64-windows/include'],
    library_dirs=['C:/src/vcpkg/installed/x64-windows/lib'],
    libraries=['gmp','gmpxx'],
    extra_compile_args=['-O3','/GS-']
)

setup(
    name='Paillier',
    version='0.1',
    ext_modules=[module]
)