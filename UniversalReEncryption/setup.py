from setuptools import setup, Extension
from pybind11.setup_helpers import Pybind11Extension, build_ext

ext_modules = [
    Pybind11Extension(
        "universal_reencryption",
        ["universal_reencryption.cpp"],
        include_dirs=["C:/src/vcpkg/installed/x64-windows/include"]
    ),
]

setup(
    name="universal_reencryption",
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext},
)



# from setuptools import setup, Extension
#
# module = Extension(
#     'paillier',
#     sources=['paillier_module.c'],
#     include_dirs=['C:/src/vcpkg/installed/x64-windows/include'],
#     library_dirs=['C:/src/vcpkg/installed/x64-windows/lib'],
#     libraries=['gmp','gmpxx'],
#     extra_compile_args=['-O3','/GS-']
# )
#
# setup(
#     name='Paillier',
#     version='0.1',
#     ext_modules=[module]
# )