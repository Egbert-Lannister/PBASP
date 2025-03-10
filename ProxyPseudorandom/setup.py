# setup.py
from setuptools import setup, Extension
from setuptools import find_packages
import pybind11
import os

cpp_args = ['-std=c++11']
include_dirs = [
    pybind11.get_include(),
    # 如果 OpenSSL 头文件不在标准路径，可在此添加 OpenSSL 的 include 目录
]

library_dirs = [
    # 如果 OpenSSL 库不在标准路径，可在此添加 OpenSSL 的 lib 目录
]

ext_modules = [
    Extension(
        "proxypseudorandom",
        ["proxypseudorandom.cpp"],
        include_dirs=include_dirs,
        library_dirs=library_dirs,
        libraries=["ssl", "crypto"],
        extra_compile_args=cpp_args,
    ),
]

setup(
    name="proxypseudorandom",
    version="0.1",
    author="Your Name",
    description="ProxyPseudorandom C++ extension module",
    ext_modules=ext_modules,
    install_requires=["pybind11", "setuptools"],
    zip_safe=False,
)
