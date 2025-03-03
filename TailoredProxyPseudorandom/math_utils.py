# math_utils.py
from curve import N

def big_int_add(a, b):
    return (a + b) % N

def big_int_sub(a, b):
    return (a - b) % N

def big_int_mul(a, b):
    return (a * b) % N

def get_invert(a):
    # 使用 Python 内置 pow 求模逆：pow(a, -1, N)
    return pow(a, -1, N)
