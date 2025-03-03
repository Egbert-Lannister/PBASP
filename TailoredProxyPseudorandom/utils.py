# utils.py
import hashlib
from curve import N, CURVE
from ecdsa import SigningKey, VerifyingKey

def concat_bytes(a, b):
    return a + b

def sha3_hash(message):
    h = hashlib.sha3_256()
    h.update(message)
    return h.digest()

def hash_to_curve(data):
    # 将哈希值映射为整数，再 mod N
    num = int.from_bytes(data, 'big')
    return num % N

def private_key_to_string(private_key):
    # 将私钥转换为十六进制字符串（使用其内部 secret 值）
    secret = private_key.privkey.secret_multiplier
    return format(secret, 'x')

def private_key_str_to_key(private_key_str):
    secret = int(private_key_str, 16)
    return SigningKey.from_secret_exponent(secret, curve=CURVE)

def public_key_to_string(public_key):
    # 将公钥转换为十六进制字符串（未压缩形式）
    b = b'\x04' + public_key.to_string()
    return b.hex()

def public_key_str_to_key(pub_key_str):
    b = bytes.fromhex(pub_key_str)
    # 去掉未压缩前缀 0x04
    if b[0] == 4:
        b = b[1:]
    return VerifyingKey.from_string(b, curve=CURVE)
