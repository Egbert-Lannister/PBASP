# curve.py
import os
from ecdsa import SigningKey, VerifyingKey, NIST256p, ellipticcurve
import gzip
import io

# 使用 NIST256p（与 P256 等价）
CURVE = NIST256p
N = CURVE.order

def generate_keys():
    """
    生成 ECDSA 私钥和公钥对
    """
    sk = SigningKey.generate(curve=CURVE)
    vk = sk.get_verifying_key()
    return sk, vk

def sign(private_key, message_hash):
    """
    ECDSA 签名，对消息摘要进行签名，并使用 gzip 压缩签名
    """
    signature = private_key.sign(message_hash.encode())
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode='wb') as f:
        f.write(signature)
    return buf.getvalue().hex()

def verify(message_hash, signature_hex, public_key):
    """
    验证签名：先解压签名，再使用公钥验证
    """
    signature_compressed = bytes.fromhex(signature_hex)
    buf = io.BytesIO(signature_compressed)
    with gzip.GzipFile(fileobj=buf, mode='rb') as f:
        signature = f.read()
    try:
        valid = public_key.verify(signature, message_hash.encode())
    except Exception:
        valid = False
    return valid

def point_scalar_add(point1, point2):
    """
    椭圆曲线点加法，输入为 ecdsa.ellipticcurve.Point 对象
    """
    return point1 + point2

def point_scalar_mul(point, scalar):
    """
    椭圆曲线点乘，scalar 为整数
    """
    return scalar * point

def big_int_mul_base(scalar):
    """
    基点乘以 scalar
    """
    generator = CURVE.generator
    return scalar * generator

def point_to_bytes(vk_or_point):
    """
    将公钥或椭圆曲线点转换为未压缩字节形式（0x04 + X + Y）
    """
    if hasattr(vk_or_point, "to_string"):
        # 假设为 VerifyingKey
        raw = vk_or_point.to_string()
        return b'\x04' + raw
    elif hasattr(vk_or_point, "x") and hasattr(vk_or_point, "y"):
        x_val = vk_or_point.x
        y_val = vk_or_point.y
        if callable(x_val):
            x_val = x_val()
        if callable(y_val):
            y_val = y_val()
        x_bytes = int(x_val).to_bytes(32, 'big')
        y_bytes = int(y_val).to_bytes(32, 'big')
        return b'\x04' + x_bytes + y_bytes
    else:
        raise TypeError("Unsupported type for point_to_bytes")



