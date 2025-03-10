# test_proxy.py
import sys
import os

# 假设编译好的模块在 ../build 目录下，将其添加到 sys.path
module_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../build"))
if module_path not in sys.path:
    sys.path.insert(0, module_path)

import proxypseudorandom

# 生成密钥对示例
priv, pub = proxypseudorandom.generate_keys()
print("私钥:", priv)
print("公钥 (bytes):", pub)

# 计算 SHA3-256 示例
data = b"Hello, Proxy Re-Encryption"
digest = proxypseudorandom.sha3_hash(data)
print("SHA3-256:", digest.hex())

# 映射到曲线整数
h_curve = proxypseudorandom.hash_to_curve(b"Sample data")
print("hash_to_curve:", h_curve)

# 示例：重加密密钥生成
# 假设 a_pri 为 Alice 的私钥，b_pub 为 Bob 的公钥（均由 generate_keys 得到）
a_pri, a_pub = proxypseudorandom.generate_keys()
b_pri, b_pub = proxypseudorandom.generate_keys()
rk, pubX = proxypseudorandom.re_key_gen(a_pri, pub=b_pub)
print("重加密密钥 rk:", rk)
print("pubX:", pubX)

# 示例：对 capsule 进行重加密
# 此处构造一个简单的 capsule（实际中 capsule 应包含 E、V 两个公钥和 s 值）
capsule = {
    "E": a_pub,  # 这里仅作示例，实际应为加密时生成的 E 值（bytes形式）
    "V": a_pub,  # 同上
    "s": "1A2B3C4D"  # 示例 s 值（hex字符串）
}
new_capsule = proxypseudorandom.re_encryption(rk, capsule)
print("重加密后的 capsule:", new_capsule)
