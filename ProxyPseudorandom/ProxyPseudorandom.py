import hashlib
import pickle

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ecdsa import SigningKey, VerifyingKey, NIST256p


class ProxyPseudorandom:
    CURVE = NIST256p
    N = NIST256p.order

    # --------------------- 基础工具函数 ---------------------
    @staticmethod
    def generate_keys():
        """
        生成 ECDSA 密钥对（私钥、对应公钥）
        """
        sk = SigningKey.generate(curve=ProxyPseudorandom.CURVE)
        vk = sk.get_verifying_key()
        return sk, vk

    @staticmethod
    def point_to_bytes(vk_or_point):
        """
        将公钥或椭圆曲线点转换为未压缩字节形式（0x04 + X + Y）
        """
        if hasattr(vk_or_point, "to_string"):
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

    @staticmethod
    def sha3_hash(message):
        sha = hashlib.sha3_256()
        sha.update(message)
        return sha.digest()

    @staticmethod
    def concat_bytes(a, b):
        return a + b

    @staticmethod
    def hash_to_curve(data):
        """
        将数据 hash 后映射到曲线上的一个整数（mod N）
        """
        num = int.from_bytes(ProxyPseudorandom.sha3_hash(data), 'big')
        return num % ProxyPseudorandom.N

    @staticmethod
    def big_int_add(a, b):
        return (a + b) % ProxyPseudorandom.N

    @staticmethod
    def big_int_mul(a, b):
        return (a * b) % ProxyPseudorandom.N

    @staticmethod
    def get_invert(a):
        return pow(a, -1, ProxyPseudorandom.N)

    @staticmethod
    def point_scalar_mul(point, scalar):
        return scalar * point

    @staticmethod
    def point_scalar_add(p1, p2):
        return p1 + p2

    # --------------------- 加密相关功能 ---------------------
    @staticmethod
    def encrypt_key_gen(pub_key):
        """
        生成加密过程中需要的 capsule 和 AES 密钥
          - 随机生成 E,V 密钥对
          - h = H2(E || V)
          - s = priV + priE * h (mod N)
          - 计算 point = pub_key^(priE + priV)
          - AES 密钥 = sha3(point_to_bytes(point))
        """
        priE, pubE = ProxyPseudorandom.generate_keys()
        priV, pubV = ProxyPseudorandom.generate_keys()
        h_data = ProxyPseudorandom.concat_bytes(
            ProxyPseudorandom.point_to_bytes(pubE),
            ProxyPseudorandom.point_to_bytes(pubV)
        )
        h = ProxyPseudorandom.hash_to_curve(h_data)
        s = ProxyPseudorandom.big_int_add(
            priV.privkey.secret_multiplier,
            ProxyPseudorandom.big_int_mul(priE.privkey.secret_multiplier, h)
        )
        total_scalar = priE.privkey.secret_multiplier + priV.privkey.secret_multiplier
        point = ProxyPseudorandom.point_scalar_mul(pub_key.pubkey.point, total_scalar)
        key_bytes = ProxyPseudorandom.sha3_hash(ProxyPseudorandom.point_to_bytes(point))
        # 将 capsule 用字典封装
        capsule = {'E': pubE, 'V': pubV, 's': s}
        return capsule, key_bytes

    @staticmethod
    def encrypt_message_by_aes_key(message, key_bytes):
        """
        使用 AES-GCM 算法加密消息：
          - 取 key_bytes 的前 32 个字符作为 AES 密钥
          - 取 key_bytes 的前 12 字节作为 nonce
        """
        full_key = key_bytes.hex()  # 长度64个字符，32字节
        aes_key = bytes.fromhex(full_key[:32])
        nonce = key_bytes[:12]
        aesgcm = AESGCM(aes_key)
        ct = aesgcm.encrypt(nonce, message.encode(), None)
        return ct

    @staticmethod
    def encrypt(message, pub_key):
        """
        加密接口：返回密文和 capsule
        """
        capsule, key_bytes = ProxyPseudorandom.encrypt_key_gen(pub_key)
        ct = ProxyPseudorandom.encrypt_message_by_aes_key(message, key_bytes)
        return ct, capsule

    @staticmethod
    def re_key_gen(a_pri, b_pub):
        """
        生成重加密密钥：
          - 生成随机密钥对 (priX, pubX)
          - 计算 point = b_pub^(priX)
          - d = H3(pubX || b_pub || point)
          - rk = a_pri * d^{-1} mod N
        """
        priX, pubX = ProxyPseudorandom.generate_keys()
        point = ProxyPseudorandom.point_scalar_mul(b_pub.pubkey.point, priX.privkey.secret_multiplier)
        d_data = ProxyPseudorandom.concat_bytes(
            ProxyPseudorandom.point_to_bytes(pubX),
            ProxyPseudorandom.point_to_bytes(b_pub)
        )
        d_data = ProxyPseudorandom.concat_bytes(d_data, ProxyPseudorandom.point_to_bytes(point))
        d = ProxyPseudorandom.hash_to_curve(d_data)
        inv_d = ProxyPseudorandom.get_invert(d)
        rk = ProxyPseudorandom.big_int_mul(a_pri.privkey.secret_multiplier, inv_d)
        rk %= ProxyPseudorandom.N
        return rk, pubX

    @staticmethod
    def _scale_public_key(vk, scalar):
        """
        将公钥点乘以标量，返回新的 VerifyingKey
        """
        point = vk.pubkey.point * scalar
        x_bytes = point.x().to_bytes(32, 'big')
        y_bytes = point.y().to_bytes(32, 'big')
        pub_bytes = x_bytes + y_bytes
        return VerifyingKey.from_string(pub_bytes, curve=ProxyPseudorandom.CURVE)

    @staticmethod
    def re_encryption(rk, capsule):
        """
        服务器侧重加密：
          - 校验 capsule 是否正确（验证 g^s == V + E^(H2(E||V))）
          - 计算 E' = E^rk, V' = V^rk
        """
        generator = ProxyPseudorandom.CURVE.generator
        left_point = generator * capsule['s']
        h_data = ProxyPseudorandom.concat_bytes(
            ProxyPseudorandom.point_to_bytes(capsule['E']),
            ProxyPseudorandom.point_to_bytes(capsule['V'])
        )
        h_val = ProxyPseudorandom.hash_to_curve(h_data)
        e_h = ProxyPseudorandom.point_scalar_mul(capsule['E'].pubkey.point, h_val)
        right_point = ProxyPseudorandom.point_scalar_add(capsule['V'].pubkey.point, e_h)
        if left_point != right_point:
            raise ValueError("Capsule not match")
        new_E = ProxyPseudorandom._scale_public_key(capsule['E'], rk)
        new_V = ProxyPseudorandom._scale_public_key(capsule['V'], rk)
        new_capsule = {'E': new_E, 'V': new_V, 's': capsule['s']}
        return new_capsule

    @staticmethod
    def decrypt_key_gen(b_pri, capsule, pubX):
        """
        生成解密所需的 AES 密钥：
          - S = pubX^(b_pri)
          - d = H3(pubX || b_pri.public_key || S)
          - key_bytes = sha3( (E+V)^d )
        """
        S_point = pubX.pubkey.point * b_pri.privkey.secret_multiplier
        b_pub = b_pri.get_verifying_key()
        d_data = ProxyPseudorandom.concat_bytes(
            ProxyPseudorandom.point_to_bytes(pubX),
            ProxyPseudorandom.point_to_bytes(b_pub)
        )
        d_data = ProxyPseudorandom.concat_bytes(d_data, ProxyPseudorandom.point_to_bytes(S_point))
        d = ProxyPseudorandom.hash_to_curve(d_data)
        point = ProxyPseudorandom.point_scalar_mul(
            ProxyPseudorandom.point_scalar_add(capsule['E'].pubkey.point, capsule['V'].pubkey.point),
            d
        )
        key_bytes = ProxyPseudorandom.sha3_hash(ProxyPseudorandom.point_to_bytes(point))
        return key_bytes

    @staticmethod
    def decrypt(b_pri, capsule, pubX, cipher_text):
        """
        解密接口：使用 Bob 私钥和重加密后的 capsule 解密
        """
        key_bytes = ProxyPseudorandom.decrypt_key_gen(b_pri, capsule, pubX)
        full_key = key_bytes.hex()
        aes_key = bytes.fromhex(full_key[:32])
        nonce = key_bytes[:12]
        aesgcm = AESGCM(aes_key)
        plain = aesgcm.decrypt(nonce, cipher_text, None)
        return plain

    @staticmethod
    def decrypt_on_my_pri(a_pri, capsule, cipher_text):
        """
        使用自己私钥解密（Alice 可直接解密自己的数据）
        """
        point1 = ProxyPseudorandom.point_scalar_add(
            capsule['E'].pubkey.point,
            capsule['V'].pubkey.point
        )
        point = ProxyPseudorandom.point_scalar_mul(point1, a_pri.privkey.secret_multiplier)
        key_bytes = ProxyPseudorandom.sha3_hash(ProxyPseudorandom.point_to_bytes(point))
        full_key = key_bytes.hex()
        aes_key = bytes.fromhex(full_key[:32])
        nonce = key_bytes[:12]
        aesgcm = AESGCM(aes_key)
        plain = aesgcm.decrypt(nonce, cipher_text, None)
        return plain

    # --------------------- Capsule 序列化接口 ---------------------
    @staticmethod
    def encode_capsule(capsule):
        data = {
            'E': ProxyPseudorandom.point_to_bytes(capsule['E']).hex(),
            'V': ProxyPseudorandom.point_to_bytes(capsule['V']).hex(),
            's': capsule['s']
        }
        return pickle.dumps(data)

    @staticmethod
    def decode_capsule(data_bytes):
        data = pickle.loads(data_bytes)
        E = VerifyingKey.from_string(bytes.fromhex(data['E'])[1:], curve=ProxyPseudorandom.CURVE)
        V = VerifyingKey.from_string(bytes.fromhex(data['V'])[1:], curve=ProxyPseudorandom.CURVE)
        s = data['s']
        return {'E': E, 'V': V, 's': s}


# --------------------- 示例调用 ---------------------
if __name__ == "__main__":
    # 生成 Alice 和 Bob 的密钥对
    a_pri, a_pub = ProxyPseudorandom.generate_keys()
    b_pri, b_pub = ProxyPseudorandom.generate_keys()
    # c_pri, c_pub = ProxyPseudorandom.generate_keys()
    message = "Hello, Proxy Re-Encryption"
    print("原始消息:", message)

    # Alice 加密消息
    cipher_text, capsule = ProxyPseudorandom.encrypt(message, a_pub)
    print(cipher_text)
    print("密文:", cipher_text.hex())

    # Capsule 序列化和反序列化测试
    encoded_capsule = ProxyPseudorandom.encode_capsule(capsule)
    capsule2 = ProxyPseudorandom.decode_capsule(encoded_capsule)

    # Alice 生成重加密密钥（发给代理服务器用于重加密）
    rk, pubX = ProxyPseudorandom.re_key_gen(a_pri, b_pub)
    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)

    # rk_c, pubX_c = ProxyPseudorandom.re_key_gen(a_pri, c_pub)
    # new_capsule_c = ProxyPseudorandom.re_encryption(rk_c, new_capsule)

    new_capsule2 = ProxyPseudorandom.re_encryption(rk, new_capsule)

    # Bob 使用重加密后的 capsule 解密
    plain_text = ProxyPseudorandom.decrypt(b_pri, new_capsule, pubX, cipher_text)
    print("Bob 解密后的消息:", plain_text.decode())

    plain_text = ProxyPseudorandom.decrypt(b_pri, new_capsule2, pubX, cipher_text)
    print("Bob 解密后的消息:", plain_text.decode())

    # # 两次重加密解密
    # plain_text_c = ProxyPseudorandom.decrypt(c_pri, new_capsule, pubX_c, cipher_text)
    # print("C 解密之后的消息:", plain_text_c.decode())

    # Alice 直接使用自己私钥解密
    plain_text_my = ProxyPseudorandom.decrypt_on_my_pri(a_pri, capsule, cipher_text)
    print("Alice 解密后的消息:", plain_text_my.decode())
