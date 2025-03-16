import hashlib
import pickle
import random
import math
import hmac
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ecdsa import SigningKey, VerifyingKey, NIST256p

from BitMap import BitMap


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
    def encrypt(message, pub_key, mode="default", search_key=None):
        """
        加密接口：
         - mode="default" 为普通消息加密（随机加密）
         - mode="keyword" 为关键字加密，此时需要提供 search_key
           生成确定性搜索令牌，并在 capsule 中记录 tag 和重加密次数（初始为 0）
        """
        if mode == "keyword":
            if search_key is None:
                raise ValueError("关键字加密必须提供 proxy_pseudorandom_key")
            # 生成初始确定性搜索令牌
            token = ProxyPseudorandom.generate_search_token(message, search_key)
            # cipher_text 就是该令牌（以 bytes 形式存储）
            cipher_text = token.encode("utf-8")
            # capsule 记录 tag 和 count，count 表示已重加密次数
            capsule = {'tag': token, 'count': 0}
            return cipher_text, capsule
        elif mode == "position":
            if search_key is None:
                raise ValueError("关键字加密必须提供 proxy_pseudorandom_key")
            # 生成初始确定性搜索令牌
            token = ProxyPseudorandom.generate_search_token(message, search_key)
            # cipher_text 就是该令牌（以 bytes 形式存储）
            cipher_text = token.encode("utf-8")
            # capsule 记录 tag 和 count，count 表示已重加密次数
            capsule = {'tag': token, 'count': 0}
            return cipher_text, capsule
        else:
            capsule, key_bytes = ProxyPseudorandom.encrypt_key_gen(pub_key)
            ct = ProxyPseudorandom.encrypt_message_by_aes_key(message, key_bytes)
            return ct, capsule

    # --------------------- 关键字重加密及查询转换 ---------------------
    @staticmethod
    def re_encrypt_keyword(capsule, server_rk):
        """
        针对关键字加密的 capsule 进行重加密：
         - 利用服务器的重加密密钥 server_rk（转换为字节作为 HMAC 密钥）
         - 对 capsule['tag'] 进行更新，更新方式可采用 HMAC 计算：
             new_tag = HMAC(server_rk, old_tag || count)
         - 同时 capsule['count'] 加1，记录重加密次数
        """
        old_tag = capsule['tag']
        count = capsule.get('count', 0)
        # 将服务器重加密密钥转换为 bytes（例如直接取字符串形式）
        round_key = str(server_rk).encode("utf-8")
        # 计算新 tag（这里简单将 count 转为字节拼接）
        new_tag = hmac.new(round_key, old_tag.encode("utf-8") + str(count).encode("utf-8"), hashlib.sha256).hexdigest()
        capsule['tag'] = new_tag
        capsule['count'] = count + 1
        return capsule

    @staticmethod
    def transform_query_token(query_token, server_rk, count):
        """
        当服务器接收到客户端查询时，
         根据存储在索引中的 capsule count，对客户端原始查询令牌进行重加密转换，
         使之与经过多次重加密后的关键字密文匹配。
         这里模拟将查询令牌经过 count 次重加密，使用与 re_encrypt_keyword 相同的逻辑。
        """
        token = query_token  # 初始令牌（十六进制字符串）
        round_key = str(server_rk).encode("utf-8")
        for i in range(count):
            token = hmac.new(round_key, token.encode("utf-8") + str(i).encode("utf-8"), hashlib.sha256).hexdigest()
        return token

    @staticmethod
    @lru_cache(maxsize=None)
    def transform_query_token_cached(rk, init_token, count):
        # 确保 init_token 是字符串
        if not isinstance(init_token, str):
            init_token = str(init_token)
        return ProxyPseudorandom.transform_query_token(init_token, rk, count)

    # --------------------- 其他重加密和解密相关功能（保持原有逻辑） ---------------------
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
        # 如果 capsule 为关键字或位置模式（包含 'tag'），则调用关键字位置重加密逻辑
        if 'tag' in capsule:
            return ProxyPseudorandom.re_encrypt_keyword(capsule, rk)
        # 否则，按照普通消息的重加密逻辑处理
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

    # --------------------- 搜索令牌（Search Token）功能 ---------------------
    @staticmethod
    def generate_search_token(keyword, search_key):
        """
        使用 HMAC-SHA256 生成确定性的搜索令牌
        参数:
            keyword: 待加密的关键字（字符串）
            search_key: 共享密钥（字符串或 bytes）
        返回:
            十六进制字符串形式的搜索令牌
        """
        if not isinstance(search_key, bytes):
            search_key = search_key.encode('utf-8')
        if not isinstance(keyword, bytes):
            keyword = keyword.encode('utf-8')
        token = hmac.new(search_key, keyword, hashlib.sha256).hexdigest()
        return token


# --------------------- 示例调用 ---------------------
if __name__ == "__main__":
    # 生成 Alice 和 Bob 的密钥对
    a_pri, a_pub = ProxyPseudorandom.generate_keys()
    b_pri, b_pub = ProxyPseudorandom.generate_keys()
    message = "Hello, Proxy Re-Encryption"
    print("原始消息:", message)

    message2 = "Hello, Proxy Re-Encryption"
    cipher_text2, capsule2 = ProxyPseudorandom.encrypt(message2, a_pub)
    print(cipher_text2)
    print(cipher_text2.hex())

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

    # Bob 使用重加密后的 capsule 解密
    plain_text = ProxyPseudorandom.decrypt(b_pri, new_capsule, pubX, cipher_text)
    print("Bob 解密后的消息:", plain_text.decode())

    # Alice 直接使用自己私钥解密
    plain_text_my = ProxyPseudorandom.decrypt_on_my_pri(a_pri, capsule, cipher_text)
    print("Alice 解密后的消息:", plain_text_my.decode())


class UniversalReEncryption:
    def __init__(self, security_param=8):
        """
        初始化：生成 Paillier 密钥对，并分割私钥为两个部分（用于分布式解密）。
        security_param 为生成素数的位数，实际应用中应设置较大值。
        """
        self.public_key, self.private_key = self._generate_paillier_keys(security_param)
        self.n, self.g = self.public_key
        self.lam, self.mu = self.private_key
        # 分割私钥，要求 pdk1 * pdk2 = lam，示例中简单设定 pdk1=2
        self.partial_key1, self.partial_key2 = self._generate_partial_keys()

    def __getstate__(self):
        # 返回一个可序列化的状态字典，排除不可序列化的成员
        state = self.__dict__.copy()
        # 如果有不可序列化的成员，可以在这里进行处理
        # 例如，删除或转换不可序列化的成员
        return state

    def __setstate__(self, state):
        # 从状态字典恢复对象状态
        self.__dict__.update(state)

    @staticmethod
    def _L(u, n):
        """
        辅助函数 L(u) = (u-1) // n
        """
        return (u - 1) // n

    @staticmethod
    def _is_prime(n):
        """
        判断一个整数 n 是否为素数
        """
        if n < 2:
            return False
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0:
                return False
        return True

    @staticmethod
    def _generate_prime(bits):
        """
        生成一个大致 bits 位的素数（暴力搜索，仅用于示例）
        """
        while True:
            num = random.getrandbits(bits)
            # 确保最高位和最低位为1
            num |= (1 << (bits - 1)) | 1
            if UniversalReEncryption._is_prime(num):
                return num

    def _generate_paillier_keys(self, bits):
        """
        生成 Paillier 公钥和私钥
          - 公钥: (n, g)
          - 私钥: (lam, mu)
        """
        p = self._generate_prime(bits)
        q = self._generate_prime(bits)
        # 保证 p 和 q 不相等
        while q == p:
            q = self._generate_prime(bits)
        n = p * q
        n_sq = n * n
        # 计算 λ = lcm(p-1, q-1)
        lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        # g 选为 n + 1 是常用的选择
        g = n + 1
        # 计算 u = g^lam mod n^2，并求 L(u)
        u = pow(g, lam, n_sq)
        L_u = self._L(u, n)
        # 求 μ 为 L(u) 在模 n 下的逆元
        mu = pow(L_u, -1, n)
        return (n, g), (lam, mu)

    def _generate_partial_keys(self):
        """
        将私钥中的 lam 简单分解为两个部分，使得 partial_key1 * partial_key2 = lam
        示例中设定 partial_key1 = 2，partial_key2 = lam // 2
        """
        partial_key1 = 2
        partial_key2 = self.private_key[0] // partial_key1
        return partial_key1, partial_key2

    def encrypt(self, m):
        """
        使用 Paillier 加密算法加密明文 m，返回密文 c
        """
        n, g = self.public_key
        n_sq = n * n
        # 选择随机数 r，要求与 n 互质
        while True:
            r = random.randrange(1, n)
            if math.gcd(r, n) == 1:
                break
        c = (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq
        return c

    def decrypt(self, c):
        """
        使用 Paillier 解密算法解密密文 c，返回明文 m
        """
        n = self.n
        n_sq = n * n
        lam, mu = self.private_key
        u = pow(c, lam, n_sq)
        L_u = self._L(u, n)
        m = (L_u * mu) % n
        return m

    def reencrypt(self, c):
        """
        重加密操作：生成一个加密 0 的密文后与原密文相乘
        实现密文的重新随机化，但不改变对应明文
        """
        n = self.n
        n_sq = n * n
        # 加密 0
        c0 = self.encrypt(0)
        # 重加密
        c_re = (c * c0) % n_sq
        return c_re

    def partial_decrypt(self, c, partial_key):
        """
        分布式解密的第一步：部分解密
        计算 c_partial = c^(partial_key) mod n^2
        """
        n_sq = self.n * self.n
        return pow(c, partial_key, n_sq)

    def final_decrypt(self, c_partial, partial_key):
        """
        分布式解密的第二步：利用第二部分密钥完成完全解密
        计算 c_full = (c_partial)^(partial_key) mod n^2，然后恢复明文
        """
        n = self.n
        n_sq = n * n
        lam, mu = self.private_key
        # 恢复 C^lam mod n^2
        c_full = pow(c_partial, partial_key, n_sq)
        L_val = self._L(c_full, n)
        m = (L_val * mu) % n
        return m

    def encrypt_bitmap(self, bitmap_str):
        """
        对位图字符串（仅由 '0' 和 '1' 构成）逐位加密，
        返回加密后的密文列表（未进行重加密）
        """
        if isinstance(bitmap_str, BitMap):
            bitmap_str = str(bitmap_str)

        ciphertext_list = []
        for bit in bitmap_str:
            m = int(bit)
            c = self.encrypt(m)
            ciphertext_list.append(c)
        return ciphertext_list

    def reencrypt_bitmap(self, ciphertext_list):
        """
        对已加密的密文列表逐个进行重加密操作，
        返回重加密后的密文列表
        """
        reencrypted_list = []
        for c in ciphertext_list:
            c_re = self.reencrypt(c)
            reencrypted_list.append(c_re)
        return reencrypted_list

    def decrypt_bitmap(self, ciphertext_list):
        """
        对加密后的密文列表执行两阶段分布式解密：
          - 第一阶段：使用 partial_key1 进行部分解密
          - 第二阶段：使用 partial_key2 完成完全解密
        返回解密后的位图字符串。
        """
        decrypted_bits = ""
        for c in ciphertext_list:
            # 阶段1：部分解密
            c_partial = self.partial_decrypt(c, self.partial_key1)
            # 阶段2：完成解密
            m = self.final_decrypt(c_partial, self.partial_key2)
            decrypted_bits += str(m)
        return decrypted_bits


# --------------------- 示例调用 ---------------------
if __name__ == '__main__':
    # 初始化重加密系统（安全参数仅为8位，示例用，实际应用应远大于此值）
    ure = UniversalReEncryption(security_param=8)
    print("公钥:", ure.public_key) # 加密
    print("私钥:", ure.private_key) # 解密
    print("部分解密密钥: partial_key1 =", ure.partial_key1, ", partial_key2 =", ure.partial_key2)

    # 待加密的位图字符串
    bitmap = "1010100110"
    bitmap2 = "10101001100"
    print("原始位图字符串:", bitmap)

    # 仅加密
    encrypted_ciphertexts = ure.encrypt_bitmap(bitmap)
    print("\n加密后的密文列表:")
    print(encrypted_ciphertexts)

    encrypted_ciphertexts2 = ure.encrypt_bitmap(bitmap2)
    print("\n加密后的密文列表:")
    print(encrypted_ciphertexts2)

    # 单独重加密
    reencrypted_ciphertexts = ure.reencrypt_bitmap(encrypted_ciphertexts)
    print("\n重加密后的密文列表:")
    print(reencrypted_ciphertexts)

    reencrypted_ciphertexts = ure.reencrypt_bitmap(reencrypted_ciphertexts)
    print("\n重加密后的密文列表:")
    print(reencrypted_ciphertexts)

    decrypted_bitmap = ure.decrypt_bitmap(reencrypted_ciphertexts)  # 使用重加密后的密文列表
    print("\n解密后的位图字符串:")
    print(decrypted_bitmap)

    # # 分布式解密：模拟两个云服务器合作解密
    # decrypted_bitmap = ure.decrypt_bitmap(encrypted_ciphertexts)
    # print("\n解密后的位图字符串:")
    # print(decrypted_bitmap)
