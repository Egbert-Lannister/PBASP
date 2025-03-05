import math
import random
import numpy as np
from multiprocessing import Pool

from BitMap import BitMap

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

    def batch_encrypt(self, messages):
        """
        批量加密：对一组明文进行加密
        """
        n, g = self.public_key
        n_sq = n * n

        # 生成随机数数组
        rs = np.random.randint(1, n, size=len(messages), dtype=int)  # 将数据类型设置为 int
        # 确保随机数与 n 互质
        valid = np.gcd(rs, n) == 1
        while not valid.all():
            rs[~valid] = np.random.randint(1, n, size=np.count_nonzero(~valid), dtype=int)
            valid = np.gcd(rs, n) == 1

        # 批量计算 g^m mod n^2 和 r^n mod n^2
        g_pows = np.array([pow(g, m, n_sq) for m in messages])
        r_pows = np.array([pow(r, n, n_sq) for r in rs])

        # 逐元素相乘并取模
        ciphertexts = (g_pows * r_pows) % n_sq
        return ciphertexts.tolist()

    def batch_reencrypt(self, ciphertexts):
        """
        批量重加密：对一组密文进行重加密
        """
        n = self.n
        n_sq = n * n

        # 加密 0
        c0 = self.encrypt(0)

        # 批量计算 reencrypted ciphertexts = c * c0 mod n^2
        reencrypted = (np.array(ciphertexts) * c0) % n_sq
        return reencrypted.tolist()

    def encrypt_bitmap(self, bitmap_str):
        """
        对位图字符串（仅由 '0' 和 '1' 构成）逐位加密，返回加密后的密文列表（未进行重加密）
        """
        if isinstance(bitmap_str, BitMap):
            bitmap_str = str(bitmap_str)

        messages = list(map(int, bitmap_str))
        # 使用批量加密
        return self.batch_encrypt(messages)

    def reencrypt_bitmap(self, ciphertext_list):
        """
        对已加密的密文列表逐个进行重加密操作，返回重加密后的密文列表
        """
        # 使用批量重加密
        return self.batch_reencrypt(ciphertext_list)

    def decrypt_bitmap(self, ciphertext_list):
        """
        对加密后的密文列表执行两阶段分布式解密：
          - 第一阶段：使用 partial_key1 进行部分解密
          - 第二阶段：使用 partial_key2 完成完全解密
        返回解密后的位图字符串。
        """
        decrypted_bits = []

        # 第一阶段：部分解密
        partial_decrypted = [self.partial_decrypt(c, self.partial_key1) for c in ciphertext_list]

        # 第二阶段：完全解密
        for c_partial in partial_decrypted:
            m = self.final_decrypt(c_partial, self.partial_key2)
            decrypted_bits.append(str(m))

        return ''.join(decrypted_bits)


# --------------------- 示例调用 ---------------------
if __name__ == '__main__':
    # 初始化重加密系统（安全参数仅为8位，示例用，实际应用应远大于此值）
    ure = UniversalReEncryption(security_param=8)
    print("公钥:", ure.public_key)
    print("私钥:", ure.private_key)
    print("部分解密密钥: partial_key1 =", ure.partial_key1, ", partial_key2 =", ure.partial_key2)

    # 待加密的位图字符串
    bitmap = "1010100110" * 200  # 示例中扩展为 2000 位
    print("原始位图字符串:", bitmap[:50], "...", bitmap[-50:])

    # 仅加密
    encrypted_ciphertexts = ure.encrypt_bitmap(bitmap)
    print("\n加密后的密文列表（部分）:", encrypted_ciphertexts[:5], "...", encrypted_ciphertexts[-5:])

    # 单独重加密
    reencrypted_ciphertexts = ure.reencrypt_bitmap(encrypted_ciphertexts)
    print("\n重加密后的密文列表（部分）:", reencrypted_ciphertexts[:5], "...", reencrypted_ciphertexts[-5:])

    # 分布式解密：模拟两个云服务器合作解密
    decrypted_bitmap = ure.decrypt_bitmap(encrypted_ciphertexts)
    print("\n解密后的位图字符串:", decrypted_bitmap[:50], "...", decrypted_bitmap[-50:])