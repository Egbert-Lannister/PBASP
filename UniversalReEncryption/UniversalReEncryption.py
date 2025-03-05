import paillier

class UniversalReEncryption:
    def __init__(self, security_param=8):
        self.public_key, self.private_key = self._generate_paillier_keys(security_param)
        self.n, self.g = self.public_key
        self.lam, self.mu = self.private_key
        self.partial_key1, self.partial_key2 = self._generate_partial_keys()

    def _generate_paillier_keys(self, bits):
        # 调用 C/C++ 扩展模块中的函数
        public_key = paillier.generate_paillier_keys(bits)
        private_key = paillier.generate_paillier_keys(bits)
        return public_key, private_key

    def encrypt(self, m):
        # 调用 C/C++ 扩展模块中的函数
        return paillier.encrypt(m, self.public_key)

    def decrypt(self, c):
        # 调用 C/C++ 扩展模块中的函数
        return paillier.decrypt(c, self.private_key, self.public_key)

    def reencrypt(self, c):
        # 调用 C/C++ 扩展模块中的函数
        return paillier.reencrypt(c, self.public_key)

    # 其他方法保持不变
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



if __name__ == '__main__':
    ure = UniversalReEncryption(security_param=8)
    print("公钥:", ure.public_key)
    print("私钥:", ure.private_key)
    print("部分解密密钥: partial_key1 =", ure.partial_key1, ", partial_key2 =", ure.partial_key2)

    bitmap = "1010100110"
    print("原始位图字符串:", bitmap)

    encrypted_ciphertexts = ure.encrypt_bitmap(bitmap)
    print("\n加密后的密文列表:")
    print(encrypted_ciphertexts)

    reencrypted_ciphertexts = ure.reencrypt_bitmap(encrypted_ciphertexts)
    print("\n重加密后的密文列表:")
    print(reencrypted_ciphertexts)

    decrypted_bitmap = ure.decrypt_bitmap(encrypted_ciphertexts)
    print("\n解密后的位图字符串:")
    print(decrypted_bitmap)