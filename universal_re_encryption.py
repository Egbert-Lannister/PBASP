# universal_re_encryption.py
import math
import sys
import random
from Crypto.Util import number
from BitMap import BitMap  # 使用你在 BitMap.py 中的 BitMap 类定义

# --------------------- 辅助函数 ---------------------
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def _rand(p):
    return random.randint(1, p - 1)

# --------------------- ElGamal 加密与重加密 ---------------------
class ElGamal(object):
    @staticmethod
    def rand(p):
        return random.randint(1, p - 1)

    @staticmethod
    def generatePrimeAndGenerator(k):
        prime = number.getPrime(k)
        g = random.randint(2, prime - 1)
        return prime, g

    @staticmethod
    def keygen(k):
        p, g = ElGamal.generatePrimeAndGenerator(k)
        x = ElGamal.rand(p)
        h = pow(g, x, p)
        return p, g, x, h

    def __init__(self, k):
        # k 为素数的位数，实际使用时应足够大
        self.p, self.g, self.x, self.y = ElGamal.keygen(k)

    def randomElement(self):
        return _rand(self.p)

    def encrypt(self, m, y):
        # 加密单个明文 m（对于位图，m 为 0 或 1）
        k0, k1 = _rand(self.p), _rand(self.p)
        alpha0 = (m * pow(y, k0, self.p)) % self.p
        beta0 = pow(self.g, k0, self.p)
        alpha1 = pow(y, k1, self.p)
        beta1 = pow(self.g, k1, self.p)
        ct = [(alpha0, beta0), (alpha1, beta1)]
        return ct

    def reencrypt(self, ct):
        # 对密文 ct 进行重加密，引入新的随机性但不改变明文
        [(alpha0, beta0), (alpha1, beta1)] = ct
        k0p, k1p = _rand(self.p), _rand(self.p)
        alpha0p = (alpha0 * pow(alpha1, k0p, self.p)) % self.p
        beta0p = (beta0 * pow(beta1, k0p, self.p)) % self.p
        alpha1p = pow(alpha1, k1p, self.p)
        beta1p = pow(beta1, k1p, self.p)
        new_ct = [(alpha0p, beta0p), (alpha1p, beta1p)]
        return new_ct

    def decrypt(self, ct, x):
        # 解密得到 m，要求 m1 解密后为 1，用以验证正确性
        [(alpha0, beta0), (alpha1, beta1)] = ct
        m0 = (alpha0 * modinv(pow(beta0, x, self.p), self.p)) % self.p
        m1 = (alpha1 * modinv(pow(beta1, x, self.p), self.p)) % self.p
        assert m1 == 1  # 验证解密正确性
        return m0

# --------------------- 针对位图的加/重加密操作 ---------------------
def encrypt_bitmap(elgamal, bitmap):
    """
    对 BitMap 对象进行加密：
    1. 调用 __str__() 方法得到位图的字符串表示（如 "10001001..."）
    2. 对字符串中每个字符（'0' 或 '1'）逐位加密，返回密文列表
    """
    bit_string = str(bitmap)
    ciphertexts = []
    for bit in bit_string:
        m = int(bit)
        ct = elgamal.encrypt(m, elgamal.y)
        ciphertexts.append(ct)
    return ciphertexts

def reencrypt_bitmap(elgamal, ciphertexts):
    """
    对位图密文列表进行重加密，返回新的密文列表
    """
    new_ciphertexts = []
    for ct in ciphertexts:
        new_ct = elgamal.reencrypt(ct)
        new_ciphertexts.append(new_ct)
    return new_ciphertexts

def decrypt_bitmap(elgamal, ciphertexts):
    """
    对位图密文列表进行解密，返回恢复后的位图字符串
    """
    decrypted_bits = []
    for ct in ciphertexts:
        m = elgamal.decrypt(ct, elgamal.x)
        decrypted_bits.append(str(m))
    return "".join(decrypted_bits)

# --------------------- 主函数 ---------------------
def main():
    # 构造一个示例位图，长度为 32 位
    size = 32
    bmp = BitMap(size)
    # 随机设置部分位为 1
    for i in range(size):
        if random.random() < 0.3:
            bmp.set_bit(i)
    print("Original Bitmap:", str(bmp))

    # 初始化 ElGamal 加密系统，参数 32 位（仅示例，实际应更大）
    elgamal = ElGamal(32)

    # 加密位图
    ciphertexts = encrypt_bitmap(elgamal, bmp)
    print("\nEncrypted Bitmap Ciphertexts:")
    for ct in ciphertexts:
        print(ct)

    # 对密文进行重加密
    reencrypted_ciphertexts = reencrypt_bitmap(elgamal, ciphertexts)
    print("\nReencrypted Bitmap Ciphertexts:")
    for ct in reencrypted_ciphertexts:
        print(ct)

    # 解密密文，恢复出位图字符串
    decrypted_bit_string = decrypt_bitmap(elgamal, reencrypted_ciphertexts)
    print("\nDecrypted Bitmap:", decrypted_bit_string)

    # 验证解密结果是否与原始位图一致
    if decrypted_bit_string == str(bmp):
        print("\nSuccess: Decrypted bitmap matches the original.")
    else:
        print("\nFailure: Decrypted bitmap does not match the original.")

if __name__ == "__main__":
    main()
