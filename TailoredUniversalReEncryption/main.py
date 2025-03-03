import random
import math


# ---------- Paillier相关函数 ----------
def L(u, n):
    return (u - 1) // n

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime(bits):
    # 生成一个大致 bits 位的素数（此处用暴力搜索，演示用途）
    while True:
        # 随机生成bits位的数
        num = random.getrandbits(bits)
        # 确保最高位和最低位为1
        num |= (1 << (bits - 1)) | 1
        if is_prime(num):
            return num

def paillier_keygen(bits=8):
    # 生成两个素数
    p = generate_prime(bits)
    q = generate_prime(bits)
    # 确保 p 和 q 不相等
    while q == p:
        q = generate_prime(bits)
    n = p * q
    n_sq = n * n
    # λ = lcm(p-1, q-1)
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    # 选取 g = n + 1 （常用选择）
    g = n + 1
    # 计算 μ = (L(g^λ mod n^2))^{-1} mod n
    u = pow(g, lam, n_sq)
    L_u = L(u, n)
    # 求 μ 的模 n 逆元
    mu = pow(L_u, -1, n)
    pk = (n, g)
    sk = (lam, mu)
    return pk, sk

def paillier_enc(m, pk):
    n, g = pk
    n_sq = n * n
    # 选随机数 r，要求与 n 互质
    while True:
        r = random.randrange(1, n)
        if math.gcd(r, n) == 1:
            break
    c = (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq
    return c

def paillier_dec(c, sk, pk):
    n, _ = pk
    lam, mu = sk
    n_sq = n * n
    u = pow(c, lam, n_sq)
    L_u = L(u, n)
    m = (L_u * mu) % n
    return m

# ---------- 定制通用重加密（TUR）实现 ----------
def TUR_Setup(security_param=8):
    # 此处 security_param 为素数位长，实际中应远大于8位
    pk, sk = paillier_keygen(bits=security_param)
    return pk, sk

def TUR_KeyGen(sk):
    lam, _ = sk
    # 简单分解：设 pdk1 * pdk2 = lam，这里选择 pdk1 = 2（假定 lam 为偶数）
    pdk1 = 2
    pdk2 = lam // pdk1
    return pdk1, pdk2

def TUR_Enc(m, pk):
    # 使用 Paillier.Enc 加密明文 m
    c = paillier_enc(m, pk)
    return c

def TUR_ReEnc(c, pk):
    # 生成 encryption of 0: Paillier.Enc(0, pk)
    c0 = paillier_enc(0, pk)
    n_sq = pk[0] * pk[0]
    # 重加密：C = c * c0 mod n^2
    C = (c * c0) % n_sq
    return C

def TUR_PDec(C, pdk):
    n_sq = pk[0] * pk[0]
    # 部分解密：计算 C_i = C^{pdk} mod n^2
    C_i = pow(C, pdk, n_sq)
    return C_i

def TUR_Dec(C_i, pdk, sk, pk):
    n, _ = pk
    n_sq = n * n
    # 完全解密：先计算 (C_i)^{pdk} = C^{pdk * pdk} = C^{lam} mod n^2
    C_full = pow(C_i, pdk, n_sq)
    # 利用 Paillier 解密公式还原 m
    lam, mu = sk
    u = C_full  # u = C^{lam} mod n^2
    L_u = L(u, n)
    m = (L_u * mu) % n
    return m

# ---------- 演示：对位图字符串进行加密与解密 ----------

# 生成主密钥和公钥
pk, sk = TUR_Setup(security_param=8)
print("公钥 pk:", pk)
print("私钥 sk:", sk)

# 分割私钥为两部分
pdk1, pdk2 = TUR_KeyGen(sk)
print("部分解密密钥 pdk1:", pdk1, "pdk2:", pdk2)

# 待加密的位图字符串（由0和1构成）
bitmap = "1010100110"
print("原始位图字符串:", bitmap)

# 对每一位进行加密和重加密
encrypted_list = []
reencrypted_list = []
for bit in bitmap:
    m = int(bit)
    c = TUR_Enc(m, pk)
    encrypted_list.append(c)
    # 重加密
    C = TUR_ReEnc(c, pk)
    reencrypted_list.append(C)

print("\n加密后的密文列表:")
print(encrypted_list)

print("\n重加密后的密文列表:")
print(reencrypted_list)

# 两步解密：假设第一个云服务器用 pdk1 部分解密，第二个用 pdk2 完成解密
decrypted_bits = ""
for C in reencrypted_list:
    # 第一步部分解密（由云服务器1执行）
    C_i = TUR_PDec(C, pdk1)
    # 第二步完全解密（由云服务器2执行），注意 pdk2 应该满足 pdk1 * pdk2 = lam
    m = TUR_Dec(C_i, pdk2, sk, pk)
    decrypted_bits += str(m)

print("\n解密后的位图字符串:")
print(decrypted_bits)
