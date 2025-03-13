import hashlib
import pickle
import hmac
from tqdm import tqdm
import random
import math

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ecdsa import SigningKey, VerifyingKey, NIST256p

# 模拟的 BitMap 类（实际中可采用更高效的数据结构）
class BitMap:
    def __init__(self, size):
        self.bits = [0] * size

    def set_bit(self, pos):
        if 0 <= pos < len(self.bits):
            self.bits[pos] = 1

    def __and__(self, other):
        return BitMap.from_list([a & b for a, b in zip(self.bits, other.bits)])

    @classmethod
    def from_list(cls, lst):
        bm = cls(len(lst))
        bm.bits = lst
        return bm

    def __str__(self):
        return str(self.bits)


class ProxyPseudorandom:
    CURVE = NIST256p
    N = NIST256p.order

    # --------------------- 基础工具函数 ---------------------
    @staticmethod
    def generate_keys():
        """生成 ECDSA 密钥对（私钥、对应公钥）"""
        sk = SigningKey.generate(curve=ProxyPseudorandom.CURVE)
        vk = sk.get_verifying_key()
        return sk, vk

    @staticmethod
    def point_to_bytes(vk_or_point):
        """将公钥或椭圆曲线点转换为未压缩字节形式（0x04 + X + Y）"""
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
        """将数据 hash 后映射到曲线上的一个整数（mod N）"""
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

    # --------------------- 消息加解密相关功能 ---------------------
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
        capsule = {'E': pubE, 'V': pubV, 's': s}
        return capsule, key_bytes

    @staticmethod
    def encrypt_message_by_aes_key(message, key_bytes):
        """
        使用 AES-GCM 算法加密消息：
         - 取 key_bytes 的前 32 个字符作为 AES 密钥
         - 取 key_bytes 的前 12 字节作为 nonce
        """
        full_key = key_bytes.hex()  # 64字符（32字节）
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
                raise ValueError("关键字加密必须提供 search_key")
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
        """将公钥点乘以标量，返回新的 VerifyingKey"""
        point = vk.pubkey.point * scalar
        x_bytes = point.x().to_bytes(32, 'big')
        y_bytes = point.y().to_bytes(32, 'big')
        pub_bytes = x_bytes + y_bytes
        return VerifyingKey.from_string(pub_bytes, curve=ProxyPseudorandom.CURVE)

    @staticmethod
    def re_encryption(rk, capsule):
        """
        服务器侧重加密：
         - 对于关键字模式（capsule 中包含 "tag"），调用 re_encrypt_keyword，
           同时记录重加密次数，不改变其他内容。
         - 对于普通消息模式，则按照原有逻辑进行重加密。
        """
        if 'tag' in capsule:
            return ProxyPseudorandom.re_encrypt_keyword(capsule, rk)
        # 原有消息重加密逻辑（略，不再重复）
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
            raise ValueError("Capsule 校验失败")
        new_E = ProxyPseudorandom._scale_public_key(capsule['E'], rk)
        new_V = ProxyPseudorandom._scale_public_key(capsule['V'], rk)
        new_capsule = {'E': new_E, 'V': new_V, 's': capsule['s']}
        return new_capsule

    @staticmethod
    def decrypt_key_gen(b_pri, capsule, pubX):
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
        key_bytes = ProxyPseudorandom.decrypt_key_gen(b_pri, capsule, pubX)
        full_key = key_bytes.hex()
        aes_key = bytes.fromhex(full_key[:32])
        nonce = key_bytes[:12]
        aesgcm = AESGCM(aes_key)
        plain = aesgcm.decrypt(nonce, cipher_text, None)
        return plain

    @staticmethod
    def decrypt_on_my_pri(a_pri, capsule, cipher_text):
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
        # 对于关键字模式，仅保存 tag 和 count
        if 'tag' in capsule:
            data = {'tag': capsule['tag'], 'count': capsule.get('count', 0)}
        else:
            data = {
                'E': ProxyPseudorandom.point_to_bytes(capsule['E']).hex(),
                'V': ProxyPseudorandom.point_to_bytes(capsule['V']).hex(),
                's': capsule['s']
            }
        return pickle.dumps(data)

    @staticmethod
    def decode_capsule(data_bytes):
        data = pickle.loads(data_bytes)
        if 'tag' in data:
            return {'tag': data['tag'], 'count': data.get('count', 0)}
        E = VerifyingKey.from_string(bytes.fromhex(data['E'])[1:], curve=ProxyPseudorandom.CURVE)
        V = VerifyingKey.from_string(bytes.fromhex(data['V'])[1:], curve=ProxyPseudorandom.CURVE)
        s = data['s']
        return {'E': E, 'V': V, 's': s}

    # --------------------- 搜索令牌生成 ---------------------
    @staticmethod
    def generate_search_token(keyword, search_key):
        """
        使用 HMAC-SHA256 生成确定性的搜索令牌
         参数:
            keyword: 待加密的关键字（字符串）
            search_key: 共享密钥（字符串或 bytes）
         返回:
            十六进制字符串形式的令牌
        """
        if not isinstance(search_key, bytes):
            search_key = search_key.encode('utf-8')
        if not isinstance(keyword, bytes):
            keyword = keyword.encode('utf-8')
        token = hmac.new(search_key, keyword, hashlib.sha256).hexdigest()
        return token


# --------------------- 示例调用 ---------------------
if __name__ == "__main__":
    # 模拟整个流程：
    # 1. DataOwner 加密关键字索引（对每个关键字采用“关键字加密模式”）
    # 2. DataOwner 发送加密后的关键字索引给云服务器，
    #    云服务器在重加密时对关键字密文（cipher_text）进行进一步重加密，
    #    同时在 capsule 中记录重加密次数（tag 和 count）
    # 3. 客户端查询时，服务器根据存储的 count 对客户端查询令牌进行相同次数的重加密转换，
    #    最终与存储在索引中的关键字密文匹配，返回对应的位图

    # DataOwner 生成密钥
    do_pri, do_pub = ProxyPseudorandom.generate_keys()
    # 共享搜索密钥（用于初始生成搜索令牌）
    search_key = "my_very_secret_key"

    # 构造关键字索引（明文关键字与对应的 BitMap）
    keyword_index_1 = {
        "Restaurants": BitMap(10),
        "Food": BitMap(10)
    }
    for doc_id in [0, 2, 4, 6]:
        keyword_index_1["Restaurants"].set_bit(doc_id)
    for doc_id in [1, 2, 3, 4, 5]:
        keyword_index_1["Food"].set_bit(doc_id)

    encrypted_keyword_index_1 = {}

    # DataOwner 加密每个关键字（使用 keyword 模式）
    for key, bitmap in tqdm(keyword_index_1.items(), desc="DataOwner encrypting keyword index...", total=len(keyword_index_1)):
        cipher_text, capsule = ProxyPseudorandom.encrypt(key, do_pub, mode="keyword", search_key=search_key)
        # 此处对 bitmap 的加密可另行实现，这里直接保存其字符串表示
        encrypted_bitmap = str(bitmap.bits)
        encrypted_keyword_index_1[cipher_text] = [capsule, encrypted_bitmap]

    # 模拟云服务器 CloudServer 对关键字索引进行重加密
    # 假设服务器生成自己的重加密密钥（这里简单使用 re_key_gen，实际中双方协商）
    cs_rk, cs_pubX = ProxyPseudorandom.re_key_gen(do_pri, do_pub)
    for ct, (capsule, enc_bitmap) in encrypted_keyword_index_1.items():
        new_capsule = ProxyPseudorandom.re_encryption(cs_rk, capsule)
        encrypted_keyword_index_1[ct] = [new_capsule, enc_bitmap]

    for ct, (capsule, enc_bitmap) in encrypted_keyword_index_1.items():
        new_capsule = ProxyPseudorandom.re_encryption(cs_rk, capsule)
        encrypted_keyword_index_1[ct] = [new_capsule, enc_bitmap]

    # 模拟客户端查询
    # 客户端使用相同的 search_key 对查询关键字进行初始加密
    query_keywords = ["Restaurants", "Food"]
    query_tokens = [ProxyPseudorandom.generate_search_token(kw, search_key) for kw in query_keywords]
    # 初始查询令牌为 bytes（与 DataOwner 加密时一致）
    query_token_bytes = [t.encode("utf-8") for t in query_tokens]

    # 服务器对客户端查询令牌进行转换：
    # 对每个关键字，根据存储在索引中的 capsule count，对查询令牌重加密相应次数
    result_bitmaps = {}
    for qt_bytes in query_token_bytes:
        # 查找时用 key 以 bytes 形式存储，故先转换为字符串
        init_token = qt_bytes.decode("utf-8")
        # 遍历加密关键字索引，寻找匹配项
        found = False
        for stored_ct, (capsule, enc_bitmap) in encrypted_keyword_index_1.items():
            # 获取重加密次数
            count = capsule.get("count", 0)
            # 对客户端原始令牌转换 count 次
            transformed_token = ProxyPseudorandom.transform_query_token(init_token, cs_rk, count)
            # 与存储在 capsule 中的 tag 比较
            if transformed_token == capsule["tag"]:
                result_bitmaps[stored_ct] = enc_bitmap
                found = True
                break
        if not found:
            result_bitmaps[init_token] = "NotFound"

    print("查询结果：")
    for k, v in result_bitmaps.items():
        print(f"关键字密文/tag {k} 对应的加密位图: {v}")

    # 说明：
    # 1. DataOwner 对明文关键字生成确定性搜索令牌并附加 count=0
    # 2. 服务器重加密时调用 re_encrypt_keyword 更新 tag 和 count
    # 3. 客户端查询时，服务器根据 count 对查询令牌进行同样次数的转换，
    #    从而与最终存储的 tag 匹配并返回对应的位图
