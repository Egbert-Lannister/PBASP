import sqlite3
import time

from tqdm import tqdm

from IndexBuilder import IndexBuilder
from encryption import ProxyPseudorandom, UniversalReEncryption

def read_data(db_path):
    """
    从 SQLite 数据库中读取数据，并返回所有行记录
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM business_table")
    rows = cursor.fetchall()
    conn.close()
    return rows

def index_building(rows):
    # 创建 IndexBuilder 实例并构建关键字索引和位置索引
    index_builder = IndexBuilder(rows)
    keyword_index = index_builder.build_keyword_index()
    print("构建了 {} 个关键字索引".format(len(keyword_index)))

    position_index = index_builder.build_position_index()
    print("构建了 {} 个位置索引前缀码".format(len(position_index)))

    return keyword_index, position_index

    # 此处可以进一步调用索引进行查询或其他操作

def data_encryption(keyword_index, position_index):
    encrypted_keyword_index = {}
    encrypted_position_index = {}

    # TPF ProxyPseudorandom 代理伪随机加密 密钥生成 (Data Owner端)
    a_pri, a_pub = ProxyPseudorandom.generate_keys()
    b_pri, b_pub = ProxyPseudorandom.generate_keys()

    # TUR UniversalReEncryption 通用重加密 密钥生成
    ure = UniversalReEncryption(security_param=8)
    print("公钥:", ure.public_key)
    print("私钥:", ure.private_key)
    print("部分解密密钥: partial_key1 =", ure.partial_key1, ", partial_key2 =", ure.partial_key2)

    # 记录开始时间
    start_time = time.time()

    # DataOwner 加密消息
    for key, value in tqdm(keyword_index.items(), desc="Encrypting the keyword index...", total=len(keyword_index)):

        cipher_text, capsule = ProxyPseudorandom.encrypt(key, a_pub)
        # print("关键词密文:", cipher_text.hex())

        # Capsule 序列化和反序列化测试
        # Capsule 后续重加密会继续处理 用于解密
        encoded_capsule = ProxyPseudorandom.encode_capsule(capsule)
        capsule2 = ProxyPseudorandom.decode_capsule(encoded_capsule)

        # 位图加密
        encrypted_ciphertexts = ure.encrypt_bitmap(value)

        encrypted_keyword_index[cipher_text] = [capsule, encrypted_ciphertexts]

    # 记录结束时间
    end_time = time.time()

    # 计算总耗时
    total_time = end_time - start_time
    print(f"Encryption completed in {total_time:.2f} seconds.")


    for key, value in tqdm(position_index.items(), desc="Encrypting the position index...", total=len(position_index)):

        cipher_text, capsule = ProxyPseudorandom.encrypt(key, a_pub)
        # print("前缀码密文:", cipher_text.hex())

        # Capsule 序列化和反序列化测试
        # Capsule 后续重加密会继续处理 用于解密
        encoded_capsule = ProxyPseudorandom.encode_capsule(capsule)
        capsule2 = ProxyPseudorandom.decode_capsule(encoded_capsule)

        # 位图加密
        encrypted_ciphertexts = ure.encrypt_bitmap(value)

        encrypted_position_index[cipher_text] = [capsule, encrypted_ciphertexts]

    return encrypted_keyword_index, encrypted_position_index


if __name__ == "__main__":

    db_path = 'data_object_2000_keyword_100.db'

    # 开始建索引
    keyword_index, position_index = index_building(read_data(db_path))

    data_encryption(keyword_index, position_index)

    # 建索引结束

    # 开始加密


















