import sqlite3
import time
import socket
import pickle
import sys
sys.path.append(r"D:\Python_Script\PBASP\UniversalReEncryption")


from tqdm import tqdm
# from universal_re_encryption import ElGamal, encrypt_bitmap

from utils import receive_data, send_to_server
from IndexBuilder import IndexBuilder
from encryption import ProxyPseudorandom, UniversalReEncryption
# from TailoredUniversalReEncryption.UniversalReEncryption_MultithreadingParallel import UniversalReEncryption
# from UniversalReEncryption.Universal_ReEncryption_cpp_Acceleration import universal_reencryption

# 定义服务器 客户端地址
HOST = 'localhost'
cs1_PORT = 12345
cs2_PORT = 12346
client_PORT = 12347
CLOUD_SERVER_1_ADDRESS = (HOST, cs1_PORT)  # CloudServer_1 的地址
CLOUD_SERVER_2_ADDRESS = (HOST, cs2_PORT)  # CloudServer_2 的地址
CLIENT_ADDRESS = (HOST, client_PORT)  # Client 客户端的地址

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

    (keyword_index_1, keyword_index_2), (position_index_1, position_index_2) = index_builder.index_or_separation()

    return keyword_index_1, keyword_index_2, position_index_1, position_index_2


def data_encryption(keyword_index_1, keyword_index_2, position_index_1, position_index_2):
    encrypted_keyword_index_1 = {}
    encrypted_keyword_index_2 = {}
    encrypted_position_index_1 = {}
    encrypted_position_index_2 = {}

    # TPF ProxyPseudorandom 代理伪随机加密 密钥生成 (Data Owner端)
    proxy_pseudorandom_do_pri, proxy_pseudorandom_do_pub = ProxyPseudorandom.generate_keys()
    b_pri, b_pub = ProxyPseudorandom.generate_keys()

    # 生成重加密密钥
    rk, pubX = ProxyPseudorandom.re_key_gen(proxy_pseudorandom_do_pri, b_pub)

    # TUR UniversalReEncryption 通用重加密 密钥生成
    ure = UniversalReEncryption(security_param=8)
    # C++ 加速方法
    # ure = universal_reencryption.UniversalReEncryption(security_param=8)
    print("公钥:", ure.public_key)
    print("私钥:", ure.private_key)
    print("部分解密密钥: partial_key1 =", ure.partial_key1, ", partial_key2 =", ure.partial_key2)

    # 发送密钥
    print("------------------------发送密钥------------------------")

    # 发送代理伪随机密钥
    send_to_server((rk, pubX), CLOUD_SERVER_1_ADDRESS)
    send_to_server((rk, pubX), CLOUD_SERVER_2_ADDRESS)
    # send_to_server((rk, pubX), CLIENT_ADDRESS)

    # 发送通用重加密密钥
    send_to_server(ure, CLOUD_SERVER_1_ADDRESS)
    send_to_server(ure, CLOUD_SERVER_2_ADDRESS)
    # send_to_server(ure, CLIENT_ADDRESS)

    """
    # 基于 ElGamal 加密系统的尝试
    # 初始化 ElGamal 加密系统（这里 k=32 位，仅用于示例，实际中应更大）
    elgamal = ElGamal(8)
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
        encrypted_ciphertexts = encrypt_bitmap(elgamal, value)

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
        encrypted_ciphertexts = encrypt_bitmap(elgamal, value)

        encrypted_position_index[cipher_text] = [capsule, encrypted_ciphertexts]
    
    """

    # 记录开始时间
    start_time_1 = time.time()

    # DataOwner 加密消息
    for key, value in tqdm(keyword_index_1.items(), desc="Encrypting the keyword index 1...", total=len(keyword_index_1)):

        cipher_text, capsule = ProxyPseudorandom.encrypt(key, proxy_pseudorandom_do_pub)
        # print("关键词密文:", cipher_text.hex())

        # Capsule 序列化和反序列化测试
        # Capsule 后续重加密会继续处理 用于解密
        encoded_capsule = ProxyPseudorandom.encode_capsule(capsule)
        capsule2 = ProxyPseudorandom.decode_capsule(encoded_capsule)

        # 位图加密
        encrypted_ciphertexts = ure.encrypt_bitmap(str(value))

        # print(type(encrypted_ciphertexts))
        # 加密之后的位图不是BitMap，是列表

        encrypted_keyword_index_1[cipher_text] = [capsule, encrypted_ciphertexts]

    for key, value in tqdm(keyword_index_2.items(), desc="Encrypting the keyword index 2...", total=len(keyword_index_2)):

        cipher_text, capsule = ProxyPseudorandom.encrypt(key, proxy_pseudorandom_do_pub)
        # print("关键词密文:", cipher_text.hex())

        # Capsule 序列化和反序列化测试
        # Capsule 后续重加密会继续处理 用于解密
        encoded_capsule = ProxyPseudorandom.encode_capsule(capsule)
        capsule2 = ProxyPseudorandom.decode_capsule(encoded_capsule)

        # 位图加密
        encrypted_ciphertexts = ure.encrypt_bitmap(str(value))

        encrypted_keyword_index_2[cipher_text] = [capsule, encrypted_ciphertexts]

    # 记录结束时间
    end_time_1 = time.time()

    # 计算总耗时
    total_time_1 = end_time_1 - start_time_1
    print(f"Keyword Index Encryption completed in {total_time_1:.3f} seconds.")

    # 记录开始时间
    start_time_2 = time.time()


    for key, value in tqdm(position_index_1.items(), desc="Encrypting the position index 1...", total=len(position_index_1)):

        cipher_text, capsule = ProxyPseudorandom.encrypt(key, proxy_pseudorandom_do_pub)
        # print("前缀码密文:", cipher_text.hex())

        # Capsule 序列化和反序列化测试
        # Capsule 后续重加密会继续处理 用于解密
        encoded_capsule = ProxyPseudorandom.encode_capsule(capsule)
        capsule2 = ProxyPseudorandom.decode_capsule(encoded_capsule)

        # 位图加密
        encrypted_ciphertexts = ure.encrypt_bitmap(str(value))

        encrypted_position_index_1[cipher_text] = [capsule, encrypted_ciphertexts]

    for key, value in tqdm(position_index_2.items(), desc="Encrypting the position index 2...", total=len(position_index_2)):

        cipher_text, capsule = ProxyPseudorandom.encrypt(key, proxy_pseudorandom_do_pub)
        # print("前缀码密文:", cipher_text.hex())

        # Capsule 序列化和反序列化测试
        # Capsule 后续重加密会继续处理 用于解密
        encoded_capsule = ProxyPseudorandom.encode_capsule(capsule)
        capsule2 = ProxyPseudorandom.decode_capsule(encoded_capsule)

        # 位图加密
        encrypted_ciphertexts = ure.encrypt_bitmap(str(value))

        encrypted_position_index_2[cipher_text] = [capsule, encrypted_ciphertexts]

    # 记录结束时间
    end_time_2 = time.time()

    # 计算总耗时
    total_time_2 = end_time_2 - start_time_2
    print(f"Position Index Encryption completed in {total_time_2:.3f} seconds.")



    return encrypted_keyword_index_1, encrypted_keyword_index_2, encrypted_position_index_1, encrypted_position_index_2

def send_to_server(data, server_address):
    """发送数据到指定的服务器"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(server_address)
            # 序列化数据
            serialized_data = pickle.dumps(data)
            # 发送数据长度
            sock.sendall(len(serialized_data).to_bytes(4, byteorder='big'))
            # 发送数据
            sock.sendall(serialized_data)
        print(f"数据已成功发送到 {server_address}")
    except Exception as e:
        print(f"发送数据到 {server_address} 时出错: {e}")


if __name__ == "__main__":
    db_path = 'data_object_2000_keyword_100.db'

    # 开始建索引
    keyword_index_1, keyword_index_2, position_index_1, position_index_2 = index_building(read_data(db_path))
    # 建索引结束

    # 开始加密
    encrypted_keyword_index_1, encrypted_keyword_index_2, encrypted_position_index_1, encrypted_position_index_2 = data_encryption(keyword_index_1, keyword_index_2, position_index_1, position_index_2)
    # 加密结束

    # 传递给服务器

    # 发送数据到服务器
    send_to_server((encrypted_keyword_index_1, encrypted_position_index_1), CLOUD_SERVER_1_ADDRESS)
    send_to_server((encrypted_keyword_index_2, encrypted_position_index_2), CLOUD_SERVER_2_ADDRESS)



