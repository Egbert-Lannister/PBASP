import time
import sys
import redis
import configparser

sys.path.append(r"D:\Python_Script\PBASP\UniversalReEncryption")

from tqdm import tqdm
from redis_utils import publish_redis_event, wait_for_redis_events
from utils import receive_data, send_to_server, read_data
from IndexBuilder import IndexBuilder
from encryption import ProxyPseudorandom
import universal_reencryption

# 读取 config.ini 配置文件
config = configparser.ConfigParser()
config.read('config.ini')

# 定义服务器和客户端地址
HOST = 'localhost'
cs1_PORT = 12345
cs2_PORT = 12346
client_PORT = 12347
CLOUD_SERVER_1_ADDRESS = (HOST, cs1_PORT)  # CloudServer_1 的地址
CLOUD_SERVER_2_ADDRESS = (HOST, cs2_PORT)  # CloudServer_2 的地址
CLIENT_ADDRESS = (HOST, client_PORT)  # Client 的地址


def index_building(rows):
    # 创建 IndexBuilder 实例并构建关键字索引和位置索引
    index_builder = IndexBuilder(rows, num_businesses=2000)
    bitmap_map_2_object_map = index_builder.build_bitmap_map_2_object()
    send_to_server(bitmap_map_2_object_map, CLIENT_ADDRESS)

    # wait_for_redis_events(r, ["bitmap_map_2_object_map"], expected_message="done")

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

    # DataOwner 端生成代理伪随机加密密钥
    proxy_pseudorandom_do_pri, proxy_pseudorandom_do_pub = ProxyPseudorandom.generate_keys()
    b_pri, b_pub = ProxyPseudorandom.generate_keys()
    proxy_pseudorandom_key = "my_very_secret_key"

    # 生成重加密密钥
    rk, pubX = ProxyPseudorandom.re_key_gen(proxy_pseudorandom_do_pri, b_pub)

    # 使用 C++ 加速版本初始化通用重加密（TUR）
    ure = universal_reencryption.UniversalReEncryption(security_param=8)
    print("公钥:", ure.public_key)
    print("私钥:", ure.private_key)
    print("部分解密密钥: partial_key1 =", ure.partial_key1, ", partial_key2 =", ure.partial_key2)

    print("------------------------发送密钥------------------------")

    publish_redis_event(r, "Key sending", message="begin")

    # 发送代理伪随机密钥
    send_to_server((rk, pubX), CLOUD_SERVER_1_ADDRESS)
    send_to_server((rk, pubX), CLOUD_SERVER_2_ADDRESS)
    send_to_server((proxy_pseudorandom_key, proxy_pseudorandom_do_pub), CLIENT_ADDRESS)
    # 发送通用重加密密钥
    send_to_server(ure, CLOUD_SERVER_1_ADDRESS)
    send_to_server(ure, CLOUD_SERVER_2_ADDRESS)
    send_to_server(ure, CLIENT_ADDRESS)

    wait_for_redis_events(r, ["Client key received", "CloudServer 1 received", "CloudServer 2 received"], expected_message="done")

    print("------------------------开始加密------------------------")

    # 开始对关键字索引进行加密
    start_time_1 = time.time()
    for key, value in tqdm(keyword_index_1.items(), desc="Encrypting the keyword index 1...",
                           total=len(keyword_index_1)):
        cipher_text, capsule = ProxyPseudorandom.encrypt(key, proxy_pseudorandom_do_pub, mode="keyword",
                                                         search_key=proxy_pseudorandom_key)
        capacity = value.capacity
        encrypted_ciphertexts = ure.encrypt_bitmap(str(value))
        encrypted_keyword_index_1[cipher_text] = [capsule, encrypted_ciphertexts, capacity]

    for key, value in tqdm(keyword_index_2.items(), desc="Encrypting the keyword index 2...",
                           total=len(keyword_index_2)):
        cipher_text, capsule = ProxyPseudorandom.encrypt(key, proxy_pseudorandom_do_pub, mode="position",
                                                         search_key=proxy_pseudorandom_key)
        capacity = value.capacity
        encrypted_ciphertexts = ure.encrypt_bitmap(str(value))
        encrypted_keyword_index_2[cipher_text] = [capsule, encrypted_ciphertexts, capacity]
    end_time_1 = time.time()
    total_time_1 = end_time_1 - start_time_1
    print(f"Keyword Index Encryption completed in {total_time_1:.3f} seconds.")

    # 开始对位置索引进行加密
    start_time_2 = time.time()
    for key, value in tqdm(position_index_1.items(), desc="Encrypting the position index 1...",
                           total=len(position_index_1)):
        cipher_text, capsule = ProxyPseudorandom.encrypt(key, proxy_pseudorandom_do_pub, mode="keyword",
                                                         search_key=proxy_pseudorandom_key)
        capacity = value.capacity
        encrypted_ciphertexts = ure.encrypt_bitmap(str(value))
        encrypted_position_index_1[cipher_text] = [capsule, encrypted_ciphertexts, capacity]

    for key, value in tqdm(position_index_2.items(), desc="Encrypting the position index 2...",
                           total=len(position_index_2)):
        cipher_text, capsule = ProxyPseudorandom.encrypt(key, proxy_pseudorandom_do_pub, mode="position",
                                                         search_key=proxy_pseudorandom_key)
        capacity = value.capacity
        encrypted_ciphertexts = ure.encrypt_bitmap(str(value))
        encrypted_position_index_2[cipher_text] = [capsule, encrypted_ciphertexts, capacity]
    end_time_2 = time.time()
    total_time_2 = end_time_2 - start_time_2
    print(f"Position Index Encryption completed in {total_time_2:.3f} seconds.")

    print("------------------------加密结束------------------------")

    return encrypted_keyword_index_1, encrypted_keyword_index_2, encrypted_position_index_1, encrypted_position_index_2


if __name__ == "__main__":
    # 建立 Redis 连接（请确保 Redis 服务已启动）
    r = redis.Redis(host='localhost', port=6379, db=0)

    origin_db_path = config['database']['origin_db_path']

    # 开始建索引
    keyword_index_1, keyword_index_2, position_index_1, position_index_2 = index_building(read_data(origin_db_path))
    # 建索引结束

    # 开始加密
    encrypted_keyword_index_1, encrypted_keyword_index_2, encrypted_position_index_1, encrypted_position_index_2 = data_encryption(
        keyword_index_1, keyword_index_2, position_index_1, position_index_2
    )

    publish_redis_event(r, "Encrypted data sending", message="begin")

    # 发送数据到服务器
    send_to_server((encrypted_keyword_index_1, encrypted_position_index_1), CLOUD_SERVER_1_ADDRESS)
    send_to_server((encrypted_keyword_index_2, encrypted_position_index_2), CLOUD_SERVER_2_ADDRESS)
