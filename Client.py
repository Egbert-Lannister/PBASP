import os
import socket
import pickle
import time

from BitMap import BitMap
from IndexBuilder import IndexBuilder
from encryption import ProxyPseudorandom
from utils import receive_data, send_to_server

def main():
    HOST = 'localhost'
    cs1_PORT = 12345
    cs2_PORT = 12346
    client_PORT = 12347
    CLOUD_SERVER_1_ADDRESS = (HOST, cs1_PORT)  # CloudServer_1 的地址
    CLOUD_SERVER_2_ADDRESS = (HOST, cs2_PORT)  # CloudServer_2 的地址

    latitude = 39.9555052
    longitude = -75.1555641

    query_keywords = ["Restaurants", "Food"]

    query_prefix_codea = IndexBuilder.get_prefix_codes(IndexBuilder.lat_lon_to_hilbert_to_64bit_binary(latitude, longitude))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, client_PORT))
        s.listen()
        print(f"Client 已启动，监听端口 {client_PORT}...")

        # 接收位图对象ID映射
        conn, addr = s.accept()
        with conn:
            data = receive_data(conn)
            if data:
                bitmap_map_2_object_map = data
                print("收到以下数据：")
                print(f"Client 收到 bitmap_map_2_object_map, 共有 :{len(bitmap_map_2_object_map)}条")

        # 接收代理伪随机密钥
        conn, addr = s.accept()
        with conn:
            data = receive_data(conn)
            if data:
                proxy_pseudorandom_key, proxy_pseudorandom_do_pub = data
                print("收到以下数据：")
                print(f"Client 收到 proxy_pseudorandom_key :{proxy_pseudorandom_key}")
                print(f"Client 收到 proxy_pseudorandom_do_pub :{proxy_pseudorandom_do_pub}")

        # 接收通用重加密密钥
        conn, addr = s.accept()
        with conn:
            data = receive_data(conn)
            if data:
                ure = data
                print("收到以下数据：")
                print(f"Client 收到 ure :{ure}")

        encrypted_query_keywords = []
        # 加密查询内容
        for value in query_keywords:
            one_encrypted_keyword = ProxyPseudorandom.generate_search_token(value, proxy_pseudorandom_key)
            encrypted_query_keywords.append(one_encrypted_keyword)

        encrypted_query_prefix_codes = []
        for value in query_prefix_codea:
            one_encrypted_prefix_code = ProxyPseudorandom.generate_search_token(value, proxy_pseudorandom_key)
            encrypted_query_prefix_codes.append(one_encrypted_prefix_code)
        # print("查询关键字")
        # print(encrypted_query_keywords)

        # 初始查询令牌为 bytes
        encrypted_query_keywords = [t.encode("utf-8") for t in encrypted_query_keywords]
        encrypted_query_prefix_codes = [t.encode("utf-8") for t in encrypted_query_prefix_codes]

        # 等待重加密完成
        while not os.path.exists("CloudServer_1_reencryption_done.lock") and not os.path.exists("CloudServer_2_reencryption_done.lock"):
            time.sleep(1)

        # 发送查询内容到服务器
        send_to_server((encrypted_query_keywords, encrypted_query_prefix_codes), CLOUD_SERVER_1_ADDRESS)
        send_to_server((encrypted_query_keywords, encrypted_query_prefix_codes), CLOUD_SERVER_2_ADDRESS)

        # 接收查询结果
        conn, addr = s.accept()
        with conn:
            data = receive_data(conn)
            if data:
                keyword_query_result_1, position_query_result_1 = data
                print("收到以下数据：")
                print(f"Client 收到 keyword_query_result_1 :{len(keyword_query_result_1)}")
                print(f"Client 收到 position_query_result_1 :{len(position_query_result_1)}")

        # 接收查询结果
        conn, addr = s.accept()
        with conn:
            data = receive_data(conn)
            if data:
                keyword_query_result_2, position_query_result_2 = data
                print("收到以下数据：")
                print("收到以下数据：")
                print(f"Client 收到 keyword_query_result_2 :{len(keyword_query_result_2)}")
                print(f"Client 收到 position_query_result_2 :{len(position_query_result_2)}")

        decrypted_keyword_query_result_1 = {}
        decrypted_position_query_result_1 = {}
        decrypted_keyword_query_result_2 = {}
        decrypted_position_query_result_2 = {}
        decrypted_keyword_query_result = []
        decrypted_position_query_result = []

        for key, value in keyword_query_result_1.items():
            decrypted_keyword_query_result_1[key] = BitMap.from_string(ure.decrypt_bitmap(value))
            decrypted_keyword_query_result.append(decrypted_keyword_query_result_1[key])

        for key, value in position_query_result_1.items():
            decrypted_position_query_result_1[key] = BitMap.from_string(ure.decrypt_bitmap(value))
            decrypted_position_query_result.append(decrypted_position_query_result_1[key])

        for key, value in keyword_query_result_2.items():
            decrypted_keyword_query_result_2[key] = BitMap.from_string(ure.decrypt_bitmap(value))
            decrypted_keyword_query_result.append(decrypted_keyword_query_result_2[key])

        for key, value in position_query_result_2.items():
            decrypted_position_query_result_2[key] = BitMap.from_string(ure.decrypt_bitmap(value))
            decrypted_position_query_result.append(decrypted_position_query_result_2[key])

        keyword_query_result_AND = BitMap.bitmaps_logical_operation(decrypted_keyword_query_result, "AND")
        position_query_result_OR = BitMap.bitmaps_logical_operation(decrypted_position_query_result, "OR")

        print(keyword_query_result_AND)
        print(position_query_result_OR)

        query_result = BitMap.bitmaps_logical_operation([keyword_query_result_AND, position_query_result_OR], "AND")

        print(query_result)

        result = query_result.get_set_bits()

        print(result)

        print(f"查询到的对象ID是{bitmap_map_2_object_map[result[0]]}")

        # 创建标志文件，查询结束锁
        with open("query_done.lock", "w") as f:
            f.write("Client Query completed")

        # 数据更新
        print("------------------------数据更新------------------------")

        decrypted_keyword_query_result = {}
        decrypted_position_query_result = {}

        for key, value in decrypted_keyword_query_result_1.items():
            decrypted_keyword_query_result[key] = BitMap.logical_operation(decrypted_keyword_query_result_1[key], decrypted_keyword_query_result_2[key], "OR")

        for key, value in decrypted_position_query_result_1.items():
            decrypted_position_query_result[key] = BitMap.logical_operation(decrypted_position_query_result_1[key], decrypted_position_query_result_2[key], "OR")

        # DataOwner 方案
        # send_to_server((decrypted_keyword_query_result, decrypted_position_query_result), DataOwner)

        update_keyword_query_result_1 = {}
        update_position_query_result_1 = {}
        update_keyword_query_result_2 = {}
        update_position_query_result_2 = {}

        for key, value in decrypted_keyword_query_result.items():
            update_keyword_query_result_1[key], update_keyword_query_result_2[key] = decrypted_keyword_query_result[key].bitmap_or_separation()

        for key, value in decrypted_position_query_result.items():
            update_position_query_result_1[key], update_position_query_result_2[key] = decrypted_position_query_result[key].bitmap_or_separation()

        encrypted_update_keyword_query_result_1 = {}
        encrypted_update_position_query_result_1 = {}
        encrypted_update_keyword_query_result_2 = {}
        encrypted_update_position_query_result_2 = {}

        # 加密
        for key, value in update_keyword_query_result_1.items():
            cipher_text, capsule = ProxyPseudorandom.encrypt(key, proxy_pseudorandom_do_pub, mode="keyword", search_key=proxy_pseudorandom_key)
            encrypted_ciphertexts = ure.encrypt_bitmap(str(value))
            encrypted_update_keyword_query_result_1[cipher_text] = [capsule, encrypted_ciphertexts]

        for key, value in update_position_query_result_1.items():
            cipher_text, capsule = ProxyPseudorandom.encrypt(key, proxy_pseudorandom_do_pub, mode="keyword", search_key=proxy_pseudorandom_key)
            encrypted_ciphertexts = ure.encrypt_bitmap(str(value))
            encrypted_update_position_query_result_1[cipher_text] = [capsule, encrypted_ciphertexts]

        for key, value in update_keyword_query_result_2.items():
            cipher_text, capsule = ProxyPseudorandom.encrypt(key, proxy_pseudorandom_do_pub, mode="keyword", search_key=proxy_pseudorandom_key)
            encrypted_ciphertexts = ure.encrypt_bitmap(str(value))
            encrypted_update_keyword_query_result_2[cipher_text] = [capsule, encrypted_ciphertexts]

        for key, value in update_position_query_result_2.items():
            cipher_text, capsule = ProxyPseudorandom.encrypt(key, proxy_pseudorandom_do_pub, mode="keyword", search_key=proxy_pseudorandom_key)
            encrypted_ciphertexts = ure.encrypt_bitmap(str(value))
            encrypted_update_position_query_result_2[cipher_text] = [capsule, encrypted_ciphertexts]

        # 发送给两个服务器
        send_to_server((encrypted_update_keyword_query_result_1, encrypted_update_position_query_result_1), CLOUD_SERVER_1_ADDRESS)
        send_to_server((encrypted_update_keyword_query_result_2, encrypted_update_position_query_result_2), CLOUD_SERVER_2_ADDRESS)

        # 数据更新完毕
        print("------------------------更新完毕------------------------")

        # 添加新对象

        # 添加一个新的数据对象
        new_object = [("Dumpling", "Hot pot"), (39.954370,116.346740)]




if __name__ == "__main__":
    main()