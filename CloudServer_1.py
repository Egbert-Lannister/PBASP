import os
import socket
import pickle
import time

from tqdm import tqdm

from BitMap import BitMap
from ProcessController import wait_for_lock_file
from encryption import ProxyPseudorandom, UniversalReEncryption
# from test_proxy import capsule
from utils import receive_data, send_to_server, re_encrypt_data
import universal_reencryption
# from TailoredUniversalReEncryption.UniversalReEncryption_MultithreadingParallel import UniversalReEncryption
# from UniversalReEncryption.Universal_ReEncryption_cpp_Acceleration import universal_reencryption

def main():
    # 定义服务器 客户端地址
    HOST = 'localhost'
    cs1_PORT = 12345
    cs2_PORT = 12346
    client_PORT = 12347
    # CLOUD_SERVER_1_ADDRESS = (HOST, cs1_PORT)  # CloudServer_1 的地址
    CLOUD_SERVER_2_ADDRESS = (HOST, cs2_PORT)  # CloudServer_2 的地址
    CLIENT_ADDRESS = (HOST, client_PORT)  # Client 客户端的地址

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, cs1_PORT))
        s.listen()
        print(f"CloudServer_1 已启动，监听端口 {cs1_PORT}...")

        # 接收代理伪随机密钥
        conn, addr = s.accept()
        with conn:
            data = receive_data(conn)
            if data:
                rk, pubX = data
                print("收到以下数据：")
                print(f"Cloud Server 1 收到 rk :{rk}")
                print(f"Cloud Server 1 收到 pubX :{pubX}")


        # 接收代理重加密密钥
        conn, addr = s.accept()
        with conn:
            data = receive_data(conn)
            if data:
                ure = data
                print("收到以下数据：")
                print(f"Cloud Server 1 收到 ure :{ure}")

        conn, addr = s.accept()
        with conn:
            print(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                encrypted_keyword_index_1, encrypted_position_index_1 = data
                print("Cloud Server 1 收到以下数据：")
                print(f"Cloud Server 1 收到 encrypted_keyword_index_1, 共有 {len(encrypted_keyword_index_1)}条")
                print(f"Cloud Server 1 收到 encrypted_position_index_1， 共有{len(encrypted_position_index_1)}条")

                # # 等待 DataOwner 完成
                # wait_for_lock_file("dataowner_done.lock")

                send_to_server((encrypted_keyword_index_1, encrypted_position_index_1), CLOUD_SERVER_2_ADDRESS)

        conn, addr = s.accept()
        with conn:
            print(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                encrypted_keyword_index_2, encrypted_position_index_2 = data
                print(f"Cloud Server 1 收到 encrypted_keyword_index_2, 共有 {len(encrypted_keyword_index_2)}条")
                print(f"Cloud Server 1 收到 encrypted_position_index_2， 共有{len(encrypted_position_index_2)}条")

                # 重加密字典
                re_encrypted_keyword_index_2_1st = {}
                re_encrypted_position_index_2_1st = {}

                for keyword, (capsule, encrypted_bitmap, capacity) in tqdm(encrypted_keyword_index_2.items(), desc="1st Re-Encrypting the keyword index 2...", total=len(encrypted_keyword_index_2)):
                    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)

                    re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)

                    re_encrypted_keyword_index_2_1st[keyword] = [new_capsule, re_encrypted_bitmap, capacity]


                # 进行重加密
                for position, (capsule, encrypted_bitmap, capacity) in tqdm(encrypted_position_index_2.items(), desc="1st Re-Encrypting the position index 2...", total=len(encrypted_position_index_2)):
                    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)

                    re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)

                    re_encrypted_position_index_2_1st[position] = [new_capsule, re_encrypted_bitmap, capacity]

                send_to_server((re_encrypted_keyword_index_2_1st, re_encrypted_position_index_2_1st), CLOUD_SERVER_2_ADDRESS)

        # 创建标志文件，通知 服务器2 重加密完成
        with open("CloudServer_1_1st_reencryption_done.lock", "w") as f:
            f.write("CloudServer 1 1st Re-encryption completed")

        # 等待服务器2第一次重加密完成
        while not os.path.exists("CloudServer_2_1st_reencryption_done.lock"):
            time.sleep(1)

        conn, addr = s.accept()
        with conn:
            print(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                re_encrypted_keyword_index_1_1st, re_encrypted_position_index_1_1st = data
                print(f"Cloud Server 1 收到 re_encrypted_keyword_index_1_1st, 共有 {len(re_encrypted_keyword_index_1_1st)}条")
                print(f"Cloud Server 1 收到 re_encrypted_position_index_1_1st， 共有{len(re_encrypted_position_index_1_1st)}条")

                # 重加密字典
                re_encrypted_keyword_index_1_2nd = {}
                re_encrypted_position_index_1_2nd = {}

                # 进行重加密
                for keyword, (capsule, encrypted_bitmap, capacity) in tqdm(re_encrypted_keyword_index_1_1st.items(), desc="2nd Re-Encrypting the keyword index 1...", total=len(re_encrypted_keyword_index_1_1st)):
                    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)

                    re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)

                    re_encrypted_keyword_index_1_2nd[keyword] = [new_capsule, re_encrypted_bitmap, capacity]

                # 进行重加密
                for position, (capsule, encrypted_bitmap, capacity) in tqdm(re_encrypted_position_index_1_1st.items(), desc="2nd Re-Encrypting the position index 1...", total=len(re_encrypted_position_index_1_1st)):
                    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)

                    re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)

                    re_encrypted_position_index_1_2nd[position] = [new_capsule, re_encrypted_bitmap, capacity]

        # 创建标志文件，通知 Client 重加密完成
        with open("CloudServer_1_reencryption_done.lock", "w") as f:
            f.write("CloudServer 1 Re-encryption completed")

        conn, addr = s.accept()
        with conn:
            print(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                encrypted_query_keywords, encrypted_query_prefix_codes = data
                print(f"Cloud Server 1 收到 encrypted_query_keywords, 共有 {len(encrypted_query_keywords)}条")
                print(f"Cloud Server 1 收到 encrypted_query_prefix_codes， 共有{len(encrypted_query_prefix_codes)}条")

                keyword_query_result = {}
                position_query_result = {}

                for qt_keyword in encrypted_query_keywords:
                    # 查找时用 key 以 bytes 形式存储，故先转换为字符串
                    init_token = qt_keyword.decode("utf-8")
                    # 遍历加密关键字索引，寻找匹配项
                    found = False
                    for encrypted_keyword, (capsule, encrypted_bitmap, capacity) in re_encrypted_keyword_index_1_2nd.items():
                        # 获取重加密次数
                        count = capsule.get("count", 0)
                        # 对客户端原始令牌转换 count 次
                        transformed_token = ProxyPseudorandom.transform_query_token(init_token, rk, count)
                        # 与存储在 capsule 中的 tag 比较
                        if transformed_token == capsule["tag"]:
                            keyword_query_result[encrypted_keyword] = encrypted_bitmap
                            found = True
                            break
                    if not found:
                        keyword_query_result[init_token] = "NotFound"

                for qt_prefix_code in encrypted_query_prefix_codes:
                    # 查找时用 key 以 bytes 形式存储，故先转换为字符串
                    init_token = qt_prefix_code.decode("utf-8")
                    # 遍历加密关键字索引，寻找匹配项
                    found = False
                    for encrypted_prefix_code, (capsule, encrypted_bitmap, capacity) in re_encrypted_position_index_1_2nd.items():
                        # 获取重加密次数
                        count = capsule.get("count", 0)
                        # 对客户端原始令牌转换 count 次
                        transformed_token = ProxyPseudorandom.transform_query_token(init_token, rk, count)
                        # 与存储在 capsule 中的 tag 比较
                        if transformed_token == capsule["tag"]:
                            position_query_result[encrypted_prefix_code] = encrypted_bitmap
                            found = True
                            break
                    if not found:
                        keyword_query_result[init_token] = "NotFound"

                # for encrypted_query_keyword in encrypted_query_keywords:
                #     keyword_query_result[encrypted_query_keyword] = re_encrypted_keyword_index_1_2nd[encrypted_query_keyword]
                #
                # for encrypted_query_prefix_code in encrypted_query_prefix_codes:
                #     position_query_result[encrypted_query_prefix_code] = re_encrypted_position_index_1_2nd[encrypted_query_prefix_code]


                send_to_server((keyword_query_result, position_query_result), CLIENT_ADDRESS)

        # 等待查询结束
        while not os.path.exists("query_done.lock"):
            time.sleep(1)

        conn, addr = s.accept()
        with conn:
            print(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                encrypted_update_keyword_query_result_1, encrypted_update_position_query_result_1 = data

                for key, value in encrypted_update_keyword_query_result_1.items():
                    re_encrypted_keyword_index_1_2nd[key] = value

                for key, value in encrypted_update_position_query_result_1.items():
                    re_encrypted_position_index_1_2nd[key] = value

        # 创建标志文件，通知 Client 查询结束的数据更新已完成
        with open("CloudServer_1_update_done.lock", "w") as f:
            f.write("CloudServer_1_update_done")

        # 接收新添加的对象
        conn, addr = s.accept()
        with conn:
            print(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                encrypted_update_data_index = data

                capacity_num = 2001
                for business_ID, (encrypted_additional_object_keywords_list, encrypted_additional_object_prefix_code_list) in tqdm(encrypted_update_data_index.items(), desc="Adding data...", total=len(encrypted_update_data_index)):

                    # 针对这个对象的所有关键词
                    for encrypted_additional_object_keyword in encrypted_additional_object_keywords_list:

                        (cipher_text, capsule_origin) = encrypted_additional_object_keyword
                        # 查找这个关键字之前存没存过
                        init_token = cipher_text.decode("utf-8")
                        found = False
                        for encrypted_keyword, (capsule, encrypted_bitmap, capacity) in re_encrypted_keyword_index_1_2nd.items():
                            # 获取重加密次数
                            count = capsule.get("count", 0)
                            # 对客户端原始令牌转换 count 次
                            transformed_token = ProxyPseudorandom.transform_query_token(init_token, rk, count)
                            # 与存储在 capsule 中的 tag 比较
                            if transformed_token == capsule["tag"]:
                                encrypted_bitmap.add_object(has_keyword=True)
                                found = True
                                break
                        if not found:
                            bitmap = BitMap(capacity=capacity_num)
                            encrypted_bitmap = ure.encrypt_bitmap(bitmap)
                            re_encrypted_keyword_index_1_2nd[encrypted_keyword] = [encrypted_bitmap, encrypted_bitmap, capacity]

                    for encrypted_additional_object_prefix_code in encrypted_additional_object_prefix_code_list:

                        (cipher_text, capsule_origin) = encrypted_additional_object_prefix_code
                        # 查找时用 key 以 bytes 形式存储，故先转换为字符串
                        init_token = cipher_text.decode("utf-8")
                        # 遍历加密关键字索引，寻找匹配项
                        found = False
                        for encrypted_prefix_code, (capsule, encrypted_bitmap) in re_encrypted_position_index_1_2nd.items():
                            # 获取重加密次数
                            count = capsule.get("count", 0)
                            # 对客户端原始令牌转换 count 次
                            transformed_token = ProxyPseudorandom.transform_query_token(init_token, rk, count)
                            # 与存储在 capsule 中的 tag 比较
                            if transformed_token == capsule["tag"]:
                                encrypted_bitmap.add_object(has_keyword=True)
                                found = True
                                break
                        if not found:
                            bitmap = BitMap(capacity=capacity_num)
                            encrypted_bitmap = ure.encrypt_bitmap(bitmap)
                            re_encrypted_position_index_1_2nd[encrypted_keyword] = [encrypted_bitmap, encrypted_bitmap, capacity]
                    capacity_num+=1

                print("------------------------添加完成------------------------")



if __name__ == "__main__":
    main()