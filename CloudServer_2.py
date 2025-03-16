import socket
import redis

from tqdm import tqdm
from encryption import ProxyPseudorandom, UniversalReEncryption
from redis_utils import publish_redis_event, wait_for_redis_events
from utils import receive_data, send_to_server, re_encrypt_data
# from TailoredUniversalReEncryption.UniversalReEncryption_MultithreadingParallel import UniversalReEncryption
# from UniversalReEncryption.Universal_ReEncryption_cpp_Acceleration import universal_reencryption
import universal_reencryption

def main():

    # 创建 Redis 连接（确保 Redis 服务已启动）
    r = redis.Redis(host='localhost', port=6379, db=0)

    # 定义服务器 客户端地址
    HOST = 'localhost'
    cs1_PORT = 12345
    cs2_PORT = 12346
    client_PORT = 12347
    CLOUD_SERVER_1_ADDRESS = (HOST, cs1_PORT)  # CloudServer_1 的地址
    # CLOUD_SERVER_2_ADDRESS = (HOST, cs2_PORT)  # CloudServer_2 的地址
    CLIENT_ADDRESS = (HOST, client_PORT)  # Client 客户端的地址

    # wait_for_redis_events(r, ["bitmap_map_2_object_map"], expected_message="done")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, cs2_PORT))
        s.listen()
        print(f"CloudServer_2 已启动，监听端口 {cs2_PORT}...")

        wait_for_redis_events(r, ["Key sending"], expected_message="begin")

        # 接收代理伪随机密钥
        conn, addr = s.accept()
        with conn:
            data = receive_data(conn)
            if data:
                rk, pubX = data
                print("收到以下数据：")
                print(f"Cloud Server 2 收到 rk :{rk}")
                print(f"Cloud Server 2 收到 pubX :{pubX}")

        # 接收代理重加密密钥
        conn, addr = s.accept()
        with conn:
            data = receive_data(conn)
            if data:
                ure = data
                print("收到以下数据：")
                print(f"Cloud Server 2 收到 ure :{ure}")

        publish_redis_event(r, "CloudServer 2 received", message="done")

        wait_for_redis_events(r, ["Encrypted data sending"], expected_message="begin")

        conn, addr = s.accept()
        with conn:
            print(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                encrypted_keyword_index_2, encrypted_position_index_2 = data
                print("Cloud Server 2 收到以下数据：")
                print(f"Cloud Server 2 收到 encrypted_keyword_index_2, 共有 {len(encrypted_keyword_index_2)}条")
                print(f"Cloud Server 2 收到 encrypted_position_index_2， 共有{len(encrypted_position_index_2)}条")

                # publish_redis_event(r, "CloudServer 2 received encrypted data", message="done")
                # wait_for_redis_events(r, ["CloudServer 1 received encrypted data"], expected_message="done")

                send_to_server((encrypted_keyword_index_2, encrypted_position_index_2), CLOUD_SERVER_1_ADDRESS)

        conn, addr = s.accept()
        with conn:
            print(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                encrypted_keyword_index_1, encrypted_position_index_1 = data
                print(f"Cloud Server 2 收到 encrypted_keyword_index_1, 共有 {len(encrypted_keyword_index_1)}条")
                print(f"Cloud Server 2 收到 encrypted_position_index_1， 共有{len(encrypted_position_index_1)}条")

                # 重加密字典
                re_encrypted_keyword_index_1_1st = {}
                re_encrypted_position_index_1_1st = {}


                # 进行重加密
                for keyword, (capsule, encrypted_bitmap, origin_capacity) in tqdm(encrypted_keyword_index_1.items(), desc="1st Re-Encrypting the keyword index 1...", total=len(encrypted_keyword_index_1)):
                    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)
                    capacity = origin_capacity

                    re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)

                    re_encrypted_keyword_index_1_1st[keyword] = [new_capsule, re_encrypted_bitmap, capacity]

                # 进行重加密
                for position, (capsule, encrypted_bitmap, origin_capacity) in tqdm(encrypted_position_index_1.items(), desc="1st Re-Encrypting the position index 1...", total=len(encrypted_keyword_index_1)):
                    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)
                    capacity = origin_capacity

                    re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)

                    re_encrypted_position_index_1_1st[position] = [new_capsule, re_encrypted_bitmap, capacity]

                # publish_redis_event(r, "Cloud Server 2 1st re-encrypted data", message="done")
                # wait_for_redis_events(r, ["Cloud Server 1 1st re-encrypted data"], expected_message="done")

                # 发送第一次重加密数据
                send_to_server((re_encrypted_keyword_index_1_1st, re_encrypted_position_index_1_1st), CLOUD_SERVER_1_ADDRESS)

        conn, addr = s.accept()
        with conn:
            print(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                re_encrypted_keyword_index_2_1st, re_encrypted_position_index_2_1st = data
                print(f"Cloud Server 2 收到 re_encrypted_keyword_index_2_1st, 共有 {len(re_encrypted_keyword_index_2_1st)}条")
                print(f"Cloud Server 2 收到 re_encrypted_position_index_2_1st， 共有{len(re_encrypted_position_index_2_1st)}条")

                # 重加密字典
                re_encrypted_keyword_index_2_2nd = {}
                re_encrypted_position_index_2_2nd = {}

                # 进行重加密
                for keyword, (capsule, encrypted_bitmap, origin_capacity) in tqdm(re_encrypted_keyword_index_2_1st.items(), desc="2nd Re-Encrypting the keyword index 2...", total=len(re_encrypted_keyword_index_2_1st)):
                    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)
                    capacity = origin_capacity

                    re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)

                    re_encrypted_keyword_index_2_2nd[keyword] = [new_capsule, re_encrypted_bitmap, capacity]

                # 进行重加密
                for position, (capsule, encrypted_bitmap, origin_capacity) in tqdm(re_encrypted_position_index_2_1st.items(), desc="2nd Re-Encrypting the position index 2...", total=len(re_encrypted_position_index_2_1st)):
                    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)
                    capacity = origin_capacity

                    re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)

                    re_encrypted_position_index_2_2nd[position] = [new_capsule, re_encrypted_bitmap, capacity]

        publish_redis_event(r, "Cloud Server 2 2nd re-encrypted data", message="done")
        wait_for_redis_events(r, ["query_begin"], expected_message="begin")

        conn, addr = s.accept()
        with conn:
            print(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                encrypted_query_keywords, encrypted_query_prefix_codes = data
                print(f"Cloud Server 2 收到 encrypted_query_keywords, 共有 {len(encrypted_query_keywords)}条")
                print(f"Cloud Server 2 收到 encrypted_query_prefix_codes， 共有{len(encrypted_query_prefix_codes)}条")

                keyword_query_result = {}
                position_query_result = {}

                for qt_keyword in encrypted_query_keywords:
                    # 查找时用 key 以 bytes 形式存储，故先转换为字符串
                    init_token = qt_keyword.decode("utf-8")
                    # 遍历加密关键字索引，寻找匹配项
                    found = False
                    for encrypted_keyword,  (capsule, encrypted_bitmap, capacity) in re_encrypted_keyword_index_2_2nd.items():
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
                    for encrypted_prefix_code,  (capsule, encrypted_bitmap, capacity) in re_encrypted_position_index_2_2nd.items():
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

                # publish_redis_event(r, "Cloud Server 1 query", message="done")
                # wait_for_redis_events(r, ["Cloud Server 2 query result sending"], expected_message="begin")
                send_to_server((keyword_query_result, position_query_result), CLIENT_ADDRESS)

        wait_for_redis_events(r, ["Data update"], expected_message="begin")

        conn, addr = s.accept()
        with conn:
            print(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                encrypted_update_keyword_query_result_2, encrypted_update_position_query_result_2 = data

                for encrypted_update_keyword, (capsule, encrypted_update_keyword_query_result_bitmap) in encrypted_update_keyword_query_result_2.items():
                    init_token = encrypted_update_keyword.decode("utf-8")
                    found = False
                    for encrypted_keyword, (capsule, encrypted_bitmap, capacity) in re_encrypted_keyword_index_2_2nd.items():
                        count = capsule.get("count", 0)
                        transformed_token = ProxyPseudorandom.transform_query_token(init_token, rk, count)
                        if transformed_token == capsule["tag"]:
                            re_encrypted_keyword_index_2_2nd[encrypted_keyword] = [capsule, encrypted_update_keyword_query_result_bitmap, capacity]
                            found = True
                            break
                    if not found:
                        keyword_query_result[init_token] = "NotFound"

                for encrypted_update_position, (capsule, encrypted_update_position_query_result_bitmap) in encrypted_update_position_query_result_2.items():
                    init_token = encrypted_update_position.decode("utf-8")
                    found = False
                    for encrypted_prefix_code, (capsule, encrypted_bitmap, capacity) in re_encrypted_position_index_2_2nd.items():
                        count = capsule.get("count", 0)
                        transformed_token = ProxyPseudorandom.transform_query_token(init_token, rk, count)
                        if transformed_token == capsule["tag"]:
                            re_encrypted_position_index_2_2nd[encrypted_prefix_code] = [capsule, encrypted_update_position_query_result_bitmap, capacity]
                            found = True
                            break
                    if not found:
                        keyword_query_result[init_token] = "NotFound"

        # publish_redis_event(r, "CloudServer_1_update_done", message="done")




if __name__ == "__main__":
    main()