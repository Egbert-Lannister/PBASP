import logging
import socket
import time
import redis
from tqdm import tqdm

from BitMap import BitMap
from encryption import ProxyPseudorandom, UniversalReEncryption
from redis_utils import publish_redis_event, wait_for_redis_events
from utils import receive_data, send_to_server, re_encrypt_data

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def main():
    # 建立 Redis 连接（确保 Redis 服务已启动，并各进程均连接同一实例）
    r = redis.Redis(host='localhost', port=6379, db=0)

    # 定义服务器、客户端地址
    HOST = 'localhost'
    cs1_PORT = 12345
    cs2_PORT = 12346
    client_PORT = 12347
    # 本示例为 CloudServer_1，故绑定 cs1_PORT
    CLOUD_SERVER_2_ADDRESS = (HOST, cs2_PORT)  # CloudServer_2 的地址
    CLIENT_ADDRESS = (HOST, client_PORT)  # Client 的地址

    # wait_for_redis_events(r, ["bitmap_map_2_object_map"], expected_message="done")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, cs1_PORT))
        s.listen()
        logging.info(f"CloudServer_1 已启动，监听端口 {cs1_PORT}...")

        wait_for_redis_events(r, ["Key sending"], expected_message="begin")

        # 接收代理伪随机密钥
        conn, addr = s.accept()
        with conn:
            data = receive_data(conn)
            if data:
                rk, pubX = data
                logging.info(f"Cloud Server 1 收到 rk : {rk}")
                logging.info(f"Cloud Server 1 收到 pubX : {pubX}")

        # 接收代理重加密密钥
        conn, addr = s.accept()
        with conn:
            data = receive_data(conn)
            if data:
                ure = data
                logging.info(f"Cloud Server 1 收到 ure : {ure}")

        publish_redis_event(r, "CloudServer 1 received", message="done")

        wait_for_redis_events(r, ["Encrypted data sending"], expected_message="begin")

        # 接收来自其他服务器或进程的加密索引数据
        conn, addr = s.accept()
        with conn:
            logging.info(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                encrypted_keyword_index_1, encrypted_position_index_1 = data
                logging.info(f"Cloud Server 1 收到 encrypted_keyword_index_1, 共 {len(encrypted_keyword_index_1)} 条")
                logging.info(f"Cloud Server 1 收到 encrypted_position_index_1, 共 {len(encrypted_position_index_1)} 条")

                # publish_redis_event(r, "CloudServer 1 received encrypted data", message="done")
                # wait_for_redis_events(r, ["CloudServer 2 received encrypted data"], expected_message="done")

                # 转发数据给 CloudServer_2
                send_to_server((encrypted_keyword_index_1, encrypted_position_index_1), CLOUD_SERVER_2_ADDRESS)

        # 接收 CloudServer_2 发送过来的加密索引数据
        conn, addr = s.accept()
        with conn:
            logging.info(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                encrypted_keyword_index_2, encrypted_position_index_2 = data
                logging.info(f"Cloud Server 1 收到 encrypted_keyword_index_2, 共 {len(encrypted_keyword_index_2)} 条")
                logging.info(f"Cloud Server 1 收到 encrypted_position_index_2, 共 {len(encrypted_position_index_2)} 条")

                # 对 CloudServer_2 的数据进行第一阶段重加密
                re_encrypted_keyword_index_2_1st = {}
                re_encrypted_position_index_2_1st = {}

                for keyword, (capsule, encrypted_bitmap, origin_capacity) in tqdm(
                        encrypted_keyword_index_2.items(),
                        desc="1st Re-Encrypting the keyword index 2...",
                        total=len(encrypted_keyword_index_2)):
                    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)
                    capacity = origin_capacity
                    re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)
                    re_encrypted_keyword_index_2_1st[keyword] = [new_capsule, re_encrypted_bitmap, capacity]

                for position, (capsule, encrypted_bitmap, origin_capacity) in tqdm(
                        encrypted_position_index_2.items(),
                        desc="1st Re-Encrypting the position index 2...",
                        total=len(encrypted_position_index_2)):
                    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)
                    capacity = origin_capacity
                    re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)
                    re_encrypted_position_index_2_1st[position] = [new_capsule, re_encrypted_bitmap, capacity]

                # publish_redis_event(r, "Cloud Server 1 1st re-encrypted data", message="done")
                # wait_for_redis_events(r, ["Cloud Server 2 1st re-encrypted data"], expected_message="done")

                send_to_server((re_encrypted_keyword_index_2_1st, re_encrypted_position_index_2_1st),
                               CLOUD_SERVER_2_ADDRESS)

        # 接收 CloudServer_2 第二阶段重加密后的索引数据
        conn, addr = s.accept()
        with conn:
            logging.info(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                re_encrypted_keyword_index_1_1st, re_encrypted_position_index_1_1st = data
                logging.info(
                    f"Cloud Server 1 收到 re_encrypted_keyword_index_1_1st, 共 {len(re_encrypted_keyword_index_1_1st)} 条")
                logging.info(
                    f"Cloud Server 1 收到 re_encrypted_position_index_1_1st, 共 {len(re_encrypted_position_index_1_1st)} 条")

                # 对 CloudServer_2 数据进行第二阶段重加密
                re_encrypted_keyword_index_1_2nd = {}
                re_encrypted_position_index_1_2nd = {}

                for keyword, (capsule, encrypted_bitmap, origin_capacity) in tqdm(
                        re_encrypted_keyword_index_1_1st.items(),
                        desc="2nd Re-Encrypting the keyword index 1...",
                        total=len(re_encrypted_keyword_index_1_1st)):
                    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)
                    capacity = origin_capacity
                    re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)
                    re_encrypted_keyword_index_1_2nd[keyword] = [new_capsule, re_encrypted_bitmap, capacity]

                for position, (capsule, encrypted_bitmap, origin_capacity) in tqdm(
                        re_encrypted_position_index_1_1st.items(),
                        desc="2nd Re-Encrypting the position index 1...",
                        total=len(re_encrypted_position_index_1_1st)):
                    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)
                    capacity = origin_capacity
                    re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)
                    re_encrypted_position_index_1_2nd[position] = [new_capsule, re_encrypted_bitmap, capacity]

        publish_redis_event(r, "Cloud Server 1 2nd re-encrypted data", message="done")

        wait_for_redis_events(r, ["query_begin"], expected_message="begin")

        # 接收来自 Client 的查询请求
        conn, addr = s.accept()
        with conn:
            logging.info(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                encrypted_query_keywords, encrypted_query_prefix_codes = data
                logging.info(f"Cloud Server 1 收到 encrypted_query_keywords, 共 {len(encrypted_query_keywords)} 条")
                logging.info(
                    f"Cloud Server 1 收到 encrypted_query_prefix_codes, 共 {len(encrypted_query_prefix_codes)} 条")

                keyword_query_result = {}
                position_query_result = {}

                # 对每个查询关键字进行查找
                for qt_keyword in encrypted_query_keywords:
                    init_token = qt_keyword.decode("utf-8")
                    found = False
                    for encrypted_keyword, (
                    capsule, encrypted_bitmap, capacity) in re_encrypted_keyword_index_1_2nd.items():
                        count = capsule.get("count", 0)
                        transformed_token = ProxyPseudorandom.transform_query_token(init_token, rk, count)
                        if transformed_token == capsule["tag"]:
                            keyword_query_result[encrypted_keyword] = encrypted_bitmap
                            found = True
                            break
                    if not found:
                        keyword_query_result[init_token] = "NotFound"

                for qt_prefix_code in encrypted_query_prefix_codes:
                    init_token = qt_prefix_code.decode("utf-8")
                    found = False
                    for encrypted_prefix_code, (
                    capsule, encrypted_bitmap, capacity) in re_encrypted_position_index_1_2nd.items():
                        count = capsule.get("count", 0)
                        transformed_token = ProxyPseudorandom.transform_query_token(init_token, rk, count)
                        if transformed_token == capsule["tag"]:
                            position_query_result[encrypted_prefix_code] = encrypted_bitmap
                            found = True
                            break
                    if not found:
                        keyword_query_result[init_token] = "NotFound"

                # publish_redis_event(r, "Cloud Server 1 query", message="done")
                # wait_for_redis_events(r, ["Cloud Server 1 query result sending"], expected_message="begin")
                send_to_server((keyword_query_result, position_query_result), CLIENT_ADDRESS)

        wait_for_redis_events(r, ["Data update"], expected_message="begin")

        # 接收 Client 更新后的查询结果（数据更新阶段）
        conn, addr = s.accept()
        with conn:
            logging.info(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                encrypted_update_keyword_query_result_1, encrypted_update_position_query_result_1 = data

                for encrypted_update_keyword, (capsule,
                                               encrypted_update_keyword_query_result_bitmap) in encrypted_update_keyword_query_result_1.items():
                    init_token = encrypted_update_keyword.decode("utf-8")
                    found = False
                    for encrypted_keyword, (
                    capsule, encrypted_bitmap, capacity) in re_encrypted_keyword_index_1_2nd.items():
                        count = capsule.get("count", 0)
                        transformed_token = ProxyPseudorandom.transform_query_token(init_token, rk, count)
                        if transformed_token == capsule["tag"]:
                            re_encrypted_keyword_index_1_2nd[encrypted_keyword] = [capsule,
                                                                                   encrypted_update_keyword_query_result_bitmap,
                                                                                   capacity]
                            found = True
                            break
                    if not found:
                        keyword_query_result[init_token] = "NotFound"

                for encrypted_update_position, (capsule,
                                                encrypted_update_position_query_result_bitmap) in encrypted_update_position_query_result_1.items():
                    init_token = encrypted_update_position.decode("utf-8")
                    found = False
                    for encrypted_prefix_code, (
                    capsule, encrypted_bitmap, capacity) in re_encrypted_position_index_1_2nd.items():
                        count = capsule.get("count", 0)
                        transformed_token = ProxyPseudorandom.transform_query_token(init_token, rk, count)
                        if transformed_token == capsule["tag"]:
                            re_encrypted_position_index_1_2nd[encrypted_prefix_code] = [capsule,
                                                                                        encrypted_update_position_query_result_bitmap,
                                                                                        capacity]
                            found = True
                            break
                    if not found:
                        keyword_query_result[init_token] = "NotFound"

        # 发布事件，通知 Client：数据更新已完成
        # publish_redis_event(r, "CloudServer_1_update_done", "done")

        # 接收新添加的对象
        conn, addr = s.accept()
        with conn:
            logging.info(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                start_adding_time = time.time()
                encrypted_update_data_index = data

                # 构建预索引：关键字和前缀码
                keyword_tag_index = {capsule["tag"]: (encrypted_keyword, capsule, encrypted_bitmap, capacity)
                                     for encrypted_keyword, (capsule, encrypted_bitmap, capacity)
                                     in re_encrypted_keyword_index_1_2nd.items()}

                prefix_code_tag_index = {capsule["tag"]: (encrypted_prefix_code, capsule, encrypted_bitmap, capacity)
                                         for encrypted_prefix_code, (capsule, encrypted_bitmap, capacity)
                                         in re_encrypted_position_index_1_2nd.items()}

                capacity_num = 2001
                for business_ID, (
                encrypted_additional_object_keywords_list, encrypted_additional_object_prefix_code_list) in tqdm(
                        encrypted_update_data_index.items(), desc="Adding data...",
                        total=len(encrypted_update_data_index)):

                    # 处理每个对象的关键词
                    for encrypted_additional_object_keyword in encrypted_additional_object_keywords_list:
                        (cipher_text, capsule_origin) = encrypted_additional_object_keyword
                        init_token = cipher_text.decode("utf-8")
                        # 这里调用缓存版本（假设已在 ProxyPseudorandom 中实现）
                        transformed_token = ProxyPseudorandom.transform_query_token_cached(init_token, rk,
                                                                                           capsule_origin.get("count",
                                                                                                              0))
                        if transformed_token in keyword_tag_index:
                            encrypted_keyword, capsule, encrypted_bitmap, capacity = keyword_tag_index[
                                transformed_token]
                            existed_bitmap = BitMap.from_string(ure.decrypt_bitmap(encrypted_bitmap),
                                                                capacity=capacity_num)
                            existed_bitmap.add_object(has_keyword=True)
                            re_encrypted_keyword_index_1_2nd[encrypted_keyword] = [capsule, ure.encrypt_bitmap(
                                str(existed_bitmap)), capacity_num]
                        else:
                            bitmap = BitMap(capacity=capacity_num)
                            encrypted_bitmap = ure.encrypt_bitmap(str(bitmap))
                            re_encrypted_keyword_index_1_2nd[cipher_text] = [capsule_origin, encrypted_bitmap,
                                                                             capacity_num]

                    # 处理每个对象的前缀码
                    for encrypted_additional_object_prefix_code in encrypted_additional_object_prefix_code_list:
                        (cipher_text, capsule_origin) = encrypted_additional_object_prefix_code
                        init_token = cipher_text.decode("utf-8")
                        transformed_token = ProxyPseudorandom.transform_query_token_cached(init_token, rk,
                                                                                           capsule_origin.get("count",
                                                                                                              0))
                        if transformed_token in prefix_code_tag_index:
                            encrypted_prefix_code, capsule, encrypted_bitmap, capacity = prefix_code_tag_index[
                                transformed_token]
                            existed_bitmap = BitMap.from_string(ure.decrypt_bitmap(encrypted_bitmap),
                                                                capacity=capacity_num)
                            existed_bitmap.add_object(has_keyword=True)
                            re_encrypted_position_index_1_2nd[encrypted_prefix_code] = [capsule, ure.encrypt_bitmap(
                                str(existed_bitmap)), capacity_num]
                        else:
                            bitmap = BitMap(capacity=capacity_num)
                            encrypted_bitmap = ure.encrypt_bitmap(str(bitmap))
                            re_encrypted_position_index_1_2nd[cipher_text] = [capsule_origin, encrypted_bitmap,
                                                                              capacity_num]

                    capacity_num += 1
                adding_end_time = time.time()
                logging.info(f"数据添加时间：{adding_end_time - start_adding_time}")
                print("------------------------添加完成------------------------")


if __name__ == "__main__":
    main()
