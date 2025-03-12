import socket
import pickle


def receive_data(sock):
    """接收数据"""
    try:
        # 接收数据长度
        data_length_bytes = sock.recv(4)
        if not data_length_bytes:
            return None
        data_length = int.from_bytes(data_length_bytes, byteorder='big')

        # 接收数据
        received_data = b''
        while len(received_data) < data_length:
            chunk = sock.recv(data_length - len(received_data))
            if not chunk:
                break
            received_data += chunk

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

    query_keyword = ["Restaurants", "Food"]

    query_prefix_code = IndexBuilder.get_prefix_codes(IndexBuilder.lat_lon_to_hilbert_to_64bit_binary(latitude, longitude))

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
                proxy_pseudorandom_do_pub = data
                print("收到以下数据：")
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
        for value in query_keyword:
            one_encrypted_keyword = ProxyPseudorandom.encrypt(value, proxy_pseudorandom_do_pub)
            encrypted_query_keywords.append(one_encrypted_keyword)

        encrypted_query_prefix_codes = []
        for value in query_prefix_code:
            one_encrypted_prefix_code = ProxyPseudorandom.encrypt(value, proxy_pseudorandom_do_pub)
            encrypted_query_prefix_codes.append(one_encrypted_prefix_code)

        # 等待重加密完成
        while not os.path.exists("CloudServer_1_reencryption_done.lock") and not os.path.exists("CloudServer_2_reencryption_done.lock"):
            time.sleep(1)

        # 发送查询内容到服务器
        send_to_server((encrypted_query_keywords, encrypted_query_prefix_codes), CLOUD_SERVER_1_ADDRESS)
        send_to_server((encrypted_query_keywords, encrypted_query_prefix_codes), CLOUD_SERVER_2_ADDRESS)





    pass


if __name__ == "__main__":
    main()