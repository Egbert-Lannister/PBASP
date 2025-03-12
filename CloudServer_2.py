import socket
import pickle

from tqdm import tqdm

from encryption import ProxyPseudorandom, UniversalReEncryption
# from TailoredUniversalReEncryption.UniversalReEncryption_MultithreadingParallel import UniversalReEncryption
# from UniversalReEncryption.Universal_ReEncryption_cpp_Acceleration import universal_reencryption

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

        # 反序列化数据
        return pickle.loads(received_data)
    except Exception as e:
        print(f"接收数据时出错: {e}")
        return None

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

def main():
    HOST = 'localhost'
    cs2_PORT = 12346
    CLOUD_SERVER_1_ADDRESS = ('localhost', 12345)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, cs2_PORT))
        s.listen()
        print(f"CloudServer_2 已启动，监听端口 {cs2_PORT}...")

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



        conn, addr = s.accept()
        with conn:
            print(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                encrypted_keyword_index_2, encrypted_position_index_2 = data
                print("Cloud Server 2 收到以下数据：")
                print(f"Cloud Server 2 收到 encrypted_keyword_index_2, 共有 {len(encrypted_keyword_index_2)}条")
                print(f"Cloud Server 2 收到 encrypted_position_index_2， 共有{len(encrypted_position_index_2)}条")

                # 在这里存储或处理数据

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
                for key, value in tqdm(encrypted_keyword_index_1.items(), desc="1st Re-Encrypting the keyword index 1...", total=len(encrypted_keyword_index_1)):
                    keyword = key
                    capsule = value[0]
                    encrypted_bitmap = value[1]

                    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)

                    re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)

                    re_encrypted_keyword_index_1_1st[keyword] = [capsule, re_encrypted_bitmap]

                # 进行重加密
                for key, value in tqdm(encrypted_position_index_1.items(), desc="1st Re-Encrypting the position index 1...", total=len(encrypted_keyword_index_1)):
                    position = key
                    capsule = value[0]
                    encrypted_bitmap = value[1]

                    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)

                    re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)

                    re_encrypted_keyword_index_1_1st[position] = [capsule, re_encrypted_bitmap]

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
                for key, value in tqdm(re_encrypted_keyword_index_2_1st.items(), desc="2nd Re-Encrypting the keyword index 2...", total=len(re_encrypted_keyword_index_2_1st)):
                    keyword = key
                    capsule = value[0]
                    encrypted_bitmap = value[1]

                    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)

                    re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)

                    re_encrypted_keyword_index_2_2nd[keyword] = [capsule, re_encrypted_bitmap]

                # 进行重加密
                for key, value in tqdm(re_encrypted_position_index_2_1st.items(), desc="2nd Re-Encrypting the position index 2...", total=len(re_encrypted_position_index_2_1st)):
                    position = key
                    capsule = value[0]
                    encrypted_bitmap = value[1]

                    new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)

                    re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)

                    re_encrypted_position_index_2_2nd[position] = [capsule, re_encrypted_bitmap]




if __name__ == "__main__":
    main()