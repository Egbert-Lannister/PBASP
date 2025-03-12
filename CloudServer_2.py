import socket
import pickle

from tqdm import tqdm

from encryption import ProxyPseudorandom, UniversalReEncryption
from utils import receive_data, send_to_server, re_encrypt_data
# from TailoredUniversalReEncryption.UniversalReEncryption_MultithreadingParallel import UniversalReEncryption
# from UniversalReEncryption.Universal_ReEncryption_cpp_Acceleration import universal_reencryption
import universal_reencryption

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