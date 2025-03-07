import socket
import pickle


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
        conn, addr = s.accept()
        with conn:
            print(f"连接来自 {addr}")
            data = receive_data(conn)
            if data:
                encrypted_keyword_index_2, encrypted_position_index_2, proxy_pseudorandom_do_pri = data
                print("收到以下数据：")
                print(f"encrypted_keyword_index_2: {encrypted_keyword_index_2}")
                print(f"encrypted_position_index_2: {encrypted_position_index_2}")
                # 在这里存储或处理数据

                send_to_server((encrypted_keyword_index_2, encrypted_position_index_2), CLOUD_SERVER_1_ADDRESS)

                proxy_pseudorandom_cs1_pri, proxy_pseudorandom_cs1_pub = ProxyPseudorandom.generate_keys()

                rk, pubX = ProxyPseudorandom.re_key_gen(proxy_pseudorandom_do_pri, proxy_pseudorandom_cs1_pub)





if __name__ == "__main__":
    main()