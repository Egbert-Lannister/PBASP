import os
import socket
import pickle
from tqdm import tqdm
from encryption import ProxyPseudorandom, UniversalReEncryption

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

def re_encrypt_data(data, rk, ure, progress_desc):
    """对数据进行重加密"""
    re_encrypted_data = {}
    for key, value in tqdm(data.items(), desc=progress_desc, total=len(data)):
        capsule = value[0]
        encrypted_bitmap = value[1]

        new_capsule = ProxyPseudorandom.re_encryption(rk, capsule)
        re_encrypted_bitmap = ure.reencrypt_bitmap(encrypted_bitmap)

        re_encrypted_data[key] = [new_capsule, re_encrypted_bitmap]
    return re_encrypted_data

def delete_lock_files():
    """删除所有锁文件"""
    lock_files = [
        "CloudServer_1_1st_reencryption_done.lock",
        "CloudServer_2_1st_reencryption_done.lock",
        "dataowner_done.lock",
        "CloudServer_1_reencryption_done.lock",
        "CloudServer_2_reencryption_done.lock",
        "query_done.lock"
    ]
    for file in lock_files:
        if os.path.exists(file):
            os.remove(file)
            print(f"已删除文件: {file}")