import atexit
import os
import signal
import socket
import pickle
import sqlite3
import sys

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
    """
    删除所有锁文件，并注册退出时的清理操作。
    当程序正常退出或被中断时，都会自动删除这些锁文件。
    """
    lock_files = [
        "CloudServer_1_1st_reencryption_done.lock",
        "CloudServer_2_1st_reencryption_done.lock",
        "data owner_done.lock",
        "CloudServer_1_reencryption_done.lock",
        "CloudServer_2_reencryption_done.lock",
        "query_done.lock",
        "CloudServer_1_update_done.lock",
        "CloudServer_2_update_done.lock",
        "CloudServer_2_query_request_done.lock",
        "CloudServer_1_query_request_done.lock",
        "query_begin.lock"
    ]

    def cleanup():
        for file in lock_files:
            if os.path.exists(file):
                os.remove(file)
                print(f"已删除文件: {file}")

    # 立即删除一次已有的锁文件
    cleanup()

    # 注册程序正常退出时的清理操作
    atexit.register(cleanup)

    # 定义信号处理函数，程序中断时调用 cleanup
    def handle_signal(signum, frame):
        print("程序中断，正在清理锁文件...")
        cleanup()
        sys.exit(0)

    # 注册信号处理（Ctrl+C 或终止信号）
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

def read_data(db_path):
    """
    从 SQLite 数据库中读取数据，并返回所有行记录
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM business_table")
    rows = cursor.fetchall()
    conn.close()
    return rows