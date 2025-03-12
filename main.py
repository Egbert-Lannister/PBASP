import subprocess
import time

def main():
    # 启动 CloudServer_1
    server1_process = subprocess.Popen(["python", "CloudServer_1.py"])

    # 启动 CloudServer_2
    server2_process = subprocess.Popen(["python", "CloudServer_2.py"])

    # 启动 Client
    client_process = subprocess.Popen(["python", "Client.py"])

    # 启动 DataOwner
    data_owner_process = subprocess.Popen(["python", "DataOwner.py"])

    print("所有进程已启动...")

    # 等待进程完成
    server1_process.wait()
    server2_process.wait()
    client_process.wait()
    data_owner_process.wait()

if __name__ == "__main__":
    main()