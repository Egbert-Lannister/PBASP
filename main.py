import subprocess
import time

from utils import delete_lock_files

def main():
    # 注册并删除已有的锁文件，同时注册退出时的清理操作
    delete_lock_files()

    # 启动 CloudServer_1
    server1_process = subprocess.Popen(["python", "CloudServer_1.py"])
    # 启动 CloudServer_2
    server2_process = subprocess.Popen(["python", "CloudServer_2.py"])
    # 启动 Client
    client_process = subprocess.Popen(["python", "Client.py"])
    # 启动 DataOwner
    data_owner_process = subprocess.Popen(["python", "DataOwner.py"])

    print("所有进程已启动...")

    try:
        # 等待所有子进程完成
        server1_process.wait()
        server2_process.wait()
        client_process.wait()
        data_owner_process.wait()
    except KeyboardInterrupt:
        print("检测到中断，正在终止子进程...")
        server1_process.terminate()
        server2_process.terminate()
        client_process.terminate()
        data_owner_process.terminate()
    finally:
        # 删除所有 .lock 文件
        delete_lock_files()
        print("程序运行结束，所有文件锁已删除")

if __name__ == "__main__":
    main()
