import subprocess
import time

def start_redis():
    try:
        # 启动 Redis 服务器（假设 redis-server 可执行文件在 PATH 中，
        # 如果有配置文件，则可以指定，如 ["redis-server", "redis.conf"]）
        redis_process = subprocess.Popen(["redis-server"])
        # 等待几秒让 Redis 服务器启动
        time.sleep(2)
        print("Redis server started.")
        return redis_process
    except Exception as e:
        print("Error starting Redis server:", e)
        return None

def main():
    # 启动 Redis 服务器
    redis_process = start_redis()

    # 启动 CloudServer_1
    server1_process = subprocess.Popen(["python", "CloudServer_1.py"])
    # 启动 CloudServer_2
    server2_process = subprocess.Popen(["python", "CloudServer_2.py"])
    # 启动 DataOwner
    data_owner_process = subprocess.Popen(["python", "DataOwner.py"])
    # 启动 Client
    client_process = subprocess.Popen(["python", "Client.py"])

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
        # 结束 Redis 服务器进程
        if redis_process:
            redis_process.terminate()
            print("Redis server terminated.")

if __name__ == "__main__":
    main()
