import time
import redis


def wait_for_redis_events(r, channels, expected_message=None, timeout=None, poll_interval=0.1):
    """
    同时等待多个 Redis 频道上发布的消息。
    参数:
      r: Redis 连接对象
      channels: 要订阅的多个频道（列表），例如 ["lock1", "lock2"]
      expected_message: 期望的消息内容（字符串），默认为 None（收到任意消息均可）
      timeout: 超时时间（秒），默认为 None（无限等待）
      poll_interval: 轮询间隔，单位秒，默认为 0.1 秒

    返回:
      一个字典，键为频道名称，值为对应接收到的消息内容
      当所有频道都收到预期消息后，返回该字典。

    抛出:
      TimeoutError 如果超过指定超时时间仍有频道未收到预期消息。
    """
    pubsub = r.pubsub()
    pubsub.subscribe(channels)
    print(f"订阅频道 {channels}，等待消息...")
    start_time = time.time()
    # 记录每个频道是否已经收到预期消息
    received = {channel: None for channel in channels}
    try:
        while True:
            message = pubsub.get_message()
            if message:
                # 只处理实际消息，不处理订阅确认消息等
                if message['type'] == 'message':
                    channel = message['channel']
                    if isinstance(channel, bytes):
                        channel = channel.decode('utf-8')
                    try:
                        data = message['data']
                        if isinstance(data, bytes):
                            data = data.decode('utf-8')
                    except Exception as e:
                        print("消息解码错误:", e)
                        data = str(message['data'])
                    print(f"频道 {channel} 收到消息：{data}")
                    # 如果 expected_message 为 None 或者消息与期望一致，则记录
                    if expected_message is None or data == expected_message:
                        received[channel] = data
            # 判断是否所有频道都已经收到消息
            if all(received[channel] is not None for channel in channels):
                return received
            if timeout is not None and (time.time() - start_time) > timeout:
                raise TimeoutError(f"等待频道 {channels} 消息超时，超过 {timeout} 秒")
            time.sleep(poll_interval)
    finally:
        pubsub.unsubscribe(channels)
        pubsub.close()


def publish_redis_event(r, channel, message="done"):
    """
    在指定频道发布消息。
    参数:
      r: Redis 连接对象
      channel: 频道名称（字符串）
      message: 要发布的消息内容，默认为 "done"
    """
    r.publish(channel, message)
    print(f"在频道 {channel} 发布消息: {message}")


# 示例：同时监听 "lock1" 和 "lock2" 两个频道
if __name__ == "__main__":
    r = redis.Redis(host='localhost', port=6379, db=0)
    try:
        result = wait_for_redis_events(r, ["lock1", "lock2"], expected_message="done", timeout=10)
        print("所有频道均已收到预期消息：", result)
    except TimeoutError as e:
        print(e)
