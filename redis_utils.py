import time
import redis


def wait_for_redis_events(r, channels, expected_message=None, timeout=None, poll_interval=0.1):
    """
    同时等待多个 Redis 频道上发布的消息，同时检查持久化状态键以规避竞态条件。

    参数:
      r: Redis 连接对象
      channels: 要订阅的多个频道（列表），例如 ["lock1", "lock2"]
      expected_message: 期望的消息内容（字符串），默认为 None（收到任意消息均可）
      timeout: 超时时间（秒），默认为 None（无限等待）
      poll_interval: 轮询间隔，单位秒，默认为 0.1 秒

    返回:
      一个字典，键为频道名称，值为对应接收到的消息内容；
      当所有频道都收到预期消息或在持久化状态中检测到该消息后，返回该字典。

    抛出:
      TimeoutError 如果超过指定超时时间仍有频道未收到预期消息。
    """
    # 先检查每个频道对应的持久化状态键（例如 "event:lock1"）
    received = {}
    for channel in channels:
        key = f"event:{channel}"
        status = r.get(key)
        if status:
            try:
                status = status.decode('utf-8')
            except Exception:
                status = str(status)
        # 如果状态存在且符合预期，则认为该频道已经收到事件
        if status and (expected_message is None or status == expected_message):
            received[channel] = status
        else:
            received[channel] = None

    # 如果所有频道都已检测到状态，则无需订阅直接返回
    if all(received[channel] is not None for channel in channels):
        return received

    # 开始订阅频道，等待实时消息
    pubsub = r.pubsub()
    pubsub.subscribe(channels)
    print(f"订阅频道 {channels}，等待消息...")
    start_time = time.time()
    try:
        while True:
            message = pubsub.get_message()
            if message:
                # 只处理实际消息，不处理订阅确认等消息
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
                    if expected_message is None or data == expected_message:
                        received[channel] = data
            # 如果所有频道都收到消息，则返回
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
    发布消息时，同时设置一个持久化状态键，确保即使订阅者还未启动，
    也可以通过检查状态键获知该事件已经发生。

    参数:
      r: Redis 连接对象
      channel: 频道名称（字符串）
      message: 要发布的消息内容，默认为 "done"
    """
    key = f"event:{channel}"
    # 先设置持久化状态键
    r.set(key, message)
    # 再通过 Pub/Sub 发布消息
    r.publish(channel, message)
    print(f"在频道 {channel} 发布消息: {message}")


# 示例：同时监听 "lock1" 和 "lock2" 两个频道
if __name__ == "__main__":
    r = redis.Redis(host='localhost', port=6379, db=0)
    try:
        # 模拟在其他进程中先发布事件
        publish_redis_event(r, "lock1", "done")
        publish_redis_event(r, "lock2", "done")

        # 再调用等待函数，此时即使订阅晚了，也能从持久化键中获取状态
        result = wait_for_redis_events(r, ["lock1", "lock2"], expected_message="done", timeout=10)
        print("所有频道均已收到预期消息：", result)
    except TimeoutError as e:
        print(e)
