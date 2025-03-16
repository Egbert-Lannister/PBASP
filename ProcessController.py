import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# 自定义事件处理器，当目标文件创建时触发回调，设置事件对象
class LockFileEventHandler(FileSystemEventHandler):
    def __init__(self, lock_file, event):
        super().__init__()
        self.lock_file = lock_file
        self.event = event

    def on_created(self, event):
        # 判断创建的文件是否是目标锁文件
        if event.src_path.endswith(self.lock_file):
            print(f"检测到 {self.lock_file} 文件已创建")
            self.event.set()  # 设置事件，解除阻塞


def wait_for_lock(lock_file, watch_directory="."):
    # 创建事件对象，用于阻塞等待
    file_created_event = threading.Event()

    # 设置文件系统事件处理器
    event_handler = LockFileEventHandler(lock_file, file_created_event)
    observer = Observer()
    observer.schedule(event_handler, path=watch_directory, recursive=False)

    observer.start()
    print(f"开始监听 {lock_file} 文件的创建...")

    # 阻塞等待直到事件被设置
    file_created_event.wait()

    # 检测到文件创建后，停止观察者并继续后续逻辑
    observer.stop()
    observer.join()
    print(f"{lock_file} 文件已创建，继续后续处理。")


if __name__ == "__main__":
    # 使用示例：替换原来的轮询等待代码
    wait_for_lock("dataowner_done.lock")
    # 后续处理代码在此处执行
    print("执行后续操作...")
