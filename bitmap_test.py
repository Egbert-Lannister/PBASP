import random


class BitMap:
    def __init__(self, capacity=0):
        """
        初始化位图
        :param capacity: 位图需要表示的实际对象数量（规范长度）
        """
        self.capacity = capacity  # 规范的对象数量
        self.bits_per_int = 32
        self.int_size = (capacity + self.bits_per_int - 1) // self.bits_per_int
        self.arr = [0] * self.int_size if self.int_size > 0 else []

        # 实际存储的有效位长度（自动计算）
        self._effective_size = 0

    def _update_effective_size(self):
        """更新有效位长度（最右边的1的位置）"""
        max_bit = -1
        for i in range(min(self.capacity - 1, len(self.arr) * self.bits_per_int - 1), -1, -1):
            if self.check_bit(i):
                max_bit = i
                break
        self._effective_size = max_bit + 1 if max_bit != -1 else 0

    @property
    def effective_size(self):
        """获取有效位长度（自动计算）"""
        self._update_effective_size()
        return self._effective_size

    def set_capacity(self, new_capacity):
        """调整规范容量"""
        if new_capacity < self.capacity:
            # 缩小容量时需要截断
            self.capacity = new_capacity
            self.int_size = (new_capacity + self.bits_per_int - 1) // self.bits_per_int
            self.arr = self.arr[:self.int_size]
        else:
            # 扩展容量
            old_capacity = self.capacity
            self.capacity = new_capacity
            new_int_size = (new_capacity + self.bits_per_int - 1) // self.bits_per_int
            if new_int_size > len(self.arr):
                self.arr += [0] * (new_int_size - len(self.arr))
            self.int_size = new_int_size

    def add_object(self, has_property):
        """
        添加一个新对象到容量末尾
        :param has_property: 该对象是否具有属性
        """
        # 扩展容量
        new_capacity = self.capacity + 1
        self.set_capacity(new_capacity)

        if has_property:
            self.set_bit(self.capacity - 1)  # 设置最后一位

    def set_bit(self, bit_index):
        """设置指定位，不超过当前容量"""
        if bit_index >= self.capacity or bit_index < 0:
            raise IndexError(f"位索引超出容量范围 [0, {self.capacity - 1}]")

        integer_index = bit_index // self.bits_per_int
        bit_offset = bit_index % self.bits_per_int
        self.arr[integer_index] |= (1 << bit_offset)

    def check_bit(self, bit_index):
        """检查指定位"""
        if bit_index >= self.capacity or bit_index < 0:
            return False
        integer_index = bit_index // self.bits_per_int
        bit_offset = bit_index % self.bits_per_int
        return (self.arr[integer_index] & (1 << bit_offset)) != 0

    def __str__(self):
        """显示到当前容量"""
        return ''.join('1' if self.check_bit(i) else '0' for i in range(self.capacity))

    # 其他方法需要调整使用capacity代替size的地方...
    # 以下是需要修改的逻辑操作方法示例
    @staticmethod
    def logical_operation(bitmap1, bitmap2, operator):
        """逻辑运算需要处理capacity"""
        max_capacity = max(bitmap1.capacity, bitmap2.capacity)
        result = BitMap(max_capacity)

        for i in range(max_capacity):
            bit1 = bitmap1.check_bit(i) if i < bitmap1.capacity else False
            bit2 = bitmap2.check_bit(i) if i < bitmap2.capacity else False

            if operator == "AND":
                res_bit = bit1 and bit2
            elif operator == "OR":
                res_bit = bit1 or bit2
            elif operator == "XOR":
                res_bit = bit1 != bit2
            else:
                raise ValueError(f"不支持的运算符: {operator}")

            if res_bit:
                result.set_bit(i)
        return result

    def bitmap_or_separation(self):
        """分离时需要保持capacity"""
        bmp1 = BitMap(self.capacity)
        bmp2 = BitMap(self.capacity)
        for i in range(self.capacity):
            if self.check_bit(i):
        # ...原有随机分配逻辑...
        return bmp1, bmp2


# 测试用例
if __name__ == "__main__":
    # 测试添加对象
    print("测试添加对象:")
    bm = BitMap(capacity=3)  # 初始容量3
    bm.set_bit(0)
    bm.set_bit(2)
    print(f"初始: {bm} (capacity={bm.capacity})")  # 100

    # 添加第四个对象（索引3）
    bm.add_object(has_property=True)
    print(f"添加后: {bm} (capacity={bm.capacity})")  # 1001

    # 添加第五个对象（索引4），无属性
    bm.add_object(has_property=False)
    print(f"继续添加: {bm} (capacity={bm.capacity})")  # 10010

    # 测试逻辑运算保持capacity
    print("\n测试逻辑运算:")
    bm1 = BitMap.from_string("101")
    bm1.set_capacity(5)  # 强制容量为5 → "10100"
    bm2 = BitMap.from_string("1100")
    bm2.set_capacity(4)

    or_result = bm1.or_operation(bm2)
    print(f"OR结果: {or_result} (capacity={or_result.capacity})")  # 11100 capacity=5