import random


class BitMap:
    def __init__(self, size=0, capacity=None):
        """初始化位图，可指定初始大小，默认为0；同时可指定位图代表的对象总数 capacity，默认为 size"""
        self.size = size
        self.bits_per_int = 32  # 假设每个整数是32位
        self.int_size = (size + self.bits_per_int - 1) // self.bits_per_int
        self.arr = [0] * self.int_size if self.int_size > 0 else []
        # 新增 capacity 属性
        self.capacity = capacity if capacity is not None else size

    def set_bit(self, bit_index):
        """设置指定位为1，必要时扩展位图"""
        if bit_index < 0:
            raise IndexError("位索引不能为负数")
        if bit_index >= self.size:
            # 扩展位图
            new_size = bit_index + 1
            new_int_size = (new_size + self.bits_per_int - 1) // self.bits_per_int
            needed_ints = new_int_size - self.int_size
            if needed_ints > 0:
                self.arr.extend([0] * needed_ints)
            self.size = new_size
            self.int_size = new_int_size
        integer_index = bit_index // self.bits_per_int
        bit_offset = bit_index % self.bits_per_int
        self.arr[integer_index] |= (1 << bit_offset)
        # 如果设置位后 size 超过了原来的 capacity，则同步更新 capacity
        if self.size > self.capacity:
            self.capacity = self.size

    def clear_bit(self, bit_index):
        """清除指定位（设置为0），不扩展位图"""
        if bit_index < 0 or bit_index >= self.size:
            return
        integer_index = bit_index // self.bits_per_int
        bit_offset = bit_index % self.bits_per_int
        self.arr[integer_index] &= ~(1 << bit_offset)

    def check_bit(self, bit_index):
        """检查指定位是否为1，超出当前大小返回False"""
        if bit_index < 0 or bit_index >= self.size:
            return False
        integer_index = bit_index // self.bits_per_int
        bit_offset = bit_index % self.bits_per_int
        return (self.arr[integer_index] & (1 << bit_offset)) != 0

    def __str__(self):
        """返回位图的字符串表示（仅包含实际有效位，不输出 capacity 后的0）"""
        result = []
        for i in range(self.size):
            result.append('1' if self.check_bit(i) else '0')
        return ''.join(result)

    def get_set_bits(self):
        """返回所有值为1的位的索引"""
        return [i for i in range(self.size) if self.check_bit(i)]

    def copy(self):
        """创建位图的深拷贝"""
        new_bm = BitMap()
        new_bm.size = self.size
        new_bm.int_size = self.int_size
        new_bm.arr = list(self.arr)  # 复制数组
        new_bm.capacity = self.capacity  # 复制 capacity
        return new_bm

    def trim(self):
        """去除末尾多余的零，更新size和arr"""
        max_set = -1
        # 从最高位开始找第一个1
        for i in range(self.size - 1, -1, -1):
            if self.check_bit(i):
                max_set = i
                break

        new_size = max_set + 1 if max_set != -1 else 0
        new_int_size = (new_size + self.bits_per_int - 1) // self.bits_per_int

        # 需要处理两种情况：
        # 1. 原arr长度大于new_int_size时需要截断
        # 2. 全零时需要清空arr
        if new_int_size < len(self.arr):
            self.arr = self.arr[:new_int_size]

        self.size = new_size
        self.int_size = new_int_size
        # trim 不改变 capacity，因为 capacity 表示实际对象总数

    @staticmethod
    def from_string(bit_str, capacity=None):
        """
        根据位图的字符串表示（如 "100000001"）创建一个 BitMap 对象
        如果指定了 capacity，则使用该值，否则默认 capacity 为 bit_str 的长度
        """
        bm = BitMap(len(bit_str), capacity if capacity is not None else len(bit_str))
        for idx, ch in enumerate(bit_str):
            if ch == "1":
                bm.set_bit(idx)
        return bm

    @staticmethod
    def logical_operation(bitmap1, bitmap2, operator):
        """对两个位图执行逻辑运算，自动处理不同长度"""
        max_size = max(bitmap1.size, bitmap2.size)
        # 结果位图的 capacity 取两个位图中较大的 capacity
        result = BitMap(max_size, max(bitmap1.capacity, bitmap2.capacity))
        for i in range(max_size):
            bit1 = bitmap1.check_bit(i) if i < bitmap1.size else False
            bit2 = bitmap2.check_bit(i) if i < bitmap2.size else False
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
        result.trim()  # 新增此行
        return result

    @staticmethod
    def bitmaps_logical_operation(bitmaps, operation):
        """
        对列表中的所有位图进行指定的逻辑操作（AND 或 OR），返回结果位图。

        :param bitmaps: 包含多个 BitMap 对象的列表
        :param operation: 指定的逻辑操作，可以是 "AND" 或 "OR"
        :return: 一个 BitMap 对象，表示逻辑操作的结果
        """
        if not bitmaps:
            raise ValueError("位图列表为空，无法进行逻辑运算")

        if operation == "AND":
            # AND操作初始应为全1，但动态位图无法确定初始范围
            # 采用渐进式AND
            result = bitmaps[0].copy()
            for bm in bitmaps[1:]:
                result = result.and_operation(bm)
                result.trim()
            return result

        elif operation == "OR":
            # OR操作初始应为空
            result = BitMap()
            for bm in bitmaps:
                result = result.or_operation(bm)
                result.trim()
            return result

        else:
            raise ValueError("不支持的逻辑操作")

    def and_operation(self, other):
        """与运算"""
        return BitMap.logical_operation(self, other, "AND")

    def or_operation(self, other):
        """或运算"""
        return BitMap.logical_operation(self, other, "OR")

    def xor_operation(self, other):
        """异或运算"""
        return BitMap.logical_operation(self, other, "XOR")

    def bitmap_or_separation(self):
        """
        将给定的位图随机分成两个位图，
        要求两个分离后的位图经过逻辑 OR 运算后能够得到原来的位图。

        思路：
        - 对于原位图中每一位：
            - 如果位为 0，则两个子位图该位均为 0；
            - 如果位为 1，则随机选择以下三种方案之一：
                1. 只在第一个位图中置 1；
                2. 只在第二个位图中置 1；
                3. 两个位图均置 1。
        """
        bmp1 = BitMap()
        bmp2 = BitMap()
        for i in range(self.size):
            if self.check_bit(i):
                choice = random.choice([1, 2, 3])
                if choice == 1:
                    bmp1.set_bit(i)
                elif choice == 2:
                    bmp2.set_bit(i)
                else:
                    bmp1.set_bit(i)
                    bmp2.set_bit(i)
        return bmp1, bmp2

    def add_object(self, has_keyword=False):
        """
        在位图中添加一个新对象：
        - 将位图所代表的对象总数 capacity 增加1；
        - 如果该对象具备关键字（has_keyword 为 True），则在对应位置置1，
          同时更新有效位（size）；如果不具备关键字，则不改变已有有效位，
          __str__ 方法输出时不会包含后面无意义的0。
        """
        new_index = self.capacity  # 新对象索引为当前 capacity
        self.capacity += 1
        if has_keyword:
            self.set_bit(new_index)
        # 如果对象不具有关键字，则不调用 set_bit，
        # 这样 self.size 保持不变，__str__ 输出也只显示有效位


# --------------------- 示例调用 ---------------------
if __name__ == "__main__":

    bmp = BitMap(capacity=9)
    print(f"初始位图: {bmp}")  # 输出：000000000
    bmp.set_bit(0)
    print(f"设置位 0 后: {bmp}")  # 输出：100000000
    bmp.set_bit(8)
    print(f"设置位 8 后: {bmp}")  # 输出：100000001

    bmp1, bmp2 = bmp.bitmap_or_separation()
    print(f"分离后的位图1: {bmp1}")
    print(f"分离后的位图2: {bmp2}")

    # 检查 OR 运算是否还原原始位图
    bmp_restored = bmp1.or_operation(bmp2)
    print(f"OR 之后的位图: {bmp_restored}")

    restored = bmp1.or_operation(bmp2)
    print(f"OR还原后: {restored}")

    # 测试不同长度位图的逻辑运算
    bm1 = BitMap.from_string("110", capacity=5)
    bm2 = BitMap.from_string("10101", capacity=5)
    or_result = bm1.or_operation(bm2)
    print(f"OR结果: {or_result}")  # 应输出 11101

    bm3 = BitMap.from_string("10001010", capacity=9)
    bm4 = BitMap.from_string("101001010", capacity=9)
    and_result = bm3.and_operation(bm4)
    print(f"AND结果：: {and_result}")

    print("\n测试自动trim功能:")
    bm1 = BitMap.from_string("10100000", capacity=8)  # 原 size=8
    bm1.trim()
    print(f"trim后: {bm1} 长度: {bm1.size}")  # 应输出 101，长度 3

    bm2 = BitMap.from_string("00100000", capacity=8)  # trim 后应为 001，长度 3
    xor_res = bm1.xor_operation(bm2)
    print(f"异或结果: {xor_res} 长度: {xor_res.size}")  # 应输出 100，长度 3

    # 测试逻辑操作
    print("\n测试多个位图的OR操作:")
    bm_list = [
        BitMap.from_string("1001", capacity=6),
        BitMap.from_string("1010", capacity=6),
        BitMap.from_string("100000", capacity=6)
    ]
    or_result = BitMap.bitmaps_logical_operation(bm_list, "OR")
    print(f"OR结果: {or_result} 长度: {or_result.size}")  # 应输出 111001（长度6）

    print("\n测试多个位图的AND操作:")
    bm_list = [
        BitMap.from_string("111100", capacity=6),
        BitMap.from_string("110011", capacity=6),
        BitMap.from_string("110000", capacity=6)
    ]
    and_result = BitMap.bitmaps_logical_operation(bm_list, "AND")
    print(f"AND结果: {and_result} 长度: {and_result.size}")  # 应输出 11（长度6）

    print("\n测试全零情况:")
    bm_list = [
        BitMap.from_string("0000", capacity=4),
        BitMap.from_string("0000", capacity=4)
    ]
    zero_result = BitMap.bitmaps_logical_operation(bm_list, "AND")
    print(f"全零结果: {zero_result} 长度: {zero_result.size}")  # 应输出空（长度0）

    print("\n测试自动trim功能:")
    bm1 = BitMap.from_string("10000000", capacity=8)
    bm2 = BitMap.from_string("00100000", capacity=8)
    xor_res = bm1.xor_operation(bm2)
    print(f"异或结果: {xor_res} 长度: {xor_res.size}")  # 应输出 10100000 → trim 后 101（长度3）

    # 测试新增的 add_object 方法
    print("\n测试新增对象操作:")
    bm = BitMap.from_string("101", capacity=5)
    print(f"初始位图: {bm}, capacity: {bm.capacity}")  # 应输出 101, capacity=5
    bm.add_object(has_keyword=True)  # 添加对象，且具备关键字
    print(f"添加对象后: {bm}, capacity: {bm.capacity}")  # 应输出 101001, capacity=6
    bm.add_object(has_keyword=False)  # 添加对象，不具备关键字
    print(f"再添加对象后: {bm}, capacity: {bm.capacity}")  # 应输出仍为 101001, capacity=7
