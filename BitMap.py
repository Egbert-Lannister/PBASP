import random


class BitMap:
    def __init__(self, size):
        """初始化位图，指定位图的大小"""
        self.size = size
        self.bits_per_int = 32  # 假设每个整数是32位
        self.int_size = (size + self.bits_per_int - 1) // self.bits_per_int
        self.arr = [0] * self.int_size

    def get_index(self, bit_index):
        """获取存储该位的整数索引和位偏移"""
        if bit_index >= self.size or bit_index < 0:
            raise IndexError("位索引超出范围")
        integer_index = bit_index // self.bits_per_int
        bit_offset = bit_index % self.bits_per_int
        return integer_index, bit_offset

    def set_bit(self, bit_index):
        """设置指定位为1"""
        integer_index, bit_offset = self.get_index(bit_index)
        self.arr[integer_index] |= (1 << bit_offset)

    def clear_bit(self, bit_index):
        """清除指定位（设置为0）"""
        integer_index, bit_offset = self.get_index(bit_index)
        self.arr[integer_index] &= ~(1 << bit_offset)

    def check_bit(self, bit_index):
        """检查指定位是否为1"""
        integer_index, bit_offset = self.get_index(bit_index)
        return (self.arr[integer_index] & (1 << bit_offset)) != 0

    def __str__(self):
        """返回位图的字符串表示"""
        result = []
        for i in range(self.size):
            result.append(str(int(self.check_bit(i))))
        return "".join(result)  # 反转以匹配二进制的高位在前

    def get_set_bits(self):
        """返回位图中所有值为1的位的索引"""
        set_bits = []
        for i in range(self.size):
            if self.check_bit(i):
                set_bits.append(i)
        return set_bits

    @staticmethod
    def from_string(bit_str):
        """
        根据位图的字符串表示（如 "100000001"）创建一个 BitMap 对象
        """
        bm = BitMap(len(bit_str))
        for idx, ch in enumerate(bit_str):
            if ch == "1":
                bm.set_bit(idx)
        return bm

    @staticmethod
    def logical_operation(bitmap1, bitmap2, operator):
        """
        对两个位图执行逻辑运算
        :param bitmap1: 第一个位图
        :param bitmap2: 第二个位图
        :param operator: 运算符 ("AND", "OR", "XOR")
        :return: 新的位图
        """
        if bitmap1.size != bitmap2.size:
            raise ValueError("位图大小不一致，无法进行逻辑运算")

        result = BitMap(bitmap1.size)
        op = None
        if operator == "AND":
            op = lambda a, b: a & b
        elif operator == "OR":
            op = lambda a, b: a | b
        elif operator == "XOR":
            op = lambda a, b: a ^ b
        else:
            raise ValueError("不支持的运算符")

        # 遍历每个整数的位置，进行逻辑运算
        for i in range(bitmap1.int_size):
            result.arr[i] = op(bitmap1.arr[i], bitmap2.arr[i])

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

        # 获取第一个位图的大小，并检查所有位图大小是否一致
        size = bitmaps[0].size
        for bmp in bitmaps:
            if bmp.size != size:
                raise ValueError("位图大小不一致，无法进行逻辑运算")

        # 初始化结果位图
        result = BitMap(size)

        # 设置初始值为第一个位图
        result = bitmaps[0]

        # 根据指定的操作选择对应的逻辑运算方法
        if operation == "AND":
            for bmp in bitmaps[1:]:
                result = result.and_operation(bmp)
        elif operation == "OR":
            for bmp in bitmaps[1:]:
                result = result.or_operation(bmp)
        else:
            raise ValueError("不支持的逻辑操作，仅支持 'AND' 或 'OR'")

        return result

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
        bmp1 = BitMap(self.size)
        bmp2 = BitMap(self.size)
        for i in range(self.size):
            if self.check_bit(i):
                # 随机选择分配方案
                choice = random.choice([1, 2, 3])
                if choice == 1:
                    bmp1.set_bit(i)
                elif choice == 2:
                    bmp2.set_bit(i)
                else:  # choice == 3
                    bmp1.set_bit(i)
                    bmp2.set_bit(i)
            # 若该位为 0，则 bmp1 与 bmp2 均保持 0，无需处理
        return bmp1, bmp2


# --------------------- 示例调用 ---------------------
if __name__ == "__main__":

    bmp = BitMap(9)
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
    bm1 = BitMap.from_string("110")
    bm2 = BitMap.from_string("10101")
    or_result = bm1.or_operation(bm2)
    print(f"OR结果: {or_result}")  # 应输出11101

    bm3 = BitMap.from_string("10001010")
    bm4 = BitMap.from_string("101001010")
    and_result = bm3.and_operation(bm4)
    print(f"AND结果：: {and_result}")

    print("\n测试自动trim功能:")
    bm1 = BitMap.from_string("10100000")  # 原size=8
    bm1.trim()
    print(f"trim后: {bm1} 长度: {bm1.size}")  # 应输出101长度3

    bm2 = BitMap.from_string("00100000")  # trim后应为001长度3
    xor_res = bm1.xor_operation(bm2)
    print(f"异或结果: {xor_res} 长度: {xor_res.size}")  # 应输出100长度3

    # 测试逻辑操作
    print("\n测试多个位图的OR操作:")
    bm_list = [
        BitMap.from_string("1001"),
        BitMap.from_string("1010"),
        BitMap.from_string("100000")
    ]
    or_result = BitMap.bitmaps_logical_operation(bm_list, "OR")
    print(f"OR结果: {or_result} 长度: {or_result.size}")  # 应输出111001（长度6）

    print("\n测试多个位图的AND操作:")
    bm_list = [
        BitMap.from_string("111100"),
        BitMap.from_string("110011"),
        BitMap.from_string("110000")
    ]
    and_result = BitMap.bitmaps_logical_operation(bm_list, "AND")
    print(f"AND结果: {and_result} 长度: {and_result.size}")  # 应输出11（长度6）

    print("\n测试全零情况:")
    bm_list = [
        BitMap.from_string("0000"),
        BitMap.from_string("0000")
    ]
    zero_result = BitMap.bitmaps_logical_operation(bm_list, "AND")
    print(f"全零结果: {zero_result} 长度: {zero_result.size}")  # 应输出空（长度0）

    print("\n测试自动trim功能:")
    bm1 = BitMap.from_string("10000000")
    bm2 = BitMap.from_string("00100000")
    xor_res = bm1.xor_operation(bm2)
    print(f"异或结果: {xor_res} 长度: {xor_res.size}")  # 应输出10100000 → trim后101（长度3）
