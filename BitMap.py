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

