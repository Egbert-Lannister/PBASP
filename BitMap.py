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

    def and_operation(self, other):
        """与运算"""
        return BitMap.logical_operation(self, other, "AND")

    def or_operation(self, other):
        """或运算"""
        return BitMap.logical_operation(self, other, "OR")

    def xor_operation(self, other):
        """异或运算"""
        return BitMap.logical_operation(self, other, "XOR")


bmp = BitMap(9)
print(f"初始位图: {bmp}")  # 输出：000000000
bmp.set_bit(0)
print(f"设置位 0 后: {bmp}")  # 输出：100000000
bmp.set_bit(8)
print(f"设置位 8 后: {bmp}")  # 输出：100000001