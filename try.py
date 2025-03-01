class BitMap:
    def __init__(self, size):
        """初始化位图，指定位图的大小"""
        self.size = size
        # 计算需要多少个整数来存储所有位
        self.bits_per_int = 32  # 假设每个整数是32位
        self.int_size = (size + self.bits_per_int - 1) // self.bits_per_int
        # 初始化为0
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
        return "".join(result[::-1])  # 反转以匹配二进制的高位在前

# 示例使用
if __name__ == "__main__":
    # 创建一个大小为10的位图
    bitmap = BitMap(10)

    # 设置第5位为1
    bitmap.set_bit(5)
    print(f"位图状态: {bitmap}")  # 输出: 0000001000

    # 检查第5位是否为1
    print(f"第5位是否为1: {bitmap.check_bit(5)}")  # 输出: True

    # 清除第5位
    bitmap.clear_bit(5)
    print(f"位图状态: {bitmap}")  # 输出: 0000000000

    # 尝试设置一个无效位
    try:
        bitmap.set_bit(15)
    except IndexError as e:
        print(e)  # 输出: 位索引超出范围