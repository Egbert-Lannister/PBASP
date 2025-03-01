import numpy as np
from hilbert import encode, decode # pip install numpy-hilbert-curve
# 如果需要解码，可以使用 decode 函数将希尔伯特数值还原为经纬度


# 建立关键字对象索引





# 建立位置对象索引

def lat_lon_to_hilbert_to_6bit_binary(lat, lon):
    """
    将经纬度转换为希尔伯特曲线上的数值

    参数：
    - lat: 纬度，浮点数
    - lon: 经度，浮点数
    - num_bits: 希尔伯特曲线的精度（位数），默认 16 位

    返回：
    - 希尔伯特曲线上的数值
    """

    # 定义希尔伯特曲线的参数
    n_dimensions = 2  # 二维空间（纬度和经度）
    n_bits = 16  # 选择合适的位数，决定了分辨率

    # 归一化到 [0, 1]
    normalized_latitude = (latitude + 90) / 180
    normalized_longitude = (longitude + 180) / 360



    # 使用希尔伯特曲线编码
    point = np.array([[lon, lat]])
    hilbert_value = encode(point, num_dims=2, num_bits=3)
    return hilbert_value

# 定义多维空间中的点
points = np.array([3, 6])

# 定义维度和位数
n_dimensions = 2
n_bits = 3

# 编码为希尔伯特整数
hilbert_integers = encode(points, n_dimensions, n_bits)
print("编码后的希尔伯特整数:", hilbert_integers)

points = decode(hilbert_integers, n_dimensions, n_bits)
print("解码后的多维空间点:", points)


# 示例经纬度
latitude = 34.0522  # 示例纬度（洛杉矶）
longitude = -118.2437  # 示例经度（洛杉矶）

# 转换为希尔伯特数值



def hilbert_to_6bit_binary(hilbert_value):
    """
    将希尔伯特数值转换为6位二进制数。

    参数：
    - hilbert_value: 希尔伯特曲线数值

    返回：
    - 6位二进制字符串
    """
    binary_str = bin(hilbert_value)[2:]  # 去掉前缀 '0b'
    # 确保为6位，不足补0，超出则截断
    binary_6bit = binary_str[-6:].zfill(6)
    return binary_6bit


# 示例希尔伯特数值
hilbert_value = 5  # 假设的希尔伯特数值

# 转换为6位二进制数
binary_result = hilbert_to_6bit_binary(hilbert_value)
print(f"6位二进制数: {binary_result}")



