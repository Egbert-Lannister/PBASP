import numpy as np
from hilbert import encode, decode # pip install numpy-hilbert-curve
from BitMap import BitMap
import sqlite3

# 读取数据库数据
db_path = 'data_object_2000_keyword_100.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# 查询数据
cursor.execute("SELECT * FROM business_table")
rows = cursor.fetchall()


# 建立位置对象索引

position_index = {}

def lat_lon_to_hilbert_to_64bit_binary(latitude, longitude):
    """
    将经纬度转换为希尔伯特曲线上的数值，之后再转化位64位的二进制字符串

    参数：
    - latitude: 纬度，浮点数
    - longitude: 经度，浮点数

    返回：
    - 64位的二进制字符串
    """

    # 定义希尔伯特曲线的参数
    n_dimensions = 2  # 二维空间（纬度和经度）
    n_bits = 16  # 选择合适的位数，决定了分辨率

    # 归一化到 [0, 1]
    normalized_latitude = (latitude + 90) / 180
    normalized_longitude = (longitude + 180) / 360

    # 缩放到 [0, 2^n_bits - 1]
    max_value = 2 ** n_bits - 1
    scaled_latitude = int(normalized_latitude * max_value)
    scaled_longitude = int(normalized_longitude * max_value)

    # 转换为 NumPy 数组
    points = np.array([scaled_latitude, scaled_longitude])

    # 编码为希尔伯特整数
    hilbert_integer = encode(points, n_dimensions, n_bits)
    print("希尔伯特整数:", hilbert_integer)

    # 解码回地理坐标（可选）
    decoded_points = decode(hilbert_integer, n_dimensions, n_bits)
    decoded_latitude = (decoded_points[0][0] / max_value) * 180 - 90
    decoded_longitude = (decoded_points[0][1] / max_value) * 360 - 180
    print("解码后的地理坐标:", (decoded_latitude, decoded_longitude))

    # 将希尔伯特整数转化为64位的二进制数
    binary_str = bin(hilbert_integer)[2:]  # 去掉前缀 '0b'
    # 确保为64位，不足补0，超出则截断
    binary_64bit = binary_str[-64:].zfill(64)
    return binary_64bit

def get_prefix_codes(bit_str):
    """
    根据输入的二进制字符串生成前缀码列表。

    例如，对于 "011001" 会生成：
      011001
      01100*
      0110**
      011***
      01****
      0*****

    参数:
    - bit_str: 输入的二进制字符串

    返回:
    - 前缀码列表，每个元素是一个字符串
    """
    prefix_codes = []
    n = len(bit_str)
    for i in range(n):
        # 保留前面的 (n-i) 位，后面补上 i 个 '*' 作为通配符
        prefix = bit_str[:n - i]
        suffix = '*' * i
        prefix_codes.append(prefix + suffix)
    return prefix_codes

prefix_codes_list = []

# 字典建好键值
for row in rows:
    latitude = row[1]
    longitude = row[2]
    print(latitude, longitude)
    prefix_codes = get_prefix_codes(lat_lon_to_hilbert_to_64bit_binary(latitude, longitude))
    for prefix_code in prefix_codes:
        if prefix_code in prefix_codes_list:
            continue
        else:
            prefix_codes_list.append(prefix_code)
            position_index[prefix_code] = BitMap(2000)

# 遍历每一行数据
for i, row in enumerate(rows):
    latitude = row[1]
    longitude = row[2]
    prefix_codes = get_prefix_codes(lat_lon_to_hilbert_to_64bit_binary(latitude, longitude))
    for prefix_code in prefix_codes:
        position_index[prefix_code].set_bit(i)


print(position_index)
print(len(position_index))


# 关闭数据库连接
conn.close()
