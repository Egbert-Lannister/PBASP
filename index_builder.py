import numpy as np
from hilbert import encode, decode # pip install numpy-hilbert-curve
from BitMap import BitMap
import sqlite3

# 读取数据库数据

# 数据库路径
db_path = 'data_object_2000_keyword_100.db'

# 连接到数据库
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# 查询数据
cursor.execute("SELECT * FROM business_table")
rows = cursor.fetchall()

# 分离 business_id 和 keywords
business_ids = [row[0] for row in rows]
keywords_list = [set(row[3].split(', ')) for row in rows]

# 建立关键字对象索引

keyword_index = {}

for row in rows:
    keyword_index[row[3]] = BitMap(2000)


for row in rows:

    # 关键字进组
    keywords = row[3].split(',')
    for keyword in keywords:
        if keyword in keywords_list:
            index = keywords_list.index(keyword)
            # 找到相应关键字之后，将该关键字位图的对象相应位置设置为 1
            keyword_index[keyword].set_bit(row)


        else:
            keywords_list.append(keyword)



    print(f"business_id: {row[0]}, keywords: {row[3]}")




bm = BitMap(10)

# 设置某些位
bm.set_bit(0)
bm.set_bit(3)
bm.set_bit(7)

# 清除某些位
bm.clear_bit(3)

# 检查某一位是否为1
print("位 0 是否为1?", bm.check_bit(0))  # True
print("位 3 是否为1?", bm.check_bit(3))  # False
print("位 7 是否为1?", bm.check_bit(7))  # True

# 输出位图的二进制表示
print("位图的二进制表示:", bm)  # 输出类似 "00000001 00000100 00000000 ..."

# 创建另一个位图
bm2 = BitMap(10)
bm2.set_bit(1)
bm2.set_bit(5)
bm2.set_bit(7)

# 执行逻辑运算
bm_and = bm.and_operation(bm2)  # AND 运算
bm_or = bm.or_operation(bm2)    # OR 运算
bm_xor = bm.xor_operation(bm2)  # XOR 运算

# 输出结果
print("AND 运算结果:", bm_and)
print("OR 运算结果:", bm_or)
print("XOR 运算结果:", bm_xor)





# 建立位置对象索引

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







