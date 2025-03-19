import math
import random

import numpy as np
from hilbert import encode, decode  # pip install numpy-hilbert-curve
from BitMap import BitMap


class IndexBuilder:
    def __init__(self, rows, num_businesses=2000, n_bits=16):
        """
        初始化 IndexBuilder

        参数：
        - rows: 从数据库中读取的所有数据行，每一行应包含 business_id、纬度、经度、关键字字符串等字段
        - num_businesses: 数据集中业务（或记录）的总数，用于初始化 BitMap 的大小
        - n_bits: 用于希尔伯特曲线编码的位数，决定了经纬度转换的分辨率
        """
        self.rows = rows
        self.num_businesses = num_businesses
        self.n_bits = n_bits
        self.keyword_index = {}  # 关键字索引字典，键为关键字，值为 BitMap 对象
        self.position_index = {}  # 位置索引字典，键为前缀码，值为 BitMap 对象

    def build_bitmap_map_2_object(self):

        bitmap_map_2_object_map = []
        for row in self.rows:
            business_id = row[0]
            business_id = business_id.strip()
            bitmap_map_2_object_map.append(business_id)

        return bitmap_map_2_object_map

    def build_keyword_index(self):
        """
        构建关键字索引：
          1. 遍历所有行，提取唯一的关键字
          2. 为每个关键字创建一个 BitMap 对象
          3. 再次遍历所有行，根据行中出现的关键字设置对应 BitMap 中的位

        返回：
          关键字索引字典
        """
        keywords_list = []
        # 收集所有唯一关键字
        for row in self.rows:
            row_keywords = row[3].split(', ') if row[3] else []
            for keyword in row_keywords:
                keyword = keyword.strip()
                if keyword not in keywords_list:
                    keywords_list.append(keyword)

        # 为每个关键字创建 BitMap
        for keyword in keywords_list:
            self.keyword_index[keyword] = BitMap(capacity=self.num_businesses)

        # 遍历每一行数据，设置相应关键字的 BitMap 对应位置为1
        for i, row in enumerate(self.rows):
            row_keywords = row[3].split(', ') if row[3] else []
            for keyword in row_keywords:
                keyword = keyword.strip()
                self.keyword_index[keyword].set_bit(i)

        return self.keyword_index

    def build_update_data_index(self):

        update_data_index = {}
        for row in self.rows:
            business_id = row[0]
            business_id = business_id.strip()

            row_keywords = row[3].split(', ') if row[3] else []

            latitude = row[1]
            longitude = row[2]
            binary_str = self.lat_lon_to_hilbert_to_64bit_binary(latitude, longitude, self.n_bits)
            prefix_codes = self.get_prefix_codes(binary_str)

            update_data_index[business_id] = (row_keywords, prefix_codes)

        return update_data_index

    @staticmethod
    def query_object_prefix_codes_generation(query_prefix_code_range, n_bits=16):
        """
        根据 query_prefix_code_range（例如 0.001）生成希尔伯特值区间的二维前缀码列表。
        整个希尔伯特值空间为 2^(2*n_bits) 个整数。
        这里起始值 start 在 [0, total_space - width] 内随机选取，
        确保区间 [start, start+width-1] 不越界。

        对区间内的每个希尔伯特整数，将其转换为 total_bits 位的二进制字符串，
        然后调用 get_prefix_codes 得到该整数对应的前缀码列表。

        返回：
          一个二维列表，每个元素是一个前缀码列表，对应区间内一个希尔伯特值。
        """
        total_bits = 2 * n_bits
        total_space = 2 ** total_bits
        # 计算区间宽度（取整），至少为 1
        width = int(query_prefix_code_range * total_space)
        if width < 1:
            width = 1

        # 随机选取起始值，确保区间 [start, start+width-1] 不超出整个空间
        start = random.randint(0, total_space - width)
        end = start + width - 1

        query_object_prefix_codes_list = []
        # 遍历区间内的所有整数
        for L in range(start, end + 1):
            # 转换为 total_bits 位的二进制字符串
            bin_str = format(L, '0{}b'.format(total_bits))
            # 调用已有的 get_prefix_codes 方法得到该二进制字符串对应的前缀码列表
            prefix_codes = IndexBuilder.get_prefix_codes(bin_str)
            query_object_prefix_codes_list.append(prefix_codes)

        return query_object_prefix_codes_list


    @staticmethod
    def lat_lon_to_hilbert_to_64bit_binary(latitude, longitude, n_bits=16):
        """
        将经纬度转换为希尔伯特曲线上的整数，再转换为64位的二进制字符串。

        参数：
        - latitude: 纬度（浮点数）
        - longitude: 经度（浮点数）
        - n_bits: 用于缩放和编码的位数

        返回：
        - 64位二进制字符串
        """
        # 归一化纬度和经度
        normalized_latitude = (latitude + 90) / 180
        normalized_longitude = (longitude + 180) / 360

        # 缩放到 [0, 2^n_bits - 1]
        max_value = 2 ** n_bits - 1
        scaled_latitude = int(normalized_latitude * max_value)
        scaled_longitude = int(normalized_longitude * max_value)

        # 形成二维点，并编码为希尔伯特整数
        points = np.array([scaled_latitude, scaled_longitude])
        hilbert_integer = encode(points, 2, n_bits)

        # 转换为二进制字符串，并保证为64位（不足补0，多余则取后64位）
        binary_str = bin(hilbert_integer)[2:]
        binary_64bit = binary_str[-64:].zfill(64)
        return binary_64bit

    @staticmethod
    def get_prefix_codes(bit_str):
        """
        根据输入的二进制字符串生成前缀码列表。
        例如，对于 "011001"，生成：
          011001
          01100*
          0110**
          011***
          01****
          0*****

        参数：
        - bit_str: 输入的二进制字符串

        返回：
        - 前缀码列表，每个元素为一个字符串
        """
        prefix_codes = []
        n = len(bit_str)
        for i in range(n):
            prefix = bit_str[:n - i]
            suffix = '*' * i
            prefix_codes.append(prefix + suffix)
        return prefix_codes

    def build_position_index(self):
        """
        构建位置索引：
          1. 遍历所有行，对每个经纬度计算对应的64位二进制字符串
          2. 根据二进制字符串生成前缀码列表，并为每个唯一的前缀码创建 BitMap 对象
          3. 再次遍历所有行，根据行中经纬度生成的前缀码设置对应 BitMap 中的位

        返回：
          位置索引字典
        """
        prefix_codes_list = []
        # 第一次遍历：初始化所有唯一前缀码对应的 BitMap 对象
        for row in self.rows:
            latitude = row[1]
            longitude = row[2]
            binary_str = self.lat_lon_to_hilbert_to_64bit_binary(latitude, longitude, self.n_bits)
            prefix_codes = self.get_prefix_codes(binary_str)
            for code in prefix_codes:
                if code not in prefix_codes_list:
                    prefix_codes_list.append(code)
                    self.position_index[code] = BitMap(capacity=self.num_businesses)

        # 第二次遍历：根据每行的经纬度设置对应前缀码的位
        for i, row in enumerate(self.rows):
            latitude = row[1]
            longitude = row[2]
            binary_str = self.lat_lon_to_hilbert_to_64bit_binary(latitude, longitude, self.n_bits)
            prefix_codes = self.get_prefix_codes(binary_str)
            for code in prefix_codes:
                self.position_index[code].set_bit(i)

        return self.position_index

    def index_or_separation(self):
        """
        通过调用 BitMap 类中的 bitmap_or_separation 函数，
        遍历关键字索引字典和位置索引字典中的每个 BitMap，
        将每个 BitMap 随机分成两个 BitMap，
        分别生成两个新的字典：
          - keyword_index_1 和 keyword_index_2
          - position_index_1 和 position_index_2

        返回：
          ((keyword_index_1, keyword_index_2), (position_index_1, position_index_2))
        """
        keyword_index_1 = {}
        keyword_index_2 = {}
        for keyword, bitmap in self.keyword_index.items():
            # 调用 BitMap 类中的 bitmap_or_separation 函数进行分离
            bmp1, bmp2 = bitmap.bitmap_or_separation()
            keyword_index_1[keyword] = bmp1
            keyword_index_2[keyword] = bmp2

        position_index_1 = {}
        position_index_2 = {}
        for code, bitmap in self.position_index.items():
            bmp1, bmp2 = bitmap.bitmap_or_separation()
            position_index_1[code] = bmp1
            position_index_2[code] = bmp2

        return (keyword_index_1, keyword_index_2), (position_index_1, position_index_2)
