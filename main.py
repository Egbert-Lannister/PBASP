import sqlite3
from IndexBuilder import IndexBuilder


def read_data(db_path):
    """
    从 SQLite 数据库中读取数据，并返回所有行记录
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM business_table")
    rows = cursor.fetchall()
    conn.close()
    return rows


def main():
    db_path = 'data_object_2000_keyword_100.db'
    rows = read_data(db_path)

    # 创建 IndexBuilder 实例并构建关键字索引和位置索引
    index_builder = IndexBuilder(rows)
    keyword_index = index_builder.build_keyword_index()
    position_index = index_builder.build_position_index()

    # 示例：打印构建好的索引信息
    print("构建了 {} 个关键字索引".format(len(keyword_index)))
    print("构建了 {} 个位置索引前缀码".format(len(position_index)))

    # 此处可以进一步调用索引进行查询或其他操作


if __name__ == "__main__":
    main()
