from BitMap import BitMap
import sqlite3

# 读取数据库数据
db_path = 'data_object_2000_keyword_100.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# 查询数据
cursor.execute("SELECT * FROM business_table")
rows = cursor.fetchall()

# 分离 business_id 和 keywords
business_ids = [row[0] for row in rows]
keywords_list = []  # 关键字列表


for row in rows:
    row_keyword_list = row[3].split(', ') if row[3] else []
    for keyword in row_keyword_list:
        keywords_list.append(keyword)

print(len(keywords_list))

# 建立关键字对象索引

# 关键字对象索引字典
keyword_index = {}

print(keywords_list)


for keyword in keywords_list:
    keyword_index[keyword] = BitMap(2000)


# 遍历每一行数据
for i, row in enumerate(rows):
    business_id = row[0]
    keywords = row[3].split(',') if row[3] else []
    print(business_id, keywords)

    for keyword in keywords:
        # 找到相应关键字之后，将该关键字位图的对象相应位置设置为 1
        keyword_index[keyword].set_bit(i)


# 关闭数据库连接
conn.close()