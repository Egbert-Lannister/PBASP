import json
import random
import sqlite3

from tqdm import tqdm

"""
基本实现了相关的功能
现在还缺乏的是，为了方便查询集对应，在后续产生更大规模的数据库时要注意关键字从第一次生成的小规模的数据库中产生
还有关键字读取过程中的去重功能
"""

# 设置读取对象个数
object_number = 2000

# 设置关键词读取个数
keyword_set_num = 100

# 数据库文件名设置
db_filename = f"data_object_{object_number}_keyword_{keyword_set_num}.db"

# 创建或连接数据库
conn = sqlite3.connect(db_filename)
cursor = conn.cursor()

# 创建表
cursor.execute('''
    CREATE TABLE IF NOT EXISTS business_table (
        business_id TEXT PRIMARY KEY,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        keywords TEXT NOT NULL
    )
''')

# JSON 文件路径
json_file_path = 'data/yelp_dataset/yelp_academic_dataset_business.json'

keyword_set = []

# 读取 JSON 文件并插入数据
with open(json_file_path, 'r', encoding='utf-8') as file:
    count = 0
    failed = 0
    inserted = 0
    for line in tqdm(file, desc="Processing JSON"):
        if inserted >= object_number:
            break

        count += 1
        try:
            data = json.loads(line)
            business_id = data['business_id']
            latitude = data['latitude']
            longitude = data['longitude']

            categories = data.get('categories')
            if categories is None:
                print(f"Skipping line {count}: 'categories' is None")
                continue

            categories = categories.split(', ')

            if len(keyword_set) >= keyword_set_num:
                # 随机选择两个 keyword_set 中的关键字
                selected = random.sample(keyword_set, 2)
                selected_category = ', '.join(selected)
            else:
                # keyword_set 个数少于100， 继续从中选取
                if len(categories) >= 2:
                    selected = random.sample(categories, 2)
                    keyword_set.extend(selected)
                else:
                    selected = categories
                    keyword_set.extend(selected) if selected else None
                selected_category = ', '.join(selected)


            # 插入数据
            cursor.execute(
                "INSERT OR IGNORE INTO business_table (business_id, latitude, longitude, keywords) VALUES (?, ?, ?, ?)",
                (business_id, latitude, longitude, selected_category)
            )

            inserted += 1

        except Exception as e:
            print(f"Error processing line {count}: {e}")
            failed += 1

print(f"Processed {count} lines, {count - failed} successful, {failed} failed")

print(keyword_set)
print(len(keyword_set))

# 提交事务
conn.commit()

# 查询数据
cursor.execute("SELECT COUNT(*) FROM business_table")
row_count = cursor.fetchone()[0]
print(f"Total records in business_table: {row_count}")

# 关闭连接
conn.close()