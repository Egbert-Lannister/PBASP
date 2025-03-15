import json
import random
import sqlite3
from tqdm import tqdm

# 参数设置
object_number = 1000
keyword_set_num = 100
db_filename = f"update_data_object_{object_number}_keyword_{keyword_set_num}.db"
json_file_path = 'data/yelp_dataset/yelp_academic_dataset_business.json'

# 创建或连接数据库
conn = sqlite3.connect(db_filename)
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS business_table (
        business_id TEXT PRIMARY KEY,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        keywords TEXT NOT NULL
    )
''')

# 读取整个文件到内存中
with open(json_file_path, 'r', encoding='utf-8') as file:
    lines = file.readlines()

# 从文件最后一行向上读取
lines_to_process = lines[-object_number:]

keyword_set = []
count = 0
failed = 0
inserted = 0

for line in tqdm(reversed(lines_to_process), desc="Processing JSON (Reverse)"):
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
            print(f"Skipping reversed line {count}: 'categories' is None")
            continue

        categories = categories.split(', ')

        if len(keyword_set) >= keyword_set_num:
            selected = random.sample(keyword_set, 2)
            selected_category = ', '.join(selected)
        else:
            if len(categories) >= 2:
                selected = random.sample(categories, 2)
            else:
                selected = categories

            # 去重加入关键词集合
            for keyword in selected:
                if len(keyword_set) >= keyword_set_num:
                    break
                if keyword not in keyword_set:
                    keyword_set.append(keyword)

            if len(keyword_set) >= keyword_set_num:
                selected_category = ', '.join(random.sample(keyword_set, 2))
            else:
                selected_category = ', '.join(selected)

        cursor.execute(
            "INSERT OR IGNORE INTO business_table (business_id, latitude, longitude, keywords) VALUES (?, ?, ?, ?)",
            (business_id, latitude, longitude, selected_category)
        )

        inserted += 1

    except Exception as e:
        print(f"Error processing reversed line {count}: {e}")
        failed += 1

print(f"Processed {count} lines, {count - failed} successful, {failed} failed")
print(keyword_set)
print(len(keyword_set))

# 提交事务并检查数据库记录数量
conn.commit()

cursor.execute("SELECT COUNT(*) FROM business_table")
row_count = cursor.fetchone()[0]
print(f"Total records in business_table: {row_count}")

# 关闭数据库连接
conn.close()
