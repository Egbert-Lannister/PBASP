import json
import random
import sqlite3
import argparse
from tqdm import tqdm


def process_data(object_number, keyword_set_num):
    # 数据库文件名设置
    db_filename = f"original_data_object_{object_number}_keyword_{keyword_set_num}.db"

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
    json_file_path = 'yelp_dataset/yelp_academic_dataset_business.json'

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
                    # keyword_set 个数少于 keyword_set_num，继续从中选取
                    if len(categories) >= 2:
                        selected = random.sample(categories, 2)
                    else:
                        selected = categories

                    # 去重并加入 keyword_set
                    for keyword in selected:
                        if len(keyword_set) >= keyword_set_num:
                            break
                        if keyword not in keyword_set:
                            keyword_set.append(keyword)

                    # 如果 keyword_set 已达到要求数量，从中随机选取2个关键词；否则使用 selected 中的关键词
                    if len(keyword_set) >= keyword_set_num:
                        selected_category = ', '.join(random.sample(keyword_set, 2))
                    else:
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
    print("Collected keywords:", keyword_set)
    print("Number of keywords collected:", len(keyword_set))

    # 提交事务
    conn.commit()

    # 查询数据
    cursor.execute("SELECT COUNT(*) FROM business_table")
    row_count = cursor.fetchone()[0]
    print(f"Total records in business_table: {row_count}")

    # 关闭连接
    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process Yelp dataset and store data into SQLite database.")
    parser.add_argument("--object_number", type=int, default=2000, help="Number of business objects to process (default: 2000)")
    parser.add_argument("--keyword_set_num", type=int, default=100, help="Number of keywords to collect (default: 100)")
    args = parser.parse_args()

    process_data(args.object_number, args.keyword_set_num)
