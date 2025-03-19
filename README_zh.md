# Privacy-Preserving Boolean Range Query to Hide Access and Search Patterns

[English Version](README.md)

---

本项目实现了一个分布式数据加密、重加密与查询系统，涵盖了 **DataOwner（数据所有者）**、**CloudServer 1**、**CloudServer 2** 和 **Client（客户端）** 四个关键角色。各组件通过 Socket 通信和 Redis 事件实现数据索引构建、加密、重加密及查询处理的完整流程。

## 项目概述

本项目主要实现以下功能：

1. **数据库配置**  
   - 创建 SQLite 数据库文件，文件名格式为 `data_object_{object_number}_keyword_{keyword_set_num}.db`。
   - 定义 `business_table` 表，包含 `business_id`、`latitude`、`longitude` 和 `keywords` 等字段。

2. **DataOwner（数据所有者）**  
   - 读取原始数据文件（路径通过 `config.ini` 配置）。
   - 构建关键字索引和位置索引。
   - 对索引数据进行加密，并将密钥与加密数据发送给各云服务器和客户端。

3. **CloudServer（云服务器）**  
   - 接收加密数据，并执行两阶段的重加密操作。
   - 协调数据更新和查询请求的处理，同时与客户端进行交互。

4. **Client（客户端）**  
   - 生成查询令牌并发送查询请求。
   - 接收并解密查询结果，通过逻辑运算得到最终查询对象的 ID。
   - 同时支持查询结果更新及新对象的添加。

## 数据集构建

本节介绍用于本模型的数据集构建过程。提供的 Python 脚本（`data/original_data_maker.py`）会生成一个包含业务对象（及其关键词、纬度和经度）的 SQLite 数据库，该数据集对于模拟和评估系统性能至关重要。

### 目的

数据集构建主要实现以下目标：

- **数据提取**：从 Yelp 数据集中提取业务对象（如餐厅、商店）。
- **关键词选择**：从业务类别中随机选择关键词，以模拟搜索行为。
- **数据库创建**：将提取的数据存储到 SQLite 数据库中，便于高效查询和分析。

### 使用方法

1. **安装依赖**  
   在项目根目录下运行以下命令安装所需的 Python 包：
   ```bash
   pip install -r requirements.txt
   ```

2. **下载数据集**  
   运行以下脚本下载 Yelp 数据集：
   ```bash
   python data/dataDownload.py
   ```
   你也可以从 [官方数据集](https://www.yelp.com/dataset) 下载 Yelp 数据，将 `yelp_academic_dataset_business.json` 文件放置于 `data/yelp_dataset/` 目录中。

3. **构建数据库**  
   - **原始数据构建**：  
     ```bash
     python data/original_data_maker.py --object_number 1000 --keyword_set_num 100
     ```
   - **更新数据构建**：  
     ```bash
     python data/update_data_maker.py --object_number 1000 --keyword_set_num 100
     ```
   其中，参数含义：
   - `object_number`：数据集中包含的业务对象数量。
   - `keyword_set_num`：跟踪的最大唯一关键词数。

4. **输出结果**  
   - 生成一个 SQLite 数据库文件（如 `data_object_2000_keyword_100.db`），其中包含 `business_table` 表。
   - 输出数据生成过程的摘要信息，包括处理行数、成功插入记录数以及唯一关键词数量。

## 配置说明

在项目根目录下创建或修改 `config.ini` 文件，以配置数据库文件的路径。例如：
```ini
[database]
origin_db_path = data_object_2000_keyword_100.db
update_dp_path = update_data_object_1000_keyword_100.db
```
如需使用其他数据库文件，只需修改此文件中的路径即可。

## 运行项目

请确保已安装 Redis 服务（项目会通过 `redis-server` 命令启动 Redis），然后运行主程序：
```bash
python main.py
```
该脚本将依次启动 Redis 服务、CloudServer 1、CloudServer 2、Client 和 DataOwner，各角色之间通过 Socket 和 Redis 事件进行通信。

## 注意事项

- 请确保已安装 Redis 服务，并且系统 PATH 中可以直接调用 `redis-server` 命令。
- 运行前请核实 `config.ini` 中配置的数据库路径正确，并确保相应的数据文件存在。

## 贡献

欢迎大家提交 issue 或 pull request，共同改进和优化项目代码。
