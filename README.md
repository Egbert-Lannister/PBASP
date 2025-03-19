# Privacy-Preserving Boolean Range Query to Hide Access and Search Patterns

---
[中文阅读](README_zh.md)

This project implements a distributed data encryption, re-encryption, and query system that involves four key roles: **DataOwner**, **CloudServer 1**, **CloudServer 2**, and **Client**. These components coordinate via socket communication and Redis events to perform data indexing, encryption, re-encryption, and query processing.


## Project Overview

The project provides the following functionalities:

1. **Database Setup**  
   - Creates a SQLite database file named `data_object_{object_number}_keyword_{keyword_set_num}.db`.
   - Defines a table `business_table` with columns for `business_id`, `latitude`, `longitude`, and `keywords`.

2. **DataOwner**  
   - Reads the raw data file (the path is configured via `config.ini`).
   - Builds keyword and location indexes.
   - Encrypts the index data and sends the encryption keys and data to the CloudServers and Client.

3. **CloudServer**  
   - Receives the encrypted data and performs a two-stage re-encryption process.
   - Coordinates data updates and query request handling, and facilitates communication with the Client.

4. **Client**  
   - Generates query tokens and sends query requests.
   - Receives and decrypts query results, then applies logical operations to obtain the final query object ID.
   - Supports both query result updates and the addition of new objects.

## Dataset Building

This section outlines the process for constructing the dataset used in this project. A provided Python script (`data/original_data_maker.py`) generates a SQLite database containing business objects along with their associated keywords, latitude, and longitude. This dataset is crucial for simulating and evaluating the system.

### Purpose

The dataset building process aims to:
- **Extract Data**: Retrieve business objects (e.g., restaurants, stores) from the Yelp Dataset.
- **Select Keywords**: Randomly choose keywords from business categories to simulate search behavior.
- **Create Database**: Store the extracted data in a SQLite database for efficient querying and analysis.


### Usage

1. **Install Dependencies**  
   Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

2. **Download Dataset**  
   Run the following script to download the Yelp Dataset:
   ```bash
   python data/dataDownload.py
   ```
   And you can download the Yelp Dataset from the [official repository](https://www.yelp.com/dataset) and place the `yelp_academic_dataset_business.json` file into the `data/yelp_dataset/` directory.

3. **Build the Database**  
   - **Original Data Maker**:  
     ```bash
     python data/original_data_maker.py --object_number 1000 --keyword_set_num 100
     ```
   - **Update Data Maker**:  
     ```bash
     python data/update_data_maker.py --object_number 1000 --keyword_set_num 100
     ```
   Adjust the parameters:
   - `object_number`: Number of business objects to include.
   - `keyword_set_num`: Maximum number of unique keywords to track.

4. **Output**  
   The process produces:
   - A SQLite database file (e.g., `data_object_2000_keyword_100.db`) containing the `business_table`.
   - A summary detailing the number of processed entries, successful insertions, and unique keywords.

## Configuration

Create or update the `config.ini` file in the project root to configure the database file paths. For example:
```ini
[database]
origin_db_path = data_object_2000_keyword_100.db
update_dp_path = update_data_object_1000_keyword_100.db
```
Simply modify these paths if you wish to use a different database file.

## Running the Project

Ensure that the Redis server is installed (the project uses the `redis-server` command to start Redis) and then run the main program:
```bash
python main.py
```
This script launches the Redis server, CloudServer 1, CloudServer 2, Client, and DataOwner sequentially. All components communicate via sockets and Redis events.

## Considerations

- Ensure that the Redis service is installed and that the `redis-server` command is available in your system PATH.
- Verify that the database paths specified in `config.ini` are correct and that the corresponding data files exist.

## Contribution

Contributions are welcome! Feel free to submit issues or pull requests to improve and optimize the project.

---

The above is the basic description and usage of the project.
