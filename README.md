# Privacy-Preserving Boolean Range Query to Hide Access and Search Patterns

Below is a sample `README.md` section for the **Dataset Building** part of your GitHub repository. This section explains the purpose, functionality, and usage of the provided code:

---

This project implements a distributed data encryption, re-encryption and query system, including four roles: DataOwner, CloudServer 1, CloudServer 2 and Client. Each role coordinates through Socket communication and Redis events to complete the complete process of data indexing, encryption, re-encryption, and query.


## Project Overview

The project performs the following functions:

1. **Database Setup**:
   - Creates a SQLite database file named `data_object_{object_number}_keyword_{keyword_set_num}.db`.
   - Defines a table `business_table` with columns for `business_id`, `latitude`, `longitude`, and `keywords`.

2. **DataOwner**
   - Read the raw data file (the path is configured through `config.ini`).
   - Build keyword indexes and location indexes.
   - Encrypts index data and sends keys and encrypted data to each CloudServer and Client.

3. **CloudServer**
   - The encrypted data is received and a two-stage re-encryption is performed.
   - Coordinate data updates, query request processing, and interaction with clients.

4. **Client**:
   - Generate query tokens and send query requests.
   - Receives the query result, decrypts the result and performs logical operations to obtain the ID of the query object.
   - Support for updating data query results and adding new objects.

## Dataset Building

This section describes the process of building the dataset used for the Privacy-Preserving Boolean Range Query to Hide Access and Search Patterns model. The provided Python script (`dataset_builder.py`) generates a SQLite database containing business objects with their associated keywords, latitude, and longitude. This dataset is essential for simulating and evaluating the model's performance.

### Purpose

The dataset building process serves the following key objectives:

1. **Data Extraction**: Extract business objects (e.g., restaurants, stores) from the Yelp Dataset.
2. **Keyword Selection**: Randomly select keywords from the business categories to simulate search patterns.
3. **Database Creation**: Store the extracted data in a SQLite database for efficient querying and analysis.

### Code Overview

The script performs the following steps:



1. **Database Setup**:
   - Creates a SQLite database file named `data_object_{object_number}_keyword_{keyword_set_num}.db`.
   - Defines a table `business_table` with columns for `business_id`, `latitude`, `longitude`, and `keywords`.

2. **Data Extraction**:
   - Reads business data from the Yelp Dataset JSON file (`yelp_academic_dataset_business.json`).
   - Extracts relevant fields: `business_id`, `latitude`, `longitude`, and `categories`.

3. **Keyword Handling**:
   - Maintains a `keyword_set` to track unique keywords.
   - Ensures that the number of unique keywords does not exceed the specified limit (`keyword_set_num`).
   - Randomly selects keywords from the `keyword_set` or the business's categories.

4. **Data Insertion**:
   - Inserts the extracted data into the `business_table`, ensuring uniqueness via `INSERT OR IGNORE`.

5. **Error Handling**:
   - Skips lines with missing or invalid data and reports the number of failed insertions.

### Usage

1. **Dataset Download**:
   - Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```
2. **Dataset Download**:
     ```bash
     python data/dataDownload.py
     ```

2. **Prerequisites**:
   - Install the required Python packages:
     ```bash
     pip install sqlite3 json random tqdm
     ```
   - Download the Yelp Dataset from the [official repository](https://www.yelp.com/dataset) and place the `yelp_academic_dataset_business.json` file in the `data/yelp_dataset/` directory.

3. **Configuration**:
   - Adjust the following parameters in the script to customize the dataset:
     - `object_number`: The number of business objects to include in the dataset.
     - `keyword_set_num`: The maximum number of unique keywords to track.
     - `db_filename`: The name of the output SQLite database file.

4. **Run the Script**:
   ```bash
   python dataset_builder.py
   ```
- Update data maker
   ```bash
   python data/update_data_maker.py  --object_number 1000 --keyword_set_num 100
   ```
   Adjust the following parameters in the script to customize the dataset:
  - `object_number`: The number of business objects to include in the dataset.
  - `keyword_set_num`: The maximum number of unique keywords to track.
4. **Output**:
   - A SQLite database file (e.g., `data_object_2000_keyword_100.db`) containing the `business_table`.
   - A summary of the dataset generation process, including the number of processed lines, successful insertions, and unique keywords.

### Example Output

```
Processing JSON: 100%|██████████| 2000/2000 [00:10<00:00, 199.01it/s]
Processed 2000 lines, 1990 successful, 10 failed
Total records in business_table: 1990
```

### Notes

1. **Keyword Uniqueness**:
   - The script ensures that keywords are unique within the `keyword_set` and avoids duplicates during insertion.

2. **Scalability**:
   - The dataset generation process is designed to handle large-scale datasets by processing the JSON file line-by-line and using efficient database operations.

3. **Error Reporting**:
   - Any errors encountered during data processing (e.g., missing fields, invalid JSON) are logged to the console for debugging.

4. **Customization**:
   - Modify the `object_number` and `keyword_set_num` variables to generate datasets of different sizes for experimentation.

### Next Steps

1. Use the generated SQLite database to simulate privacy-preserving boolean range queries.
2. Extend the keyword selection logic to prioritize specific categories or business types.
3. Integrate the dataset with the rest of the model implementation for evaluation and testing.

---

Let me know if you need further refinements or additional details!



