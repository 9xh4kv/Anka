# Usage
![ankaMenu](https://github.com/user-attachments/assets/f16d9092-b2ef-4975-9b13-72f7bc7b5f34)
## Attack types
`-a <attackType>`
### 1. Scan
Use the **scan** method to identify valid boolean payloads for a vulnerable parameter using a wordlist.

**Note:** Make sure to add `*` at the parameter you want to scan.
#### GET Request parameter
![getScan](https://github.com/user-attachments/assets/c2c0e4cc-50fb-4f46-a4f4-8fa530df9140)
#### POST Request data
![postScan](https://github.com/user-attachments/assets/2951cbbc-d739-40d3-a395-051b1975c8dc)
#### POST Request JSON data
![post-jsonScan](https://github.com/user-attachments/assets/6b58f6ba-4969-424c-aece-feb64c644e93)
#### Cookies parameter
![cookiesScan](https://github.com/user-attachments/assets/6031d310-515c-4b41-85e3-ae5a34c7b76c)

### 2. Scheme
Use the **scheme** method to identify the structure of the database

#### Database Reconnaissance
![databaseScan](https://github.com/user-attachments/assets/8798f024-1eb6-4742-9275-e09570568bbb)
#### Table Reconnaissance
![tableScan](https://github.com/user-attachments/assets/92a44116-3bbf-4794-87f8-e67efa2edcbe)
#### Column Reconnaissance
![columnScan](https://github.com/user-attachments/assets/98670451-faa3-4d2e-9e60-1326fb6d36cc)
#### Column value Reconnaissance
![valueScan](https://github.com/user-attachments/assets/bb507f6e-ee79-41a0-9b73-bab572211c63)
### 3. Secret
Use the **secret** method to extract the value of a specific column (e.g., password) for a particular entry (e.g., user alice).
Unlike the **schema** method, which enumerates all values for all entries, **secret** targets a single entry and automatically searches for both uppercase and lowercase characters.
![secretScan](https://github.com/user-attachments/assets/de106152-fd80-41aa-b42e-b1a54f28fbce)

