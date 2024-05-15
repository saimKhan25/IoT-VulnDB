# Vulnerability Data Processing

This Python script processes vulnerability data stored in JSON files and inserts relevant information into a SQLite database. 

## Prerequisites

- Python 3.x installed on your system.
- An Integrated Development Environment (IDE) such as Visual Studio Code (VSCode) or any other preferred IDE.

## Setup

1. **Database Setup**: 
    - Open your preferred IDE.
    - Copy and paste the provided SQLite database setup code into a new Python file.
    - Run the database setup script to create the SQLite database and necessary tables.
  
2. **Data Download**: 
    - Download the CVE JSON files from [CVE - Downloads](https://www.cve.org/Downloads).
    - Store the downloaded JSON files in a directory on your local machine.
    - A SQLite database browser like DB Browser for SQLite or any other preferred tool. Can be downloaded from [SQLitebrowser](https://sqlitebrowser.org/dl/).


3. **Python Script Setup**:
    - Open a new file in your IDE.
    - Copy and paste the provided Python script into the new file.
    - Modify the `root_dir` variable in the script to point to the directory containing the downloaded CVE JSON files. **Make sure filepath format is compatible! It varies by operating system!

## Running the Script

1. **Database Connection**:
    - Ensure that the SQLite database file (`vulnerabilities.db`) is present in the working directory.

2. **Running the Script**:
    - Execute the Python script in your IDE:
        - Copy the entire script.
        - Paste it into a new file in your IDE.
        - Adjust the file path in the script to match the location of your downloaded JSON files.
        - Run the script.

3. **Processing Output**:
    - The script will parse the JSON files, identify IoT-related vulnerabilities, and insert relevant information into the SQLite database.

## Customization - OPTIONAL

- **Regex Pattern**: Modify the `regex_pattern` variable to include additional keywords or adjust the pattern for identifying IoT-related vulnerabilities.

- **Database Schema**: Modify the database schema or SQL queries in the database setup script according to specific requirements.

- **Output Handling**: Customize the error handling or output messages as needed.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.