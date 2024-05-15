import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect('vulnerabilities.db')

# Create a cursor object using the cursor method
cursor = conn.cursor()

# SQL statement to create the Vulnerabilities table
create_vulnerabilities_table = """
CREATE TABLE IF NOT EXISTS Vulnerabilities (
    File_ID INTEGER PRIMARY KEY AUTOINCREMENT,
    CVE_ID TEXT,
    File_name TEXT,
    Description TEXT,
    Publish_Date TEXT,
    Date_Updated TEXT,
    Assigner_Short_Name TEXT,
    BaseScore TEXT,
    Version TEXT,
    URLs TEXT,  
    Problem_Types TEXT,
    Data_Type TEXT,
    Data_Version TEXT,
    Matched_Keywords TEXT
);
"""

# Execute the SQL statements to create the table
cursor.execute(create_vulnerabilities_table)

# Commit the changes
conn.commit()

# Close the connection
conn.close()

print("Database and table created successfully.")
