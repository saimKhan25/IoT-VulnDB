import os
import json
import sqlite3
import re

# Define the path to the root directory containing CVE files. example "C:\\Users\\Desktop\\cvelistV5-main\\cvelistV5-main\\cves"
root_dir = '' 

# Compile the regex pattern for IoT-related keywords
regex_pattern = re.compile(r'\b(IoT|smart device|smart home|embedded|sensor|internet of things)\b', re.IGNORECASE)

# Connect to the SQLite database
conn = sqlite3.connect('vulnerabilities.db')
cursor = conn.cursor()

# Inserts a vulnerability record into the database. It uses a try-except block to handle potential integrity errors during insertion.
def insert_vulnerability(cve_id, file_name, description, publish_date, date_updated, assigner_short_name, base_score, version, urls, problem_types, data_type, data_version, matched_keywords, cursor):
    """Insert a vulnerability record into the database."""
    try:
        cursor.execute(
            "INSERT INTO Vulnerabilities (CVE_ID, File_name, Description, Publish_Date, Date_Updated, Assigner_Short_Name, BaseScore, Version, URLs, Problem_Types, Data_Type, Data_Version, Matched_Keywords) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (cve_id, file_name, description, publish_date, date_updated, assigner_short_name, base_score, version, urls, problem_types, data_type, data_version, matched_keywords))
        conn.commit()
    except sqlite3.IntegrityError as e:
        print(f"Failed to insert {cve_id} due to a database error: {e}")

# A utility function to navigate through nested dictionaries/lists safely, returning a default value if the specified path does not exist.
def safe_get(dictionary, keys, default=None):
    """Safely get a value from a nested dictionary or list using a list of keys."""
    for key in keys:
        try:
            dictionary = dictionary[key]
        except (KeyError, TypeError, IndexError):
            return default
    return dictionary

# Extracts the highest base CVSS score and the corresponding version from the provided JSON data.
def find_cvss_metrics(data):
    """Extract the highest base score and its corresponding CVSS version from JSON data."""
    max_base_score = 0
    cvss_version_used = ''

    metrics = safe_get(data, ['containers', 'cna', 'metrics'], [])
    if metrics:
        for metric in metrics:
            for key, value in metric.items():
                if key.startswith("cvss"):
                    base_score = safe_get(value, ['baseScore'], None)
                    if base_score and base_score > max_base_score:
                        max_base_score = base_score
                        cvss_version_used = safe_get(value, ['version'], '')

    return max_base_score if max_base_score > 0 else '', cvss_version_used

# Extracts and consolidates URLs and problem types from the JSON data.
def extract_urls_and_problem_types(data):
    """Extract URLs and problem types from JSON data."""
    urls = [ref['url'] for ref in safe_get(data, ['containers', 'cna', 'references'], [])]
    unique_urls = '; '.join(set(urls))
    problem_types = '; '.join([desc['description'] for desc in safe_get(data, ['containers', 'cna', 'problemTypes', 0, 'descriptions'], [])])
    return unique_urls, problem_types

# Identifies unique IoT-related keywords in the CVE description, capitalizing them for consistency.
def find_iot_keywords(text, pattern):
    """Find all unique IoT-related keywords in the CVE description and capitalize them."""
    matches = pattern.findall(text)
    unique_keywords = set(match.capitalize() for match in matches)
    if unique_keywords:
        return '; '.join(unique_keywords)
    return ''

# The script traverses the specified root_dir for JSON files
for subdir, dirs, files in os.walk(root_dir):
    for file in files:
        if file.endswith('.json'):
            file_path = os.path.join(subdir, file)
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                descriptions = safe_get(data, ['containers', 'cna', 'descriptions'], [])
                for desc in descriptions:
                    description_value = safe_get(desc, ['value'], '')
                    matched_keywords = find_iot_keywords(description_value, regex_pattern)
                    if matched_keywords:
                        cve_id = safe_get(data, ['cveMetadata', 'cveId'], 'Unknown CVE ID')
                        file_name = os.path.basename(file_path)
                        publish_date = safe_get(data, ['cveMetadata', 'datePublished'], 'Unknown date')
                        date_updated = safe_get(data, ['cveMetadata', 'dateUpdated'], 'Unknown date')
                        assigner_short_name = safe_get(data, ['cveMetadata', 'assignerShortName'], 'Unknown Assigner')
                        base_score, cvss_version = find_cvss_metrics(data)  # Notice the change here
                        urls, problem_types = extract_urls_and_problem_types(data)
                        data_type = safe_get(data, ['dataType'], 'Unknown Type')
                        data_version = safe_get(data, ['dataVersion'], 'Unknown Version')
                        
                        insert_vulnerability(cve_id, file_name, description_value, publish_date, date_updated, assigner_short_name, base_score, cvss_version, urls, problem_types, data_type, data_version, matched_keywords, cursor)

conn.close()

print("Done!")
