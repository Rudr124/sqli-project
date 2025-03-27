import requests
import csv
import os
import random
import time
from concurrent.futures import ThreadPoolExecutor
import re

# List of user-agents to mimic real browser requests
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0"
]

# Function to detect SQL errors dynamically similar to sqlmap
def detect_sql_error(response_text):
    sql_error_patterns = [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlClient\.", r"check the manual that corresponds to your MySQL",
        r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", r"ERROR:\s*invalid input syntax for type", r"SQLSTATE\[", 
        r"syntax error at or near", r"SQLite\/JDBCDriver", r"SQLITE_ERROR", r"ORA-\d{5}", 
        r"unrecognized token", r"unexpected end of SQL command", r"Microsoft SQL Server.*error",
        r"Incorrect syntax near", r"Unclosed quotation mark after the character string", r"ODBC SQL Server Driver",
        r"missing right parenthesis", r"Dynamic SQL generation is not supported", r"Data type mismatch in criteria expression",
        r"supplied argument is not a valid MySQL", r"JDBCDriver.*SQL", r"native client SQL error",
        r"quoted string not properly terminated"
    ]
    for pattern in sql_error_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True
    return False

# Function to send request with SQL payload
def send_request(base_url, param, payload):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    url = f"{base_url.rstrip('/')}?{param}={payload}"
    try:
        start_time = time.time()
        response = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
        response_time = time.time() - start_time
        status = response.status_code
        output = f"Checking: {url} - Status: {status} - Response Time: {response_time:.2f}s"
        print(output)
        
        # Check for SQL injection indicators
        if status == 200 or detect_sql_error(response.text) or response_time > 5:
            print(f"[+] Possible SQL Injection Detected: {url}")
            return [url, status, response_time]
    except requests.exceptions.RequestException as e:
        print(f"[-] Error checking {url}: {e}")
    return None

# Function to check SQL injection with multithreading
def check_sql_injection(base_url, input_csv, output_csv):
    results = []
    
    with open(input_csv, "r") as file:
        reader = csv.reader(file)
        test_cases = [(base_url, row[0].strip(), row[1].strip()) for row in reader if len(row) >= 2]
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_results = [executor.submit(send_request, *test) for test in test_cases]
        for future in future_results:
            result = future.result()
            if result:
                results.append(result)
    
    if not results:
        print("No vulnerabilities found.")
    
    with open(output_csv, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["URL", "Status Code", "Response Time (s)"])
        writer.writerows(results)
    
    print(f"Results saved to {output_csv}")
    input("Press Enter to exit...")

if __name__ == "__main__":
    target_url = input("Enter target website URL (e.g., https://example.com): ")
    input_csv_file = "sqli.csv"  # File containing parameters and payloads
    output_csv_file = input("Enter output CSV file name (e.g., results.csv): ")
    
    if not output_csv_file.endswith(".csv"):
        output_csv_file += ".csv"
    
    check_sql_injection(target_url, input_csv_file, output_csv_file)
