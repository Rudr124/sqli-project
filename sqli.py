import requests
import csv
import os
import random
import time
import asyncio
import aiohttp
import re
import urllib.parse
from concurrent.futures import ProcessPoolExecutor

# ASCII Art for startup
def display_ascii_art():
    print("""
     _____    _____    _____    _____  
    |  _  |  |  _  |  |  _  |  |  _  | 
    | |_| |  | | | |  | |_| |  | | | |
    | | | |  | ||| |  | | | |  | ||| | 
    | |_| |  | | | |  | |_| |  | | | |
    |_____|  |_| |_|  |_____|  |_| |_| 
    """)

display_ascii_art()

# User-Agents List
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0"
]

# Enhanced SQL error patterns
SQL_ERROR_PATTERNS = re.compile(
    r"SQL syntax.*MySQL|Warning.*mysql_|MySqlClient.|check the manual that corresponds to your MySQL|"
    r"PostgreSQL.*ERROR|Warning.*\Wpg_|ERROR:\s*invalid input syntax for type|SQLSTATE\[|"
    r"syntax error at or near|SQLite\/JDBCDriver|SQLITE_ERROR|ORA-\d{5}|"
    r"unexpected end of SQL command|Microsoft SQL Server.*error|"
    r"incorrect syntax near|unclosed quotation mark|ODBC SQL Server Driver|"
    r"missing right parenthesis|data type mismatch|duplicate key value|row not found|"
    r"illegal mix of collations|invalid identifier|unknown column|table.*does not exist", re.IGNORECASE)

# Detect SQL errors in response
def detect_sql_error(response_text):
    return bool(SQL_ERROR_PATTERNS.search(response_text))

# Asynchronous HTTP request function
async def send_request(session, base_url, param, payload):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    encoded_payload = urllib.parse.quote(payload)
    url = f"{base_url.rstrip('/')}?{param}={encoded_payload}"
    try:
        start_time = time.time()
        async with session.get(url, headers=headers, timeout=5) as response:
            response_time = time.time() - start_time
            status = response.status
            response_text = await response.text()
            print(f"Checking: {url} - Status: {status} - Response Time: {response_time:.2f}s")

            # SQL Injection Detection
            if status == 200 and (detect_sql_error(response_text) or response_time > 1.5):
                print(f"[+] Possible SQL Injection Detected: {url}")
                return [url, status, response_time, payload]
    except Exception:
        return None
    return None

# Semaphore-limited requests
async def limited_send_request(session, base_url, param, payload, semaphore):
    async with semaphore:
        return await send_request(session, base_url, param, payload)

# Asynchronous SQL Injection Scanner
async def sql_injection_scanner(base_url, input_csv, output_csv):
    if not os.path.exists(input_csv):
        print(f"Error: Input file '{input_csv}' not found.")
        return
    
    with open(input_csv, "r") as file:
        reader = csv.reader(file)
        test_cases = [(row[0].strip(), row[1].strip()) for row in reader if len(row) >= 2]

    print(f"Loaded {len(test_cases)} test cases from {input_csv}.")

    results = []
    semaphore = asyncio.Semaphore(500)
    connector = aiohttp.TCPConnector(limit_per_host=500)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [asyncio.create_task(limited_send_request(session, base_url, param, payload, semaphore)) for param, payload in test_cases]
        responses = await asyncio.gather(*tasks)
        results = [res for res in responses if res is not None]

    if results:
        with open(output_csv, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["URL", "Status Code", "Response Time (s)", "Payload"])
            writer.writerows(results)
        print(f"Results saved to {output_csv}")
    else:
        print("No vulnerabilities found.")

# Entry Point
if __name__ == "__main__":
    target_url = input("Enter target website URL (e.g., https://example.com): ").strip()
    input_csv_file = "structured_sqli_payloads.csv"  # Ensure this file exists
    output_csv_file = input("Enter output CSV file name (e.g., results.csv): ").strip()
    
    if not output_csv_file.endswith(".csv"):
        output_csv_file += ".csv"

    asyncio.run(sql_injection_scanner(target_url, input_csv_file, output_csv_file))
