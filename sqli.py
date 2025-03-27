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
import torch

# ASCII Art for startup
def display_ascii_art():
    ascii_art = """
     _____    _____    _____    _____  
    |  _  |  |  _  |  |  _  |  |  _  | 
    | |_| |  | | | |  | |_| |  | | | |
    | | | |  | ||| |  | | | |  | ||| | 
    | |_| |  | | | |  | |_| |  | | | |
    |_____|  |_| |_|  |_____|  |_| |_| 
    """
    print(ascii_art)

display_ascii_art()

# List of user-agents to mimic real browser requests
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0"
]

# Enhanced SQL error detection patterns
SQL_ERROR_PATTERNS = re.compile(
    r"SQL syntax.*MySQL|Warning.*mysql_|MySqlClient.|check the manual that corresponds to your MySQL|"
    r"PostgreSQL.*ERROR|Warning.*\Wpg_|ERROR:\s*invalid input syntax for type|SQLSTATE\[|"
    r"syntax error at or near|SQLite\/JDBCDriver|SQLITE_ERROR|ORA-\d{5}|"
    r"unrecognized token|unexpected end of SQL command|Microsoft SQL Server.*error|"
    r"Incorrect syntax near|Unclosed quotation mark after the character string|ODBC SQL Server Driver|"
    r"missing right parenthesis|Dynamic SQL generation is not supported|Data type mismatch in criteria expression|"
    r"supplied argument is not a valid MySQL|JDBCDriver.*SQL|native client SQL error|"
    r"quoted string not properly terminated|unexpected token|unterminated quoted string|"
    r"division by zero|subquery returned more than 1 row|multiple primary keys defined|"
    r"invalid use of NULL|failed for parameter|out of range value|"
    r"Conversion failed when converting|value out of range|"
    r"invalid identifier|unknown column|invalid character|"
    r"table.*does not exist|column.*does not exist|no such table|"
    r"ambiguous column name|incorrect number of arguments|"
    r"duplicate key value violates unique constraint|row not found|"
    r"supplied argument is not a valid PostgreSQL|unterminated string literal|"
    r"mismatched input|invalid use of group function|"
    r"unexpected end of input|division by zero|"
    r"relation does not exist|conversion failed|"
    r"unterminated quoted identifier|invalid hexadecimal literal|"
    r"failed for parameter|deadlock detected|"
    r"malformed function or procedure|error while executing the query|"
    r"unexpected keyword|invalid boolean expression|"
    r"syntax error in query expression|incorrect column specifier|"
    r"data exception|syntax error in SQL statement|"
    r"incorrect datetime value|subquery has too many columns|"
    r"invalid regular expression|duplicate entry|"
    r"truncated incorrect|Data truncation|"
    r"illegal mix of collations|parameter index out of range", re.IGNORECASE)

# Function to detect SQL errors dynamically similar to sqlmap
def detect_sql_error(response_text):
    return bool(SQL_ERROR_PATTERNS.search(response_text))

# Asynchronous function to send request with SQL payload
async def send_request(session, base_url, param, payload):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    encoded_payload = urllib.parse.quote(payload)
    url = f"{base_url.rstrip('/')}?{param}={encoded_payload}"
    try:
        start_time = time.time()
        async with session.get(url, headers=headers, timeout=2) as response:
            response_time = time.time() - start_time
            status = response.status
            response_text = await response.text()
            output = f"Checking: {url} - Status: {status} - Response Time: {response_time:.2f}s"
            print(output)
            
            # Check for SQL injection indicators
            if status == 200 or detect_sql_error(response_text) or response_time > 1.5:
                print(f"[+] Possible SQL Injection Detected: {url}")
                return [url, status, response_time, payload]
    except Exception:
        return None
    return None

# Asynchronous function to check SQL injection
def check_sql_injection(base_url, input_csv, output_csv):
    with open(input_csv, "r") as file:
        reader = csv.reader(file)
        test_cases = [(row[0].strip(), row[1].strip()) for row in reader if len(row) >= 2]
    
    # Utilize both CPU and GPU (if available)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using {device} for processing...")
    
    async def main():
        results = []
        semaphore = asyncio.Semaphore(500)
        connector = aiohttp.TCPConnector(limit_per_host=500)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [asyncio.create_task(limited_send_request(session, base_url, param, payload, semaphore)) for param, payload in test_cases]
            responses = await asyncio.gather(*tasks)
            results = [res for res in responses if res is not None]
        
        if not results:
            print("No vulnerabilities found.")
        
        with open(output_csv, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["URL", "Status Code", "Response Time (s)", "Payload"])
            writer.writerows(results)
        
        print(f"Results saved to {output_csv}")
        input("Press Enter to exit...")
    
    asyncio.run(main())

async def limited_send_request(session, base_url, param, payload, semaphore):
    async with semaphore:
        return await send_request(session, base_url, param, payload)

if __name__ == "__main__":
    target_url = input("Enter target website URL (e.g., https://example.com): ")
    input_csv_file = "structured_sqli_payloads.csv"  # File containing parameters and payloads
    output_csv_file = input("Enter output CSV file name (e.g., results.csv): ")
    
    if not output_csv_file.endswith(".csv"):
        output_csv_file += ".csv"
    
    check_sql_injection(target_url, input_csv_file, output_csv_file)
