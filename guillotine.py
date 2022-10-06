#!/usr/bin/env python3
#_*_ coding: utf8 _*_

#------------------------------------------------------------
#-----            GUILLOTINE                           -----|
# ----            FINDER HTTP SECURITY HEADERS          ----|
# ----            Gohanckz                              ----|
# ----            Contact : igonzalez@pwnsec.cl         ----|
# ----            Version : 2.0                         ----|
#------------------------------------------------------------
try:
    from banner import banner
    from prettytable import PrettyTable
    import requests
    import argparse
    from urllib3.exceptions import InsecureRequestWarning
except ImportError as err:
    print("Some libraries are missing:")
    print(err)

parser = argparse.ArgumentParser(description="Finder Security Headers")
parser.add_argument("-t","--target",help="Show http security headers enabled and missing")
parser.add_argument("-v","--verbose",action="store_true",help="Show full response")
parser = parser.parse_args()

try:
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    url = requests.get(url=parser.target, verify=False)    


    security_headers = [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "X-Permitted-Cross-Domain-Policies",
        "Referrer-Policy",
        "Clear-Site-Data",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Cache-Control"
    ]

    info_headers = []
    headers_site = []
    security_headers_site = []
    missing_headers = []

    headers = dict(url.headers)

    for i in headers:
        headers_site.append(i)

    for i in headers:
        info_headers.append(headers[i])

    for i in headers_site: 
        if i in security_headers:
            security_headers_site.append(i)
        
    for j in security_headers:
        if not j in [h for h in headers_site]:
            missing_headers.append(j)

    table = PrettyTable()
    table.add_column("Header",headers_site)
    table.add_column("Information",info_headers)
    table.align="l"

    while len(security_headers_site) < len(missing_headers):
        security_headers_site.append(" ")

    while len(security_headers_site) > len(missing_headers):
        missing_headers.append(" ")

    count = 0
    for i in security_headers_site:
        if i != " ":
            count += 1
            
    count_m = 0
    for j in missing_headers:
        if j != " ":
            count_m +=1

    s_table = PrettyTable()
    s_table.add_column("Enabled Security Header",security_headers_site)
    s_table.add_column("Missing Security Header",missing_headers)
    s_table.align="l"
except:
    print("[!] time out, unable to connect to site.")

def main():
    banner()
    try:
        print("\n[*] Analyzing target : ",parser.target)
        print("[*] Security headers enabled :", count)
        print("[*] Missing Security Headers :",len(missing_headers))
    except:
        print("[!] Syntax Error.")
        print("[+] Usage: python3 guillotine.py -t http://examplse.site")
def target():
    try:      
        print(s_table)
    except:
        pass
def verbose():
    try:
        print(table)
    except:
        pass
if __name__ == '__main__':
    main()
    if parser.verbose:
        verbose()
    elif parser.target:
        target()
