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

recommended_versions = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self';",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "no-referrer-when-downgrade",
    "Feature-Policy": "vibrate 'none'; geolocation 'none';",
    "Permissions-Policy": "geolocation=(), microphone=()",
    "Expect-CT": "max-age=86400, enforce"
}

def check_security_header_versions(headers):
    outdated_headers = {}
    for header, value in headers.items():
        if header in recommended_versions and value != recommended_versions[header]:
            outdated_headers[header] = value
    return outdated_headers

parser = argparse.ArgumentParser(description="Finder Security Headers")
parser.add_argument("-t","--target",help="Show http security headers enabled and missing")
parser.add_argument("-v","--verbose",action="store_true",help="Show full response")
parser = parser.parse_args()

try:
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    url = requests.get(url=parser.target, verify=False)

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
        print("[*] Missing Security Headers :",count_m)
    except:
        print("[!] Syntax Error.")
        print("[+] Usage: python3 guillotine.py -t http://example.site")
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
    outdated_headers = check_security_header_versions(headers)
    if outdated_headers:
        print("\n[!] The following headers are outdated:")
        for header, value in outdated_headers.items():
            print(f"  - {header}: Current value: {value}, Recommended: {recommended_versions[header]}")
    if parser.verbose:
        verbose()
    elif parser.target:
        target()
