#!/usr/bin/env python3
#_*_ coding: utf8 _*_

#------------------------------------------------------------
#-----            GUILLOTINE                           -----|
#----             FINDER HTTP SECURITY HEADERS          ----|
#----             Gohanckz                              ----|
#----             Contact : gohanckz@gmail.com          ----|
#----             Version : 2.2                         ----|
#------------------------------------------------------------
try:
    from banner import banner
    from prettytable import PrettyTable
    import requests
    import argparse
    from urllib3.exceptions import InsecureRequestWarning
    from requests.auth import HTTPBasicAuth
    from requests_ntlm import HttpNtlmAuth
except ImportError as err:
    print("Some libraries are missing:")
    print(err)

security_headers = [
    "Strict-Transport-Security".lower(),
    "X-Frame-Options".lower(),
    "X-Content-Type-Options".lower(),
    "Content-Security-Policy".lower(),
    "X-Permitted-Cross-Domain-Policies".lower(),
    "Referrer-Policy".lower(),
    "Clear-Site-Data".lower(),
    "Cross-Origin-Embedder-Policy".lower(),
    "Cross-Origin-Opener-Policy".lower(),
    "Cross-Origin-Resource-Policy".lower(),
    "Cache-Control".lower(),
]

recommended_versions = {
    "Strict-Transport-Security".lower(): "max-age=31536000; includeSubDomains",
    "X-Frame-Options".lower(): "SAMEORIGIN",
    "X-Content-Type-Options".lower(): "nosniff",
    "Content-Security-Policy".lower(): "default-src 'self';",
    "X-Permitted-Cross-Domain-Policies".lower(): "none",
    "Referrer-Policy".lower(): "no-referrer-when-downgrade",
    "Clear-Site-Data".lower(): '"cache", "cookies", "storage", "executionContexts"',
    "Cross-Origin-Embedder-Policy".lower(): "require-corp",
    "Cross-Origin-Opener-Policy".lower(): "same-origin",
    "Cross-Origin-Resource-Policy".lower(): "same-origin",
    "Cache-Control".lower(): "no-cache, no-store, must-revalidate",
    "X-XSS-Protection".lower(): "1; mode=block",
    "Feature-Policy".lower(): "vibrate 'none'; geolocation 'none';",
    "Permissions-Policy".lower(): "geolocation=(), microphone=()",
    "Expect-CT".lower(): "max-age=86400, enforce"
}

def check_security_header_versions(headers, parser):
    outdated_headers = {}
    for header, value in headers.items():
        if (
                header.lower() in recommended_versions
            ) and (
                value.lower() != recommended_versions[header.lower()].lower()
                ):
            outdated_headers[header] = (value[:38]+"..." if (len(value) > 40 and not parser.verbose) else value)
    return outdated_headers

parser = argparse.ArgumentParser(description="Finder Security Headers")
parser.add_argument("-t","--target",help="Show http security headers enabled and missing", required=True)
parser.add_argument("--compare-versions",action="store_true",help="Show the recomended version for headers in use.")
parser.add_argument("--ntlm", help="Use NTLM Authentication. Format: [<domain>\\\\]<username>:<password>")
parser.add_argument("--basic", help="Use BASIC Authentication. Format: <username>:<password>")
parser.add_argument("-v","--verbose",action="store_true",help="Show full response")
parser = parser.parse_args()

try:
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    
    auth = None
    if( parser.basic ):
        basicAuth = parser.basic.split(":")
        auth = HTTPBasicAuth(basicAuth[0], "".join(basicAuth[1:]))
    elif( parser.ntlm ):
        ntlmAuth = parser.ntlm.split(":")
        auth = HttpNtlmAuth(ntlmAuth[0], "".join(ntlmAuth[1:]))

    url = requests.get(url=parser.target, verify=False, auth=auth)

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
        if i.lower() in security_headers:
            security_headers_site.append(i)
        
    for j in security_headers:
        if not j.lower() in [h.lower() for h in headers_site]:
            missing_headers.append( "-".join( [ word.capitalize() for word in j.split("-") ] ) )

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
    if( parser.compare_versions or parser.verbose ):
        outdated_headers = check_security_header_versions(headers, parser)
        if outdated_headers:
            print("\n[!] The following headers are outdated:")
            for header, value in outdated_headers.items():
                CapHeader = "-".join( [ word.capitalize() for word in header.split("-") ] )
                print(f"    - {CapHeader}:")
                print(f"        Current value: {value}")
                print(f"        Recommended:   {recommended_versions[header.lower()]}")
    if parser.verbose:
        verbose()
    elif parser.target:
        target()
