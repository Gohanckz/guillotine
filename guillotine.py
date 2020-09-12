#!/usr/bin/env python
#_*_ coding: utf8 _*_

#------------------------------------------------------------
#-----            GUILLOTINE                           -----|
# ----            SECURITY HEADERS HTTP FINDER          ----|
# ----            Gohanckz - W0lf_F4ng                  ----|
# ----            Contact : gohanckz@gmail.cl           ----|
# ----            Contact : ms@w0lff4ng.org             ----|
# ----            Version : 1.0                         ----|
#------------------------------------------------------------


try:
    import requests
    import argparse
    from banner import banner
    import termcolor as t
except ImportError as err:
    print("Some libraries are missing:")
    print(err)
    
parser = argparse.ArgumentParser(description="GUILLOTINE")
parser.add_argument('-t','--target',help="example: python guillotine.py -t https://www.domain.com")
parser = parser.parse_args()

# Security headers
security_headers =['Strict-Transport-Security',
                    'X-XSS-Protection',
                    'X-Content-Type-Options',
                    'X-Frame-Options',
                    'Content-Security-Policy',
                    'Public-Key-Pins',
                    'X-Permitted-Cross-Domain',
                    'Referrer-Policy',
                    'Expect-CT',
                    'Feature-Policy',
                    'Content-Security-Policy-Report-Only',
                    'Expect-CT',
                    'Public-Key-Pins-Report-Only',
                    'Upgrate-Insecure-Requests',
                    'X-Powered-By']


def main():
    banner()
    headers = []
    enabled_headers = []
    if parser.target:
        try:
            url = requests.get(url=parser.target)
            hdrs = dict(url.headers)
            for i in hdrs:
                headers.append(i)
            missing_headers = set(security_headers) - set(headers)
            for k in hdrs:
                if k in security_headers:
                    enabled_headers.append(k)
            
            print("+------------------------------------------+")
            print("|          ENABLED SECURITY HEADERS        |")
            print("+------------------------------------------+")
            for i in enabled_headers:
                print("|_"+t.colored(" [+] ","green")+ i+" "*(35-len(i))+"_|")
            print("+------------------------------------------+")
            print("|          MISSING SECURITY HEADERS        |")
            print("+------------------------------------------+")
            for i in missing_headers:
                print("|_"+t.colored(" [x] ","red")+ i+" "*(35-len(i))+"_|")
            print("+------------------------------------------+")
        except:
            print("connection cannot be established...\nusage: python guillotine.py -t https://www.domain.com")
       
    else:
        print("you must set a target...\nusage: python guillotine.py -t https://www.domain.com")
       


if __name__=='__main__':
    main()

    
