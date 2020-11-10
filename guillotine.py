#!/usr/bin/env python3
#_*_ coding: utf8 _*_

#------------------------------------------------------------
#-----            GUILLOTINE                           -----|
# ----            SECURITY HEADERS HTTP FINDER          ----|
# ----            Gohanckz - W0lf_F4ng                  ----|
# ----            Contact : gohanckz@gmail.cl           ----|
# ----            Contact : ms@w0lff4ng.org             ----|
# ----            Version : 1.0.1                       ----|
#------------------------------------------------------------


try:
    import requests
    import argparse
    from banner import banner
    from prettytable import PrettyTable
    import termcolor as t
    from textwrap import fill
    import sys
except ImportError as err:
    print("Some libraries are missing:")
    print(err)
    
parser = argparse.ArgumentParser(description="GUILLOTINE")
parser.add_argument('-t','--target',help="example: python -t https://www.domain.com")
parser.add_argument('-v','--verbose',action='store_true',help="show all information from headers")
parser.add_argument('-o','--output',help="save report in a file.")
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

table = PrettyTable()
table_info = PrettyTable()

column_names = ["         HEADER         ", "             INFORMATION               "]
column_names_report = ["   ENABLED SECURITY HEADERS   ","     MISSING SECURITY HEADERS     "]

def main():
    headers = []
    enabled_headers = []
    info_headers = []
    if parser.target:
        url = requests.get(url=parser.target)
        hdrs = dict(url.headers)

        for i in hdrs:
            headers.append(i)
            info_headers.append(hdrs[i])

        missing_headers = [] 
        for sh in security_headers:
            if not sh.lower() in [h.lower() for h in headers]:
                missing_headers.append(sh)

        for k in hdrs:
            if k.lower() in [sh.lower() for sh in security_headers]:
                enabled_headers.append(k)

        while len(enabled_headers) < len(missing_headers):
            enabled_headers.append(" ")

        while len(enabled_headers) > len(missing_headers):
            missing_headers.append(" ")
        
        if parser.verbose:
            banner()
            table_info.add_column(column_names_report[0],enabled_headers)
            table_info.add_column(column_names_report[1],missing_headers)
            table_info.align="l"
            print(table_info)
            table.add_column(column_names[0],headers)
            table.add_column(column_names[1],list(map(lambda text: fill(text,width = 46),info_headers)))
            table.align="l"
            print(table)                                            
        else:
            banner()
            table_info.add_column(column_names_report[0],enabled_headers)
            table_info.add_column(column_names_report[1],missing_headers)
            table_info.align="l"
            print(table_info)

        if parser.output:
            path = parser.output
            with open(path,'w') as f: 
                if parser.verbose:
                    f.write(str(table_info))
                    f.write('\n')
                    f.write(str(table))
                else:
                    f.write(str(table_info))
            f.close() 
        
    else:
        print("connection can't be established...")
        print("type python3 guillotine.py -h to show more options")
       


if __name__=='__main__':
    main()
