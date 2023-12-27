# Guillotine

Guillotine - HTTP Security Headers Finder



##### Finds the security headers that are not enabled in a specific domain.




### HTTP Security Headers List

You can detect the following HTTP security headers:

- [x] Strict-Transport-Security
- [x] X-Frame-Options
- [x] X-Content-Type-Options
- [x] Content-Security-Policy
- [x] X-Permitted-Cross-Domain-Policies
- [x] Referrer-Policy
- [x] Clear-Site-Data
- [x] Cross-Origin-Embedder-Policy
- [x] Cross-Origin-Opener-Policy
- [x] Cross-Origin-Resource-Policy
- [x] Cache-Control
- [x] Permissions-Policy

**note:** you can add security headers by directly modifying the code.

**referer:** https://owasp.org/www-project-secure-headers/

### INSTALL

1. Clone the repository

```
git clone https://github.com/Gohanckz/guillotine.git
```

2. Move in to repository

```
cd guillotine
```

3. Install the requirements.

```
pip3 install -r requirements.txt
```

### USAGE

The use is very simple.

1. Show http security headers enabled and missing
```
python guillotine.py -t https://www.domain.com
```

2. Show and compare headers with recommended versions.
```
python guillotine.py -t https://www.domain.com --compare-versions
```

3. Show warnings on important headers.
```
python guillotine.py -t https://www.domain.com --warnings
python guillotine.py -t https://www.domain.com -w
```

4. Show full response
```
python guillotine.py -t https://www.domain.com --verbose
python guillotine.py -t https://www.domain.com -v
```

5. Use custom headers.
```
python guillotine.py -t https://www.domain.com --headers "<header>:<value>|<header2>:<value2>|..."
python guillotine.py -t https://www.domain.com -H "<header>:<value>|<header2>:<value2>|..."
```

6. Use BASIC Authenticacion to retrieve the site
```
python guillotine.py -t https://www.domain.com --basic <username>:<password>
```

7. Use NTLM Authenticacion to retrieve the site
```
python guillotine.py -t https://www.domain.com --ntlm [<domain>\\]<username>:<password>
```

DEVELOPED | CONTACT | VERSION
----------|---------|-------
[Gohanckz](https://github.com/Gohanckz) | Gohanckz@gmail.com | 2.0
[ignaciocorball](https://github.com/ignaciocorball) | ignaciocorball@gmail.com | 2.1
[BSolarV](https://github.com/BSolarV) | bastian.solar.v@gmail.com | 2.2.3

