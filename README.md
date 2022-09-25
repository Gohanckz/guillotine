# Guillotine

Guillotine - HTTP Security Headers Finder



##### Finds the security headers that are not enabled in a specific domain.

![test](https://raw.githubusercontent.com/Gohanckz/Banners/master/guillotinebanner.png)


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

**note:** you can add security headers by directly modifying the code.

**referer:** https://owasp.org/www-project-secure-headers/

### INSTALL

```
pip install -r requirements.txt
```

### USAGE

The use is very simple.

1. Show http security headers enabled and missing

```
python guillotine.py -t https://www.domain.com
```

2. Show full response

```
python guillotine.py -t https://www.domain.com -v
```


DEVELOPED| CONTACT | VERSION
----------|---------|-------
Gohanckz |igonzalez@pwnsec.cl | 2.0


