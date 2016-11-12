# nginxauto
automatic compile Nginx from source, on CentOS 6.

### security

- limit req
- User-Agent block
- Header defense

### modules
- [BoringSSL](https://github.com/google/boringssl)  fork OpenSSL, that is meet Google's needs (HTTP/2 + ALPN support)
- [LibreSSL](http://www.libressl.org/) (ChaCha20 cipher, HTTP/2 + ALPN support)
- [OpenSSL](https://www.openssl.org/) from source (HTTP/2 + ALPN support)
- [ngx_pagespeed](https://github.com/pagespeed/ngx_pagespeed)
- [ngx_brotli](https://github.com/google/ngx_brotli)
- [ngx_headers_more](https://github.com/openresty/headers-more-nginx-module)
- [GeoIP](http://dev.maxmind.com/geoip/geoip2/geolite2/) module and databases
- [Cloudflare's Chacha20 patch](https://blog.cloudflare.com/do-the-chacha-better-mobile-performance-with-cryptography/) : add the ChaCha20 + Poly1305 cipher suite

### Install
Join install and uninstall options
```
$ chmod +x nginx-auto.sh
$ ./nginx-auto.sh install
```

With BoringSSL
```
$ ./nginx-auto.sh install --boringssl
```

With LibreSSL
```
$ ./nginx-auto.sh install --libressl
```

With OpenSSL ChaCha20 cipher
```
$ ./nginx-auto.sh install --openssl
```

### Uninstall
```
$ ./nginx-auto.sh uninstall
```
