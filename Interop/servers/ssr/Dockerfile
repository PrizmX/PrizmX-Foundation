# ShadowsocksR reference server (Python, shadowsocksrr). OpenSSL 3 keeps
# RC4 (rc4-md5) in its legacy provider, which openssl.cnf activates; its API
# renamed EVP_CIPHER_CTX_cleanup to _reset. chacha20 comes from libsodium.
FROM python:3.9-slim-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends libsodium23 \
    && rm -rf /var/lib/apt/lists/*
# akkariiin/master
ARG SSR_REF=b365980a82d7309f4ed368c6bd958ee080cdd37b
RUN python -c "import io, sys, tarfile, urllib.request; \
tarfile.open(fileobj=io.BytesIO(urllib.request.urlopen('https://codeload.github.com/shadowsocksrr/shadowsocksr/tar.gz/' + sys.argv[1]).read())).extractall('/tmp')" "$SSR_REF" \
    && mv /tmp/shadowsocksr-* /ssr \
    && sed -i 's/EVP_CIPHER_CTX_cleanup/EVP_CIPHER_CTX_reset/g' /ssr/shadowsocks/crypto/openssl.py
COPY openssl.cnf /etc/ssl/openssl-legacy.cnf
ENV OPENSSL_CONF=/etc/ssl/openssl-legacy.cnf
COPY start.sh /start.sh
ENTRYPOINT ["/bin/sh", "/start.sh"]
