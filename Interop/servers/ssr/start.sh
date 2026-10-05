#!/bin/sh
# One SSR server per method / protocol / obfs combination (password
# "interop"); together they cover every option PrizmX implements.
cd /ssr/shadowsocks
run() { python server.py -s 0.0.0.0 -p "$1" -k interop -m "$2" -O "$3" -o "$4" & }
run 10300 aes-256-cfb origin plain
run 10301 chacha20-ietf auth_aes128_md5 http_simple
run 10302 aes-128-ctr auth_aes128_sha1 http_post
run 10303 rc4-md5 auth_chain_a tls1.2_ticket_auth
run 10304 none auth_chain_a plain
run 10305 aes-192-cfb auth_sha1_v4 tls1.2_ticket_fastauth
run 10306 chacha20 origin http_simple
wait
