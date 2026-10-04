#!/bin/sh
# One ss-server per plugin variant (aes-128-gcm, password "interop").
run() { ss-server -s 0.0.0.0 -p "$1" -k interop -m aes-128-gcm -u --plugin "$2" --plugin-opts "$3" & }
run 10200 obfs-server "obfs=http;obfs-host=cdn.prizmx.test"
run 10201 obfs-server "obfs=tls;obfs-host=cdn.prizmx.test"
run 10202 v2ray-plugin "server;path=/v2"
run 10203 v2ray-plugin "server;tls;host=interop.prizmx.test;path=/v2;cert=/certs/server.crt;key=/certs/server.key"
wait
