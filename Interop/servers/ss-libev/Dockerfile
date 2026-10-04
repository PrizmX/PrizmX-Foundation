# shadowsocks-libev with both SIP003 plugins: v2ray-plugin (in the base
# image) and simple-obfs' obfs-server (built here).
FROM alpine:3.24 AS build
RUN apk add --no-cache build-base autoconf automake libtool libev-dev linux-headers git
RUN git clone --depth 1 https://github.com/shadowsocks/simple-obfs.git /src \
    && cd /src && git submodule update --init --recursive \
    && ./autogen.sh && ./configure --disable-documentation && make && make install

FROM teddysun/shadowsocks-libev:3.3.6
COPY --from=build /usr/local/bin/obfs-server /usr/local/bin/obfs-server
COPY start.sh /start.sh
ENTRYPOINT ["/bin/sh", "/start.sh"]
