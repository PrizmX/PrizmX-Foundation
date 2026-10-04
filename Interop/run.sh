#!/bin/sh
# Starts the interop stack, runs PrizmXInteropTests against it, and tears the
# stack down again (see README.md).
#
#   ./Interop/run.sh [swift test args…]
#
#   PRIZMX_INTEROP_FILTER   swift test filter (default PrizmXInteropTests)
#   PRIZMX_INTEROP_NODES    comma-separated node names to run (default all)
#   PRIZMX_INTEROP_LOAD=1   also run the load suite (PRIZMX_LOAD_* knobs)
#   PRIZMX_INTEROP_KEEP=1   leave the stack running afterwards
#   PRIZMX_INTEROP_RELEASE=1  optimized build (for load numbers)
set -eu
cd "$(dirname "$0")"
here=$(pwd)

# Test CA, proxy-server certificate (interop.prizmx.test / 127.0.0.1) and the
# internal target's certificate (web.test). Reissued before they expire.
if [ ! -f certs/ca.crt ] || ! openssl x509 -checkend 86400 -noout -in certs/web.crt >/dev/null 2>&1; then
    rm -rf certs && mkdir -p certs
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=PrizmX Interop CA" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout certs/ca.key -out certs/ca.crt 2>/dev/null
    issue() { # name cn san
        openssl req -newkey rsa:2048 -nodes -subj "/CN=$2" \
            -keyout "certs/$1.key" -out "certs/$1.csr" 2>/dev/null
        printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$3" > "certs/$1.ext"
        # Apple trust rejects TLS server certificates valid for over 825 days.
        openssl x509 -req -in "certs/$1.csr" -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
            -days 800 -extfile "certs/$1.ext" -out "certs/$1.crt" 2>/dev/null
        rm "certs/$1.csr" "certs/$1.ext"
    }
    issue server interop.prizmx.test "DNS:interop.prizmx.test,IP:127.0.0.1"
    issue web web.test "DNS:web.test"
    chmod 644 certs/*.key
fi

# mihomo runs in a container: it reaches the published ports via the host.
mkdir -p .generated
{
    printf 'mixed-port: 7890\nallow-lan: true\nbind-address: "*"\nmode: rule\n'
    printf 'log-level: warning\nipv6: false\nexternal-controller: 0.0.0.0:9090\n\n'
    sed 's/server: 127\.0\.0\.1/server: host.docker.internal/' profile.yaml
} > .generated/mihomo.yaml

if [ "${PRIZMX_INTEROP_KEEP:-0}" != 1 ]; then
    trap 'docker compose --project-directory "$here" down --remove-orphans >/dev/null 2>&1' EXIT INT TERM
fi
docker compose up -d --build --force-recreate --quiet-pull

# Ready once mihomo's controller answers (it starts after the servers).
tries=0
until curl -fs http://127.0.0.1:19090/version >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -gt 60 ]; then
        echo "interop stack did not become ready" >&2
        docker compose logs --tail 50 >&2
        exit 1
    fi
    sleep 0.5
done

cd ..
if [ "${PRIZMX_INTEROP_RELEASE:-0}" = 1 ]; then
    # The tests use @testable imports, which release builds allow only with
    # -enable-testing.
    set -- -c release -Xswiftc -enable-testing "$@"
fi
PRIZMX_INTEROP=1 swift test --filter "${PRIZMX_INTEROP_FILTER:-PrizmXInteropTests}" "$@"
