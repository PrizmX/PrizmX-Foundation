// Target services for the PrizmX interop suite. They live on an internal
// Docker network, so a client reaches them only through a proxy server.
//
//	web.test:80 / :443   HTTP(S): /ping, /bytes, /upload, /delay
//	dns.test:53/udp      authoritative for *.test (A 198.51.100.7)
//	echo.test:7          TCP and UDP echo
//
// Payloads come from a seeded xorshift64* stream (see pattern below) that
// the Swift harness regenerates, so both sides verify bytes while streaming
// without buffering or hashing; the same endpoints serve load tests.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// pattern is the shared deterministic byte stream: xorshift64* seeded with
// seed ^ 0x9E3779B97F4A7C15, eight little-endian bytes per step.
type pattern struct {
	state uint64
	block [8]byte
	used  int
}

func newPattern(seed uint64) *pattern {
	state := seed ^ 0x9E3779B97F4A7C15
	if state == 0 {
		state = 1
	}
	return &pattern{state: state, used: 8}
}

func (p *pattern) Read(buf []byte) (int, error) {
	for i := range buf {
		if p.used == 8 {
			x := p.state
			x ^= x >> 12
			x ^= x << 25
			x ^= x >> 27
			p.state = x
			binary.LittleEndian.PutUint64(p.block[:], x*0x2545F4914F6CDD1D)
			p.used = 0
		}
		buf[i] = p.block[p.used]
		p.used++
	}
	return len(buf), nil
}

func queryUint(r *http.Request, key string, fallback uint64) uint64 {
	value, err := strconv.ParseUint(r.URL.Query().Get(key), 10, 64)
	if err != nil {
		return fallback
	}
	return value
}

func webHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "pong")
	})
	// GET /bytes?n=N&seed=S: N pattern bytes.
	mux.HandleFunc("/bytes", func(w http.ResponseWriter, r *http.Request) {
		n := queryUint(r, "n", 1024)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatUint(n, 10))
		io.CopyN(w, newPattern(queryUint(r, "seed", 0)), int64(n))
	})
	// POST /upload?seed=S: verifies the body against the pattern.
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		expected := newPattern(queryUint(r, "seed", 0))
		reader := bufio.NewReaderSize(r.Body, 64*1024)
		got := make([]byte, 32*1024)
		want := make([]byte, 32*1024)
		var total int64
		for {
			n, err := reader.Read(got)
			if n > 0 {
				expected.Read(want[:n])
				for i := 0; i < n; i++ {
					if got[i] != want[i] {
						http.Error(w, fmt.Sprintf("mismatch at %d", total+int64(i)), http.StatusUnprocessableEntity)
						return
					}
				}
				total += int64(n)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		fmt.Fprintf(w, "ok %d", total)
	})
	// GET /delay?ms=M: answers after M milliseconds.
	mux.HandleFunc("/delay", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Duration(queryUint(r, "ms", 0)) * time.Millisecond)
		io.WriteString(w, "ok")
	})
	return mux
}

func serveWeb() {
	handler := webHandler()
	go func() {
		log.Fatal(http.ListenAndServe(":80", handler))
	}()
	server := &http.Server{Addr: ":443", Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	log.Fatal(server.ListenAndServeTLS("/certs/web.crt", "/certs/web.key"))
}

// serveDNS answers A queries for names under .test with 198.51.100.7,
// other types under .test with no data, and everything else NXDOMAIN.
func serveDNS() {
	conn, err := net.ListenPacket("udp", ":53")
	if err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			log.Fatal(err)
		}
		if reply := dnsReply(buf[:n]); reply != nil {
			conn.WriteTo(reply, peer)
		}
	}
}

func dnsReply(query []byte) []byte {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil
	}
	// Walk the question name (no compression in queries).
	offset := 12
	var labels []string
	for offset < len(query) && query[offset] != 0 {
		length := int(query[offset])
		if offset+1+length > len(query) {
			return nil
		}
		labels = append(labels, string(query[offset+1:offset+1+length]))
		offset += 1 + length
	}
	offset++
	if offset+4 > len(query) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(query[offset : offset+2])
	question := query[12 : offset+4]
	name := strings.ToLower(strings.Join(labels, "."))

	reply := make([]byte, 12, 64+len(question))
	copy(reply, query[:2])
	flags := uint16(0x8400) // response, authoritative
	inZone := name == "test" || strings.HasSuffix(name, ".test")
	if !inZone {
		flags |= 3 // NXDOMAIN
	}
	binary.BigEndian.PutUint16(reply[2:4], flags|uint16(query[2]&0x01)<<8)
	binary.BigEndian.PutUint16(reply[4:6], 1)
	reply = append(reply, question...)
	if inZone && qtype == 1 {
		binary.BigEndian.PutUint16(reply[6:8], 1)
		reply = append(reply, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 7)
	}
	return reply
}

func serveEcho() {
	udp, err := net.ListenPacket("udp", ":7")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, peer, err := udp.ReadFrom(buf)
			if err != nil {
				log.Fatal(err)
			}
			udp.WriteTo(buf[:n], peer)
		}
	}()
	tcp, err := net.Listen("tcp", ":7")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := tcp.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer conn.Close()
			io.Copy(conn, conn)
		}()
	}
}

func main() {
	go serveDNS()
	go serveEcho()
	serveWeb()
}
