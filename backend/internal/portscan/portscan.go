package portscan

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"dua/internal/scan"
)

type Options struct {
	Start       int
	End         int
	Timeout     time.Duration
	Concurrency int
}

func Run(host string, opt Options) ([]scan.PortFinding, error) {
	if opt.Start <= 0 {
		opt.Start = 1
	}
	if opt.End <= 0 || opt.End > 65535 {
		opt.End = 65535
	}
	if opt.Start > opt.End {
		opt.Start, opt.End = opt.End, opt.Start
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 800 * time.Millisecond
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = 300
	}

	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.Split(host, "/")[0]

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, opt.Concurrency)
		out = make([]scan.PortFinding, 0, 128)
	)

	for p := opt.Start; p <= opt.End; p++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
			conn, err := net.DialTimeout("tcp", addr, opt.Timeout)
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(opt.Timeout))

			f := scan.PortFinding{
				Port:   port,
				Status: "open",
			}

			// Banner (si el servicio habla primero)
			if banner, ok := tryBanner(conn); ok {
				f.Banner = banner
			}

			// TLS handshake (no depende de puerto fijo)
			if isTLS(host, port, opt.Timeout) {
				f.Service = "tls"
				f.Notes = "tls handshake succeeded"
			}

			// HTTP probe (texto plano). Si es HTTPS real, normalmente fallará aquí,
			// pero ya quedaría marcado como tls arriba.
			if svc, note, ok := isHTTP(host, port, opt.Timeout); ok {
				f.Service = svc
				f.Notes = mergeNotes(f.Notes, note)
			}

			// SSH banner (si aplica)
			if f.Service == "" && strings.Contains(strings.ToLower(f.Banner), "ssh-") {
				f.Service = "ssh"
				f.Notes = mergeNotes(f.Notes, "ssh banner detected")
			}

			if f.Service == "" {
				f.Service = "unknown"
			}

			_ = conn.Close()

			mu.Lock()
			out = append(out, f)
			mu.Unlock()
		}(p)
	}

	wg.Wait()

	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out, nil
}

func mergeNotes(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + "; " + b
}

func tryBanner(conn net.Conn) (string, bool) {
	_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	r := bufio.NewReader(conn)

	// intenta leer algo sin bloquear mucho
	buf := make([]byte, 200)
	n, err := r.Read(buf)
	if err != nil || n <= 0 {
		return "", false
	}

	s := strings.TrimSpace(string(buf[:n]))
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	if s == "" {
		return "", false
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s, true
}

func isTLS(host string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	d := &net.Dialer{Timeout: timeout}

	c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // recon only
		ServerName:         host,
	})
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func isHTTP(host string, port int, timeout time.Duration) (service string, note string, ok bool) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", "", false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	req := "HEAD / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: DUA-Scanner/0.1\r\n\r\n"
	_, _ = conn.Write([]byte(req))

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n <= 0 {
		return "", "", false
	}

	s := strings.ToLower(string(buf[:n]))
	if strings.HasPrefix(s, "http/") {
		return "http", "http response detected", true
	}
	return "", "", false
}
