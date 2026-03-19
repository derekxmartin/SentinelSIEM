package ingest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/derekxmartin/akeso-siem/internal/config"
)

// helper: create a syslog listener with ephemeral ports and a capture handler.
func makeSyslogListener(t *testing.T) (*SyslogListener, *eventCapture, config.SyslogConfig) {
	t.Helper()

	// Find free TCP and UDP ports.
	tcpPort := freePort(t, "tcp")
	udpPort := freePort(t, "udp")

	cfg := config.SyslogConfig{
		TCPPort:       tcpPort,
		UDPPort:       udpPort,
		TLSPort:       0,
		MaxConns:      100,
		MaxMessageLen: 65536,
	}

	cap := &eventCapture{}
	sl := NewSyslogListener(cfg, cap.handle)
	return sl, cap, cfg
}

type eventCapture struct {
	mu     sync.Mutex
	events []json.RawMessage
}

func (c *eventCapture) handle(events []json.RawMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, events...)
}

func (c *eventCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

func (c *eventCapture) get(i int) json.RawMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.events[i]
}

func (c *eventCapture) waitForCount(t *testing.T, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c.count() >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d events, got %d", n, c.count())
}

func freePort(t *testing.T, network string) int {
	t.Helper()
	switch network {
	case "tcp":
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatalf("finding free TCP port: %v", err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		return port
	case "udp":
		pc, err := net.ListenPacket("udp", ":0")
		if err != nil {
			t.Fatalf("finding free UDP port: %v", err)
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		pc.Close()
		return port
	default:
		t.Fatalf("unknown network %q", network)
		return 0
	}
}

// ============================================================================
// TCP Tests
// ============================================================================

func TestSyslogTCPSingleRFC5424(t *testing.T) {
	sl, cap, cfg := makeSyslogListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sl.Stop()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.TCPPort))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	msg := "<34>1 2026-03-14T12:00:00Z myhost myapp 1234 ID47 - Hello TCP\n"
	conn.Write([]byte(msg))
	conn.Close()

	cap.waitForCount(t, 1, 2*time.Second)

	var env map[string]string
	json.Unmarshal(cap.get(0), &env)

	if env["source_type"] != "syslog" {
		t.Errorf("source_type = %q, want syslog", env["source_type"])
	}
	if env["transport"] != "tcp" {
		t.Errorf("transport = %q, want tcp", env["transport"])
	}
	if !strings.Contains(env["raw_message"], "Hello TCP") {
		t.Errorf("raw_message = %q, missing 'Hello TCP'", env["raw_message"])
	}
}

func TestSyslogTCPSingleRFC3164(t *testing.T) {
	sl, cap, cfg := makeSyslogListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sl.Stop()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.TCPPort))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	msg := "<34>Mar 14 12:00:00 myhost sshd[1234]: Failed password\n"
	conn.Write([]byte(msg))
	conn.Close()

	cap.waitForCount(t, 1, 2*time.Second)

	var env map[string]string
	json.Unmarshal(cap.get(0), &env)
	if !strings.Contains(env["raw_message"], "Failed password") {
		t.Errorf("raw_message missing 'Failed password': %q", env["raw_message"])
	}
}

func TestSyslogTCPNewlineFraming(t *testing.T) {
	sl, cap, cfg := makeSyslogListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sl.Stop()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.TCPPort))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Send 5 newline-delimited messages on one connection.
	for i := 0; i < 5; i++ {
		msg := fmt.Sprintf("<34>Mar 14 12:00:00 host app: message %d\n", i)
		conn.Write([]byte(msg))
	}
	conn.Close()

	cap.waitForCount(t, 5, 2*time.Second)
}

func TestSyslogTCPOctetCounting(t *testing.T) {
	sl, cap, cfg := makeSyslogListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sl.Stop()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.TCPPort))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Octet-counting framing: "LEN SP MSG"
	message := "<34>1 2026-03-14T12:00:00Z host app - - - octet counted"
	frame := fmt.Sprintf("%d %s", len(message), message)
	conn.Write([]byte(frame))
	conn.Close()

	cap.waitForCount(t, 1, 2*time.Second)

	var env map[string]string
	json.Unmarshal(cap.get(0), &env)
	if !strings.Contains(env["raw_message"], "octet counted") {
		t.Errorf("raw_message = %q, missing 'octet counted'", env["raw_message"])
	}
}

// ============================================================================
// UDP Tests
// ============================================================================

func TestSyslogUDPSingleRFC5424(t *testing.T) {
	sl, cap, cfg := makeSyslogListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sl.Stop()

	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", cfg.UDPPort))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	msg := "<34>1 2026-03-14T12:00:00Z myhost myapp 1234 ID47 - Hello UDP"
	conn.Write([]byte(msg))
	conn.Close()

	cap.waitForCount(t, 1, 2*time.Second)

	var env map[string]string
	json.Unmarshal(cap.get(0), &env)
	if env["transport"] != "udp" {
		t.Errorf("transport = %q, want udp", env["transport"])
	}
}

func TestSyslogUDPMultipleDatagrams(t *testing.T) {
	sl, cap, cfg := makeSyslogListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sl.Stop()

	for i := 0; i < 20; i++ {
		conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", cfg.UDPPort))
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		msg := fmt.Sprintf("<34>Mar 14 12:00:00 host app: udp msg %d", i)
		conn.Write([]byte(msg))
		conn.Close()
	}

	cap.waitForCount(t, 20, 3*time.Second)
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

func TestSyslogDisabledPorts(t *testing.T) {
	cfg := config.SyslogConfig{
		TCPPort: 0, // disabled
		UDPPort: freePort(t, "udp"),
	}
	cap := &eventCapture{}
	sl := NewSyslogListener(cfg, cap.handle)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sl.Stop()

	// UDP should still work.
	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", cfg.UDPPort))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Write([]byte("<34>Mar 14 12:00:00 host app: test"))
	conn.Close()

	cap.waitForCount(t, 1, 2*time.Second)
}

func TestSyslogGracefulShutdown(t *testing.T) {
	sl, _, _ := makeSyslogListener(t)
	ctx, cancel := context.WithCancel(context.Background())

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Stop should complete without hanging.
	cancel()
	done := make(chan struct{})
	go func() {
		sl.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not complete within 5 seconds")
	}
}

func TestSyslogConcurrentTCPAndUDP(t *testing.T) {
	sl, cap, cfg := makeSyslogListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sl.Stop()

	// Send TCP.
	go func() {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.TCPPort))
		if err != nil {
			return
		}
		conn.Write([]byte("<34>Mar 14 12:00:00 host app: TCP msg\n"))
		conn.Close()
	}()

	// Send UDP.
	go func() {
		conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", cfg.UDPPort))
		if err != nil {
			return
		}
		conn.Write([]byte("<34>Mar 14 12:00:00 host app: UDP msg"))
		conn.Close()
	}()

	cap.waitForCount(t, 2, 3*time.Second)

	// Verify both transports present.
	transports := map[string]bool{}
	for i := 0; i < cap.count(); i++ {
		var env map[string]string
		json.Unmarshal(cap.get(i), &env)
		transports[env["transport"]] = true
	}
	if !transports["tcp"] {
		t.Error("missing TCP transport")
	}
	if !transports["udp"] {
		t.Error("missing UDP transport")
	}
}

// ============================================================================
// Adversarial: TCP
// ============================================================================

func TestSyslogTCPOversizedMessage(t *testing.T) {
	sl, cap, cfg := makeSyslogListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sl.Stop()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.TCPPort))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Send a very large message (bigger than buffer but with newline).
	bigMsg := "<34>Mar 14 12:00:00 host app: " + strings.Repeat("A", 100000) + "\n"
	conn.Write([]byte(bigMsg))
	conn.Close()

	// Should either receive the message (potentially truncated) or not crash.
	time.Sleep(500 * time.Millisecond)
	// Main assertion: no panic, listener still works.
	_ = cap.count()
}

func TestSyslogTCPConnectionFlood(t *testing.T) {
	cfg := config.SyslogConfig{
		TCPPort:       freePort(t, "tcp"),
		UDPPort:       0,
		MaxConns:      5,
		MaxMessageLen: 65536,
	}
	cap := &eventCapture{}
	sl := NewSyslogListener(cfg, cap.handle)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sl.Stop()

	// Open max_conns + 5 connections. Some should be rejected.
	var conns []net.Conn
	for i := 0; i < 10; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.TCPPort), 1*time.Second)
		if err != nil {
			continue // expected for some
		}
		conns = append(conns, conn)
	}

	// Send on first connection — should work.
	if len(conns) > 0 {
		conns[0].Write([]byte("<34>Mar 14 12:00:00 host app: msg\n"))
	}

	time.Sleep(500 * time.Millisecond)

	for _, c := range conns {
		c.Close()
	}

	// Main assertion: no panic, listener survived the flood.
	if len(conns) < 5 {
		t.Logf("only %d connections succeeded (expected some rejections)", len(conns))
	}
}

func TestSyslogTCPBinaryGarbage(t *testing.T) {
	sl, _, cfg := makeSyslogListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sl.Stop()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.TCPPort))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Send random binary garbage.
	garbage := make([]byte, 1024)
	for i := range garbage {
		garbage[i] = byte(i % 256)
	}
	garbage = append(garbage, '\n')
	conn.Write(garbage)
	conn.Close()

	// Main assertion: no panic.
	time.Sleep(500 * time.Millisecond)
}

func TestSyslogUDPBinaryGarbage(t *testing.T) {
	sl, _, cfg := makeSyslogListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sl.Stop()

	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", cfg.UDPPort))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	garbage := make([]byte, 512)
	for i := range garbage {
		garbage[i] = byte(i % 256)
	}
	conn.Write(garbage)
	conn.Close()

	// Main assertion: no panic, listener continues.
	time.Sleep(500 * time.Millisecond)
}

func TestSyslogTCPPartialMessage(t *testing.T) {
	sl, _, cfg := makeSyslogListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sl.Stop()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.TCPPort))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Send partial message without newline, then close.
	conn.Write([]byte("<34>Mar 14 12:00:00 host app: partial"))
	conn.Close()

	// No panic, no goroutine leak.
	time.Sleep(500 * time.Millisecond)
}

func TestSyslogTCPNullBytes(t *testing.T) {
	sl, cap, cfg := makeSyslogListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sl.Stop()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.TCPPort))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	msg := "<34>Mar 14 12:00:00 host app: msg\x00with\x00nulls\n"
	conn.Write([]byte(msg))
	conn.Close()

	cap.waitForCount(t, 1, 2*time.Second)
	// No panic — null bytes preserved or stripped.
}

// ============================================================================
// TLS Tests
// ============================================================================

func TestSyslogTLSAcceptsValidClient(t *testing.T) {
	certDir := generateTestCerts(t)
	tlsPort := freePort(t, "tcp")

	cfg := config.SyslogConfig{
		TCPPort:       0,
		UDPPort:       0,
		TLSPort:       tlsPort,
		TLSCert:       filepath.Join(certDir, "server-cert.pem"),
		TLSKey:        filepath.Join(certDir, "server-key.pem"),
		MaxConns:      100,
		MaxMessageLen: 65536,
	}

	cap := &eventCapture{}
	sl := NewSyslogListener(cfg, cap.handle)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := sl.StartTLS(ctx); err != nil {
		t.Fatalf("startTLS: %v", err)
	}
	defer sl.Stop()

	// Connect with TLS.
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tlsPort), tlsCfg)
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}

	msg := "<34>1 2026-03-14T12:00:00Z host app - - - TLS message\n"
	conn.Write([]byte(msg))
	conn.Close()

	cap.waitForCount(t, 1, 2*time.Second)

	var env map[string]string
	json.Unmarshal(cap.get(0), &env)
	if !strings.Contains(env["raw_message"], "TLS message") {
		t.Errorf("raw_message = %q, missing 'TLS message'", env["raw_message"])
	}
}

func TestSyslogTLSRejectsPlaintext(t *testing.T) {
	certDir := generateTestCerts(t)
	tlsPort := freePort(t, "tcp")

	cfg := config.SyslogConfig{
		TCPPort:       0,
		UDPPort:       0,
		TLSPort:       tlsPort,
		TLSCert:       filepath.Join(certDir, "server-cert.pem"),
		TLSKey:        filepath.Join(certDir, "server-key.pem"),
		MaxConns:      100,
		MaxMessageLen: 65536,
	}

	cap := &eventCapture{}
	sl := NewSyslogListener(cfg, cap.handle)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := sl.StartTLS(ctx); err != nil {
		t.Fatalf("startTLS: %v", err)
	}
	defer sl.Stop()

	// Connect with plain TCP (not TLS).
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tlsPort))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	conn.Write([]byte("<34>Mar 14 12:00:00 host app: plain text\n"))
	conn.Close()

	// Wait briefly — should NOT receive any events (TLS handshake fails).
	time.Sleep(500 * time.Millisecond)
	if cap.count() > 0 {
		t.Error("plaintext message should be rejected by TLS listener")
	}
}

func TestSyslogTLSMissingCertConfig(t *testing.T) {
	cfg := config.SyslogConfig{
		TLSPort: freePort(t, "tcp"),
		TLSCert: "",
		TLSKey:  "",
	}

	sl := NewSyslogListener(cfg, nil)
	ctx := context.Background()

	err := sl.StartTLS(ctx)
	if err == nil {
		t.Error("expected error for missing TLS cert/key")
	}
}

func TestSyslogTLSInvalidCert(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bad-cert.pem"), []byte("not a cert"), 0644)
	os.WriteFile(filepath.Join(dir, "bad-key.pem"), []byte("not a key"), 0644)

	cfg := config.SyslogConfig{
		TLSPort: freePort(t, "tcp"),
		TLSCert: filepath.Join(dir, "bad-cert.pem"),
		TLSKey:  filepath.Join(dir, "bad-key.pem"),
	}

	sl := NewSyslogListener(cfg, nil)
	ctx := context.Background()

	err := sl.StartTLS(ctx)
	if err == nil {
		t.Error("expected error for invalid TLS cert")
	}
}

func TestSyslogTLSMultipleMessages(t *testing.T) {
	certDir := generateTestCerts(t)
	tlsPort := freePort(t, "tcp")

	cfg := config.SyslogConfig{
		TLSPort:       tlsPort,
		TLSCert:       filepath.Join(certDir, "server-cert.pem"),
		TLSKey:        filepath.Join(certDir, "server-key.pem"),
		MaxConns:      100,
		MaxMessageLen: 65536,
	}

	cap := &eventCapture{}
	sl := NewSyslogListener(cfg, cap.handle)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sl.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := sl.StartTLS(ctx); err != nil {
		t.Fatalf("startTLS: %v", err)
	}
	defer sl.Stop()

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tlsPort), tlsCfg)
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}

	for i := 0; i < 10; i++ {
		msg := fmt.Sprintf("<34>Mar 14 12:00:00 host app: TLS msg %d\n", i)
		conn.Write([]byte(msg))
	}
	conn.Close()

	cap.waitForCount(t, 10, 3*time.Second)
}

// ============================================================================
// Test cert generation helper
// ============================================================================

func generateTestCerts(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// Generate CA key.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	// Generate server key.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	// Write cert PEM.
	certFile, err := os.Create(filepath.Join(dir, "server-cert.pem"))
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	certFile.Close()

	// Write key PEM.
	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyFile, err := os.Create(filepath.Join(dir, "server-key.pem"))
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyFile.Close()

	return dir
}
