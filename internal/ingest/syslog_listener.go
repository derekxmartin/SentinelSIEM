package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SentinelSIEM/sentinel-siem/internal/config"
	"github.com/SentinelSIEM/sentinel-siem/internal/metrics"
)

// SyslogListener accepts syslog messages over TCP and UDP, wraps them in JSON
// envelopes, and delivers them to the pipeline via the EventHandler callback.
type SyslogListener struct {
	cfg     config.SyslogConfig
	handler EventHandler

	tcpLn  net.Listener
	udpPC  net.PacketConn
	tlsLn  net.Listener

	connSem chan struct{} // connection semaphore
	wg      sync.WaitGroup
	cancel  context.CancelFunc
}

// NewSyslogListener creates a syslog listener that delegates to the given handler.
func NewSyslogListener(cfg config.SyslogConfig, handler EventHandler) *SyslogListener {
	maxConns := cfg.MaxConns
	if maxConns <= 0 {
		maxConns = 1000
	}

	return &SyslogListener{
		cfg:     cfg,
		handler: handler,
		connSem: make(chan struct{}, maxConns),
	}
}

// Start begins listening on configured TCP and UDP ports. Blocks until ctx is cancelled.
func (s *SyslogListener) Start(ctx context.Context) error {
	ctx, s.cancel = context.WithCancel(ctx)

	maxMsgLen := s.cfg.MaxMessageLen
	if maxMsgLen <= 0 {
		maxMsgLen = 65536
	}

	// Start TCP listener.
	if s.cfg.TCPPort > 0 {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.cfg.TCPPort))
		if err != nil {
			return fmt.Errorf("syslog tcp: %w", err)
		}
		s.tcpLn = ln
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveTCP(ctx, ln, maxMsgLen)
		}()
		log.Printf("[syslog] TCP listening on :%d", s.cfg.TCPPort)
	}

	// Start UDP listener.
	if s.cfg.UDPPort > 0 {
		pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", s.cfg.UDPPort))
		if err != nil {
			if s.tcpLn != nil {
				s.tcpLn.Close()
			}
			return fmt.Errorf("syslog udp: %w", err)
		}
		s.udpPC = pc
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveUDP(ctx, pc, maxMsgLen)
		}()
		log.Printf("[syslog] UDP listening on :%d", s.cfg.UDPPort)
	}

	return nil
}

// Stop gracefully shuts down all listeners and waits for connections to drain.
func (s *SyslogListener) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.tcpLn != nil {
		s.tcpLn.Close()
	}
	if s.udpPC != nil {
		s.udpPC.Close()
	}
	if s.tlsLn != nil {
		s.tlsLn.Close()
	}
	s.wg.Wait()
	return nil
}

// serveTCP accepts TCP connections and handles each in a goroutine.
func (s *SyslogListener) serveTCP(ctx context.Context, ln net.Listener, maxMsgLen int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if !isClosedError(err) {
					log.Printf("[syslog] TCP accept error: %v", err)
				}
				return
			}
		}

		// Connection semaphore — reject if at capacity.
		select {
		case s.connSem <- struct{}{}:
		default:
			log.Printf("[syslog] TCP connection limit reached, rejecting %s", conn.RemoteAddr())
			conn.Close()
			continue
		}

		s.wg.Add(1)
		metrics.SyslogConnections.WithLabelValues("tcp").Inc()
		go func() {
			defer s.wg.Done()
			defer func() { <-s.connSem }()
			defer metrics.SyslogConnections.WithLabelValues("tcp").Dec()
			s.handleTCPConn(ctx, conn, maxMsgLen)
		}()
	}
}

// handleTCPConn reads syslog messages from a single TCP connection.
// Supports newline-delimited and octet-counting framing.
func (s *SyslogListener) handleTCPConn(ctx context.Context, conn net.Conn, maxMsgLen int) {
	defer conn.Close()

	// Set idle timeout.
	idleTimeout := 60 * time.Second
	conn.SetDeadline(time.Now().Add(idleTimeout))

	reader := bufio.NewReaderSize(conn, maxMsgLen)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Try octet-counting first: peek to see if line starts with digits.
		msg, err := s.readSyslogMessage(reader, maxMsgLen)
		if err != nil {
			if !isClosedError(err) && !isTimeoutError(err) {
				// Only log non-routine errors.
				if err.Error() != "EOF" {
					log.Printf("[syslog] TCP read error from %s: %v", conn.RemoteAddr(), err)
				}
			}
			return
		}

		if len(msg) == 0 {
			continue
		}

		// Reset idle timeout on successful read.
		conn.SetDeadline(time.Now().Add(idleTimeout))

		// Wrap and deliver.
		metrics.SyslogMessages.WithLabelValues("tcp").Inc()
		event := wrapSyslogEvent(msg, "tcp", conn.RemoteAddr().String())
		if s.handler != nil {
			s.handler([]json.RawMessage{event})
		}
	}
}

// readSyslogMessage reads a single syslog message using octet-counting or newline framing.
func (s *SyslogListener) readSyslogMessage(reader *bufio.Reader, maxMsgLen int) (string, error) {
	// Peek at the first bytes to detect octet-counting.
	peek, err := reader.Peek(1)
	if err != nil {
		return "", err
	}

	// If first char is a digit, try octet-counting: "123 <PRI>..."
	if peek[0] >= '0' && peek[0] <= '9' {
		// Read until space to get the length.
		lenStr, err := reader.ReadString(' ')
		if err != nil {
			return "", err
		}
		lenStr = strings.TrimSpace(lenStr)
		msgLen, err := strconv.Atoi(lenStr)
		if err == nil && msgLen > 0 && msgLen <= maxMsgLen {
			// Valid octet count — read exactly that many bytes.
			buf := make([]byte, msgLen)
			n := 0
			for n < msgLen {
				r, err := reader.Read(buf[n:])
				n += r
				if err != nil {
					return string(buf[:n]), err
				}
			}
			return string(buf), nil
		}
		// Not a valid octet count — treat the lenStr + rest of line as a message.
		rest, err := reader.ReadString('\n')
		if err != nil {
			return lenStr + " " + rest, err
		}
		return strings.TrimRight(lenStr+" "+rest, "\r\n"), nil
	}

	// Newline-delimited framing.
	line, err := reader.ReadString('\n')
	if err != nil {
		if len(line) > 0 {
			return strings.TrimRight(line, "\r\n"), nil
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// serveUDP reads syslog datagrams from a UDP socket.
func (s *SyslogListener) serveUDP(ctx context.Context, pc net.PacketConn, maxMsgLen int) {
	buf := make([]byte, maxMsgLen)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set read deadline to allow periodic context checks.
		pc.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if isTimeoutError(err) {
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
				if !isClosedError(err) {
					log.Printf("[syslog] UDP read error: %v", err)
				}
				return
			}
		}

		if n == 0 {
			continue
		}

		msg := string(buf[:n])
		metrics.SyslogMessages.WithLabelValues("udp").Inc()
		event := wrapSyslogEvent(msg, "udp", addr.String())
		if s.handler != nil {
			s.handler([]json.RawMessage{event})
		}
	}
}

// wrapSyslogEvent wraps a raw syslog message in a JSON envelope for the pipeline.
func wrapSyslogEvent(rawMessage, transport, remoteAddr string) json.RawMessage {
	envelope := map[string]string{
		"source_type": "syslog",
		"raw_message": rawMessage,
		"transport":   transport,
		"remote_addr": remoteAddr,
	}
	data, _ := json.Marshal(envelope)
	return data
}

// isClosedError checks if an error is due to a closed connection/listener.
func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), "closed")
}

// isTimeoutError checks if an error is a network timeout.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}
