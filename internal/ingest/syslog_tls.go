package ingest

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
)

// StartTLS begins the TLS syslog listener on the configured port.
// Must be called after Start() if TLS is configured.
func (s *SyslogListener) StartTLS(ctx context.Context) error {
	if s.cfg.TLSPort <= 0 {
		return nil // TLS disabled
	}

	if s.cfg.TLSCert == "" || s.cfg.TLSKey == "" {
		return fmt.Errorf("syslog tls: tls_cert and tls_key are required when tls_port is set")
	}

	tlsCfg, err := loadSyslogTLSConfig(s.cfg.TLSCert, s.cfg.TLSKey)
	if err != nil {
		return fmt.Errorf("syslog tls: %w", err)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.cfg.TLSPort))
	if err != nil {
		return fmt.Errorf("syslog tls listen: %w", err)
	}

	tlsLn := tls.NewListener(ln, tlsCfg)
	s.tlsLn = tlsLn

	maxMsgLen := s.cfg.MaxMessageLen
	if maxMsgLen <= 0 {
		maxMsgLen = 65536
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.serveTCP(ctx, tlsLn, maxMsgLen)
	}()

	log.Printf("[syslog] TLS listening on :%d", s.cfg.TLSPort)
	return nil
}

// loadSyslogTLSConfig loads the server certificate and configures TLS.
func loadSyslogTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading cert/key: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
