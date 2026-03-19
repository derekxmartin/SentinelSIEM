package sources

import (
	"fmt"
	"strings"
)

// GenerateSnippet produces a configuration snippet for the given source
// in the requested format: toml, yaml, rsyslog, or pfsense.
func GenerateSnippet(src *SourceConfig, format string) (string, error) {
	switch strings.ToLower(format) {
	case "toml":
		return snippetTOML(src), nil
	case "yaml":
		return snippetYAML(src), nil
	case "rsyslog":
		return snippetRsyslog(src), nil
	case "pfsense":
		return snippetPfSense(src), nil
	default:
		return "", fmt.Errorf("unsupported snippet format: %q (use toml, yaml, rsyslog, or pfsense)", format)
	}
}

func snippetTOML(src *SourceConfig) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# AkesoSIEM source config for %s\n", src.Name))
	b.WriteString(fmt.Sprintf("# Type: %s | Parser: %s\n\n", src.Type, src.Parser))

	switch {
	case strings.HasPrefix(src.Protocol, "syslog"):
		b.WriteString("[syslog_output]\n")
		proto := "tcp"
		if src.Protocol == "syslog_udp" {
			proto = "udp"
		} else if src.Protocol == "syslog_tls" {
			proto = "tcp+tls"
		}
		b.WriteString(fmt.Sprintf("  protocol = %q\n", proto))
		b.WriteString(fmt.Sprintf("  target = \"<AKESO_HOST>:%d\"\n", syslogPort(src)))
		b.WriteString(fmt.Sprintf("  source_type = %q\n", src.Parser))
	default: // http
		b.WriteString("[http_output]\n")
		b.WriteString("  endpoint = \"https://<AKESO_HOST>:8080/api/v1/ingest\"\n")
		b.WriteString(fmt.Sprintf("  source_type = %q\n", src.Parser))
		b.WriteString("  api_key = \"<YOUR_API_KEY>\"\n")
		b.WriteString("  batch_size = 100\n")
		b.WriteString("  flush_interval = \"5s\"\n")
	}

	if len(src.ExpectedHosts) > 0 {
		b.WriteString(fmt.Sprintf("\n  # Expected hosts: %s\n", strings.Join(src.ExpectedHosts, ", ")))
	}

	return b.String()
}

func snippetYAML(src *SourceConfig) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# AkesoSIEM source config for %s\n", src.Name))
	b.WriteString(fmt.Sprintf("# Type: %s | Parser: %s\n\n", src.Type, src.Parser))

	switch {
	case strings.HasPrefix(src.Protocol, "syslog"):
		proto := "tcp"
		if src.Protocol == "syslog_udp" {
			proto = "udp"
		} else if src.Protocol == "syslog_tls" {
			proto = "tcp+tls"
		}
		b.WriteString("syslog_output:\n")
		b.WriteString(fmt.Sprintf("  protocol: %q\n", proto))
		b.WriteString(fmt.Sprintf("  target: \"<AKESO_HOST>:%d\"\n", syslogPort(src)))
		b.WriteString(fmt.Sprintf("  source_type: %q\n", src.Parser))
	default:
		b.WriteString("http_output:\n")
		b.WriteString("  endpoint: \"https://<AKESO_HOST>:8080/api/v1/ingest\"\n")
		b.WriteString(fmt.Sprintf("  source_type: %q\n", src.Parser))
		b.WriteString("  api_key: \"<YOUR_API_KEY>\"\n")
		b.WriteString("  batch_size: 100\n")
		b.WriteString("  flush_interval: \"5s\"\n")
	}

	return b.String()
}

func snippetRsyslog(src *SourceConfig) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# rsyslog config for forwarding to AkesoSIEM — %s\n", src.Name))
	b.WriteString("# Add this to /etc/rsyslog.d/akeso.conf\n\n")

	port := syslogPort(src)

	switch src.Protocol {
	case "syslog_tls":
		b.WriteString("# Load TLS module\n")
		b.WriteString("module(load=\"omfwd\")\n\n")
		b.WriteString("# TLS settings\n")
		b.WriteString("global(\n")
		b.WriteString("  defaultNetstreamDriverCAFile=\"/etc/rsyslog.d/akeso-ca.pem\"\n")
		b.WriteString(")\n\n")
		b.WriteString("# Forward all logs via TLS\n")
		b.WriteString("action(\n")
		b.WriteString("  type=\"omfwd\"\n")
		b.WriteString(fmt.Sprintf("  target=\"<AKESO_HOST>\" port=\"%d\" protocol=\"tcp\"\n", port))
		b.WriteString("  streamDriver=\"gtls\" streamDriverMode=\"1\" streamDriverAuthMode=\"x509/name\"\n")
		b.WriteString(")\n")
	case "syslog_udp":
		b.WriteString(fmt.Sprintf("*.* @<AKESO_HOST>:%d\n", port))
	default: // syslog_tcp
		b.WriteString(fmt.Sprintf("*.* @@<AKESO_HOST>:%d\n", port))
	}

	return b.String()
}

func snippetPfSense(src *SourceConfig) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# pfSense syslog configuration for AkesoSIEM — %s\n", src.Name))
	b.WriteString("# Navigate to: Status > System Logs > Settings\n\n")
	b.WriteString("# 1. Check \"Enable Remote Logging\"\n")
	b.WriteString("# 2. Set the following:\n")
	b.WriteString(fmt.Sprintf("#    Remote log servers: <AKESO_HOST>:%d\n", syslogPort(src)))
	b.WriteString("#    Remote Syslog Contents: Everything\n")

	if src.Protocol == "syslog_udp" {
		b.WriteString("#    IP Protocol: UDP (default)\n")
	} else {
		b.WriteString("#    IP Protocol: TCP\n")
	}

	b.WriteString("#\n")
	b.WriteString("# 3. Click Save\n")
	b.WriteString("#\n")
	b.WriteString("# Note: pfSense sends RFC 3164 format by default.\n")
	b.WriteString(fmt.Sprintf("# Parser %q will handle normalization.\n", src.Parser))

	return b.String()
}

func syslogPort(src *SourceConfig) int {
	if src.Port > 0 {
		return src.Port
	}
	return 1514 // default syslog port
}
