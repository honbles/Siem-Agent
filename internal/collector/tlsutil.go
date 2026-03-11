//go:build windows

package collector

// tlsutil.go — helpers for building TLS clients that trust ObsidianWatch's
// self-signed CA certificates.
//
// The agent talks to two separate TLS endpoints:
//   - Backend :8443  → uses ca_file
//   - Management :80/:443 → uses management_ca_file (falls back to ca_file)
//
// When management_ca_file is empty AND management uses HTTPS, the agent
// automatically falls back to ca_file. This means if both backend and
// management share the same self-signed CA (the common case), you only
// need to set ca_file in agent.yaml.

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

// tlsConfigForCA builds a *tls.Config that trusts the given CA cert file.
// If caFile is empty, returns a default config (trusts system roots).
func tlsConfigForCA(caFile string) *tls.Config {
	if caFile == "" {
		return &tls.Config{}
	}
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return &tls.Config{}
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	return &tls.Config{RootCAs: pool}
}

// resolveCAFile returns the management CA file, falling back to the backend
// CA file if management_ca_file is not set. This handles the common case
// where both endpoints share the same self-signed CA.
func resolveCAFile(managementCAFile, backendCAFile string) string {
	if managementCAFile != "" {
		return managementCAFile
	}
	return backendCAFile
}

// httpClientForCA returns an *http.Client that trusts the given CA cert.
func httpClientForCA(caFile string) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfigForCA(caFile),
		},
	}
}

// wsDialerForCA returns a gorilla WebSocket dialer that trusts the given CA cert.
func wsDialerForCA(caFile string) websocket.Dialer {
	return websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		TLSClientConfig:  tlsConfigForCA(caFile),
	}
}
