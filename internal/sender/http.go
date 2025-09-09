package sender

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"padecer/internal/config"
	"padecer/internal/scanner"
)

const (
	DefaultTimeout = 10 * time.Second
	AlertTimeout   = 20 * time.Second
)

type AlertPayload struct {
	Host            string    `json:"host"`
	Timestamp       time.Time `json:"timestamp"`
	Level           string    `json:"level"`
	Message         string    `json:"message"`
	Path            string    `json:"path"`
	ExpirationDate  time.Time `json:"expirationDate"`
	DaysUntilExpiry int       `json:"daysUntilExpiry"`
	Subject         string    `json:"subject,omitempty"`
	SerialNumber    string    `json:"serialNumber,omitempty"`
}

type HTTPSender struct {
	client   *http.Client
	endpoint string
}

func NewHTTPSender(endpoint string) *HTTPSender {
	return &HTTPSender{
		client: &http.Client{
			Timeout: DefaultTimeout,
		},
		endpoint: endpoint,
	}
}

func (s *HTTPSender) SendAlert(ctx context.Context, certInfo *scanner.CertificateInfo) error {
	if s.endpoint == "" {
		return nil
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, AlertTimeout)
	defer cancel()

	p := AlertPayload{
		Host:            config.Hostname,
		Timestamp:       time.Now(),
		Level:           "WARN",
		Message:         "Certificate expiring soon",
		Path:            certInfo.Path,
		ExpirationDate:  certInfo.ExpirationDate,
		DaysUntilExpiry: certInfo.DaysUntilExpiry,
		Subject:         certInfo.Subject,
		SerialNumber:    certInfo.SerialNumber,
	}

	return s.send(timeoutCtx, p)
}

func (s *HTTPSender) send(ctx context.Context, p AlertPayload) error {
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func (s *HTTPSender) Close() error {
	s.client.CloseIdleConnections()
	return nil
}
