package sender

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"padecer/internal/scanner"
)

func createTestCertInfo() *scanner.CertificateInfo {
	return &scanner.CertificateInfo{
		Path:            "/etc/ssl/certs/test.pem",
		Subject:         "CN=Test Certificate,O=Test Org,C=US",
		ExpirationDate:  time.Now().Add(15 * 24 * time.Hour),
		DaysUntilExpiry: 15,
		IsExpired:       false,
		IsExpiringSoon:  true,
		SerialNumber:    "1234567890ABCDEF",
		Issuer:          "CN=Test CA,O=Test CA Org,C=US",
	}
}

func BenchmarkAlertPayloadMarshaling(b *testing.B) {
	certInfo := createTestCertInfo()

	p := AlertPayload{
		Host:            "test-host",
		Timestamp:       time.Now(),
		Level:           "WARN",
		Message:         "Certificate expiring soon",
		Path:            certInfo.Path,
		ExpirationDate:  certInfo.ExpirationDate,
		DaysUntilExpiry: certInfo.DaysUntilExpiry,
		Subject:         certInfo.Subject,
		SerialNumber:    certInfo.SerialNumber,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(p)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHTTPRequestCreation(b *testing.B) {
	certInfo := createTestCertInfo()
	endpoint := "http://localhost:8080/alerts"

	p := AlertPayload{
		Host:            "test-host",
		Timestamp:       time.Now(),
		Level:           "WARN",
		Message:         "Certificate expiring soon",
		Path:            certInfo.Path,
		ExpirationDate:  certInfo.ExpirationDate,
		DaysUntilExpiry: certInfo.DaysUntilExpiry,
		Subject:         certInfo.Subject,
		SerialNumber:    certInfo.SerialNumber,
	}

	data, _ := json.Marshal(p)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, nil)
		if err != nil {
			b.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		_ = req
		_ = data
	}
}

func BenchmarkHTTPSenderCreation(b *testing.B) {
	endpoints := []string{
		"http://localhost:8080/alerts",
		"https://monitoring.example.com/webhooks/alerts",
		"http://10.0.0.1:9090/api/v1/alerts",
		"",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, endpoint := range endpoints {
			sender := NewHTTPSender(endpoint)
			sender.Close()
		}
	}
}

func BenchmarkSendAlert(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender := NewHTTPSender(server.URL)
	defer sender.Close()

	certInfo := createTestCertInfo()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := sender.SendAlert(ctx, certInfo)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSendAlertWithTimeout(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender := NewHTTPSender(server.URL)
	defer sender.Close()

	certInfo := createTestCertInfo()

	timeouts := []time.Duration{
		100 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
		5 * time.Second,
	}

	for _, timeout := range timeouts {
		b.Run(fmt.Sprintf("Timeout%v", timeout), func(b *testing.B) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				sender.SendAlert(ctx, certInfo)
			}
		})
	}
}

func BenchmarkSendAlertEmptyEndpoint(b *testing.B) {
	sender := NewHTTPSender("")
	defer sender.Close()

	certInfo := createTestCertInfo()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := sender.SendAlert(ctx, certInfo)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMultipleConcurrentAlerts(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender := NewHTTPSender(server.URL)
	defer sender.Close()

	certInfo := createTestCertInfo()
	ctx := context.Background()

	concurrencyLevels := []int{1, 5, 10, 25}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("Concurrency%d", concurrency), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					err := sender.SendAlert(ctx, certInfo)
					if err != nil {
						b.Error(err)
					}
				}
			})
		})
	}
}

func BenchmarkAlertPayloadSizes(b *testing.B) {
	baseCertInfo := createTestCertInfo()

	subjects := []string{
		"CN=Short",
		"CN=Medium Certificate Name,O=Test Organization,C=US",
		"CN=Very Long Certificate Name With Many Fields,O=Test Organization Name,OU=Department Name,L=City Name,ST=State Name,C=US,emailAddress=test@example.com",
	}

	for i, subject := range subjects {
		b.Run(fmt.Sprintf("SubjectSize%d", i+1), func(b *testing.B) {
			certInfo := *baseCertInfo
			certInfo.Subject = subject

			p := AlertPayload{
				Host:            "test-host",
				Timestamp:       time.Now(),
				Level:           "WARN",
				Message:         "Certificate expiring soon",
				Path:            certInfo.Path,
				ExpirationDate:  certInfo.ExpirationDate,
				DaysUntilExpiry: certInfo.DaysUntilExpiry,
				Subject:         certInfo.Subject,
				SerialNumber:    certInfo.SerialNumber,
			}

			b.ResetTimer()
			b.ReportAllocs()

			for j := 0; j < b.N; j++ {
				_, err := json.Marshal(p)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}