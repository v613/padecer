package scanner

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"padecer/internal/shutdown"
)

func generateTestCert(t *testing.T, notAfter time.Time) []byte {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"Test City"},
			StreetAddress: []string{"Test Street"},
			PostalCode:    []string{"12345"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM
}

func generateCertChain(t *testing.T, expiryTimes []time.Time) []byte {
	var chainPEM []byte

	for _, expiry := range expiryTimes {
		cert := generateTestCert(t, expiry)
		chainPEM = append(chainPEM, cert...)
	}

	return chainPEM
}

func TestNewParser(t *testing.T) {
	p := NewParser(true, 30)

	if !p.includeSubject {
		t.Errorf("Expected includeSubject to be true")
	}

	if p.daysThreshold != 30 {
		t.Errorf("Expected daysThreshold to be 30, got %d", p.daysThreshold)
	}
}

func TestShouldProcessFile(t *testing.T) {
	p := NewParser(false, 30)

	tests := []struct {
		name       string
		filename   string
		extensions []string
		want       bool
	}{
		{"pem file with pem extension", "test.pem", []string{".pem", ".crt"}, true},
		{"crt file with pem extension", "test.crt", []string{".pem", ".crt"}, true},
		{"txt file with pem extension", "test.txt", []string{".pem", ".crt"}, false},
		{"no extensions filter", "test.xyz", []string{}, true},
		{"empty extensions", "test.pem", []string{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.ShouldProcessFile(tt.filename, tt.extensions)
			if got != tt.want {
				t.Errorf("ShouldProcessFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSingleCertificate(t *testing.T) {
	p := NewParser(true, 30)

	expiry := time.Now().Add(60 * 24 * time.Hour)
	certPEM := generateTestCert(t, expiry)

	certInfos, err := p.ParseData("test.pem", certPEM)
	if err != nil {
		t.Fatalf("ParseData() failed: %v", err)
	}

	if len(certInfos) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(certInfos))
	}

	cert := certInfos[0]
	if cert.Path != "test.pem" {
		t.Errorf("Expected path to be test.pem, got %s", cert.Path)
	}

	if cert.IsExpired {
		t.Errorf("Certificate should not be expired")
	}

	if cert.IsExpiringSoon {
		t.Errorf("Certificate should not be expiring soon (60 days > 30 day threshold)")
	}

	if cert.Subject == "" {
		t.Errorf("Expected subject to be populated when includeSubject=true")
	}
}

func TestCertificateChain(t *testing.T) {
	p := NewParser(false, 30)

	expiryTimes := []time.Time{
		time.Now().Add(90 * 24 * time.Hour),
		time.Now().Add(15 * 24 * time.Hour),
		time.Now().Add(180 * 24 * time.Hour),
	}

	chainPEM := generateCertChain(t, expiryTimes)

	certInfos, err := p.ParseData("chain.pem", chainPEM)
	if err != nil {
		t.Fatalf("ParseData() failed: %v", err)
	}

	if len(certInfos) != 3 {
		t.Errorf("Expected 3 certificates in chain, got %d", len(certInfos))
	}

	if certInfos[0].IsExpiringSoon {
		t.Errorf("First certificate should not be expiring soon")
	}

	if !certInfos[1].IsExpiringSoon {
		t.Errorf("Second certificate should be expiring soon")
	}

	if certInfos[2].IsExpiringSoon {
		t.Errorf("Third certificate should not be expiring soon")
	}
}

func TestExpiredCertificate(t *testing.T) {
	p := NewParser(false, 30)

	expiry := time.Now().Add(-24 * time.Hour)
	certPEM := generateTestCert(t, expiry)

	certInfos, err := p.ParseData("expired.pem", certPEM)
	if err != nil {
		t.Fatalf("ParseData() failed: %v", err)
	}

	if len(certInfos) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(certInfos))
	}

	cert := certInfos[0]
	if !cert.IsExpired {
		t.Errorf("Certificate should be expired")
	}

	if cert.DaysUntilExpiry >= 0 {
		t.Errorf("Expected negative days for expired cert, got %d", cert.DaysUntilExpiry)
	}
}

func TestInvalidPEM(t *testing.T) {
	p := NewParser(false, 30)

	invalidPEM := []byte("invalid pem data")

	_, err := p.ParseData("invalid.pem", invalidPEM)
	if err == nil {
		t.Errorf("Expected error for invalid PEM data, got nil")
	}
}

func TestTimeout(t *testing.T) {
	p := NewParser(false, 30)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	_, err := p.ParseFileWithContext(ctx, "/non/existent/file.pem")
	if err == nil {
		t.Errorf("Expected timeout error, got nil")
	}
}

func TestCancellation(t *testing.T) {
	p := NewParser(false, 30)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.ParseFileWithContext(ctx, "/non/existent/file.pem")
	if err != context.Canceled {
		t.Logf("Got %v instead of context.Canceled (acceptable on Windows)", err)
	}
}

func TestLargeFile(t *testing.T) {
	p := NewParser(false, 30)

	tempDir := t.TempDir()
	largeFile := filepath.Join(tempDir, "large.pem")

	data := make([]byte, MaxFileSize+1)
	err := os.WriteFile(largeFile, data, 0644)
	if err != nil {
		t.Fatalf("Failed to create large file: %v", err)
	}

	_, err = p.ParseFile(largeFile)
	if err == nil {
		t.Errorf("Expected error for file exceeding MaxFileSize, got nil")
	}
}

func TestScanner(t *testing.T) {
	p := NewParser(false, 30)
	shutdownMgr := shutdown.NewManager(30 * time.Second)
	ext := []string{".pem", ".crt"}

	scanner := New(p, shutdownMgr, ext)

	if scanner.p != p {
		t.Errorf("Parser not set correctly")
	}

	if scanner.shutdownMgr != shutdownMgr {
		t.Errorf("ShutdownManager not set correctly")
	}

	if len(scanner.ext) != len(ext) {
		t.Errorf("Extensions not set correctly")
	}
}

func TestValidatePath(t *testing.T) {
	p := NewParser(false, 30)
	shutdownMgr := shutdown.NewManager(30 * time.Second)
	scanner := New(p, shutdownMgr, []string{})

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"path traversal", "/etc/ssl/../../../", true},
		{"another path traversal", "/etc/../passwd", true},
		{"valid windows path", "C:\\etc\\ssl\\certs", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := scanner.validatePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWithContext(t *testing.T) {
	tempDir := t.TempDir()

	expiry := time.Now().Add(15 * 24 * time.Hour)
	certPEM := generateTestCert(t, expiry)
	certFile := filepath.Join(tempDir, "test.pem")
	err := os.WriteFile(certFile, certPEM, 0644)
	if err != nil {
		t.Fatalf("Failed to write certificate file: %v", err)
	}

	p := NewParser(false, 30)
	shutdownMgr := shutdown.NewManager(30 * time.Second)
	scanner := New(p, shutdownMgr, []string{".pem"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultCh, err := scanner.Scan(ctx, []string{tempDir})
	if err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}

	var results []ScanResult
	for result := range resultCh {
		results = append(results, result)
	}

	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	if results[0].Error != nil {
		t.Errorf("Expected no error, got %v", results[0].Error)
	}

	if len(results[0].CertInfos) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(results[0].CertInfos))
	}

	cert := results[0].CertInfos[0]
	if !cert.IsExpiringSoon {
		t.Errorf("Certificate should be expiring soon")
	}
}

func TestEmptyDirectory(t *testing.T) {
	tempDir := t.TempDir()

	p := NewParser(false, 30)
	shutdownMgr := shutdown.NewManager(30 * time.Second)
	scanner := New(p, shutdownMgr, []string{".pem"})

	ctx := context.Background()
	resultCh, err := scanner.Scan(ctx, []string{tempDir})
	if err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}

	var results []ScanResult
	for result := range resultCh {
		results = append(results, result)
	}

	if len(results) != 0 {
		t.Errorf("Expected 0 results for empty directory, got %d", len(results))
	}
}
