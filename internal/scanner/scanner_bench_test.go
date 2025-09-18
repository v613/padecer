package scanner

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"padecer/internal/shutdown"
)

func generateBenchmarkCert(size int) []byte {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Benchmark Org"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"Benchmark City"},
			StreetAddress: []string{"Benchmark Street"},
			PostalCode:    []string{"12345"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	if size == 1 {
		return certPEM
	}

	var chain []byte
	for i := 0; i < size; i++ {
		chain = append(chain, certPEM...)
	}
	return chain
}

func BenchmarkSingleCertificateParsing(b *testing.B) {
	p := NewParser(false, 30)
	certPEM := generateBenchmarkCert(1)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := p.ParseData("bench.pem", certPEM)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSingleCertificateParsingWithSubject(b *testing.B) {
	p := NewParser(true, 30)
	certPEM := generateBenchmarkCert(1)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := p.ParseData("bench.pem", certPEM)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCertificateChainParsing(b *testing.B) {
	p := NewParser(false, 30)

	sizes := []int{5, 10, 25, 50}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Chain%d", size), func(b *testing.B) {
			chainPEM := generateBenchmarkCert(size)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				certs, err := p.ParseData("bench.pem", chainPEM)
				if err != nil {
					b.Fatal(err)
				}
				if len(certs) != size {
					b.Fatalf("Expected %d certs, got %d", size, len(certs))
				}
			}
		})
	}
}

func BenchmarkCertificateInfoBuilding(b *testing.B) {
	p := NewParser(true, 30)

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = p.buildCertificateInfo("test.pem", cert)
	}
}

func BenchmarkShouldProcessFile(b *testing.B) {
	p := NewParser(false, 30)
	extensions := []string{".pem", ".crt", ".cer", ".key"}

	testFiles := []string{
		"cert.pem",
		"cert.crt",
		"cert.cer",
		"cert.key",
		"cert.txt",
		"certificate.pem",
		"very-long-certificate-filename-with-extension.pem",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, f := range testFiles {
			p.ShouldProcessFile(f, extensions)
		}
	}
}

func BenchmarkDERvsPEMParsing(b *testing.B) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	p := NewParser(false, 30)

	b.Run("PEM", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := p.ParseData("test.pem", certPEM)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("DER", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := p.ParseData("test.der", certDER)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkConcurrentScanning(b *testing.B) {
	tempDir := b.TempDir()
	certPEM := generateBenchmarkCert(1)

	fileCounts := []int{10, 50, 100, 500}

	for _, count := range fileCounts {
		b.Run(fmt.Sprintf("Files%d", count), func(b *testing.B) {
			for i := 0; i < count; i++ {
				f := fmt.Sprintf("%s/cert%d.pem", tempDir, i)
				os.WriteFile(f, certPEM, 0644)
			}

			p := NewParser(false, 30)
			shutdownMgr := shutdown.NewManager(30 * time.Second)
			scanner := New(p, shutdownMgr, []string{".pem"})

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				ctx := context.Background()
				resultCh, err := scanner.Scan(ctx, []string{tempDir})
				if err != nil {
					b.Fatal(err)
				}

				var resultCount int
				for range resultCh {
					resultCount++
				}

				if resultCount != count {
					b.Fatalf("Expected %d results, got %d", count, resultCount)
				}
			}
		})
	}
}

func BenchmarkPathValidation(b *testing.B) {
	p := NewParser(false, 30)
	shutdownMgr := shutdown.NewManager(30 * time.Second)
	scanner := New(p, shutdownMgr, []string{})

	paths := []string{
		"/etc/ssl/certs",
		"/var/lib/kubelet/pki",
		"/usr/share/ca-certificates",
		"/etc/pki/tls/certs",
		"C:\\Program Files\\Common Files\\SSL",
		"C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\INetCookies",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			scanner.validatePath(path)
		}
	}
}

func BenchmarkChannelOperations(b *testing.B) {
	tempDir := b.TempDir()
	certPEM := generateBenchmarkCert(1)

	for i := 0; i < 100; i++ {
		f := fmt.Sprintf("%s/cert%d.pem", tempDir, i)
		os.WriteFile(f, certPEM, 0644)
	}

	p := NewParser(false, 30)
	shutdownMgr := shutdown.NewManager(30 * time.Second)
	scanner := New(p, shutdownMgr, []string{".pem"})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		fileCh := make(chan string, BuffSize)
		resultCh := make(chan ScanResult, BuffSize)

		go func() {
			defer close(fileCh)
			scanner.walkPaths(ctx, []string{tempDir}, fileCh)
		}()

		go func() {
			defer close(resultCh)
			scanner.processFiles(ctx, fileCh, resultCh)
		}()

		for range resultCh {
		}
	}
}