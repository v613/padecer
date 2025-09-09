package scanner

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"padecer/internal/config"
	"padecer/internal/shutdown"
)

const (
	workers     = 10
	MaxDepth    = 20
	BuffSize    = 100
	MaxFileSize = 100 * 1024 * 1024 // 100MB limit
	CertTimeout = 1 * time.Minute   // Per-certificate timeout
)

type CertificateInfo struct {
	Path            string    `json:"path"`
	Subject         string    `json:"subject,omitempty"`
	ExpirationDate  time.Time `json:"expires"`
	DaysUntilExpiry int       `json:"daysUntilExpiry"`
	IsExpired       bool      `json:"isExpired"`
	IsExpiringSoon  bool      `json:"isExpiringSoon"`
	SerialNumber    string    `json:"serialNumber,omitempty"`
	Issuer          string    `json:"issuer,omitempty"`
}

type Parser struct {
	includeSubject bool
	daysThreshold  int
}

type Scanner struct {
	p           *Parser
	shutdownMgr *shutdown.Manager
	ext         []string
}

type ScanResult struct {
	CertInfos []*CertificateInfo
	Error     error
}

func New(p *Parser, shutdownMgr *shutdown.Manager, ext []string) *Scanner {
	return &Scanner{
		p:           p,
		shutdownMgr: shutdownMgr,
		ext:         ext,
	}
}

func NewParser(includeSubject bool, daysThreshold int) *Parser {
	return &Parser{
		includeSubject: includeSubject,
		daysThreshold:  daysThreshold,
	}
}

func (s *Scanner) Scan(ctx context.Context, paths []string) (<-chan ScanResult, error) {
	resultCh := make(chan ScanResult, BuffSize)
	fileCh := make(chan string, BuffSize)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(fileCh)
		s.walkPaths(ctx, paths, fileCh)
	}()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.processFiles(ctx, fileCh, resultCh)
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	return resultCh, nil
}

func (s *Scanner) walkPaths(ctx context.Context, paths []string, fileCh chan<- string) {
	for _, rootPath := range paths {
		if s.shutdownMgr.IsShuttingDown() {
			return
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		s.walkPath(ctx, rootPath, fileCh, 0)
	}
}

func (s *Scanner) walkPath(ctx context.Context, rootPath string, fileCh chan<- string, depth int) {
	if depth > MaxDepth {
		config.Log.Warn("Maximum directory depth exceeded", "path", rootPath, "depth", depth)
		return
	}

	if s.shutdownMgr.IsShuttingDown() {
		return
	}

	select {
	case <-ctx.Done():
		return
	default:
	}

	if err := s.validatePath(rootPath); err != nil {
		config.Log.Warn("Invalid path detected", "path", rootPath, "error", err)
		return
	}

	entries, err := os.ReadDir(rootPath)
	if err != nil {
		config.Log.Warn("Failed to read directory", "path", rootPath, "error", err)
		return
	}

	for _, entry := range entries {
		if s.shutdownMgr.IsShuttingDown() {
			return
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		fullPath := filepath.Join(rootPath, entry.Name())

		if entry.IsDir() {
			s.walkPath(ctx, fullPath, fileCh, depth+1)
		} else if s.p.ShouldProcessFile(entry.Name(), s.ext) {
			select {
			case fileCh <- fullPath:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *Scanner) processFiles(ctx context.Context, fileCh <-chan string, resultCh chan<- ScanResult) {
	for {
		select {
		case <-ctx.Done():
			return
		case fp, ok := <-fileCh:
			if !ok {
				return
			}

			if s.shutdownMgr.IsShuttingDown() {
				return
			}

			s.shutdownMgr.Add(1)
			result := s.processFileWithContext(ctx, fp)
			s.shutdownMgr.Done()

			select {
			case resultCh <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *Scanner) processFileWithContext(parentCtx context.Context, fp string) ScanResult {
	ctx, cancel := context.WithTimeout(parentCtx, CertTimeout)
	defer cancel()

	certInfos, err := s.p.ParseFileWithContext(ctx, fp)
	if err != nil {
		if err == context.DeadlineExceeded {
			config.Log.Warn("Certificate parsing timeout", "path", fp, "timeout", CertTimeout)
			return ScanResult{Error: fmt.Errorf("timeout parsing %s after %v", fp, CertTimeout)}
		}
		if err == context.Canceled {
			config.Log.Debug("Certificate parsing cancelled", "path", fp)
			return ScanResult{Error: fmt.Errorf("cancelled parsing %s", fp)}
		}
		config.Log.Debug("Failed to parse certificate", "path", fp, "error", err)
		return ScanResult{Error: fmt.Errorf("failed to parse %s: %w", fp, err)}
	}

	return ScanResult{CertInfos: certInfos}
}

func (s *Scanner) validatePath(path string) error {
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal detected")
	}

	cleanPath := filepath.Clean(path)
	if cleanPath != path && !strings.HasSuffix(path, string(filepath.Separator)) {
		return fmt.Errorf("suspicious path detected")
	}

	return nil
}

func (p *Parser) ParseFile(fp string) ([]*CertificateInfo, error) {
	return p.ParseFileWithContext(context.Background(), fp)
}

func (p *Parser) ParseFileWithContext(ctx context.Context, fp string) ([]*CertificateInfo, error) {
	fi, err := os.Stat(fp)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	if fi.Size() > MaxFileSize {
		return nil, fmt.Errorf("file size exceeds maximum allowed size of %d bytes", MaxFileSize)
	}

	data, err := p.readFileWithContext(ctx, fp)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return p.ParseData(fp, data)
}

func (p *Parser) ParseData(fp string, data []byte) ([]*CertificateInfo, error) {
	var certs []*CertificateInfo
	remaining := data

	// Try PEM format first - process all certificate blocks
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, p.buildCertificateInfo(fp, cert))
		}

		remaining = rest
	}

	// If no PEM certificates found, try DER format
	if len(certs) == 0 {
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		certs = append(certs, p.buildCertificateInfo(fp, cert))
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in file")
	}

	return certs, nil
}

func (p *Parser) buildCertificateInfo(fp string, cert *x509.Certificate) *CertificateInfo {
	now := time.Now()
	days := int(cert.NotAfter.Sub(now).Hours() / 24)

	info := &CertificateInfo{
		Path:            fp,
		ExpirationDate:  cert.NotAfter,
		DaysUntilExpiry: days,
		IsExpired:       cert.NotAfter.Before(now),
		IsExpiringSoon:  days <= p.daysThreshold && days >= 0,
		SerialNumber:    cert.SerialNumber.String(),
	}

	if p.includeSubject {
		info.Subject = cert.Subject.String()
		info.Issuer = cert.Issuer.String()
	}

	return info
}

func (p *Parser) ShouldProcessFile(f string, ext []string) bool {
	if len(ext) == 0 {
		return true
	}

	for _, ext := range ext {
		if len(f) >= len(ext) && f[len(f)-len(ext):] == ext {
			return true
		}
	}

	return false
}

func (p *Parser) readFileWithContext(ctx context.Context, fp string) ([]byte, error) {
	done := make(chan struct{})
	var data []byte
	var err error

	go func() {
		defer close(done)
		data, err = os.ReadFile(fp)
	}()

	select {
	case <-done:
		return data, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
