package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"padecer/internal/config"
	"padecer/internal/scanner"
	"padecer/internal/sender"
	"padecer/internal/shutdown"
)

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	shutdownMgr := shutdown.NewManager(30 * time.Second)
	go func() {
		sig := <-sigCh
		config.Log.Info("Received shutdown signal", "signal", sig.String())
		shutdownMgr.Shutdown()
		cancel()
	}()

	if err := execute(ctx, config.Hostname, shutdownMgr); err != nil {
		config.Log.Error("Application failed", "error", err)
		os.Exit(1)
	}
	config.Log.Info("Padecer shutdown completed")
}

func execute(ctx context.Context, h string, shutdownMgr *shutdown.Manager) error {
	cfg := config.New()
	if err := cfg.ParseFlags(); err != nil {
		return fmt.Errorf("failed to parse configuration: %w", err)
	}

	if cfg.ShutdownTimeout > 0 {
		shutdownMgr = shutdown.NewManager(cfg.ShutdownTimeout)
	}
	p := scanner.NewParser(cfg.IncludeSubject, cfg.Days)

	httpSender := sender.NewHTTPSender(cfg.SendTo)
	defer httpSender.Close()

	s := scanner.New(p, shutdownMgr, cfg.Extensions)
	config.Log.Info("Certificate scan configuration", "days_threshold", cfg.Days, "paths", cfg.Paths, "ext", cfg.Extensions)

	resultCh, err := s.Scan(ctx, cfg.Paths)
	if err != nil {
		return fmt.Errorf("failed to start scan: %w", err)
	}

	var processedCount, warningCount, errorCount int
	for result := range resultCh {
		if shutdownMgr.IsShuttingDown() {
			config.Log.Info("Shutdown requested, stopping processing")
			break
		}

		if result.Error != nil {
			errorCount++
			config.Log.Error("Scan error", "error", result.Error)
			continue
		}

		for _, certInfo := range result.CertInfos {
			processedCount++
			if certInfo.IsExpiringSoon {
				warningCount++
				fmt.Fprintf(os.Stderr, "%s::%s => %s\n", h, certInfo.Path, certInfo.ExpirationDate.Format("2006-01-02T15:04:05Z07:00"))

				if err := httpSender.SendAlert(ctx, certInfo); err != nil {
					config.Log.Error("Failed to send HTTP alert", "path", certInfo.Path, "error", err)
				}
			} else {
				outputCert := struct {
					Host            string `json:"host"`
					Path            string `json:"path"`
					Expires         string `json:"expires"`
					DaysUntilExpiry int    `json:"daysUntilExpiry"`
					Subject         string `json:"subject,omitempty"`
					SerialNumber    string `json:"serialNumber,omitempty"`
				}{
					Host:            h,
					Path:            certInfo.Path,
					Expires:         certInfo.ExpirationDate.Format("2006-01-02T15:04:05Z07:00"),
					DaysUntilExpiry: certInfo.DaysUntilExpiry,
					Subject:         certInfo.Subject,
					SerialNumber:    certInfo.SerialNumber,
				}

				if data, err := json.Marshal(outputCert); err == nil {
					fmt.Println(string(data))
				}
			}
		}
	}

	config.Log.Info("Scan completed", "processed", processedCount, "warnings", warningCount, "errors", errorCount)
	shutdownMgr.Wait()
	return nil
}
