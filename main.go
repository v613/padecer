package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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

	cfg := config.New()
	if err := cfg.ParseFlags(); err != nil {
		config.Log.Error("Failed to parse configuration", "error", err)
		os.Exit(1)
	}

	if cfg.Server {
		if err := runServer(ctx, cfg, shutdownMgr); err != nil {
			config.Log.Error("Server failed", "error", err)
			os.Exit(1)
		}
	} else {
		if err := execute(ctx, config.Hostname, shutdownMgr, cfg); err != nil {
			config.Log.Error("Application failed", "error", err)
			os.Exit(1)
		}
	}
	config.Log.Info("Padecer shutdown completed")
}

func execute(ctx context.Context, h string, shutdownMgr *shutdown.Manager, cfg *config.Config) error {

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

type Alert struct {
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

func runServer(ctx context.Context, cfg *config.Config, shutdownMgr *shutdown.Manager) error {
	_ = shutdownMgr
	alertsFile := "frontend/alerts.json"

	http.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		handleAlert(w, r, alertsFile)
	})

	http.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		handleGetAlerts(w, r, alertsFile)
	})

	http.Handle("/", http.FileServer(http.Dir("frontend/")))

	addr := fmt.Sprintf(":%d", cfg.Port)
	server := &http.Server{
		Addr:    addr,
		Handler: nil,
	}

	go func() {
		<-ctx.Done()
		config.Log.Info("Shutting down HTTP server")
		server.Shutdown(context.Background())
	}()

	config.Log.Info("Dashboard running", "port", cfg.Port, "endpoint", fmt.Sprintf("http://localhost:%d/alerts", cfg.Port))
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server failed: %w", err)
	}

	return nil
}

func handleAlert(w http.ResponseWriter, r *http.Request, f string) {
	var alert Alert
	if err := json.NewDecoder(r.Body).Decode(&alert); err != nil {
		config.Log.Error("Invalid JSON payload", "error", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if alert.Host == "" || alert.Path == "" || alert.ExpirationDate.IsZero() {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now()
	}

	alerts, err := loadAlerts(f)
	if err != nil {
		config.Log.Error("Failed to load alerts", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	existingIndex := -1
	for i, a := range alerts {
		if a.Host == alert.Host && a.Path == alert.Path {
			existingIndex = i
			break
		}
	}

	if existingIndex >= 0 {
		alerts[existingIndex] = alert
	} else {
		alerts = append(alerts, alert)
	}

	if err := saveAlerts(f, alerts...); err != nil {
		config.Log.Error("Failed to save alerts", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	config.Log.Info("Alert received", "host", alert.Host, "path", alert.Path, "expires", alert.ExpirationDate.Format("2006-01-02T15:04:05Z07:00"))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Alert received successfully"})
}

func handleGetAlerts(w http.ResponseWriter, r *http.Request, alertsFile string) {
	_ = r
	alerts, err := loadAlerts(alertsFile)
	if err != nil {
		config.Log.Error("Failed to load alerts", "error", err)
		http.Error(w, "Failed to load alerts", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func loadAlerts(filename string) ([]Alert, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return []Alert{}, nil
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var alerts []Alert
	if err := json.Unmarshal(data, &alerts); err != nil {
		return nil, err
	}

	return alerts, nil
}

func saveAlerts(f string, a ...Alert) error {
	if err := os.MkdirAll(filepath.Dir(f), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(f, data, 0644)
}
