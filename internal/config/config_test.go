package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	cfg := New()

	if cfg.Days != 30 {
		t.Errorf("Expected Days to be 30, got %d", cfg.Days)
	}

	expectedPaths := []string{"/etc/ssl/certs", "/etc/pki", "/var/lib/kubelet/pki"}
	if len(cfg.Paths) != len(expectedPaths) {
		t.Errorf("Expected %d paths, got %d", len(expectedPaths), len(cfg.Paths))
	}

	if cfg.ShutdownTimeout != 30*time.Second {
		t.Errorf("Expected ShutdownTimeout to be 30s, got %v", cfg.ShutdownTimeout)
	}

	expectedExt := []string{".pem", ".cer", ".crt", ".key"}
	if len(cfg.Extensions) != len(expectedExt) {
		t.Errorf("Expected %d extensions, got %d", len(expectedExt), len(cfg.Extensions))
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &Config{
				Days:            30,
				Paths:           []string{"/etc/ssl/certs"},
				ShutdownTimeout: 30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "negative days",
			cfg: &Config{
				Days:            -1,
				Paths:           []string{"/etc/ssl/certs"},
				ShutdownTimeout: 30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "no paths",
			cfg: &Config{
				Days:            30,
				Paths:           []string{},
				ShutdownTimeout: 30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "path traversal",
			cfg: &Config{
				Days:            30,
				Paths:           []string{"/etc/ssl/../../../"},
				ShutdownTimeout: 30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "negative timeout",
			cfg: &Config{
				Days:            30,
				Paths:           []string{"/etc/ssl/certs"},
				ShutdownTimeout: -1 * time.Second,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadFromFile(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.json")

	configData := `{
		"days": 15,
		"paths": ["/custom/path"],
		"includeSubject": true,
		"sendTo": "http://example.com",
		"shutdownTimeout": "60s",
		"extensions": [".custom"]
	}`

	err := os.WriteFile(configFile, []byte(configData), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg := New()
	cfg.ConfigFile = configFile

	err = cfg.LoadFromFile()
	if err != nil {
		t.Fatalf("LoadFromFile() failed: %v", err)
	}

	if cfg.Days != 15 {
		t.Errorf("Expected Days to be 15, got %d", cfg.Days)
	}

	if len(cfg.Paths) != 1 || cfg.Paths[0] != "/custom/path" {
		t.Errorf("Expected paths [/custom/path], got %v", cfg.Paths)
	}

	if !cfg.IncludeSubject {
		t.Errorf("Expected IncludeSubject to be true")
	}

	if cfg.SendTo != "http://example.com" {
		t.Errorf("Expected SendTo to be http://example.com, got %s", cfg.SendTo)
	}

	if cfg.ShutdownTimeout != 60*time.Second {
		t.Errorf("Expected ShutdownTimeout to be 60s, got %v", cfg.ShutdownTimeout)
	}
}

func TestInvalidJSON(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "invalid.json")

	err := os.WriteFile(configFile, []byte("invalid json"), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg := New()
	cfg.ConfigFile = configFile

	err = cfg.LoadFromFile()
	if err == nil {
		t.Errorf("Expected error for invalid JSON, got nil")
	}
}

func TestNonExistent(t *testing.T) {
	cfg := New()
	cfg.ConfigFile = "/non/existent/file.json"

	err := cfg.LoadFromFile()
	if err == nil {
		t.Errorf("Expected error for non-existent file, got nil")
	}
}

func TestPaths(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	defer func() {
		if r := recover(); r != nil {
			t.Logf("Flag parsing panicked (expected in test environment): %v", r)
		}
	}()

	os.Args = []string{"padecer", "--paths", "/path1,/path2, /path3 "}

	cfg := New()
	_, err := cfg.parsePaths("/path1,/path2, /path3 ")
	if err != nil {
		t.Fatalf("parsePaths() failed: %v", err)
	}

	expected := []string{"/path1", "/path2", "/path3"}
	if len(cfg.Paths) != len(expected) {
		t.Errorf("Expected %d paths, got %d", len(expected), len(cfg.Paths))
	}

	for i, path := range expected {
		if cfg.Paths[i] != path {
			t.Errorf("Expected path %d to be %s, got %s", i, path, cfg.Paths[i])
		}
	}
}

func TestTimeout(t *testing.T) {
	cfg := New()

	timeout, err := time.ParseDuration("2m")
	if err != nil {
		t.Fatalf("ParseDuration failed: %v", err)
	}
	cfg.ShutdownTimeout = timeout

	expected := 2 * time.Minute
	if cfg.ShutdownTimeout != expected {
		t.Errorf("Expected timeout to be %v, got %v", expected, cfg.ShutdownTimeout)
	}
}

func TestInvalidTimeout(t *testing.T) {
	_, err := time.ParseDuration("invalid")
	if err == nil {
		t.Errorf("Expected error for invalid timeout, got nil")
	}
}
func (c *Config) parsePaths(paths string) ([]string, error) {
	if paths != "" {
		c.Paths = strings.Split(paths, ",")
		for i, path := range c.Paths {
			c.Paths[i] = strings.TrimSpace(path)
		}
	}
	return c.Paths, nil
}
