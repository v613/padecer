package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func createTestConfigFile(b *testing.B, cfg Config) string {
	tempFile := fmt.Sprintf("%s/config_bench_%d.json", b.TempDir(), time.Now().UnixNano())

	data, err := json.Marshal(cfg)
	if err != nil {
		b.Fatal(err)
	}

	err = os.WriteFile(tempFile, data, 0644)
	if err != nil {
		b.Fatal(err)
	}

	return tempFile
}

func BenchmarkConfigCreation(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		cfg := New()
		_ = cfg
	}
}

func BenchmarkConfigValidation(b *testing.B) {
	cfgs := []*Config{
		{
			Days:            30,
			Paths:           []string{"/etc/ssl/certs", "/var/lib/kubelet/pki"},
			IncludeSubject:  false,
			SendTo:          "",
			ShutdownTimeout: 30 * time.Second,
			Extensions:      []string{".pem", ".crt"},
		},
		{
			Days:            7,
			Paths:           []string{"/etc/ssl", "/opt/certs", "/usr/local/ssl"},
			IncludeSubject:  true,
			SendTo:          "http://monitoring.example.com:8080/alerts",
			ShutdownTimeout: 60 * time.Second,
			Extensions:      []string{".pem", ".crt", ".cer", ".key"},
		},
		{
			Days:            -1, // Invalid
			Paths:           []string{},
			IncludeSubject:  false,
			SendTo:          "",
			ShutdownTimeout: -1 * time.Second, // Invalid
			Extensions:      []string{},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, cfg := range cfgs {
			cfg.Validate()
		}
	}
}

func BenchmarkConfigFileLoading(b *testing.B) {
	testConfigs := []Config{
		{
			Days:            30,
			Paths:           []string{"/etc/ssl/certs"},
			IncludeSubject:  false,
			SendTo:          "",
			ShutdownTimeout: 30 * time.Second,
			Extensions:      []string{".pem"},
		},
		{
			Days:            7,
			Paths:           []string{"/etc/ssl/certs", "/var/lib/kubelet/pki", "/opt/ssl"},
			IncludeSubject:  true,
			SendTo:          "https://monitoring.company.com/api/alerts",
			ShutdownTimeout: 120 * time.Second,
			Extensions:      []string{".pem", ".crt", ".cer", ".key", ".p12"},
		},
	}

	for i, testCfg := range testConfigs {
		b.Run(fmt.Sprintf("Config%d", i+1), func(b *testing.B) {
			configFile := createTestConfigFile(b, testCfg)

			b.ResetTimer()
			b.ReportAllocs()

			for j := 0; j < b.N; j++ {
				cfg := New()
				cfg.ConfigFile = configFile
				err := cfg.LoadFromFile()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPathListParsing(b *testing.B) {
	pathStrings := []string{
		"/etc/ssl/certs",
		"/etc/ssl/certs,/var/lib/kubelet/pki",
		"/etc/ssl/certs, /var/lib/kubelet/pki, /opt/certificates, /usr/local/ssl",
		"/etc/ssl/certs,/var/lib/kubelet/pki,/opt/certificates,/usr/local/ssl,/home/user/certs,/tmp/ssl",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, pathStr := range pathStrings {
			paths := strings.Split(pathStr, ",")
			for j, path := range paths {
				paths[j] = strings.TrimSpace(path)
			}
		}
	}
}

func BenchmarkPathTraversalValidation(b *testing.B) {
	paths := []string{
		"/etc/ssl/certs",
		"/var/lib/kubelet/pki",
		"/usr/share/ca-certificates",
		"/etc/ssl/../etc/ssl/certs", // Contains ..
		"/etc/../../../etc/passwd",  // Contains ..
		"/etc/ssl/./certs",
		"C:\\Program Files\\Common Files\\SSL",
		"C:\\Windows\\System32\\config\\systemprofile",
		"/opt/certificates",
		"/home/user/.ssl/certs",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			contains := strings.Contains(path, "..")
			_ = contains
		}
	}
}

func BenchmarkConfigJSON(b *testing.B) {
	cfg := Config{
		Days:            30,
		Paths:           []string{"/etc/ssl/certs", "/var/lib/kubelet/pki", "/opt/certificates"},
		IncludeSubject:  true,
		SendTo:          "https://monitoring.example.com/api/v1/alerts",
		ShutdownTimeout: 60 * time.Second,
		Extensions:      []string{".pem", ".crt", ".cer", ".key"},
	}

	b.Run("Marshal", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := json.Marshal(cfg)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	data, _ := json.Marshal(cfg)

	b.Run("Unmarshal", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var newCfg Config
			err := json.Unmarshal(data, &newCfg)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkTimeoutParsing(b *testing.B) {
	timeoutStrings := []string{
		"30s",
		"1m",
		"5m30s",
		"1h",
		"2h30m45s",
		"invalid", // Will cause error
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, timeoutStr := range timeoutStrings {
			_, err := time.ParseDuration(timeoutStr)
			_ = err // Ignore errors for benchmark
		}
	}
}

func BenchmarkConfigCombinedOperations(b *testing.B) {
	testCfg := Config{
		Days:            7,
		Paths:           []string{"/etc/ssl/certs", "/var/lib/kubelet/pki"},
		IncludeSubject:  true,
		SendTo:          "http://monitoring.example.com:8080/webhook",
		ShutdownTimeout: 45 * time.Second,
		Extensions:      []string{".pem", ".crt", ".cer"},
	}

	configFile := createTestConfigFile(b, testCfg)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		cfg := New()
		cfg.ConfigFile = configFile

		err := cfg.LoadFromFile()
		if err != nil {
			b.Fatal(err)
		}

		err = cfg.Validate()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPathValidationAtScale(b *testing.B) {
	var paths []string
	for i := 0; i < 1000; i++ {
		paths = append(paths, fmt.Sprintf("/etc/ssl/certs/cert%d", i))
	}

	cfg := &Config{Paths: paths}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, path := range cfg.Paths {
			strings.Contains(path, "..")
		}
	}
}