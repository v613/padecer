package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

type Config struct {
	Days            int           `json:"days"`
	Paths           []string      `json:"paths"`
	APaths          []string      `json:"-"`
	IncludeSubject  bool          `json:"includeSubject"`
	SendTo          string        `json:"sendTo"`
	ConfigFile      string        `json:"-"`
	ShutdownTimeout time.Duration `json:"shutdownTimeout"`
	Extensions      []string      `json:"extensions"`
}

var (
	Log         *slog.Logger
	Hostname, _ = os.Hostname()
)

func init() {
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			_ = groups
			if a.Key == slog.TimeKey {
				return slog.Attr{
					Key:   "time",
					Value: slog.StringValue(a.Value.Time().Format(time.RFC3339)),
				}
			}
			return a
		},
	}
	handler := slog.NewJSONHandler(os.Stderr, opts).WithAttrs([]slog.Attr{
		slog.String("host", Hostname),
		slog.String("date", time.Now().Format("2006-01-02")),
	})

	Log = slog.New(handler)
}

func New() *Config {
	return &Config{
		Days:            30,
		Paths:           []string{"/etc/ssl/certs", "/etc/pki", "/var/lib/kubelet/pki"},
		ShutdownTimeout: 30 * time.Second,
		Extensions:      []string{".pem", ".cer", ".crt", ".key"},
	}
}

func (c *Config) ParseFlags() error {
	var paths string
	var apaths string
	var t string

	flag.IntVar(&c.Days, "days", c.Days, "Alert threshold in days before expiration")
	flag.StringVar(&paths, "paths", "", "Comma-separated list of paths to scan for certificates (replaces defaults)")
	flag.StringVar(&apaths, "apaths", "", "Comma-separated list of additional paths to append to defaults")
	flag.BoolVar(&c.IncludeSubject, "include-subject", c.IncludeSubject, "Include certificate subject in output")
	flag.StringVar(&c.SendTo, "send-to", c.SendTo, "IP or hostname to send warnings via HTTP request")
	flag.StringVar(&c.ConfigFile, "config", "", "JSON configuration file path")
	flag.StringVar(&t, "shutdown-timeout", "30s", "Maximum time to wait for graceful shutdown")
	flag.Parse()

	if paths != "" {
		c.Paths = strings.Split(paths, ",")
		for i, path := range c.Paths {
			c.Paths[i] = strings.TrimSpace(path)
		}
	}

	if apaths != "" {
		c.APaths = strings.Split(apaths, ",")
		for i, path := range c.APaths {
			c.APaths[i] = strings.TrimSpace(path)
		}
		c.Paths = append(c.Paths, c.APaths...)
	}

	if t != "" {
		timeout, err := time.ParseDuration(t)
		if err != nil {
			return fmt.Errorf("invalid shutdown timeout: %w", err)
		}
		c.ShutdownTimeout = timeout
	}

	if c.ConfigFile != "" {
		if err := c.LoadFromFile(); err != nil {
			return fmt.Errorf("failed to load config file: %w", err)
		}
	}

	return c.Validate()
}

func (c *Config) LoadFromFile() error {
	data, err := os.ReadFile(c.ConfigFile)
	if err != nil {
		return err
	}

	var fileCfg Config
	if err := json.Unmarshal(data, &fileCfg); err != nil {
		return err
	}

	c.Days = fileCfg.Days
	c.Paths = fileCfg.Paths
	c.IncludeSubject = fileCfg.IncludeSubject
	c.SendTo = fileCfg.SendTo
	c.ShutdownTimeout = fileCfg.ShutdownTimeout
	c.Extensions = fileCfg.Extensions
	return nil
}

func (c *Config) Validate() error {
	if c.Days < 0 {
		return fmt.Errorf("days threshold cannot be negative")
	}

	if len(c.Paths) == 0 {
		return fmt.Errorf("at least one path must be specified")
	}

	for _, path := range c.Paths {
		if strings.Contains(path, "..") {
			return fmt.Errorf("path traversal detected in path: %s", path)
		}
	}

	if c.ShutdownTimeout < 0 {
		return fmt.Errorf("shutdown timeout cannot be negative")
	}
	return nil
}
