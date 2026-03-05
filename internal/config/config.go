package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level agent configuration.
type Config struct {
	Agent     AgentConfig     `yaml:"agent"`
	Collector CollectorConfig `yaml:"collector"`
	Forwarder ForwarderConfig `yaml:"forwarder"`
	Queue     QueueConfig     `yaml:"queue"`
	Log       LogConfig       `yaml:"log"`
}

type AgentConfig struct {
	// ID uniquely identifies this agent. If empty, the machine hostname is used.
	ID      string `yaml:"id"`
	Version string `yaml:"version"`
}

type CollectorConfig struct {
	EventLog EventLogConfig `yaml:"event_log"`
	Sysmon   SysmonConfig   `yaml:"sysmon"`
	Network  NetworkConfig  `yaml:"network"`
	Process  ProcessConfig  `yaml:"process"`
	Registry RegistryConfig `yaml:"registry"`
}

type EventLogConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Channels []string `yaml:"channels"`
	// Batch read interval
	PollInterval time.Duration `yaml:"poll_interval"`
}

type SysmonConfig struct {
	Enabled bool `yaml:"enabled"`
}

type NetworkConfig struct {
	Enabled      bool          `yaml:"enabled"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

type ProcessConfig struct {
	Enabled bool `yaml:"enabled"`
}

type RegistryConfig struct {
	Enabled bool     `yaml:"enabled"`
	Keys    []string `yaml:"keys"`
}

type ForwarderConfig struct {
	BackendURL    string        `yaml:"backend_url"`
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	// mTLS
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
	// API key fallback (no mTLS)
	APIKey string `yaml:"api_key"`
}

type QueueConfig struct {
	// Path to local SQLite file used for offline buffering
	DBPath  string `yaml:"db_path"`
	MaxRows int    `yaml:"max_rows"`
}

type LogConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // text, json
}

// Load reads and validates the config from the given YAML file path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open %q: %w", path, err)
	}
	defer f.Close()

	cfg := defaults()
	if err := yaml.NewDecoder(f).Decode(cfg); err != nil {
		return nil, fmt.Errorf("config: decode: %w", err)
	}

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("config: validate: %w", err)
	}
	return cfg, nil
}

func defaults() *Config {
	return &Config{
		Agent: AgentConfig{
			Version: "0.1.0",
		},
		Collector: CollectorConfig{
			EventLog: EventLogConfig{
				Enabled:      true,
				Channels:     []string{"Security", "System", "Application"},
				PollInterval: 5 * time.Second,
			},
			Sysmon:  SysmonConfig{Enabled: true},
			Network: NetworkConfig{Enabled: true, PollInterval: 30 * time.Second},
			Process: ProcessConfig{Enabled: true},
			Registry: RegistryConfig{
				Enabled: true,
				Keys: []string{
					`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
					`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
				},
			},
		},
		Forwarder: ForwarderConfig{
			BatchSize:     200,
			FlushInterval: 5 * time.Second,
		},
		Queue: QueueConfig{
			DBPath:  "agent_queue.db",
			MaxRows: 100_000,
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

func validate(cfg *Config) error {
	if cfg.Forwarder.BackendURL == "" {
		return fmt.Errorf("forwarder.backend_url is required")
	}
	if cfg.Forwarder.BatchSize <= 0 {
		return fmt.Errorf("forwarder.batch_size must be > 0")
	}
	return nil
}
