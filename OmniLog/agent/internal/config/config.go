package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// AgentConfig holds the configuration for the dedicated Force-Fields Agent.
type AgentConfig struct {
	AgentID           string `json:"agent_id" yaml:"agent_id"`
	ManagerURL        string `json:"manager_url" yaml:"manager_url"`
	APIKey            string `json:"api_key" yaml:"api_key"`
	OSCategory        string `json:"os_category" yaml:"os_category"`
	BatchSize         int    `json:"batch_size" yaml:"batch_size"`
	HeartbeatInterval int    `json:"heartbeat_interval" yaml:"heartbeat_interval"` // in seconds
	QueueDir          string `json:"queue_dir" yaml:"queue_dir"`
	StateFile         string `json:"state_file" yaml:"state_file"`
}

// DefaultConfig returns default runtime configuration.
func DefaultConfig() *AgentConfig {
	return &AgentConfig{
		AgentID:           "",
		ManagerURL:        "http://localhost:8000",
		APIKey:            "",
		OSCategory:        "",
		BatchSize:         100,
		HeartbeatInterval: 10,
		QueueDir:          "./data/queue",
		StateFile:         "./data/offsets.json",
	}
}

// LoadConfig reads the configuration file (YAML or key-value format).
func LoadConfig(path string) (*AgentConfig, error) {
	cfg := DefaultConfig()

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"'`)

		switch key {
		case "agent_id":
			cfg.AgentID = val
		case "manager_url":
			cfg.ManagerURL = strings.TrimRight(val, "/")
		case "api_key":
			cfg.APIKey = val
		case "os_category":
			cfg.OSCategory = val
		case "batch_size":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				cfg.BatchSize = n
			}
		case "heartbeat_interval":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				cfg.HeartbeatInterval = n
			}
		case "queue_dir":
			cfg.QueueDir = val
		case "state_file":
			cfg.StateFile = val
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// SaveConfig persists the configuration to disk in clean YAML format.
func SaveConfig(path string, cfg *AgentConfig) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	content := fmt.Sprintf(`# Force-Fields Agent Configuration
agent_id: %s
manager_url: %s
api_key: %s
os_category: %s
batch_size: %d
heartbeat_interval: %d
queue_dir: %s
state_file: %s
`, cfg.AgentID, cfg.ManagerURL, cfg.APIKey, cfg.OSCategory, cfg.BatchSize, cfg.HeartbeatInterval, cfg.QueueDir, cfg.StateFile)

	return os.WriteFile(path, []byte(content), 0600)
}
