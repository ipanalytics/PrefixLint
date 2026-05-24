package prefixlint

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	Rules map[string]string `json:"rules"`
}

func LoadConfig(path string) (Config, error) {
	if path == "" {
		return Config{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	for rule, severity := range cfg.Rules {
		if severity == "off" {
			continue
		}
		parsed, err := ParseSeverityThreshold(severity)
		if err != nil || parsed == SeverityNone {
			return Config{}, fmt.Errorf("invalid severity %q for rule %q", severity, rule)
		}
	}
	return cfg, nil
}

func applyConfig(findings []Finding, cfg Config) []Finding {
	if len(cfg.Rules) == 0 {
		return findings
	}
	out := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if severity, ok := cfg.Rules[finding.Rule]; ok {
			if severity == "off" {
				continue
			}
			finding.Severity = severity
		}
		out = append(out, finding)
	}
	return out
}
