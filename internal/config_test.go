package internal

import (
	"os"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	configContent := `
server:
  port: "8080"
  host: "0.0.0.0"
  mode: "release"

auth:
  enabled: true
  username: "admin"
  password: "test123"
  session_timeout: 24h

user_groups:
  openai_group:
    name: "OpenAI Official"
    provider_type: "openai"
    base_url: "https://api.openai.com/v1"
    enabled: true
    timeout: 30s
    max_retries: 3
    rotation_strategy: "round_robin"
    api_keys:
      - "sk-test-key-1"
      - "sk-test-key-2"
    headers:
      Content-Type: "application/json"

  gemini_group:
    name: "Google Gemini"
    provider_type: "gemini"
    base_url: "https://generativelanguage.googleapis.com/v1beta"
    enabled: true
    timeout: 30s
    max_retries: 3
    rotation_strategy: "random"
    api_keys:
      - "gemini-key-1"
    models:
      - "gemini-pro"
      - "gemini-pro-vision"

global_settings:
  default_rotation_strategy: "round_robin"
  default_timeout: 30s
  default_max_retries: 3

monitoring:
  enabled: true
  metrics_endpoint: "/metrics"
  health_endpoint: "/health"

logging:
  level: "info"
  file: "logs/turnsapi.log"

database:
  path: "data/turnsapi.db"
  retention_days: 30
`

	// Write to temporary file
	tmpFile, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpFile.Close()

	// Load config
	config, err := LoadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test basic server config
	if config.Server.Port != "8080" {
		t.Errorf("Expected port 8080, got %s", config.Server.Port)
	}

	if config.Server.Host != "0.0.0.0" {
		t.Errorf("Expected host 0.0.0.0, got %s", config.Server.Host)
	}

	if config.Server.Mode != "release" {
		t.Errorf("Expected mode release, got %s", config.Server.Mode)
	}

	// Test auth config
	if !config.Auth.Enabled {
		t.Error("Expected auth to be enabled")
	}

	if config.Auth.Username != "admin" {
		t.Errorf("Expected username admin, got %s", config.Auth.Username)
	}

	if config.Auth.SessionTimeout != 24*time.Hour {
		t.Errorf("Expected session timeout 24h, got %v", config.Auth.SessionTimeout)
	}

	// Test user groups
	if len(config.UserGroups) != 2 {
		t.Errorf("Expected 2 user groups, got %d", len(config.UserGroups))
	}

	// Test OpenAI group
	openaiGroup, exists := config.UserGroups["openai_group"]
	if !exists {
		t.Error("Expected openai_group to exist")
	} else {
		if openaiGroup.Name != "OpenAI Official" {
			t.Errorf("Expected name 'OpenAI Official', got %s", openaiGroup.Name)
		}

		if openaiGroup.ProviderType != "openai" {
			t.Errorf("Expected provider_type 'openai', got %s", openaiGroup.ProviderType)
		}

		if !openaiGroup.Enabled {
			t.Error("Expected openai_group to be enabled")
		}

		if len(openaiGroup.APIKeys) != 2 {
			t.Errorf("Expected 2 API keys, got %d", len(openaiGroup.APIKeys))
		}

		if openaiGroup.RotationStrategy != "round_robin" {
			t.Errorf("Expected rotation_strategy 'round_robin', got %s", openaiGroup.RotationStrategy)
		}
	}

	// Test Gemini group
	geminiGroup, exists := config.UserGroups["gemini_group"]
	if !exists {
		t.Error("Expected gemini_group to exist")
	} else {
		if geminiGroup.ProviderType != "gemini" {
			t.Errorf("Expected provider_type 'gemini', got %s", geminiGroup.ProviderType)
		}

		if len(geminiGroup.Models) != 2 {
			t.Errorf("Expected 2 models, got %d", len(geminiGroup.Models))
		}

		if geminiGroup.RotationStrategy != "random" {
			t.Errorf("Expected rotation_strategy 'random', got %s", geminiGroup.RotationStrategy)
		}
	}

	// Test global settings
	if config.GlobalSettings.DefaultRotationStrategy != "round_robin" {
		t.Errorf("Expected default_rotation_strategy 'round_robin', got %s", config.GlobalSettings.DefaultRotationStrategy)
	}

	// 移除了健康检查间隔的测试

	// Test monitoring
	if !config.Monitoring.Enabled {
		t.Error("Expected monitoring to be enabled")
	}

	if config.Monitoring.MetricsEndpoint != "/metrics" {
		t.Errorf("Expected metrics_endpoint '/metrics', got %s", config.Monitoring.MetricsEndpoint)
	}
}

func TestBackwardCompatibility(t *testing.T) {
	// Create a legacy config file
	legacyConfigContent := `
server:
  port: "8080"
  host: "0.0.0.0"

openrouter:
  base_url: "https://openrouter.ai/api/v1"
  timeout: 30s
  max_retries: 3

api_keys:
  keys:
    - "or-key-1"
    - "or-key-2"
  rotation_strategy: "round_robin"

logging:
  level: "info"

database:
  path: "data/turnsapi.db"
  retention_days: 30
`

	// Write to temporary file
	tmpFile, err := os.CreateTemp("", "legacy_config_test_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(legacyConfigContent); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpFile.Close()

	// Load config
	config, err := LoadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load legacy config: %v", err)
	}

	// Test that default mode is set for legacy config
	if config.Server.Mode != "release" {
		t.Errorf("Expected default mode 'release', got %s", config.Server.Mode)
	}

	// Should create a default OpenRouter group
	if len(config.UserGroups) != 1 {
		t.Errorf("Expected 1 user group (default), got %d", len(config.UserGroups))
	}

	defaultGroup, exists := config.UserGroups["openrouter_default"]
	if !exists {
		t.Error("Expected openrouter_default group to be created")
	} else {
		if defaultGroup.ProviderType != "openai" {
			t.Errorf("Expected provider_type 'openai', got %s", defaultGroup.ProviderType)
		}

		if defaultGroup.BaseURL != "https://openrouter.ai/api/v1" {
			t.Errorf("Expected base_url from legacy config, got %s", defaultGroup.BaseURL)
		}

		if len(defaultGroup.APIKeys) != 2 {
			t.Errorf("Expected 2 API keys from legacy config, got %d", len(defaultGroup.APIKeys))
		}

		if !defaultGroup.Enabled {
			t.Error("Expected default group to be enabled")
		}
	}

	// Test that it's detected as legacy config
	if !config.IsLegacyConfig() {
		t.Error("Expected config to be detected as legacy")
	}
}

func TestGetEnabledGroups(t *testing.T) {
	config := &Config{
		UserGroups: map[string]*UserGroup{
			"group1": {
				Name:    "Group 1",
				Enabled: true,
			},
			"group2": {
				Name:    "Group 2",
				Enabled: false,
			},
			"group3": {
				Name:    "Group 3",
				Enabled: true,
			},
		},
	}

	enabledGroups := config.GetEnabledGroups()

	if len(enabledGroups) != 2 {
		t.Errorf("Expected 2 enabled groups, got %d", len(enabledGroups))
	}

	if _, exists := enabledGroups["group1"]; !exists {
		t.Error("Expected group1 to be in enabled groups")
	}

	if _, exists := enabledGroups["group2"]; exists {
		t.Error("Expected group2 to not be in enabled groups")
	}

	if _, exists := enabledGroups["group3"]; !exists {
		t.Error("Expected group3 to be in enabled groups")
	}
}

func TestGetGroupByModel(t *testing.T) {
	config := &Config{
		UserGroups: map[string]*UserGroup{
			"openai_group": {
				Name:         "OpenAI",
				ProviderType: "openai",
				Enabled:      true,
				Models:       []string{"gpt-3.5-turbo", "gpt-4"},
			},
			"gemini_group": {
				Name:         "Gemini",
				ProviderType: "gemini",
				Enabled:      true,
				Models:       []string{"gemini-pro"},
			},
			"disabled_group": {
				Name:         "Disabled",
				ProviderType: "openai",
				Enabled:      false,
				Models:       []string{"gpt-3.5-turbo"},
			},
			"all_models_group": {
				Name:         "All Models",
				ProviderType: "anthropic",
				Enabled:      true,
				Models:       []string{}, // Empty means supports all models
			},
		},
	}

	// Test specific model match
	group, groupID := config.GetGroupByModel("gpt-3.5-turbo")
	if group == nil {
		t.Error("Expected to find group for gpt-3.5-turbo")
	} else if groupID != "openai_group" {
		t.Errorf("Expected openai_group, got %s", groupID)
	}

	// Test model in different group
	group, groupID = config.GetGroupByModel("gemini-pro")
	if group == nil {
		t.Error("Expected to find group for gemini-pro")
	} else if groupID != "gemini_group" {
		t.Errorf("Expected gemini_group, got %s", groupID)
	}

	// Test model not in any specific group (should return group with empty models list)
	group, groupID = config.GetGroupByModel("unknown-model")
	if group == nil {
		t.Error("Expected to find group for unknown-model")
	} else if groupID != "all_models_group" {
		t.Errorf("Expected all_models_group, got %s", groupID)
	}

	// Test disabled group is not returned
	config.UserGroups["openai_group"].Enabled = false
	group, _ = config.GetGroupByModel("gpt-3.5-turbo")
	if group != nil && group.Name == "OpenAI" {
		t.Error("Expected not to find disabled group")
	}
}

func TestGetAddress(t *testing.T) {
	config := &Config{
		Server: struct {
			Port string `yaml:"port"`
			Host string `yaml:"host"`
			Mode string `yaml:"mode"`
		}{
			Port: "8080",
			Host: "localhost",
			Mode: "release",
		},
	}

	address := config.GetAddress()
	expected := "localhost:8080"

	if address != expected {
		t.Errorf("Expected address %s, got %s", expected, address)
	}
}
