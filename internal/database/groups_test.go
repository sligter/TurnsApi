package database

import (
	"path/filepath"
	"testing"
	"time"
)

func TestGroupsDBPersistsAdvancedGroupFields(t *testing.T) {
	db, err := NewGroupsDB(filepath.Join(t.TempDir(), "groups.db"))
	if err != nil {
		t.Fatalf("NewGroupsDB() error = %v", err)
	}
	defer db.Close()

	group := &UserGroup{
		Name:                "Primary",
		ProviderType:        "openai",
		BaseURL:             "https://example.com/v1",
		APIVersion:          "2024-02-15-preview",
		Enabled:             true,
		Timeout:             45 * time.Second,
		MaxRetries:          4,
		RotationStrategy:    "round_robin",
		APIKeys:             []string{"key-1", "key-2"},
		Models:              []string{"gpt-4o-mini"},
		Headers:             map[string]string{"Content-Type": "application/json"},
		RequestParams:       map[string]interface{}{"temperature": 0.2},
		ModelMappings:       map[string]string{"chat-model": "gpt-4o-mini"},
		UseNativeResponse:   true,
		UseResponsesAPI:     true,
		RPMLimit:            120,
		DisablePermanentBan: true,
		MaxErrorCount:       9,
		RateLimitCooldown:   180,
	}

	if err := db.SaveGroup("g1", group); err != nil {
		t.Fatalf("SaveGroup() error = %v", err)
	}

	loaded, err := db.LoadGroup("g1")
	if err != nil {
		t.Fatalf("LoadGroup() error = %v", err)
	}

	if loaded.APIVersion != group.APIVersion {
		t.Fatalf("APIVersion = %q, want %q", loaded.APIVersion, group.APIVersion)
	}
	if loaded.DisablePermanentBan != group.DisablePermanentBan {
		t.Fatalf("DisablePermanentBan = %v, want %v", loaded.DisablePermanentBan, group.DisablePermanentBan)
	}
	if loaded.MaxErrorCount != group.MaxErrorCount {
		t.Fatalf("MaxErrorCount = %d, want %d", loaded.MaxErrorCount, group.MaxErrorCount)
	}
	if loaded.RateLimitCooldown != group.RateLimitCooldown {
		t.Fatalf("RateLimitCooldown = %d, want %d", loaded.RateLimitCooldown, group.RateLimitCooldown)
	}
	if len(loaded.APIKeys) != 2 || loaded.APIKeys[0] != "key-1" || loaded.APIKeys[1] != "key-2" {
		t.Fatalf("APIKeys = %v, want [key-1 key-2]", loaded.APIKeys)
	}

	metadata, err := db.GetGroupsWithMetadata()
	if err != nil {
		t.Fatalf("GetGroupsWithMetadata() error = %v", err)
	}

	groupInfo, ok := metadata["g1"]
	if !ok {
		t.Fatalf("metadata missing group g1")
	}

	if got, ok := groupInfo["api_version"].(string); !ok || got != group.APIVersion {
		t.Fatalf("metadata api_version = %#v, want %q", groupInfo["api_version"], group.APIVersion)
	}
	if got, ok := groupInfo["disable_permanent_ban"].(bool); !ok || got != group.DisablePermanentBan {
		t.Fatalf("metadata disable_permanent_ban = %#v, want %v", groupInfo["disable_permanent_ban"], group.DisablePermanentBan)
	}
	if got, ok := groupInfo["max_error_count"].(int); !ok || got != group.MaxErrorCount {
		t.Fatalf("metadata max_error_count = %#v, want %d", groupInfo["max_error_count"], group.MaxErrorCount)
	}
	if got, ok := groupInfo["rate_limit_cooldown"].(int); !ok || got != group.RateLimitCooldown {
		t.Fatalf("metadata rate_limit_cooldown = %#v, want %d", groupInfo["rate_limit_cooldown"], group.RateLimitCooldown)
	}
}
