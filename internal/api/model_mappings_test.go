package api

import (
	"testing"

	"turnsapi/internal"
)

func TestApplyModelMappings_KeepOriginalModelWhenAliasExists(t *testing.T) {
	s := &MultiProviderServer{}
	group := &internal.UserGroup{
		ModelMappings: map[string]string{
			"deepseek-chat": "deepseek-v3",
		},
	}

	models := []map[string]interface{}{
		{
			"id":       "deepseek-v3",
			"object":   "model",
			"owned_by": "deepseek",
		},
		{
			"id":       "deepseek-r1",
			"object":   "model",
			"owned_by": "deepseek",
		},
	}

	got := s.applyModelMappings(models, group, false)

	var aliasEntry map[string]interface{}
	var originalEntry map[string]interface{}
	var otherEntry map[string]interface{}

	for _, m := range got {
		id, _ := m["id"].(string)
		switch id {
		case "deepseek-chat":
			aliasEntry = m
		case "deepseek-v3":
			originalEntry = m
		case "deepseek-r1":
			otherEntry = m
		}
	}

	if aliasEntry == nil {
		t.Fatalf("alias model not found in result")
	}
	if originalEntry == nil {
		t.Fatalf("original model not found in result")
	}
	if otherEntry == nil {
		t.Fatalf("unmapped model should remain in result")
	}

	if isAlias, _ := aliasEntry["is_alias"].(bool); !isAlias {
		t.Fatalf("alias entry is_alias = %#v, want true", aliasEntry["is_alias"])
	}
	if originalModel, _ := aliasEntry["original_model"].(string); originalModel != "deepseek-v3" {
		t.Fatalf("alias original_model = %q, want %q", originalModel, "deepseek-v3")
	}

	if isOriginal, _ := originalEntry["is_original"].(bool); !isOriginal {
		t.Fatalf("original entry is_original = %#v, want true", originalEntry["is_original"])
	}
	aliases, ok := originalEntry["has_aliases"].([]string)
	if !ok || len(aliases) != 1 || aliases[0] != "deepseek-chat" {
		t.Fatalf("original entry has_aliases = %#v, want [deepseek-chat]", originalEntry["has_aliases"])
	}
}

func TestApplyModelMappings_EnforceModelMappingsHidesOriginalModel(t *testing.T) {
	s := &MultiProviderServer{}
	group := &internal.UserGroup{
		ModelMappings: map[string]string{
			"deepseek-chat": "deepseek-v3",
		},
	}

	models := []map[string]interface{}{
		{
			"id":       "deepseek-v3",
			"object":   "model",
			"owned_by": "deepseek",
		},
		{
			"id":       "deepseek-r1",
			"object":   "model",
			"owned_by": "deepseek",
		},
	}

	got := s.applyModelMappings(models, group, true)

	var aliasEntry map[string]interface{}
	var originalEntry map[string]interface{}
	var otherEntry map[string]interface{}

	for _, m := range got {
		id, _ := m["id"].(string)
		switch id {
		case "deepseek-chat":
			aliasEntry = m
		case "deepseek-v3":
			originalEntry = m
		case "deepseek-r1":
			otherEntry = m
		}
	}

	if aliasEntry == nil {
		t.Fatalf("alias model not found in result")
	}
	if originalEntry != nil {
		t.Fatalf("original model should be hidden when enforcement is enabled")
	}
	if otherEntry == nil {
		t.Fatalf("unmapped model should remain in result")
	}

	if isAlias, _ := aliasEntry["is_alias"].(bool); !isAlias {
		t.Fatalf("alias entry is_alias = %#v, want true", aliasEntry["is_alias"])
	}
	if _, exists := aliasEntry["original_model"]; exists {
		t.Fatalf("alias entry should not expose original_model when enforcement is enabled: %#v", aliasEntry["original_model"])
	}
}
