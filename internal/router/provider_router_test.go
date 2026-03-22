package router

import (
	"testing"
	"time"

	"turnsapi/internal"
)

func newTestProviderRouter() *ProviderRouter {
	return &ProviderRouter{
		config: &internal.Config{
			UserGroups: map[string]*internal.UserGroup{
				"deepseek": {
					Name:         "DeepSeek",
					ProviderType: "openai",
					Enabled:      true,
					Timeout:      time.Second,
					Models:       []string{"deepseek-v3", "deepseek-r1"},
					ModelMappings: map[string]string{
						"deepseek-chat": "deepseek-v3",
					},
				},
				"gemini": {
					Name:         "Gemini",
					ProviderType: "gemini",
					Enabled:      true,
					Timeout:      time.Second,
					Models:       []string{"gemini-2.5-pro"},
					ModelMappings: map[string]string{
						"gemini-pro": "gemini-2.5-pro",
					},
				},
				"plain-openai": {
					Name:         "OpenAI",
					ProviderType: "openai",
					Enabled:      true,
					Timeout:      time.Second,
					Models:       []string{"gpt-4o"},
				},
			},
		},
	}
}

func TestGetGroupsForModel_EnforceModelMappingsBlocksOriginalName(t *testing.T) {
	pr := newTestProviderRouter()

	got := pr.GetGroupsForModel("deepseek-v3", []string{"deepseek", "plain-openai"}, true)
	if len(got) != 0 {
		t.Fatalf("GetGroupsForModel() with enforcement returned %v, want no groups for original model", got)
	}

	aliasGroups := pr.GetGroupsForModel("deepseek-chat", []string{"deepseek", "plain-openai"}, true)
	if len(aliasGroups) != 1 || aliasGroups[0] != "deepseek" {
		t.Fatalf("GetGroupsForModel() alias groups = %v, want [deepseek]", aliasGroups)
	}
}

func TestGetGroupsForModel_WithoutEnforcementKeepsOriginalNameAvailable(t *testing.T) {
	pr := newTestProviderRouter()

	got := pr.GetGroupsForModel("deepseek-v3", []string{"deepseek", "plain-openai"}, false)
	if len(got) != 1 || got[0] != "deepseek" {
		t.Fatalf("GetGroupsForModel() without enforcement = %v, want [deepseek]", got)
	}
}

func TestGetGroupsByProviderType_EnforceModelMappingsBlocksOriginalName(t *testing.T) {
	pr := newTestProviderRouter()

	got := pr.GetGroupsByProviderType("gemini", []string{"gemini"}, "gemini-2.5-pro", true)
	if len(got) != 0 {
		t.Fatalf("GetGroupsByProviderType() with original model returned %v, want no groups", got)
	}

	aliasGroups := pr.GetGroupsByProviderType("gemini", []string{"gemini"}, "gemini-pro", true)
	if len(aliasGroups) != 1 || aliasGroups[0] != "gemini" {
		t.Fatalf("GetGroupsByProviderType() alias groups = %v, want [gemini]", aliasGroups)
	}
}
